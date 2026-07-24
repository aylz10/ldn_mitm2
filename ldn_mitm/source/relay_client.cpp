/*
 * Copyright (c) 2018 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "relay_client.hpp"
#include "debug.hpp"
#include "nifm_manager.hpp"
#include "session_registry.hpp"
#include "ldnmitm_config.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <sys/time.h>
#include <atomic>
#include <mutex>
#include <cstdio>

namespace ams::mitm::ldn::relay {

    namespace {
        /* lan-play relay message types (switch-lan-play/src/lan-client.c). */
        constexpr u8 TypeKeepalive = 0x00;
        constexpr u8 TypeIpv4      = 0x01;
        constexpr u8 TypePing      = 0x02;
        constexpr u8 TypeIpv4Frag  = 0x03;

        /* 1500 MTU minus relay type, IP and UDP headers. */
        constexpr size_t MaxWrapPayload = 1500 - 1 - 20 - 8;

        u16 IpChecksum(const u8 *d, size_t n) {
            u32 s = 0;
            for (size_t i = 0; i + 1 < n; i += 2) {
                s += (static_cast<u32>(d[i]) << 8) | d[i + 1];
            }
            if (n & 1) {
                s += static_cast<u32>(d[n - 1]) << 8;
            }
            while (s >> 16) {
                s = (s & 0xffff) + (s >> 16);
            }
            return static_cast<u16>(~s & 0xffff);
        }

        /* ip is 0 when host is a hostname. */
        struct Server { char name[ServerNameLen]; char host[64]; u32 ip; u16 port; };
        Server g_servers[MaxServers];
        int g_count = 0;
        std::atomic_int  g_selected{0};
        std::atomic_bool g_enabled{false};
    }

    namespace {
        /* "name", "name=value" or "name value"; nullptr if not this directive. */
        const char *DirectiveValue(const char *l, const char *name) {
            const size_t n = std::strlen(name);
            if (std::strncmp(l, name, n) != 0) {
                return nullptr;
            }
            const char c = l[n];
            if (c != '\0' && c != '=' && c != ' ' && c != '\t') {
                return nullptr;
            }
            const char *v = l + n;
            while (*v == '=' || *v == ' ' || *v == '\t') { v++; }
            return v;
        }

        bool IsDirectiveLine(const char *l) {
            return DirectiveValue(l, "enabled")   != nullptr ||
                   DirectiveValue(l, "broadcast") != nullptr ||
                   DirectiveValue(l, "selected")  != nullptr;
        }

        void ReadConfigFile(char *buf, size_t cap) {
            buf[0] = '\0';
            fs::FileHandle f;
            if (R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Read))) {
                return;
            }
            s64 size = 0;
            if (R_SUCCEEDED(fs::GetFileSize(std::addressof(size), f)) && size > 0) {
                const size_t n = static_cast<size_t>(size) < cap - 1 ? static_cast<size_t>(size) : cap - 1;
                if (R_SUCCEEDED(fs::ReadFile(f, 0, buf, n))) {
                    buf[n] = '\0';
                }
            }
            fs::CloseFile(f);
        }
    }

    void LoadConfig() {
        /* Format: docs/relay.cfg.example. */
        g_count = 0;
        g_selected = 0;
        g_enabled = false;
        char pending_selected[ServerNameLen] = {};

        char buf[1024];
        ReadConfigFile(buf, sizeof(buf));

        char *save = nullptr;
        for (char *line = strtok_r(buf, "\r\n", std::addressof(save));
             line != nullptr && g_count < MaxServers;
             line = strtok_r(nullptr, "\r\n", std::addressof(save))) {
            while (*line == ' ' || *line == '\t') { line++; }
            if (*line == '#' || *line == '\0') {
                continue;
            }
            if (const char *v = DirectiveValue(line, "enabled")) {
                g_enabled = (std::atoi(v) != 0);
                continue;
            }
            if (const char *v = DirectiveValue(line, "broadcast")) {
                LdnConfig::setBroadcastRelay(std::atoi(v) != 0);
                continue;
            }
            if (const char *v = DirectiveValue(line, "selected")) {
                std::strncpy(pending_selected, v, sizeof(pending_selected) - 1);
                continue;
            }
            char name[ServerNameLen] = {};
            char addr[64] = {};
            if (std::sscanf(line, "%31s %63s", name, addr) < 2) {
                if (std::sscanf(line, "%63s", addr) < 1) {
                    continue;
                }
                std::strncpy(name, addr, sizeof(name) - 1);
            }

            unsigned port = 11451;
            char *colon = std::strchr(addr, ':');
            if (colon != nullptr) {
                *colon = '\0';
                port = static_cast<unsigned>(std::atoi(colon + 1));
            }
            if (addr[0] == '\0' || port == 0 || port > 65535) {
                continue;
            }
            unsigned a = 0, b = 0, c = 0, d = 0;
            u32 ip = 0;
            if (std::sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
                a <= 255 && b <= 255 && c <= 255 && d <= 255) {
                ip = (a << 24) | (b << 16) | (c << 8) | d;
            }

            Server &s = g_servers[g_count];
            std::strncpy(s.name, name, sizeof(s.name) - 1);
            s.name[sizeof(s.name) - 1] = '\0';
            std::strncpy(s.host, addr, sizeof(s.host) - 1);
            s.host[sizeof(s.host) - 1] = '\0';
            s.ip   = ip;
            s.port = static_cast<u16>(port);
            g_count++;
        }

        for (char *e = pending_selected + std::strlen(pending_selected);
             e > pending_selected && (e[-1] == ' ' || e[-1] == '\t'); ) {
            *--e = '\0';
        }
        if (pending_selected[0] != '\0') {
            for (int i = 0; i < g_count; i++) {
                if (std::strcmp(g_servers[i].name, pending_selected) == 0) {
                    g_selected = i;
                    break;
                }
            }
        }
        LogFormat("relay: loaded %d server(s), selected %d", g_count, g_selected.load());
    }

    namespace {
        void PersistConfig() {
            char buf[1024];
            ReadConfigFile(buf, sizeof(buf));
            fs::FileHandle f;

            char out[1280];
            size_t pos = static_cast<size_t>(std::snprintf(out, sizeof(out), "enabled=%d\nbroadcast=%d\n",
                g_enabled.load() ? 1 : 0, LdnConfig::getBroadcastRelay() ? 1 : 0));
            const int sel = g_selected.load();
            if (sel >= 0 && sel < g_count) {
                pos += static_cast<size_t>(std::snprintf(out + pos, sizeof(out) - pos,
                    "selected=%s\n", g_servers[sel].name));
            }

            char *save = nullptr;
            for (char *line = strtok_r(buf, "\r\n", std::addressof(save));
                 line != nullptr;
                 line = strtok_r(nullptr, "\r\n", std::addressof(save))) {
                const char *p = line;
                while (*p == ' ' || *p == '\t') { p++; }
                if (IsDirectiveLine(p)) {
                    continue;
                }
                const size_t need = std::strlen(line) + 1;
                if (pos + need >= sizeof(out)) {
                    break;
                }
                std::memcpy(out + pos, line, need - 1);
                out[pos + need - 1] = '\n';
                pos += need;
            }

            if (R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) {
                if (R_FAILED(fs::CreateFile(RelayConfigPath, 0)) ||
                    R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) {
                    LogFormat("relay: persisting settings failed (open)");
                    return;
                }
            }
            fs::SetFileSize(f, 0);
            if (R_FAILED(fs::WriteFile(f, 0, out, pos, fs::WriteOption::Flush))) {
                LogFormat("relay: persisting settings failed (write)");
            }
            fs::CloseFile(f);
        }
    }

    void PersistSettings()    { PersistConfig(); }

    bool IsEnabled()          { return g_enabled.load() && g_count > 0; }
    void SetRelayEnabled(bool on) { g_enabled = on; PersistConfig(); }
    bool GetRelayEnabled()    { return g_enabled.load(); }

    int  ServerCount()        { return g_count; }
    const char *ServerName(int i) { return (i >= 0 && i < g_count) ? g_servers[i].name : ""; }

    int  SelectedServer()     { return g_selected.load(); }
    void SelectServer(int i)  { if (i >= 0 && i < g_count) { g_selected = i; PersistConfig(); } }

    u32  ServerIp() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].ip : 0;
    }
    const char *ServerHost() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].host : "";
    }
    u16  ServerPort() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].port : 0;
    }

    /* Bridge sends run under g_bridge_mutex, so a transport is unused once
       unpublished. */
    namespace {
        constinit os::SdkMutex g_bridge_mutex;
        constinit RelayTransport *g_bridge_transport = nullptr;
    }

    int BridgeSendGameBroadcast(const void *payload, size_t len, u16 dport) {
        std::scoped_lock lk(g_bridge_mutex);
        if (g_bridge_transport == nullptr) {
            return -1;
        }
        return g_bridge_transport->SendGameBroadcast(payload, len, dport);
    }

    int BridgeSendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip) {
        std::scoped_lock lk(g_bridge_mutex);
        if (g_bridge_transport == nullptr) {
            return -1;
        }
        return g_bridge_transport->SendGameUnicast(payload, len, dport, dst_ip);
    }

    u32 RelayTransport::ResolveHostname(const char *host) {
        if (host == nullptr || host[0] == '\0') {
            return 0;
        }
        u32 a = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
        nifmGetCurrentIpConfigInfo(&a, &mask, &gw, &dns1, &dns2);

        struct sockaddr_in srv = {};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(53);
        srv.sin_addr.s_addr = (dns1 != 0) ? dns1 : htonl(0x08080808u);

        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            return 0;
        }
        if (m_have_req) {
            nifmRequestRegisterSocketDescriptor(&m_req, fd);
        }
        struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        auto cleanup = [&]() {
            if (m_have_req) { nifmRequestUnregisterSocketDescriptor(&m_req, fd); }
            close(fd);
        };

        u8 q[300];
        size_t p = 0;
        /* DNS header: id, flags=RD, qdcount=1, an/ns/ar=0; then qname, qtype A, qclass IN. */
        q[p++] = 0x13; q[p++] = 0x37;
        q[p++] = 0x01; q[p++] = 0x00;
        q[p++] = 0x00; q[p++] = 0x01;
        q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0;
        const char *s = host;
        while (*s != '\0') {
            const char *dot = std::strchr(s, '.');
            const size_t len = dot ? static_cast<size_t>(dot - s) : std::strlen(s);
            if (len == 0 || len > 63 || p + len + 6 >= sizeof(q)) {
                cleanup();
                return 0;
            }
            q[p++] = static_cast<u8>(len);
            std::memcpy(q + p, s, len);
            p += len;
            s += len;
            if (*s == '.') { s++; }
        }
        q[p++] = 0x00;
        q[p++] = 0x00; q[p++] = 0x01;
        q[p++] = 0x00; q[p++] = 0x01;

        if (::sendto(fd, q, p, 0, reinterpret_cast<struct sockaddr *>(&srv), sizeof(srv)) < 0) {
            cleanup();
            return 0;
        }

        u8 r[512];
        const ssize_t n = ::recvfrom(fd, r, sizeof(r), 0, nullptr, nullptr);
        cleanup();
        if (n < 12) {
            return 0;
        }
        const int ancount = (r[6] << 8) | r[7];
        if (ancount < 1) {
            return 0;
        }

        size_t off = 12;
        while (off < static_cast<size_t>(n) && r[off] != 0) {
            if ((r[off] & 0xc0) == 0xc0) { off += 1; break; }
            off += r[off] + 1;
        }
        off += 1 + 4;

        for (int i = 0; i < ancount && off + 12 <= static_cast<size_t>(n); i++) {
            if ((r[off] & 0xc0) == 0xc0) {
                off += 2;
            } else {
                while (off < static_cast<size_t>(n) && r[off] != 0) { off += r[off] + 1; }
                off += 1;
            }
            if (off + 10 > static_cast<size_t>(n)) {
                break;
            }
            const int type  = (r[off] << 8) | r[off + 1];
            const int rdlen = (r[off + 8] << 8) | r[off + 9];
            off += 10;
            if (type == 1 && rdlen == 4 && off + 4 <= static_cast<size_t>(n)) {
                return (r[off] << 24) | (r[off + 1] << 16) | (r[off + 2] << 8) | r[off + 3];
            }
            off += rdlen;
        }
        return 0;
    }

    Result RelayTransport::Open() {
        /* Internet route, not LocalNetworkMode. */
        Result rc = NifmSessionManager::Acquire();
        if (R_FAILED(rc)) {
            LogFormat("relay xport: nifm acquire failed %x", rc);
            return rc;
        }
        m_have_nifm_session = true;

        rc = nifmCreateRequest(&m_req, true);
        if (R_FAILED(rc)) {
            LogFormat("relay xport: nifmCreateRequest %x", rc);
            this->Close();
            return rc;
        }
        m_have_req = true;

        rc = nifmRequestSubmitAndWait(&m_req);
        if (R_FAILED(rc)) {
            LogFormat("relay xport: submit %x", rc);
            this->Close();
            return rc;
        }
        /* Submit can return before the request is Available. */
        for (int i = 0; i < 10; i++) {
            NifmRequestState st = NifmRequestState_Invalid;
            if (R_FAILED(nifmGetRequestState(&m_req, &st)) || st == NifmRequestState_Available) {
                break;
            }
            svcSleepThread(500000000L);
        }

        /* Virtual src 10.13.<ip3>.<ip4>; game frames carry the real IP. */
        u32 ip = 0;
        if (R_SUCCEEDED(nifmGetCurrentIpAddress(&ip))) {
            ip = ntohl(ip);
            m_rsrc = ip;
            m_vsrc = (10u << 24) | (13u << 16) | (((ip >> 8) & 0xff) << 8) | (ip & 0xff);
        } else {
            m_rsrc = 0;
            m_vsrc = (10u << 24) | (13u << 16) | 0x0001;
        }

        u32 server_ip = ServerIp();
        if (server_ip == 0) {
            server_ip = this->ResolveHostname(ServerHost());
        }
        if (server_ip == 0) {
            LogFormat("relay xport: no/unresolvable server address ('%s')", ServerHost());
            this->Close();
            return MAKERESULT(0xFD, 102);
        }

        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LogFormat("relay xport: socket %d", errno);
            this->Close();
            return MAKERESULT(0xFD, 100);
        }

        struct sockaddr_in srv = {};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(ServerPort());
        srv.sin_addr.s_addr = htonl(server_ip);

        nifmRequestRegisterSocketDescriptor(&m_req, fd);

        int conn = -1;
        for (int i = 0; i < 3; i++) {
            conn = connect(fd, (struct sockaddr *)&srv, sizeof(srv));
            if (conn == 0) {
                break;
            }
            svcSleepThread(1000000000L);
        }
        if (conn != 0) {
            LogFormat("relay xport: connect failed %d", errno);
            nifmRequestUnregisterSocketDescriptor(&m_req, fd);
            close(fd);
            this->Close();
            return MAKERESULT(0xFD, 101);
        }

        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        m_fd = fd;
        m_ping_misses = 0;
        m_ping_supported = false;
        for (auto &f : m_frags) {
            f.used = false;
        }

        {
            std::scoped_lock lk(g_bridge_mutex);
            g_bridge_transport = this;
        }

        this->SendKeepalive();
        LogFormat("relay xport: open, vsrc=%08x rsrc=%08x fd=%d", m_vsrc, m_rsrc, m_fd);
        R_SUCCEED();
    }

    void RelayTransport::Close() {
        /* Unpublish before closing: bridge sends run under g_bridge_mutex. */
        {
            std::scoped_lock lk(g_bridge_mutex);
            if (g_bridge_transport == this) {
                g_bridge_transport = nullptr;
            }
        }
        if (m_fd >= 0) {
            if (m_have_req) {
                nifmRequestUnregisterSocketDescriptor(&m_req, m_fd);
            }
            close(m_fd);
            m_fd = -1;
        }
        if (m_have_req) {
            nifmRequestCancel(&m_req);
            nifmRequestClose(&m_req);
            m_have_req = false;
        }
        if (m_have_nifm_session) {
            NifmSessionManager::Release();
            m_have_nifm_session = false;
        }
    }

    int RelayTransport::SendKeepalive() {
        if (m_fd < 0) {
            return -1;
        }
        const u8 ka = TypeKeepalive;
        return send(m_fd, &ka, sizeof(ka), 0);
    }

    int RelayTransport::SendPing() {
        if (m_fd < 0) {
            return -1;
        }
        ++m_ping_misses;
        const u8 p[4] = { TypePing, 'l', 'd', 'n' };
        return send(m_fd, p, sizeof(p), 0);
    }

    bool RelayTransport::PathDead() const {
        return m_fd < 0 || (m_ping_supported && m_ping_misses >= PingMaxMisses);
    }

    int RelayTransport::SendWrapped(u32 src, u32 dst, u16 sport, u16 dport, u16 ip_id, const void *payload, size_t len) {
        u8 buf[1500];
        const u16 udplen = static_cast<u16>(8 + len);
        const u16 total  = static_cast<u16>(20 + udplen);
        buf[0] = TypeIpv4;
        u8 *ip = buf + 1;
        ip[0] = 0x45; ip[1] = 0x00; ip[2] = total >> 8; ip[3] = total & 0xff;
        ip[4] = ip_id >> 8; ip[5] = ip_id & 0xff; ip[6] = 0x40; ip[7] = 0x00;
        ip[8] = 64; ip[9] = 17; ip[10] = 0; ip[11] = 0;
        ip[12] = (src >> 24) & 0xff; ip[13] = (src >> 16) & 0xff;
        ip[14] = (src >> 8) & 0xff;  ip[15] = src & 0xff;
        ip[16] = (dst >> 24) & 0xff; ip[17] = (dst >> 16) & 0xff;
        ip[18] = (dst >> 8) & 0xff;  ip[19] = dst & 0xff;
        const u16 cs = IpChecksum(ip, 20);
        ip[10] = cs >> 8; ip[11] = cs & 0xff;
        u8 *udp = ip + 20;
        udp[0] = sport >> 8; udp[1] = sport & 0xff;
        udp[2] = dport >> 8; udp[3] = dport & 0xff;
        udp[4] = udplen >> 8; udp[5] = udplen & 0xff;
        udp[6] = 0; udp[7] = 0;
        std::memcpy(udp + 8, payload, len);
        return send(m_fd, buf, 1 + total, 0);
    }

    int RelayTransport::SendBroadcast(const void *lan_packet, size_t size) {
        if (m_fd < 0 || size > MaxWrapPayload) {
            return -1;
        }
        return this->SendWrapped(m_vsrc, 0x0A0DFFFFu, 11452, 11452, 0x4243, lan_packet, size);
    }

    int RelayTransport::SendGameBroadcast(const void *payload, size_t len, u16 dport) {
        return this->SendGameUnicast(payload, len, dport, 0xFFFFFFFFu);
    }

    int RelayTransport::SendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip) {
        if (m_fd < 0 || m_rsrc == 0 || len == 0 || len > MaxWrapPayload) {
            return -1;
        }
        /* sport = dport: SendTo does not expose the source port. */
        return this->SendWrapped(m_rsrc, dst_ip, dport, dport, 0x474D, payload, len);
    }

    void RelayTransport::InjectGameFrame(const u8 *ip, size_t iplen) {
        if (m_rsrc == 0) {
            return;
        }
        const size_t ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20 || ihl + 8 > iplen) {
            return;
        }
        const u8 *udp = ip + ihl;
        const u16 sport = (udp[0] << 8) | udp[1];
        const u16 dport = (udp[2] << 8) | udp[3];
        const u8 *payload = udp + 8;
        const size_t plen = (ip + iplen) - payload;
        if (plen == 0 || plen > MaxWrapPayload) {
            return;
        }
        const u32 src = (ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8) | ip[15];

        if (src == m_rsrc) {
            return;
        }
        SessionRegistry::Snapshot snap;
        SessionRegistry::Get(&snap);
        if (!snap.active) {
            return;
        }

        /* The local stack cannot deliver a foreign source IP; bsd:u RecvFrom
           serves it from GameRx instead. */
        GameRx::Push(src, sport, dport, payload, plen);
    }

    int RelayTransport::RecvBroadcast(void *out, size_t max_size, u32 *out_src_ip) {
        if (m_fd < 0) {
            return -1;
        }
        u8 buf[2048];
        const ssize_t n = recv(m_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            return (n == 0) ? 0 : -1;
        }
        m_ping_misses = 0;
        const u8 type = buf[0] & 0x7f;
        if (type == TypePing) {
            m_ping_supported = true;
            return 0;
        }
        if (type == TypeIpv4Frag) {
            size_t iplen = 0;
            const u8 *ip = this->ReassembleFrag(buf + 1, static_cast<size_t>(n) - 1, &iplen);
            if (ip == nullptr) {
                return 0;
            }
            return this->ProcessIpv4(ip, iplen, out, max_size, out_src_ip);
        }
        if (type != TypeIpv4) {
            return 0;
        }
        return this->ProcessIpv4(buf + 1, static_cast<size_t>(n) - 1, out, max_size, out_src_ip);
    }

    const u8 *RelayTransport::ReassembleFrag(const u8 *p, size_t n, size_t *out_len) {
        /* lan-play IPV4_FRAG header (16B, BE): src dst id part total_part len
           pmtu; the chunk sits at pmtu*part. */
        constexpr size_t HeaderLen = 16;
        if (n < HeaderLen) {
            return nullptr;
        }
        const u32 src   = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
        const u16 id    = (p[8] << 8) | p[9];
        const u8  part  = p[10];
        const u8  total = p[11];
        const u16 len   = (p[12] << 8) | p[13];
        const u16 pmtu  = (p[14] << 8) | p[15];
        const size_t off = static_cast<size_t>(pmtu) * part;
        /* Untrusted header: bound every field before use as an offset; the
           completion mask is 8 bits. */
        if (total == 0 || total > 8 || part >= total ||
            len > n - HeaderLen || off + len > sizeof(m_frags[0].buffer)) {
            return nullptr;
        }

        FragSlot *slot = nullptr;
        for (auto &f : m_frags) {
            if (f.used && f.id == id && f.src == src) {
                slot = &f;
                break;
            }
        }
        if (slot == nullptr) {
            for (auto &f : m_frags) {
                if (!f.used) {
                    slot = &f;
                    break;
                }
            }
            if (slot == nullptr) {
                slot = &m_frags[m_frag_evict++ % FragSlots];
            }
            slot->used = true;
            slot->id = id;
            slot->src = src;
            slot->mask = 0;
            slot->total_len = 0;
        }

        slot->mask |= 1u << part;
        std::memcpy(slot->buffer + off, p + HeaderLen, len);
        if (part == total - 1) {
            slot->total_len = static_cast<u16>(off + len);
        }
        if (slot->mask == static_cast<u8>(~(0xFFu << total))) {
            slot->used = false;
            *out_len = slot->total_len;
            return slot->buffer;
        }
        return nullptr;
    }

    int RelayTransport::ProcessIpv4(const u8 *ip, size_t iplen, void *out, size_t max_size, u32 *out_src_ip) {
        if (iplen < 20) {
            return 0;
        }
        const size_t ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20 || ihl > iplen || ip[9] != 17) {
            return 0;
        }
        const u8 *udp = ip + ihl;
        if (ip + iplen < udp + 8) {
            return 0;
        }
        const u16 dport = (udp[2] << 8) | udp[3];
        if (dport != 11452) { /* LANDiscovery::DefaultPort */
            this->InjectGameFrame(ip, iplen);
            return 0;
        }
        const u8 *payload = udp + 8;
        const size_t plen = static_cast<size_t>((ip + iplen) - payload);
        if (plen == 0 || plen > max_size) {
            return 0;
        }
        if (out_src_ip) {
            *out_src_ip = (ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8) | ip[15];
        }
        std::memcpy(out, payload, plen);
        return static_cast<int>(plen);
    }

}
