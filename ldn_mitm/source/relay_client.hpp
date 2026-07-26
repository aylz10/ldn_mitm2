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

#pragma once
#include <switch.h>
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    namespace relay {

        /* Format: docs/relay.cfg.example. */
        constexpr const char RelayConfigPath[] = "sdmc:/config/ldn_mitm/relay.cfg";
        constexpr int MaxServers    = 8;
        constexpr int ServerNameLen = 32;

        void LoadConfig();
        bool IsEnabled();
        void SetRelayEnabled(bool on);
        void PersistSettings();
        bool GetRelayEnabled();
        int  ServerCount();
        const char *ServerName(int index);
        int  SelectedServer();
        void SelectServer(int index);

        /* ServerIp is 0 when the server is a hostname; resolve ServerHost then. */
        u32 ServerIp();
        const char *ServerHost();
        u16 ServerPort();

        /* Thread-safe; -1 when no transport is open. Ports and IPs are host order. */
        int BridgeSendGameBroadcast(const void *payload, size_t len, u16 dport);
        int BridgeSendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip);

        /* Not thread-safe; owned by one LANDiscovery worker. */
        class RelayTransport {
            public:
                RelayTransport() = default;
                ~RelayTransport() { this->Close(); }

                Result Open();
                void Close();
                bool IsOpen() const { return m_fd >= 0; }
                int GetFd() const { return m_fd; }

                int SendBroadcast(const void *lan_packet, size_t size);
                int SendKeepalive();

                int SendPing();

                /* Ping misses count only once the server has echoed a ping. */
                bool PathDead() const;

                /* Returns a discovery frame's length; game frames are
                   dispatched internally (returns 0). <0 on error. */
                int RecvBroadcast(void *out, size_t max_size, u32 *out_src_ip);

                int SendGameBroadcast(const void *payload, size_t len, u16 dport);
                int SendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip);
                /* Thread-safe. */
                void LearnPeer(u32 real_ip, u32 vsrc);
                int SendScope(u32 token);

            private:
                int SendWrapped(u32 src, u32 dst, u16 sport, u16 dport, u16 ip_id, const void *payload, size_t len);

                int SendFragmented(u32 src, u32 dst, const u8 *packet, size_t total);

                int ProcessIpv4(const u8 *ip, size_t iplen, void *out, size_t max_size, u32 *out_src_ip);

                const u8 *ReassembleFrag(const u8 *p, size_t n, size_t *out_len);

                /* Hand-built DNS query: libnx getaddrinfo aborts in this sysmodule. */
                u32 ResolveHostname(const char *host);

                void InjectGameFrame(const u8 *ip, size_t iplen);

                int m_fd = -1;
                NifmRequest m_req{};
                bool m_have_req = false;
                bool m_have_nifm_session = false;
                u16 m_frag_send_id = 0;
                u32 m_vsrc = 0;
                u32 m_rsrc = 0;

                static constexpr int PeerMapMax = 16;
                struct PeerAddr { u32 real; u32 vsrc; };
                mutable os::SdkMutex m_peer_mutex;
                PeerAddr m_peers[PeerMapMax] = {};
                int m_peer_next = 0;
                u32 LookupVsrc(u32 real_ip) const;

                static constexpr u32 PingMaxMisses = 4;
                u32 m_ping_misses = 0;
                bool m_ping_supported = false;

                static constexpr int FragSlots = 4;
                struct FragSlot {
                    bool used;
                    u16 id;
                    u32 src;
                    u8 mask;
                    u16 total_len;
                    u8 buffer[1600];
                };
                FragSlot m_frags[FragSlots] = {};
                u8 m_frag_evict = 0;
        };

    }

}
