#include "tcp_relay.hpp"
#include "relay_client.hpp"
#include "session_registry.hpp"
#include "nifm_manager.hpp"
#include "debug.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <mutex>

namespace ams::mitm::ldn::tcprelay {

    namespace {

        constexpr int MaxStreams    = 8;
        constexpr size_t MaxChunk   = 1024;
        constexpr size_t PendingMax = 8 * 1024;
        constexpr u32 LoopbackIp    = 0x7F000001;

        enum TunnelType : u8 {
            TunnelOpen  = 1,
            TunnelData  = 2,
            TunnelClose = 3,
        };

        /* Whose id space `stream` belongs to, from the receiver's view; both
           sides allocate ids independently. */
        enum : u8 { OwnerSender = 0, OwnerReceiver = 1 };

        struct TunnelHeader {
            u8  type;
            u8  owner;
            u16 stream;
            u16 port;
            u16 len;
        };
        static_assert(sizeof(TunnelHeader) == 8);

        struct Stream {
            bool  used;
            bool  originator;   /* we redirected the game's connect */
            u16   id;
            u32   peer_ip;
            s32   game_fd;
            u16   local_port;
            int   listener;
            int   sock;
            u8    pending[PendingMax];
            size_t pending_len;
        };

        os::SdkMutex g_mutex;
        Stream g_streams[MaxStreams];
        u16 g_next_id = 1;

        os::ThreadType g_thread;
        alignas(os::ThreadStackAlignment) u8 g_stack[0x4000];
        bool g_running = false;

        void SetNonBlocking(int fd) {
            const int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) {
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }
        }

        /* Requires g_mutex. */
        Stream *FindById(u32 peer_ip, u16 id, bool originator) {
            for (auto &s : g_streams) {
                if (s.used && s.id == id && s.peer_ip == peer_ip && s.originator == originator) {
                    return std::addressof(s);
                }
            }
            return nullptr;
        }

        /* Requires g_mutex. */
        Stream *FindByGameFd(s32 fd) {
            for (auto &s : g_streams) {
                if (s.used && s.originator && s.game_fd == fd) {
                    return std::addressof(s);
                }
            }
            return nullptr;
        }

        u8 OwnerOf(const Stream *s) {
            return s->originator ? OwnerSender : OwnerReceiver;
        }

        /* Requires g_mutex. */
        Stream *Alloc() {
            for (auto &s : g_streams) {
                if (!s.used) {
                    s = {};
                    s.used     = true;
                    s.listener = -1;
                    s.sock     = -1;
                    s.game_fd  = -1;
                    return std::addressof(s);
                }
            }
            return nullptr;
        }

        /* Requires g_mutex. */
        void Release(Stream *s) {
            if (s->listener >= 0) { ::close(s->listener); }
            if (s->sock >= 0)     { ::close(s->sock); }
            *s = {};
            s->listener = -1;
            s->sock     = -1;
            s->game_fd  = -1;
        }

        int SendTunnel(u32 peer_ip, u8 type, u16 id, u16 port, const void *data, size_t len, u8 owner) {
            u8 buf[sizeof(TunnelHeader) + MaxChunk];
            if (len > MaxChunk) {
                len = MaxChunk;
            }
            auto *h = reinterpret_cast<TunnelHeader *>(buf);
            h->type   = type;
            h->owner  = owner;
            h->stream = id;
            h->port   = port;
            h->len    = static_cast<u16>(len);
            if (len > 0 && data != nullptr) {
                std::memcpy(buf + sizeof(TunnelHeader), data, len);
            }
            return relay::BridgeSendGameUnicast(buf, sizeof(TunnelHeader) + len, TcpTunnelPort, peer_ip);
        }

        u32 GetSelfIp() {
            ScopedNifmSession session;
            if (R_FAILED(session.GetResult())) {
                return 0;
            }
            u32 ip = 0;
            if (R_FAILED(nifmGetCurrentIpAddress(std::addressof(ip)))) {
                return 0;
            }
            return ntohl(ip);
        }

        /* Real address first: 127.0.0.1 is refused for game listeners. */
        int ConnectLocal(u16 port) {
            const u32 targets[2] = { GetSelfIp(), LoopbackIp };
            for (u32 ip : targets) {
                if (ip == 0) {
                    continue;
                }
                const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0) {
                    continue;
                }
                struct sockaddr_in sa = {};
                sa.sin_family      = AF_INET;
                sa.sin_port        = htons(port);
                sa.sin_addr.s_addr = htonl(ip);
                if (::connect(fd, reinterpret_cast<struct sockaddr *>(std::addressof(sa)), sizeof(sa)) == 0) {
                    LogFormat("tcprelay: local connect to %08x:%u ok (fd %d)", ip, port, fd);
                    SetNonBlocking(fd);
                    return fd;
                }
                LogFormat("tcprelay: local connect to %08x:%u failed errno %d", ip, port, errno);
                ::close(fd);
            }
            return -1;
        }

        /* Requires g_mutex. May release s. */
        void FlushPending(Stream *s) {
            while (s->pending_len > 0 && s->sock >= 0) {
                const ssize_t n = ::send(s->sock, s->pending, s->pending_len, 0);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        return;
                    }
                    LogFormat("tcprelay: stream %u local send failed errno %d", s->id, errno);
                    SendTunnel(s->peer_ip, TunnelClose, s->id, 0, nullptr, 0, OwnerOf(s));
                    Release(s);
                    return;
                }
                std::memmove(s->pending, s->pending + n, s->pending_len - n);
                s->pending_len -= static_cast<size_t>(n);
            }
        }

        void PumpThread(void *) {
            while (g_running) {
                struct pollfd pfds[MaxStreams * 2];
                Stream *owners[MaxStreams * 2];
                bool is_listener[MaxStreams * 2];
                nfds_t n = 0;

                {
                    std::scoped_lock lk(g_mutex);
                    for (auto &s : g_streams) {
                        if (!s.used) {
                            continue;
                        }
                        if (s.listener >= 0) {
                            pfds[n] = { .fd = s.listener, .events = POLLIN, .revents = 0 };
                            owners[n] = std::addressof(s);
                            is_listener[n] = true;
                            n++;
                        }
                        if (s.sock >= 0) {
                            pfds[n] = { .fd = s.sock, .events = POLLIN, .revents = 0 };
                            owners[n] = std::addressof(s);
                            is_listener[n] = false;
                            n++;
                        }
                    }
                }

                if (n == 0) {
                    svcSleepThread(20000000L);
                    continue;
                }

                const int rc = ::poll(pfds, n, 20);
                if (rc <= 0) {
                    std::scoped_lock lk(g_mutex);
                    for (auto &s : g_streams) {
                        if (s.used) { FlushPending(std::addressof(s)); }
                    }
                    continue;
                }

                for (nfds_t i = 0; i < n; i++) {
                    if (pfds[i].revents == 0) {
                        continue;
                    }
                    std::scoped_lock lk(g_mutex);
                    Stream *s = owners[i];
                    if (!s->used) {
                        continue;
                    }
                    /* poll() ran unlocked: act only if the slot still owns this fd. */
                    if (is_listener[i] ? (s->listener != pfds[i].fd) : (s->sock != pfds[i].fd)) {
                        continue;
                    }

                    if (is_listener[i]) {
                        if (pfds[i].revents & POLLIN) {
                            const int fd = ::accept(s->listener, nullptr, nullptr);
                            if (fd >= 0) {
                                SetNonBlocking(fd);
                                ::close(s->listener);
                                s->listener = -1;
                                s->sock     = fd;
                                LogFormat("tcprelay: stream %u game connected (fd %d)", s->id, fd);
                                FlushPending(s);
                            }
                        }
                        continue;
                    }

                    if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                        LogFormat("tcprelay: stream %u local socket closed", s->id);
                        SendTunnel(s->peer_ip, TunnelClose, s->id, 0, nullptr, 0, OwnerOf(s));
                        Release(s);
                        continue;
                    }

                    if (pfds[i].revents & POLLIN) {
                        u8 buf[MaxChunk];
                        const ssize_t got = ::recv(s->sock, buf, sizeof(buf), 0);
                        if (got > 0) {
                            SendTunnel(s->peer_ip, TunnelData, s->id, 0, buf, static_cast<size_t>(got), OwnerOf(s));
                        } else if (got == 0) {
                            LogFormat("tcprelay: stream %u closed by game", s->id);
                            SendTunnel(s->peer_ip, TunnelClose, s->id, 0, nullptr, 0, OwnerOf(s));
                            Release(s);
                        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            LogFormat("tcprelay: stream %u recv errno %d", s->id, errno);
                            SendTunnel(s->peer_ip, TunnelClose, s->id, 0, nullptr, 0, OwnerOf(s));
                            Release(s);
                        }
                    }
                }
            }
        }

    }

    bool RedirectConnect(::Service *fwd, s32 sockfd, u32 dst_ip, u16 dst_port,
                         s32 *out_ret, s32 *out_bsd_errno) {
        if (!relay::IsEnabled()) {
            return false;
        }

        SessionRegistry::Snapshot snap;
        SessionRegistry::Get(std::addressof(snap));
        bool is_peer = false;
        for (int i = 0; i < snap.peer_count; i++) {
            if (snap.active && dst_ip == snap.peer_ips[i]) {
                is_peer = true;
                break;
            }
        }
        if (!is_peer) {
            return false;
        }

        std::scoped_lock lk(g_mutex);

        /* Repeat connect on the same socket is the game polling a
           non-blocking connect; re-point it at the existing proxy. */
        if (Stream *existing = FindByGameFd(sockfd); existing != nullptr) {
            struct sockaddr_in again = {};
            again.sin_family      = AF_INET;
            again.sin_port        = htons(existing->local_port);
            again.sin_addr.s_addr = htonl(LoopbackIp);

            const struct { s32 sockfd; } in_again = { sockfd };
            struct { s32 ret; s32 bsd_errno; } out_again = {};
            const Result rc_again = serviceDispatchInOut(fwd, 14, in_again, out_again,
                .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_In },
                .buffers = { { std::addressof(again), sizeof(again) } },
            );
            if (R_FAILED(rc_again)) {
                return false;
            }
            *out_ret       = out_again.ret;
            *out_bsd_errno = out_again.bsd_errno;
            return true;
        }

        Stream *s = Alloc();
        if (s == nullptr) {
            LogFormat("tcprelay: out of streams, forwarding connect unchanged");
            return false;
        }

        const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0) {
            Release(s);
            return false;
        }
        struct sockaddr_in la = {};
        la.sin_family      = AF_INET;
        la.sin_port        = 0;
        la.sin_addr.s_addr = htonl(LoopbackIp);
        if (::bind(lfd, reinterpret_cast<struct sockaddr *>(std::addressof(la)), sizeof(la)) != 0 ||
            ::listen(lfd, 1) != 0) {
            LogFormat("tcprelay: proxy listener setup failed errno %d", errno);
            ::close(lfd);
            Release(s);
            return false;
        }
        socklen_t alen = sizeof(la);
        if (::getsockname(lfd, reinterpret_cast<struct sockaddr *>(std::addressof(la)), std::addressof(alen)) != 0) {
            ::close(lfd);
            Release(s);
            return false;
        }
        const u16 local_port = ntohs(la.sin_port);
        SetNonBlocking(lfd);

        s->originator = true;
        s->id         = g_next_id++;
        s->peer_ip    = dst_ip;
        s->listener   = lfd;
        s->game_fd    = sockfd;
        s->local_port = local_port;

        /* bsd Connect is cmd 14: in { s32 sockfd }, AutoSelect-In sockaddr,
           out { s32 ret; s32 errno }. */
        struct sockaddr_in target = {};
        target.sin_family      = AF_INET;
        target.sin_port        = htons(local_port);
        target.sin_addr.s_addr = htonl(LoopbackIp);

        const struct { s32 sockfd; } in = { sockfd };
        struct { s32 ret; s32 bsd_errno; } out = {};
        const Result rc = serviceDispatchInOut(fwd, 14, in, out,
            .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_In },
            .buffers = { { std::addressof(target), sizeof(target) } },
        );
        if (R_FAILED(rc)) {
            LogFormat("tcprelay: redirected connect dispatch failed %x", rc);
            Release(s);
            return false;
        }

        LogFormat("tcprelay: stream %u redirect connect fd %d -> %08x:%u via 127.0.0.1:%u (ret %d errno %d)",
            s->id, sockfd, dst_ip, dst_port, local_port, out.ret, out.bsd_errno);

        SendTunnel(dst_ip, TunnelOpen, s->id, dst_port, nullptr, 0, OwnerSender);

        *out_ret       = out.ret;
        *out_bsd_errno = out.bsd_errno;
        return true;
    }

    void OnTunnelFrame(u32 src_ip, const u8 *payload, size_t len) {
        if (len < sizeof(TunnelHeader)) {
            return;
        }
        TunnelHeader h;
        std::memcpy(std::addressof(h), payload, sizeof(h));
        const u8 *data = payload + sizeof(TunnelHeader);
        const size_t avail    = len - sizeof(TunnelHeader);
        const size_t data_len = avail < static_cast<size_t>(h.len) ? avail : static_cast<size_t>(h.len);

        std::scoped_lock lk(g_mutex);

        switch (h.type) {
            case TunnelOpen: {
                if (FindById(src_ip, h.stream, false) != nullptr) {
                    return;
                }
                Stream *s = Alloc();
                if (s == nullptr) {
                    LogFormat("tcprelay: out of streams for incoming open");
                    return;
                }
                s->originator = false;
                s->id         = h.stream;
                s->peer_ip    = src_ip;
                s->sock       = ConnectLocal(h.port);
                if (s->sock < 0) {
                    LogFormat("tcprelay: stream %u could not reach local game port %u", h.stream, h.port);
                    SendTunnel(src_ip, TunnelClose, h.stream, 0, nullptr, 0, OwnerReceiver);
                    Release(s);
                    return;
                }
                LogFormat("tcprelay: stream %u opened for peer %08x -> local port %u", h.stream, src_ip, h.port);
                break;
            }
            case TunnelData: {
                Stream *s = FindById(src_ip, h.stream, h.owner == OwnerReceiver);
                if (s == nullptr || data_len == 0) {
                    return;
                }
                if (s->pending_len + data_len > PendingMax) {
                    /* Dropping bytes would corrupt the stream; close it. */
                    LogFormat("tcprelay: stream %u pending overflow, closing", h.stream);
                    SendTunnel(s->peer_ip, TunnelClose, s->id, 0, nullptr, 0, OwnerOf(s));
                    Release(s);
                    return;
                }
                std::memcpy(s->pending + s->pending_len, data, data_len);
                s->pending_len += data_len;
                FlushPending(s);
                break;
            }
            case TunnelClose: {
                Stream *s = FindById(src_ip, h.stream, h.owner == OwnerReceiver);
                if (s != nullptr) {
                    LogFormat("tcprelay: stream %u closed by peer", h.stream);
                    Release(s);
                }
                break;
            }
            default:
                break;
        }
    }

    void Start() {
        std::scoped_lock lk(g_mutex);
        if (g_running) {
            return;
        }
        for (auto &s : g_streams) {
            s = {};
            s.listener = -1;
            s.sock     = -1;
        }
        g_running = true;
        /* AMS priority (0..31), same as the LANDiscovery worker. */
        if (R_FAILED(os::CreateThread(std::addressof(g_thread), PumpThread, nullptr,
                                      g_stack, sizeof(g_stack), 0x15))) {
            g_running = false;
            LogFormat("tcprelay: failed to start pump thread");
            return;
        }
        os::SetThreadNamePointer(std::addressof(g_thread), "ldn_mitm::TcpRelay");
        os::StartThread(std::addressof(g_thread));
        LogFormat("tcprelay: started");
    }

    void Stop() {
        {
            std::scoped_lock lk(g_mutex);
            if (!g_running) {
                return;
            }
            g_running = false;
        }
        os::WaitThread(std::addressof(g_thread));
        os::DestroyThread(std::addressof(g_thread));
        {
            std::scoped_lock lk(g_mutex);
            for (auto &s : g_streams) {
                if (s.used) { Release(std::addressof(s)); }
            }
        }
        LogFormat("tcprelay: stopped");
    }

}
