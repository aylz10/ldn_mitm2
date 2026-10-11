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

#include "bsd_mitm_service.hpp"
#include "session_registry.hpp"
#include "ldnmitm_config.hpp"
#include "relay_client.hpp"
#include "tcp_relay.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <algorithm>
#include <atomic>
#include <cstring>

namespace ams::mitm::ldn {

    namespace {

        /* Longer or infinite waits are re-issued in WaitCapMs slices so a dead
           client cannot pin a real bsd:u request. */
        constexpr s32 WaitCapMs    = 1000;
        constexpr s32 ForwardMaxMs = 60000;
        /* While relay frames are queued, so a game not polling its session fd
           returns promptly to collect them. */
        constexpr s32 QueuedWaitCapMs = 2;
        constexpr s64 MaxSelectSec = 0x7FFFFFFF;

        struct BsdOutData {
            s32 ret;
            s32 bsd_errno;
        };

        class LogSampler {
            private:
                std::atomic<u32> m_count{0};
            public:
                u32 Next() {
                    const u32 n = m_count.fetch_add(1, std::memory_order_relaxed) + 1;
                    return (n <= 8 || (n % 256) == 0) ? n : 0;
                }
        };

        /* getsockname, bsd cmd 16. */
        bool GetForwardBoundPort(::Service *fwd, s32 sockfd, u16 *out_port) {
            struct sockaddr_in sa = {};
            const struct { s32 sockfd; } in = { sockfd };
            struct { s32 ret; s32 bsd_errno; u32 addrlen; } out = {};
            const Result rc = serviceDispatchInOut(fwd, 16, in, out,
                .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out },
                .buffers = { { std::addressof(sa), sizeof(sa) } },
            );
            if (R_FAILED(rc) || out.ret != 0 || out.addrlen < sizeof(sa)) {
                return false;
            }
            *out_port = ntohs(sa.sin_port);
            return true;
        }

        /* fcntl F_GETFL, bsd cmd 20. bsd returns its native non-blocking bit
           (0x800), not newlib's O_NONBLOCK. */
        constexpr s32 BsdNativeNonBlock = 1 << 11;

        bool ForwardSocketNonBlocking(::Service *fwd, s32 sockfd) {
            const struct { s32 sockfd; s32 cmd; s32 flags; } in = { sockfd, F_GETFL, 0 };
            struct { s32 ret; s32 bsd_errno; } out = {};
            const Result rc = serviceDispatchInOut(fwd, 20, in, out);
            return R_SUCCEEDED(rc) && out.ret >= 0 && (out.ret & BsdNativeNonBlock) != 0;
        }

        /* getsockopt, bsd cmd 17. */
        bool GetForwardSockType(::Service *fwd, s32 sockfd, s32 *out_type) {
            s32 so_type = 0;
            const struct { s32 sockfd; u32 level; u32 optname; } in = { sockfd, SOL_SOCKET, SO_TYPE };
            struct { s32 ret; s32 bsd_errno; u32 optlen; } out = {};
            const Result rc = serviceDispatchInOut(fwd, 17, in, out,
                .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out },
                .buffers = { { std::addressof(so_type), sizeof(so_type) } },
            );
            if (R_FAILED(rc) || out.ret != 0 || out.optlen < sizeof(so_type)) {
                return false;
            }
            *out_type = so_type;
            return true;
        }

        enum class FdKind {
            NotSocket,
            Socket,
            GameRecv,
        };

        FdKind ClassifyFd(::Service *fwd, s32 sockfd, u16 session_port) {
            s32 so_type = 0;
            if (!GetForwardSockType(fwd, sockfd, std::addressof(so_type))) {
                return FdKind::NotSocket;
            }
            if (session_port == 0 || so_type != SOCK_DGRAM) {
                return FdKind::Socket;
            }
            u16 bound = 0;
            if (!GetForwardBoundPort(fwd, sockfd, std::addressof(bound)) || bound != session_port) {
                return FdKind::Socket;
            }
            return FdKind::GameRecv;
        }

        bool IsGameRecvSocket(::Service *fwd, s32 sockfd) {
            const u16 port = GameRx::SessionDport();
            return port != 0 && ClassifyFd(fwd, sockfd, port) == FdKind::GameRecv;
        }

        struct RelayWaitSet {
            s32  rx = -1;             /* pollfd index for Poll, fd for Select */
            bool any_socket = false;
        };

        RelayWaitSet ClassifyPollSet(::Service *fwd, const struct pollfd *fds, u32 nfds) {
            RelayWaitSet set;
            const u16 port = GameRx::SessionDport();
            for (u32 i = 0; i < nfds; i++) {
                if (fds[i].fd < 0) {
                    continue;
                }
                const FdKind kind = ClassifyFd(fwd, fds[i].fd, port);
                if (kind == FdKind::NotSocket) {
                    continue;
                }
                set.any_socket = true;
                if (kind == FdKind::GameRecv && (fds[i].events & POLLIN)) {
                    set.rx = static_cast<s32>(i);
                    break;
                }
            }
            return set;
        }

        /* rd_size must cover both the in and out read sets. */
        RelayWaitSet ClassifySelectSet(::Service *fwd, s32 nfds,
                                       const u8 *rd, size_t rd_size,
                                       const u8 *wr, size_t wr_size,
                                       const u8 *ex, size_t ex_size) {
            RelayWaitSet set;
            const u16 port = GameRx::SessionDport();
            for (s32 fd = 0; fd < nfds; fd++) {
                const size_t byte = static_cast<size_t>(fd) / 8;
                const u8 mask = static_cast<u8>(1u << (fd % 8));
                const bool in_rd = byte < rd_size && (rd[byte] & mask);
                const bool in_wr = byte < wr_size && (wr[byte] & mask);
                const bool in_ex = byte < ex_size && (ex[byte] & mask);
                if (!in_rd && !in_wr && !in_ex) {
                    continue;
                }
                const FdKind kind = ClassifyFd(fwd, fd, port);
                if (kind == FdKind::NotSocket) {
                    continue;
                }
                set.any_socket = true;
                if (kind == FdKind::GameRecv && in_rd) {
                    set.rx = fd;
                    break;
                }
            }
            return set;
        }

        /* Poll, bsd cmd 6. */
        Result ForwardPoll(::Service *fwd, u32 nfds, s32 timeout,
                           const void *fds_in, size_t in_size, void *fds_out, size_t out_size,
                           BsdOutData *out) {
            const struct { u32 nfds; s32 timeout; } in = { nfds, timeout };
            R_RETURN((serviceDispatchInOut(fwd, 6, in, *out,
                .buffer_attrs = {
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                },
                .buffers = {
                    { fds_in,  in_size  },
                    { fds_out, out_size },
                },
            )));
        }

        /* Select, bsd cmd 5. */
        Result ForwardSelect(::Service *fwd, const BsdSelectInData &in,
                             const sf::InAutoSelectBuffer &rd_in, const sf::InAutoSelectBuffer &wr_in, const sf::InAutoSelectBuffer &ex_in,
                             const sf::OutAutoSelectBuffer &rd_out, const sf::OutAutoSelectBuffer &wr_out, const sf::OutAutoSelectBuffer &ex_out,
                             BsdOutData *out) {
            R_RETURN((serviceDispatchInOut(fwd, 5, in, *out,
                .buffer_attrs = {
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                },
                .buffers = {
                    { rd_in.GetPointer(),  rd_in.GetSize()  },
                    { wr_in.GetPointer(),  wr_in.GetSize()  },
                    { ex_in.GetPointer(),  ex_in.GetSize()  },
                    { rd_out.GetPointer(), rd_out.GetSize() },
                    { wr_out.GetPointer(), wr_out.GetSize() },
                    { ex_out.GetPointer(), ex_out.GetSize() },
                },
            )));
        }

        /* Any revents counts: errors surface through the verbatim forward. */
        bool ForwardSocketReadable(::Service *fwd, s32 sockfd) {
            struct pollfd pfd_in  = { .fd = sockfd, .events = POLLIN, .revents = 0 };
            struct pollfd pfd_out = pfd_in;
            BsdOutData out = {};
            const Result rc = ForwardPoll(fwd, 1, 0, std::addressof(pfd_in), sizeof(pfd_in),
                                          std::addressof(pfd_out), sizeof(pfd_out), std::addressof(out));
            return R_SUCCEEDED(rc) && out.ret > 0 && pfd_out.revents != 0;
        }

        /* False means forward verbatim. */
        bool WaitForGameRx(::Service *fwd, s32 sockfd) {
            constexpr int WaitSliceMs   = 2;
            constexpr u32 RealPeekEvery = 12;
            for (u32 slice = 0; ; slice++) {
                if (GameRx::HasData()) {
                    return true;
                }
                SessionRegistry::Snapshot snap;
                SessionRegistry::Get(std::addressof(snap));
                if (!snap.active) {
                    return false;
                }
                if ((slice % RealPeekEvery) == 0 && ForwardSocketReadable(fwd, sockfd)) {
                    return false;
                }
                svcSleepThread(WaitSliceMs * 1000000L);
            }
        }

        /* False means forward verbatim. */
        bool ServeQueuedPayload(::Service *fwd, s32 sockfd, bool dontwait, const sf::OutAutoSelectBuffer &message,
                                sf::Out<s32> &ret, sf::Out<s32> &bsd_errno, const char *tag,
                                u32 *out_src_ip = nullptr, u16 *out_sport = nullptr) {
            if (!IsGameRecvSocket(fwd, sockfd)) {
                return false;
            }

            u32 src_ip = 0;
            u16 sport = 0;
            size_t out_len = 0;
            bool may_wait_checked = false;
            while (!GameRx::Pop(std::addressof(src_ip), std::addressof(sport), message.GetPointer(), message.GetSize(), std::addressof(out_len))) {
                if (!may_wait_checked) {
                    if (dontwait || ForwardSocketNonBlocking(fwd, sockfd)) {
                        return false;
                    }
                    may_wait_checked = true;
                }
                if (!WaitForGameRx(fwd, sockfd)) {
                    return false;
                }
            }

            ret.SetValue(static_cast<s32>(out_len));
            bsd_errno.SetValue(0);
            if (out_src_ip != nullptr) { *out_src_ip = src_ip; }
            if (out_sport != nullptr)  { *out_sport = sport; }

            static LogSampler s_served;
            if (const u32 n = s_served.Next(); n != 0) {
                LogFormat("diag %s SERVED #%u fd %d src %08x:%u len %zu depth %d dropped ovf %u stale %u",
                    tag, n, sockfd, src_ip, sport, out_len, GameRx::Depth(),
                    GameRx::OverflowDropped(), GameRx::StaleDropped());
            }
            return true;
        }

        Result WakePoll(::Service *fwd, u32 nfds, const sf::InAutoSelectBuffer &fds_in, const sf::OutAutoSelectBuffer &fds_out,
                        s32 rx, BsdOutData *out) {
            R_TRY(ForwardPoll(fwd, nfds, 0, fds_in.GetPointer(), fds_in.GetSize(),
                              fds_out.GetPointer(), fds_out.GetSize(), out));
            if (out->ret >= 0) {
                struct pollfd &p = reinterpret_cast<struct pollfd *>(fds_out.GetPointer())[rx];
                /* poll() counts fds with any revents set. */
                if (p.revents == 0) {
                    out->ret += 1;
                }
                p.revents |= POLLIN;

                static LogSampler s_wake;
                if (const u32 n = s_wake.Next(); n != 0) {
                    LogFormat("diag Poll WAKE #%u fd %d ret %d", n, p.fd, out->ret);
                }
            }
            R_SUCCEED();
        }

        Result WakeSelect(::Service *fwd, const BsdSelectInData &in_data,
                          const sf::InAutoSelectBuffer &rd_in, const sf::InAutoSelectBuffer &wr_in, const sf::InAutoSelectBuffer &ex_in,
                          const sf::OutAutoSelectBuffer &rd_out, const sf::OutAutoSelectBuffer &wr_out, const sf::OutAutoSelectBuffer &ex_out,
                          s32 rx, BsdOutData *out) {
            BsdSelectInData in = in_data;
            in.is_null = 0;
            in.tv_sec  = 0;
            in.tv_usec = 0;
            R_TRY(ForwardSelect(fwd, in, rd_in, wr_in, ex_in, rd_out, wr_out, ex_out, out));
            if (out->ret >= 0) {
                const size_t byte = static_cast<size_t>(rx) / 8;
                const u8 mask = static_cast<u8>(1u << (rx % 8));
                u8 *rout = rd_out.GetPointer();
                if ((rout[byte] & mask) == 0) {
                    rout[byte] |= mask;
                    out->ret += 1;
                }

                static LogSampler s_wake;
                if (const u32 n = s_wake.Next(); n != 0) {
                    LogFormat("diag Select WAKE #%u fd %d ret %d", n, rx, out->ret);
                }
            }
            R_SUCCEED();
        }

    }

    Result BsdMitmService::Select(sf::Out<s32> ret, sf::Out<s32> bsd_errno, BsdSelectInData in_data, sf::InAutoSelectBuffer rd_in, sf::InAutoSelectBuffer wr_in, sf::InAutoSelectBuffer ex_in, sf::OutAutoSelectBuffer rd_out, sf::OutAutoSelectBuffer wr_out, sf::OutAutoSelectBuffer ex_out) {
        ::Service *fwd = this->m_forward_service.get();
        const bool relay_on = relay::IsEnabled();

        RelayWaitSet set;
        bool classified = false;
        auto queued_set = [&]() -> const RelayWaitSet * {
            if (!relay_on || !GameRx::HasData()) {
                return nullptr;
            }
            if (!classified) {
                set = ClassifySelectSet(fwd, in_data.nfds,
                    rd_in.GetPointer(), std::min(rd_in.GetSize(), rd_out.GetSize()),
                    wr_in.GetPointer(), wr_in.GetSize(),
                    ex_in.GetPointer(), ex_in.GetSize());
                classified = true;
            }
            return std::addressof(set);
        };

        BsdOutData out = {};
        if (const RelayWaitSet *qs = queued_set(); qs != nullptr && qs->rx >= 0) {
            R_TRY(WakeSelect(fwd, in_data, rd_in, wr_in, ex_in, rd_out, wr_out, ex_out, qs->rx, std::addressof(out)));
            ret.SetValue(out.ret);
            bsd_errno.SetValue(out.bsd_errno);
            R_SUCCEED();
        }

        const bool finite = (in_data.is_null == 0);
        s64 remaining = 0;
        if (finite) {
            if (in_data.tv_sec < 0 || in_data.tv_usec < 0) {
                R_RETURN(sm::mitm::ResultShouldForwardToSession());
            }
            remaining = std::min<s64>(in_data.tv_sec, MaxSelectSec) * 1000 + in_data.tv_usec / 1000;
            if (remaining <= ForwardMaxMs) {
                R_RETURN(sm::mitm::ResultShouldForwardToSession());
            }
        }

        static LogSampler s_capped;
        if (const u32 n = s_capped.Next(); n != 0) {
            LogFormat("bsd Select capped #%u nfds %d is_null %d tv %lld.%06lld",
                n, in_data.nfds, static_cast<int>(in_data.is_null),
                static_cast<long long>(in_data.tv_sec), static_cast<long long>(in_data.tv_usec));
        }

        /* An infinite wait returns after one slice; the game re-issues it. */
        for (;;) {
            s64 slice = WaitCapMs;
            if (const RelayWaitSet *qs = queued_set(); qs != nullptr) {
                if (qs->rx >= 0) {
                    R_TRY(WakeSelect(fwd, in_data, rd_in, wr_in, ex_in, rd_out, wr_out, ex_out, qs->rx, std::addressof(out)));
                    ret.SetValue(out.ret);
                    bsd_errno.SetValue(out.bsd_errno);
                    R_SUCCEED();
                }
                if (!qs->any_socket) {
                    slice = QueuedWaitCapMs;
                }
            }
            if (finite && remaining < slice) {
                slice = remaining;
            }
            BsdSelectInData in = in_data;
            in.is_null = 0;
            in.tv_sec  = slice / 1000;
            in.tv_usec = (slice % 1000) * 1000;
            out = {};
            R_TRY(ForwardSelect(fwd, in, rd_in, wr_in, ex_in, rd_out, wr_out, ex_out, std::addressof(out)));

            if (out.ret != 0 || !finite) {
                ret.SetValue(out.ret);
                bsd_errno.SetValue(out.bsd_errno);
                R_SUCCEED();
            }

            remaining -= slice;
            if (remaining <= 0) {
                ret.SetValue(0);
                bsd_errno.SetValue(out.bsd_errno);
                R_SUCCEED();
            }
        }
    }

    Result BsdMitmService::Poll(sf::Out<s32> ret, sf::Out<s32> bsd_errno, u32 nfds, s32 timeout, sf::InAutoSelectBuffer fds_in, sf::OutAutoSelectBuffer fds_out) {
        ::Service *fwd = this->m_forward_service.get();
        const size_t need = static_cast<size_t>(nfds) * sizeof(struct pollfd);
        const bool relay_on = relay::IsEnabled() && fds_in.GetSize() >= need && fds_out.GetSize() >= need;

        RelayWaitSet set;
        bool classified = false;
        auto queued_set = [&]() -> const RelayWaitSet * {
            if (!relay_on || !GameRx::HasData()) {
                return nullptr;
            }
            if (!classified) {
                set = ClassifyPollSet(fwd, reinterpret_cast<const struct pollfd *>(fds_in.GetPointer()), nfds);
                classified = true;
            }
            return std::addressof(set);
        };

        BsdOutData out = {};
        if (const RelayWaitSet *qs = queued_set(); qs != nullptr && qs->rx >= 0) {
            R_TRY(WakePoll(fwd, nfds, fds_in, fds_out, qs->rx, std::addressof(out)));
            ret.SetValue(out.ret);
            bsd_errno.SetValue(out.bsd_errno);
            R_SUCCEED();
        }

        if (timeout >= 0 && timeout <= ForwardMaxMs) {
            R_RETURN(sm::mitm::ResultShouldForwardToSession());
        }

        static LogSampler s_capped;
        if (const u32 n = s_capped.Next(); n != 0) {
            LogFormat("bsd Poll capped #%u nfds %u timeout %d", n, nfds, timeout);
        }

        /* An infinite wait returns after one slice; the game re-polls. */
        const bool finite = (timeout >= 0);
        s64 remaining = timeout;
        for (;;) {
            s32 slice = WaitCapMs;
            if (const RelayWaitSet *qs = queued_set(); qs != nullptr) {
                if (qs->rx >= 0) {
                    R_TRY(WakePoll(fwd, nfds, fds_in, fds_out, qs->rx, std::addressof(out)));
                    ret.SetValue(out.ret);
                    bsd_errno.SetValue(out.bsd_errno);
                    R_SUCCEED();
                }
                if (!qs->any_socket) {
                    slice = QueuedWaitCapMs;
                }
            }
            if (finite && remaining < slice) {
                slice = static_cast<s32>(remaining);
            }
            out = {};
            R_TRY(ForwardPoll(fwd, nfds, slice, fds_in.GetPointer(), fds_in.GetSize(),
                              fds_out.GetPointer(), fds_out.GetSize(), std::addressof(out)));

            if (out.ret != 0 || !finite) {
                ret.SetValue(out.ret);
                bsd_errno.SetValue(out.bsd_errno);
                R_SUCCEED();
            }

            remaining -= slice;
            if (remaining <= 0) {
                ret.SetValue(0);
                bsd_errno.SetValue(out.bsd_errno);
                R_SUCCEED();
            }
        }
    }

    Result BsdMitmService::RecvFrom(sf::Out<s32> ret, sf::Out<s32> bsd_errno, sf::Out<u32> addrlen, s32 sockfd, u32 flags, sf::OutAutoSelectBuffer message, sf::OutAutoSelectBuffer src_addr) {
        if (!relay::IsEnabled()) {
            R_RETURN(sm::mitm::ResultShouldForwardToSession());
        }

        static LogSampler s_calls;
        if (const u32 n = s_calls.Next(); n != 0) {
            LogFormat("diag RecvFrom #%u fd %d hasdata %d peek %d addrlen %zu",
                n, sockfd, static_cast<int>(GameRx::HasData()),
                static_cast<int>((flags & MSG_PEEK) != 0), src_addr.GetSize());
        }

        u32 src_ip = 0;
        u16 sport = 0;
        if ((flags & MSG_PEEK) == 0 &&
            ServeQueuedPayload(this->m_forward_service.get(), sockfd, (flags & MSG_DONTWAIT) != 0,
                               message, ret, bsd_errno, "RecvFrom", std::addressof(src_ip), std::addressof(sport))) {
            struct sockaddr_in sa = {};
            sa.sin_family = AF_INET;
            sa.sin_port = htons(sport);
            sa.sin_addr.s_addr = htonl(src_ip);
            const size_t sa_len = std::min(src_addr.GetSize(), sizeof(sa));
            if (sa_len > 0) {
                std::memcpy(src_addr.GetPointer(), std::addressof(sa), sa_len);
            }
            addrlen.SetValue(static_cast<u32>(sa_len));
            R_SUCCEED();
        }

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

    Result BsdMitmService::Recv(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, u32 flags, sf::OutAutoSelectBuffer message) {
        if (!relay::IsEnabled()) {
            R_RETURN(sm::mitm::ResultShouldForwardToSession());
        }

        static LogSampler s_calls;
        if (const u32 n = s_calls.Next(); n != 0) {
            LogFormat("diag Recv #%u fd %d hasdata %d peek %d",
                n, sockfd, static_cast<int>(GameRx::HasData()), static_cast<int>((flags & MSG_PEEK) != 0));
        }

        if ((flags & MSG_PEEK) == 0 &&
            ServeQueuedPayload(this->m_forward_service.get(), sockfd, (flags & MSG_DONTWAIT) != 0,
                               message, ret, bsd_errno, "Recv")) {
            R_SUCCEED();
        }

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

    Result BsdMitmService::Connect(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, sf::InAutoSelectBuffer dst_addr) {
        if (relay::IsEnabled() && dst_addr.GetSize() >= sizeof(struct sockaddr_in)) {
            const auto *sa = reinterpret_cast<const struct sockaddr_in *>(dst_addr.GetPointer());
            if (sa->sin_family == AF_INET) {
                const u32 ip   = ntohl(sa->sin_addr.s_addr);
                const u16 port = ntohs(sa->sin_port);
                s32 so_type = 0;
                if (GetForwardSockType(this->m_forward_service.get(), sockfd, std::addressof(so_type)) &&
                    so_type == SOCK_STREAM) {
                    s32 r = 0, e = 0;
                    if (tcprelay::RedirectConnect(this->m_forward_service.get(), sockfd, ip, port,
                                                  std::addressof(r), std::addressof(e))) {
                        ret.SetValue(r);
                        bsd_errno.SetValue(e);
                        R_SUCCEED();
                    }
                }
            }
        }

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

    Result BsdMitmService::Read(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, sf::OutAutoSelectBuffer message) {
        if (!relay::IsEnabled()) {
            R_RETURN(sm::mitm::ResultShouldForwardToSession());
        }

        static LogSampler s_calls;
        if (const u32 n = s_calls.Next(); n != 0) {
            LogFormat("diag Read #%u fd %d hasdata %d", n, sockfd, static_cast<int>(GameRx::HasData()));
        }

        if (ServeQueuedPayload(this->m_forward_service.get(), sockfd, false,
                               message, ret, bsd_errno, "Read")) {
            R_SUCCEED();
        }

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

    Result BsdMitmService::SendTo(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, s32 flags, sf::InAutoSelectBuffer message, sf::InAutoSelectBuffer dst_addr) {
        AMS_UNUSED(ret, bsd_errno);

        const bool want_fanout = LdnConfig::getBroadcastRelay();
        const bool want_relay  = relay::IsEnabled();
        if ((want_fanout || want_relay) && dst_addr.GetSize() >= sizeof(struct sockaddr_in)) {
            const auto *sa = reinterpret_cast<const struct sockaddr_in *>(dst_addr.GetPointer());
            if (sa->sin_family == AF_INET) {
                const u32 ip = ntohl(sa->sin_addr.s_addr);
                const u16 port = ntohs(sa->sin_port);

                SessionRegistry::Snapshot snap;
                SessionRegistry::Get(std::addressof(snap));

                const bool is_bcast = (ip == 0xFFFFFFFFu) || (snap.active && ip == snap.bcast_ip);

                static LogSampler s_sendto;
                if (const u32 n = s_sendto.Next(); n != 0) {
                    LogFormat("diag SendTo #%u fd %d dst %08x:%u len %zu bcast %d | active %d peers %d bcast_ip %08x",
                        n, sockfd, ip, port, message.GetSize(), static_cast<int>(is_bcast),
                        static_cast<int>(snap.active), snap.peer_count, snap.bcast_ip);
                }

                if (want_relay && snap.active && !is_bcast && ip != 0 && ip != 0x7F000001u) {
                    for (int i = 0; i < snap.peer_count; i++) {
                        if (ip == snap.peer_ips[i]) {
                            GameRx::NoteSessionPort(port);
                            relay::BridgeSendGameUnicast(message.GetPointer(), message.GetSize(), port, ip);
                            break;
                        }
                    }
                }

                if (snap.active && snap.peer_count > 0 && is_bcast) {
                    /* The original broadcast is still forwarded below. */
                    if (want_fanout) {
                        ::Service *fwd = this->m_forward_service.get();
                        for (int i = 0; i < snap.peer_count; i++) {
                            struct sockaddr_in peer = *sa;
                            peer.sin_addr.s_addr = htonl(snap.peer_ips[i]);

                            const struct { s32 sockfd; s32 flags; } in = { sockfd, flags };
                            BsdOutData out = {};

                            /* SendTo, bsd cmd 11; best-effort. */
                            serviceDispatchInOut(fwd, 11, in, out,
                                .buffer_attrs = {
                                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                },
                                .buffers = {
                                    { message.GetPointer(), message.GetSize() },
                                    { std::addressof(peer), sizeof(peer) },
                                },
                            );
                        }
                    }

                    if (want_relay) {
                        GameRx::NoteSessionPort(port);
                        relay::BridgeSendGameBroadcast(message.GetPointer(), message.GetSize(), port);
                    }
                }
            }
        }

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

    namespace {

        void LogUnrelayedSend(::Service *fwd, const char *what, s32 sockfd, size_t len, LogSampler &sampler) {
            if (!relay::IsEnabled() && !LdnConfig::getBroadcastRelay()) {
                return;
            }
            const u32 n = sampler.Next();
            if (n == 0) {
                return;
            }
            s32 so_type = 0;
            const bool got_type = GetForwardSockType(fwd, sockfd, std::addressof(so_type));

            SessionRegistry::Snapshot snap;
            SessionRegistry::Get(std::addressof(snap));

            LogFormat("diag %s #%u fd %d len %zu type %d active %d peers %d NOT RELAYED",
                what, n, sockfd, len, got_type ? so_type : -1,
                static_cast<int>(snap.active), snap.peer_count);
        }

    }

    Result BsdMitmService::Send(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, s32 flags, sf::InAutoSelectBuffer message) {
        AMS_UNUSED(ret, bsd_errno, flags);

        static LogSampler s_send;
        LogUnrelayedSend(this->m_forward_service.get(), "Send", sockfd, message.GetSize(), s_send);

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

    Result BsdMitmService::Write(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, sf::InAutoSelectBuffer message) {
        AMS_UNUSED(ret, bsd_errno);

        static LogSampler s_write;
        LogUnrelayedSend(this->m_forward_service.get(), "Write", sockfd, message.GetSize(), s_write);

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

}
