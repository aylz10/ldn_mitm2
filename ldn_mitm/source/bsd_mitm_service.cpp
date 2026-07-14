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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <atomic>

namespace ams::mitm::ldn {

    namespace {

        /* Longer or infinite waits are re-issued capped at WaitCapMs so a dead
           client cannot pin a real bsd:u request. */
        constexpr s32 WaitCapMs    = 1000;
        constexpr s32 ForwardMaxMs = 60000;

        struct BsdOutData {
            s32 ret;
            s32 bsd_errno;
        };

        bool ShouldLogCapped(u32 n) {
            return n <= 8 || (n % 256) == 0;
        }

    }

    Result BsdMitmService::Select(sf::Out<s32> ret, sf::Out<s32> bsd_errno, BsdSelectInData in_data, sf::InAutoSelectBuffer rd_in, sf::InAutoSelectBuffer wr_in, sf::InAutoSelectBuffer ex_in, sf::OutAutoSelectBuffer rd_out, sf::OutAutoSelectBuffer wr_out, sf::OutAutoSelectBuffer ex_out) {
        /* tv_sec is bounded first so the ms conversion cannot overflow. */
        if (in_data.is_null == 0 && in_data.tv_sec >= 0 && in_data.tv_sec <= ForwardMaxMs / 1000) {
            const s64 wait_ms = in_data.tv_sec * 1000 + in_data.tv_usec / 1000;
            if (wait_ms <= ForwardMaxMs) {
                R_RETURN(sm::mitm::ResultShouldForwardToSession());
            }
        }

        static std::atomic<u32> s_capped{0};
        const u32 n = s_capped.fetch_add(1, std::memory_order_relaxed) + 1;
        if (ShouldLogCapped(n)) {
            LogFormat("bsd Select capped #%u nfds %d is_null %d tv %lld.%06lld",
                n, in_data.nfds, static_cast<int>(in_data.is_null),
                static_cast<long long>(in_data.tv_sec), static_cast<long long>(in_data.tv_usec));
        }

        /* Select, bsd cmd 5. */
        BsdSelectInData in = in_data;
        in.is_null = 0;
        in.tv_sec  = WaitCapMs / 1000;
        in.tv_usec = 0;
        BsdOutData out = {};

        ::Service *fwd = this->m_forward_service.get();
        R_TRY((serviceDispatchInOut(fwd, 5, in, out,
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

        ret.SetValue(out.ret);
        bsd_errno.SetValue(out.bsd_errno);
        R_SUCCEED();
    }

    Result BsdMitmService::Poll(sf::Out<s32> ret, sf::Out<s32> bsd_errno, u32 nfds, s32 timeout, sf::InAutoSelectBuffer fds_in, sf::OutAutoSelectBuffer fds_out) {
        if (timeout >= 0 && timeout <= ForwardMaxMs) {
            R_RETURN(sm::mitm::ResultShouldForwardToSession());
        }

        static std::atomic<u32> s_capped{0};
        const u32 n = s_capped.fetch_add(1, std::memory_order_relaxed) + 1;
        if (ShouldLogCapped(n)) {
            LogFormat("bsd Poll capped #%u nfds %u timeout %d", n, nfds, timeout);
        }

        /* Poll, bsd cmd 6. */
        const struct {
            u32 nfds;
            s32 timeout;
        } in = { nfds, WaitCapMs };
        BsdOutData out = {};

        ::Service *fwd = this->m_forward_service.get();
        R_TRY((serviceDispatchInOut(fwd, 6, in, out,
            .buffer_attrs = {
                SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
            },
            .buffers = {
                { fds_in.GetPointer(),  fds_in.GetSize()  },
                { fds_out.GetPointer(), fds_out.GetSize() },
            },
        )));

        ret.SetValue(out.ret);
        bsd_errno.SetValue(out.bsd_errno);
        R_SUCCEED();
    }

    Result BsdMitmService::SendTo(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, s32 flags, sf::InAutoSelectBuffer message, sf::InAutoSelectBuffer dst_addr) {
        AMS_UNUSED(ret, bsd_errno);

        if (LdnConfig::getBroadcastRelay() && dst_addr.GetSize() >= sizeof(struct sockaddr_in)) {
            const auto *sa = reinterpret_cast<const struct sockaddr_in *>(dst_addr.GetPointer());
            if (sa->sin_family == AF_INET) {
                const u32 ip = ntohl(sa->sin_addr.s_addr);

                SessionRegistry::Snapshot snap;
                SessionRegistry::Get(std::addressof(snap));

                const bool is_bcast = (ip == 0xFFFFFFFFu) || (snap.active && ip == snap.bcast_ip);

                if (snap.active && snap.peer_count > 0 && is_bcast) {
                    /* The original broadcast is still forwarded below. */
                    ::Service *fwd = this->m_forward_service.get();
                    for (int i = 0; i < snap.peer_count; i++) {
                        struct sockaddr_in peer = *sa;
                        peer.sin_addr.s_addr = htonl(snap.peer_ips[i]);

                        const struct {
                            s32 sockfd;
                            s32 flags;
                        } in = { sockfd, flags };
                        struct {
                            s32 ret;
                            s32 bsd_errno;
                        } out = {};

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
                    LogFormat("bsd SendTo fanout %d peer(s) fd %d len %zu",
                        snap.peer_count, sockfd, message.GetSize());
                }
            }
        }

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

}
