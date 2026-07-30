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
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    /* libnx bsdSelect's 32-byte in-data, as one struct so the sf packer cannot
       reorder or re-pad it. */
    struct BsdSelectInData {
        s32 nfds;
        u32 _pad;
        s64 tv_sec;
        s64 tv_usec;
        u8  is_null;
        u8  _pad2[7];
    };
    static_assert(sizeof(BsdSelectInData) == 32);
    static_assert(__builtin_offsetof(BsdSelectInData, tv_sec) == 8);
    static_assert(__builtin_offsetof(BsdSelectInData, is_null) == 24);

}

/* Signatures must match libnx bsd.c's wire format exactly (Poll's nfds is u32).
   Unlisted commands are forwarded verbatim. */
#define AMS_BSD_MITM_INTERFACE(C, H)                                                                                                                                                              \
    AMS_SF_METHOD_INFO(C, H, 5,  Result, Select, (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, ams::mitm::ldn::BsdSelectInData in_data, ams::sf::InAutoSelectBuffer rd_in, ams::sf::InAutoSelectBuffer wr_in, ams::sf::InAutoSelectBuffer ex_in, ams::sf::OutAutoSelectBuffer rd_out, ams::sf::OutAutoSelectBuffer wr_out, ams::sf::OutAutoSelectBuffer ex_out), (ret, bsd_errno, in_data, rd_in, wr_in, ex_in, rd_out, wr_out, ex_out)) \
    AMS_SF_METHOD_INFO(C, H, 8,  Result, Recv,   (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, s32 sockfd, u32 flags, ams::sf::OutAutoSelectBuffer message), (ret, bsd_errno, sockfd, flags, message)) \
    AMS_SF_METHOD_INFO(C, H, 14, Result, Connect, (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, s32 sockfd, ams::sf::InAutoSelectBuffer dst_addr), (ret, bsd_errno, sockfd, dst_addr)) \
    AMS_SF_METHOD_INFO(C, H, 25, Result, Read,   (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, s32 sockfd, ams::sf::OutAutoSelectBuffer message), (ret, bsd_errno, sockfd, message)) \
    AMS_SF_METHOD_INFO(C, H, 6,  Result, Poll,   (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, u32 nfds, s32 timeout, ams::sf::InAutoSelectBuffer fds_in, ams::sf::OutAutoSelectBuffer fds_out), (ret, bsd_errno, nfds, timeout, fds_in, fds_out)) \
    AMS_SF_METHOD_INFO(C, H, 9,  Result, RecvFrom, (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, ams::sf::Out<u32> addrlen, s32 sockfd, u32 flags, ams::sf::OutAutoSelectBuffer message, ams::sf::OutAutoSelectBuffer src_addr), (ret, bsd_errno, addrlen, sockfd, flags, message, src_addr)) \
    AMS_SF_METHOD_INFO(C, H, 11, Result, SendTo, (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, s32 sockfd, s32 flags, ams::sf::InAutoSelectBuffer message, ams::sf::InAutoSelectBuffer dst_addr), (ret, bsd_errno, sockfd, flags, message, dst_addr)) \
    AMS_SF_METHOD_INFO(C, H, 10, Result, Send,   (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, s32 sockfd, s32 flags, ams::sf::InAutoSelectBuffer message), (ret, bsd_errno, sockfd, flags, message)) \
    AMS_SF_METHOD_INFO(C, H, 24, Result, Write,  (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, s32 sockfd, ams::sf::InAutoSelectBuffer message), (ret, bsd_errno, sockfd, message))

AMS_SF_DEFINE_MITM_INTERFACE(ams::mitm::ldn, IBsdMitmInterface, AMS_BSD_MITM_INTERFACE, 0x7B5D0C41)
