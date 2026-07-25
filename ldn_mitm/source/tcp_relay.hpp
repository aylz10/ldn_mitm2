#pragma once
#include <switch.h>
#include <stratosphere.hpp>

namespace ams::mitm::ldn::tcprelay {

    constexpr u16 TcpTunnelPort = 11453;

    /* False means forward the connect unchanged. */
    bool RedirectConnect(::Service *fwd, s32 sockfd, u32 dst_ip, u16 dst_port,
                         s32 *out_ret, s32 *out_bsd_errno);

    void OnTunnelFrame(u32 src_ip, const u8 *payload, size_t len);

    void Start();
    void Stop();

}
