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

    /* Own mutex: no lock-order coupling with LANDiscovery. IPs are host order. */
    class SessionRegistry {
        public:
            static constexpr int MaxPeers = 8;
            struct Snapshot {
                bool active;
                u32  bcast_ip;
                int  peer_count;
                u32  peer_ips[MaxPeers];     /* excludes self */
            };

            static void Publish(u32 bcast_ip, const u32 *peer_ips, int peer_count);

            static void Clear();

            static void Get(Snapshot *out);
    };

    class GameRx {
        public:
            static constexpr int  MaxEntries = 32;
            static constexpr int  MaxPayload = 1472;   /* 1500 MTU - IP/UDP headers */

            static void SetGameFd(s32 fd);
            static s32  GameFd();

            /* Host byte order. Drops the oldest entry if full. */
            static void Push(u32 src_ip, u16 sport, u16 dport, const void *data, size_t len);

            static bool Pop(u32 *src_ip, u16 *sport, void *out, size_t max_len, size_t *out_len);

            /* dport of the oldest queued frame, 0 if empty. */
            static u16 PeekDport();

            static bool HasData();

            static void Clear();
    };

}
