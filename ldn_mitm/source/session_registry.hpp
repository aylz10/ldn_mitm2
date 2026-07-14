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

}
