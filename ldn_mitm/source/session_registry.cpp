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

#include "session_registry.hpp"

namespace ams::mitm::ldn {

    namespace {
        os::SdkMutex g_mutex;
        SessionRegistry::Snapshot g_state = {};
    }

    void SessionRegistry::Publish(u32 bcast_ip, const u32 *peer_ips, int peer_count) {
        std::scoped_lock lk(g_mutex);
        if (peer_count > MaxPeers) {
            peer_count = MaxPeers;
        }
        g_state.active     = true;
        g_state.bcast_ip   = bcast_ip;
        g_state.peer_count = peer_count;
        for (int i = 0; i < peer_count; i++) {
            g_state.peer_ips[i] = peer_ips[i];
        }
    }

    void SessionRegistry::Clear() {
        std::scoped_lock lk(g_mutex);
        g_state = {};
    }

    void SessionRegistry::Get(Snapshot *out) {
        std::scoped_lock lk(g_mutex);
        *out = g_state;
    }

}
