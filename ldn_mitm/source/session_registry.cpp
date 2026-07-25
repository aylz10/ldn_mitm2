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
#include <mutex>
#include <cstring>

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
        {
            std::scoped_lock lk(g_mutex);
            g_state = {};
        }
        /* The relay receive queue shares the session lifetime. */
        GameRx::Clear();
    }

    void SessionRegistry::Get(Snapshot *out) {
        std::scoped_lock lk(g_mutex);
        *out = g_state;
    }

    namespace {
        struct GameRxEntry {
            u32 src_ip;
            u16 sport;
            u16 dport;
            u16 len;
            u8  data[GameRx::MaxPayload];
        };
        os::SdkMutex g_rx_mutex;
        GameRxEntry g_rx_ring[GameRx::MaxEntries];
        int g_rx_head = 0;
        int g_rx_count = 0;
        s32 g_game_fd = -1;
        u16 g_session_dport = 0;
    }

    void GameRx::SetGameFd(s32 fd) {
        std::scoped_lock lk(g_rx_mutex);
        g_game_fd = fd;
    }

    s32 GameRx::GameFd() {
        std::scoped_lock lk(g_rx_mutex);
        return g_game_fd;
    }

    void GameRx::Push(u32 src_ip, u16 sport, u16 dport, const void *data, size_t len) {
        if (len == 0 || len > MaxPayload) {
            return;
        }
        std::scoped_lock lk(g_rx_mutex);
        /* Enqueue even before the game fd is known. */
        int slot;
        if (g_rx_count == MaxEntries) {
            slot = g_rx_head;
            g_rx_head = (g_rx_head + 1) % MaxEntries;
        } else {
            slot = (g_rx_head + g_rx_count) % MaxEntries;
            g_rx_count++;
        }
        GameRxEntry &e = g_rx_ring[slot];
        e.src_ip = src_ip;
        e.sport = sport;
        e.dport = dport;
        e.len = static_cast<u16>(len);
        g_session_dport = dport;
        std::memcpy(e.data, data, len);
    }

    bool GameRx::Pop(u32 *src_ip, u16 *sport, void *out, size_t max_len, size_t *out_len) {
        std::scoped_lock lk(g_rx_mutex);
        if (g_rx_count == 0) {
            return false;
        }
        const GameRxEntry &e = g_rx_ring[g_rx_head];
        const size_t n = e.len < max_len ? e.len : max_len;
        std::memcpy(out, e.data, n);
        if (src_ip)  { *src_ip = e.src_ip; }
        if (sport)   { *sport = e.sport; }
        if (out_len) { *out_len = n; }
        g_rx_head = (g_rx_head + 1) % MaxEntries;
        g_rx_count--;
        return true;
    }

    bool GameRx::HasData() {
        std::scoped_lock lk(g_rx_mutex);
        return g_rx_count > 0;
    }

    void GameRx::NoteSessionPort(u16 port) {
        if (port == 0) {
            return;
        }
        std::scoped_lock lk(g_rx_mutex);
        g_session_dport = port;
    }

    u16 GameRx::SessionDport() {
        std::scoped_lock lk(g_rx_mutex);
        return g_session_dport;
    }

    u16 GameRx::PeekDport() {
        std::scoped_lock lk(g_rx_mutex);
        if (g_rx_count == 0) {
            return 0;
        }
        return g_rx_ring[g_rx_head].dport;
    }

    void GameRx::Clear() {
        std::scoped_lock lk(g_rx_mutex);
        g_rx_count = 0;
        g_rx_head = 0;
        g_game_fd = -1;
        g_session_dport = 0;
    }

}
