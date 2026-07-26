#!/usr/bin/env python3
"""
Self-hosted relay server for ldn_mitm (and switch-lan-play) internet play.

Protocol: UDP datagrams of [u8 type][payload].
  0x00 KEEPALIVE  refreshes this endpoint's mappings; carries no address, so
                  it cannot learn one
  0x01 IPV4       bare IPv4 packet
  0x02 PING       first 4 bytes echoed back
  0x03 IPV4_FRAG  16-byte header (src[4] dst[4] ...); forwarded as-is
  0x20 SCOPE      ldn_mitm extension: [u32 BE session token], 0 = none

Routing: learn (scope token, src IP) -> endpoint; discovery broadcasts (UDP
dport 11452) reach every client, game broadcasts only the sender's scope
(everyone if unscoped); unicast goes to the dst IP's owner. Idle >60s expires.

Usage: python relay_server.py [--port 11451] [--bind 0.0.0.0] [-v]
"""
import argparse
import socket
import time

TYPE_KEEPALIVE = 0x00
TYPE_IPV4 = 0x01
TYPE_PING = 0x02
TYPE_IPV4_FRAG = 0x03
TYPE_SCOPE = 0x20
IDLE_TIMEOUT = 60.0
SCOPE_TIMEOUT = 300.0
DISCOVERY_PORT = 11452  # LANDiscovery traffic always crosses scopes


def ip_str(b):
    return ".".join(str(x) for x in b)


def is_broadcast(dst4):
    return dst4 == b"\xff\xff\xff\xff" or dst4[3] == 0xFF


def udp_dport(payload):
    if len(payload) < 20:
        return None
    ihl = (payload[0] & 0x0F) * 4
    if ihl < 20 or payload[9] != 17 or len(payload) < ihl + 4:
        return None
    return (payload[ihl + 2] << 8) | payload[ihl + 3]


def main():
    ap = argparse.ArgumentParser(description="Self-hosted lan-play/ldn_mitm relay server.")
    ap.add_argument("--port", "-p", type=int, default=11451, help="UDP port to bind (default 11451)")
    ap.add_argument("--bind", default="0.0.0.0", help="address to bind (default 0.0.0.0)")
    ap.add_argument("--verbose", "-v", action="store_true", help="log every relayed packet")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    print(f"[relay] listening on {args.bind}:{args.port} (Ctrl-C to stop)")

    # (scope token, virtual-src 4 bytes) -> (udp_endpoint, last_seen)
    clients = {}
    # udp_endpoint -> (scope token, last_declared); absent/expired = unscoped
    scopes = {}
    endpoints = set()

    def scope_of(ep, now):
        entry = scopes.get(ep)
        if entry is None:
            return 0
        token, seen = entry
        if now - seen > SCOPE_TIMEOUT:
            del scopes[ep]
            return 0
        return token

    def active_endpoints(now, exclude=None, token=None):
        # Unscoped endpoints match any token: stock lan-play clients never
        # declare one.
        eps = set()
        for key, (ep, seen) in list(clients.items()):
            if now - seen > IDLE_TIMEOUT:
                del clients[key]
                continue
            if ep == exclude:
                continue
            if token is not None:
                ep_scope = scope_of(ep, now)
                if ep_scope != token and ep_scope != 0:
                    continue
            eps.add(ep)
        return eps

    def find_owner(now, token, dst4):
        def live(entry):
            return entry if entry is not None and now - entry[1] <= IDLE_TIMEOUT else None

        owner = live(clients.get((token, dst4))) or live(clients.get((0, dst4)))
        if owner is None and token == 0:
            for (_, ip), entry in clients.items():
                if ip == dst4 and live(entry):
                    return entry
        return owner

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except ConnectionResetError:
            # Windows: ICMP port-unreachable from an earlier send.
            continue
        if not data:
            continue

        if addr not in endpoints:
            endpoints.add(addr)
            print(f"[relay] new client {addr[0]}:{addr[1]}  ({len(active_endpoints(time.time())) + 1} online)")

        now = time.time()
        msg_type, payload = data[0], data[1:]

        if msg_type == TYPE_KEEPALIVE:
            for key, (ep, _) in list(clients.items()):
                if ep == addr:
                    clients[key] = (ep, now)
            continue

        if msg_type == TYPE_PING:
            try:
                sock.sendto(data[:4], addr)
            except OSError:
                pass
            continue

        if msg_type == TYPE_SCOPE:
            if len(payload) < 4:
                continue
            token = int.from_bytes(payload[0:4], "big")
            prev = scope_of(addr, now)
            scopes[addr] = (token, now)
            if token != prev:
                # Re-key so unicast keeps working without waiting for a data frame.
                for (old_token, vsrc), (ep, seen) in list(clients.items()):
                    if ep == addr and old_token == prev:
                        del clients[(old_token, vsrc)]
                        clients[(token, vsrc)] = (ep, seen)
                if args.verbose:
                    print(f"[relay] scope {addr[0]}:{addr[1]} {prev:#x} -> {token:#x}")
            if len(scopes) > 256:
                for ep in [e for e, (_, seen) in scopes.items() if now - seen > SCOPE_TIMEOUT]:
                    del scopes[ep]
            continue

        if msg_type == TYPE_IPV4 and len(payload) >= 20:
            src4 = payload[12:16]
            dst4 = payload[16:20]
            dport = udp_dport(payload)
        elif msg_type == TYPE_IPV4_FRAG and len(payload) >= 16:
            src4 = payload[0:4]
            dst4 = payload[4:8]
            # Only part 0 has the UDP header; discovery frames never fragment.
            dport = None
        else:
            continue

        token = scope_of(addr, now)
        prev = clients.get((token, src4))
        clients[(token, src4)] = (addr, now)
        if prev is None or prev[0] != addr:
            print(f"[relay] learn {ip_str(src4)} (scope {token:#x}) -> {addr[0]}:{addr[1]}")

        if is_broadcast(dst4):
            # Discovery crosses scopes: a scanner is not in a session yet.
            if dport == DISCOVERY_PORT or token == 0:
                targets = active_endpoints(now, exclude=addr)
            else:
                targets = active_endpoints(now, exclude=addr, token=token)
            sent = 0
            for ep in targets:
                try:
                    sock.sendto(data, ep)
                    sent += 1
                except OSError:
                    pass
            if args.verbose:
                kind = "disc" if dport == DISCOVERY_PORT else "game"
                print(f"[relay] bcast {ip_str(src4)} -> {ip_str(dst4)} "
                      f"({len(payload)}B {kind} scope {token:#x}) x{sent}")
        else:
            owner = find_owner(now, token, dst4)
            if owner and owner[0] != addr:
                try:
                    sock.sendto(data, owner[0])
                    if args.verbose:
                        print(f"[relay] ucast {ip_str(src4)} -> {ip_str(dst4)} "
                              f"({len(payload)}B scope {token:#x})")
                except OSError:
                    pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[relay] stopped")
