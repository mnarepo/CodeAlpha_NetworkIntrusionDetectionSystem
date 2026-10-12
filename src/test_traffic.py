#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time


def udp_probe(target: str, port: int = 9999) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"CODEALPHA-NIDS-LAB-UDP", (target, port))
    print(f"[OK] Sent harmless UDP test datagram to {target}:{port}")


def tcp_connect(target: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        try:
            sock.connect((target, port)); print(f"[OK] Connected to {target}:{port}")
        except (ConnectionRefusedError, TimeoutError, OSError):
            print(f"[INFO] Connection was not established to {target}:{port}; the test attempt was still sent.")


def repeated_tcp(target: str, port: int = 8080, count: int = 5) -> None:
    for _ in range(count):
        tcp_connect(target, port); time.sleep(0.25)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate harmless CodeAlpha NIDS lab traffic.")
    parser.add_argument("--target", default="127.0.0.1", help="Authorized target host. Default: 127.0.0.1")
    parser.add_argument("--mode", choices=("udp","tcp4444","repeated8080"), required=True)
    args = parser.parse_args()
    print("Authorized-use notice: test only systems/networks you own or are permitted to test.")
    if args.mode == "udp": udp_probe(args.target)
    elif args.mode == "tcp4444": tcp_connect(args.target, 4444)
    else: repeated_tcp(args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
