#!/usr/bin/env python3
"""micropotctl — management-plane client for micropot-c5.

Sends HMAC-SHA256-signed control commands over UDP (default) or TCP:

    micropotctl.py --host 192.168.1.15 --psk secret status
    micropotctl.py --host 192.168.1.15 --psk secret set log.port 514
    micropotctl.py --host 192.168.1.15 --psk secret --tcp list

Commands: ping, status, list, get K, set K V, unset K, reset,
          log.stats, log.test, reboot
"""
import argparse
import hashlib
import hmac
import json
import socket
import sys
import time

_id = 0


def build_line(psk: str, cmd: str, key: str | None, value: str | None) -> bytes:
    global _id
    _id += 1
    parts = [f"id={_id}", f"ts={int(time.time())}", f"cmd={cmd}"]
    if key is not None:
        parts.append(f"k={key}")
    msg = " ".join(parts)
    if value is not None:
        msg += f" v={value}"
    mac = hmac.new(psk.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{msg} mac={mac}\n".encode()


def exchange_udp(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(4096)
        return data


def exchange_tcp(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(payload)
        s.settimeout(timeout)
        line = b""
        while not line.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            line += chunk
        return line


def main() -> int:
    ap = argparse.ArgumentParser(description="micropot-c5 management client")
    ap.add_argument("--host", required=True, help="management vdev IP")
    ap.add_argument("--port", type=int, default=55555)
    ap.add_argument("--psk", required=True, help="control channel PSK")
    ap.add_argument("--tcp", action="store_true", help="use TCP (default UDP)")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--raw", action="store_true", help="print the raw reply")
    ap.add_argument("cmd", help="ping|status|list|get|set|unset|reset|log.stats|log.test|reboot")
    ap.add_argument("key", nargs="?")
    ap.add_argument("value", nargs="?")
    args = ap.parse_args()

    payload = build_line(args.psk, args.cmd, args.key, args.value)
    exchange = exchange_tcp if args.tcp else exchange_udp
    try:
        reply = exchange(args.host, args.port, payload, args.timeout)
    except (socket.timeout, TimeoutError):
        print("error: no reply (timeout)", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.raw:
        sys.stdout.write(reply.decode(errors="replace"))
        return 0
    try:
        obj = json.loads(reply)
    except json.JSONDecodeError:
        sys.stdout.write(reply.decode(errors="replace"))
        return 1
    if obj.get("ok"):
        print(json.dumps(obj.get("result"), indent=2, ensure_ascii=False)
              if isinstance(obj.get("result"), (dict, list))
              else obj.get("result"))
        return 0
    print(f"error: {obj.get('err')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
