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
import json
import sys

from micropot_proto import CtlError, call, exchange


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

    try:
        if args.raw:
            sys.stdout.write(
                exchange(args.host, args.port, args.psk, args.cmd,
                         args.key, args.value, args.tcp, args.timeout)
                .decode(errors="replace"))
            return 0
        result = call(args.host, args.port, args.psk, args.cmd,
                      args.key, args.value, args.tcp, args.timeout)
    except CtlError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2, ensure_ascii=False)
          if isinstance(result, (dict, list)) else result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
