#!/usr/bin/env python3
"""MicroPot-C5 structured log collector.

Receives the honeypot's JSON events over UDP and/or TCP, pretty-prints them
to the terminal and appends every raw line to a JSONL file.

Examples:
    python3 log_collector.py --host 0.0.0.0 --port 9999
    python3 log_collector.py --proto tcp --out logs/
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from collections import Counter
from datetime import datetime

KIND_COLOR = {
    "telnet.login_attempt": "\033[33m",
    "http.login_attempt": "\033[33m",
    "telnet.connect": "\033[36m",
    "telnet.command": "\033[35m",
    "http.request": "\033[36m",
    "http.notfound": "\033[31m",
    "ssh.connect": "\033[36m",
    "ssh.banner": "\033[35m",
    "log.dropped": "\033[41;97m",
    "svc.overload": "\033[41;97m",
    "net.up": "\033[32m",
    "svc": "\033[32m",
}
RESET = "\033[0m"


def _supports_color() -> bool:
    """True when the terminal is likely to interpret ANSI SGR sequences."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Windows Terminal / ANSICON / ConEmu enable VT processing; the
        # legacy conhost shows raw escape sequences instead.
        return bool(os.environ.get("WT_SESSION")
                    or os.environ.get("ANSICON")
                    or os.environ.get("ConEmuANSI") == "ON")
    return True


class Collector:
    def __init__(self, out_dir: str, quiet: bool,
                 color: bool | None = None) -> None:
        os.makedirs(out_dir, exist_ok=True)
        self.out_dir = out_dir
        self.quiet = quiet
        self.use_color = _supports_color() if color is None else color
        self._day = datetime.now().strftime("%Y%m%d")
        self.path = os.path.join(out_dir, f"micropot-{self._day}.jsonl")
        self.fp = open(self.path, "a", encoding="utf-8")
        self.total = 0
        self.by_kind: Counter[str] = Counter()
        self.by_src: Counter[str] = Counter()

    def close(self) -> None:
        self.fp.close()

    def _rotate_if_needed(self) -> None:
        """Start a new file when a long-running collector crosses midnight."""
        day = datetime.now().strftime("%Y%m%d")
        if day == self._day:
            return
        self.fp.close()
        self._day = day
        self.path = os.path.join(self.out_dir, f"micropot-{day}.jsonl")
        self.fp = open(self.path, "a", encoding="utf-8")

    def _format(self, evt: dict) -> str:
        data = evt.get("data", {})
        parts = [f"{k}={v}" for k, v in data.items()]
        src = f"{evt.get('sip', '?')}:{evt.get('sport', '?')}"
        dst = f"{evt.get('dip', '?')}:{evt.get('dport', '?')}"
        sid = evt.get("sid", 0)
        color = KIND_COLOR.get(evt.get("evt", ""), "") if self.use_color else ""
        reset = RESET if self.use_color else ""
        label = evt.get("evt", "?")
        return (f"{src:>21} -> {dst:<21} sid={sid:<5} {color}{label:<20}{reset} "
                f"{' '.join(parts)}")

    def handle_line(self, raw: bytes, transport: str) -> None:
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return
        self._rotate_if_needed()
        self.fp.write(text + "\n")
        self.fp.flush()
        try:
            evt = json.loads(text)
        except json.JSONDecodeError:
            if not self.quiet:
                print(f"[{transport}] (unparsed) {text}")
            return
        self.total += 1
        self.by_kind[evt.get("evt", "?")] += 1
        self.by_src[evt.get("sip", "?")] += 1
        if not self.quiet:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] {transport} {self._format(evt)}")

    def summary(self) -> None:
        print("\n===== capture summary =====")
        print(f"total events : {self.total}")
        print(f"log file     : {self.path}")
        if self.by_kind:
            print("by event     :")
            for kind, count in self.by_kind.most_common():
                print(f"  {kind:<24} {count}")
        if self.by_src:
            print("top sources  :")
            for src, count in self.by_src.most_common(10):
                print(f"  {src:<20} {count}")


class UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: Collector) -> None:
        self.collector = collector

    def datagram_received(self, data: bytes, addr) -> None:
        self.collector.handle_line(data, "udp")


async def run(args: argparse.Namespace) -> None:
    collector = Collector(args.out, args.quiet,
                          False if args.no_color else None)
    loop = asyncio.get_running_loop()
    servers = []

    if args.proto in ("udp", "both"):
        await loop.create_datagram_endpoint(
            lambda: UdpProtocol(collector),
            local_addr=(args.host, args.port),
        )
        servers.append("udp")

    if args.proto in ("tcp", "both"):
        async def on_tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            while True:
                line = await reader.readline()
                if not line:
                    break
                collector.handle_line(line, "tcp")
            writer.close()

        await asyncio.start_server(on_tcp, args.host, args.port)
        servers.append("tcp")

    print(f"listening on {args.host}:{args.port} ({'+'.join(servers)})")
    print(f"appending to {collector.path}")
    print("press Ctrl-C to stop\n")

    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    try:
        await stop.wait()
    finally:
        # Windows has no loop.add_signal_handler(); Ctrl-C surfaces as
        # KeyboardInterrupt, but the summary/flush path must still run.
        collector.summary()
        collector.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="MicroPot-C5 log collector")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--proto", choices=["udp", "tcp", "both"], default="udp")
    parser.add_argument("--out", default="logs", help="directory for JSONL files")
    parser.add_argument("--quiet", action="store_true", help="only write files")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colours in the terminal output")
    args = parser.parse_args()

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
