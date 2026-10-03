#!/usr/bin/env python3
"""Mock attacker client for MicroPot-C5 behavior regression checks.

Drives the honeypot's Telnet and HTTP services through a fixed script of
interactions and prints a normalized transcript (`## <step>` headers plus
raw replies) that can be diffed across firmware builds. Pair with
golden_check.py on the collector's JSONL output for full behavior
regression.

Examples:
    python3 mock_client.py --host 192.168.1.100 --persona camera --mode both
    python3 mock_client.py --host 192.168.1.100 --mode all
    python3 mock_client.py --host 192.168.1.100 --mode telnet --user admin --password 12345
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TELNET_IAC = 255

PERSONAS = {
    "camera": {"user": "admin", "password": "12345", "fail_hint": b"Login incorrect",
               "cmds": ("id", "uname -a", "ls", "ifconfig")},
    "router": {"user": "admin", "password": "admin",
               "fail_hint": b"Incorrect username or password",
               "cmds": ("id", "uname -a", "ls", "ifconfig", "route")},
    "printer": {"user": "admin", "password": "0000", "fail_hint": b"Login incorrect",
                "cmds": ("help", "info", "status", "pages")},
}

TELNET_BOGUS_COMMAND = "boguscmd-not-found"


def strip_iac(data: bytes) -> bytes:
    """Remove Telnet IAC negotiation sequences from a byte stream."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == TELNET_IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd == 250:  # SB ... SE
                i += 2
                while i + 1 < len(data) and not (data[i] == TELNET_IAC and data[i + 1] == 240):
                    i += 1
                i += 2
            elif 251 <= cmd <= 254:
                i += 3
            else:
                i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


def drain(sock: socket.socket, seconds: float = 1.0) -> bytes:
    sock.settimeout(0.3)
    end = time.time() + seconds
    buf = b""
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            continue
    return buf


class Reporter:
    """Normalized transcript output and critical-failure tracking."""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def step(self, name: str) -> None:
        print(f"\n## {name}")

    def raw(self, data: bytes) -> None:
        text = data.decode(errors="replace")
        if text:
            print(text, end="" if text.endswith("\n") else "\n")

    def info(self, msg: str) -> None:
        print(msg)

    def fail(self, step: str, why: str) -> None:
        self.failures.append(f"{step}: {why}")
        print(f"FAIL {why}")


def telnet_exchange(rep: Reporter, sock: socket.socket, line: str, wait: float = 0.6) -> bytes:
    """Send one command line (LF-terminated) and print the stripped reply."""
    rep.info(f"> {line}")
    sock.sendall(line.encode() + b"\n")
    reply = strip_iac(drain(sock, wait))
    rep.raw(reply)
    return reply


def run_telnet(rep: Reporter, host: str, port: int, user: str, password: str,
               fail_hint: bytes, commands: tuple[str, ...]) -> None:
    rep.step(f"telnet.connect {host}:{port}")
    try:
        s = socket.create_connection((host, port), timeout=10)
    except OSError as e:
        rep.info(f"ERROR {e}")
        rep.fail("telnet.connect", str(e))
        return
    with s:
        rep.raw(strip_iac(drain(s)))

        # Failed login first: the failure path must produce an event too.
        rep.step("telnet.login bad-credentials")
        telnet_exchange(rep, s, "baduser")
        reply = telnet_exchange(rep, s, "badpass")
        if fail_hint not in reply:
            rep.fail("telnet.login bad-credentials",
                     f"expected {fail_hint.decode()!r}")

        rep.step("telnet.login")
        telnet_exchange(rep, s, user)
        reply = telnet_exchange(rep, s, password, wait=1.0)
        if fail_hint in reply:
            rep.fail("telnet.login", "valid credentials rejected")
            return

        for cmd in commands:
            rep.step(f"telnet.cmd {cmd!r}")
            telnet_exchange(rep, s, cmd, wait=0.5)

        rep.step(f"telnet.cmd {TELNET_BOGUS_COMMAND!r}")
        reply = telnet_exchange(rep, s, TELNET_BOGUS_COMMAND, wait=0.5)
        if b"not found" not in reply:
            rep.fail("telnet.cmd bogus", "expected 'not found' reply")

        rep.step("telnet.exit")
        telnet_exchange(rep, s, "exit", wait=0.5)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(_NoRedirect)


def http_request(rep: Reporter, step: str, method: str, url: str,
                 data: bytes | None = None, expect: int | None = None
                 ) -> tuple[int, dict, bytes] | None:
    rep.step(step)
    req = urllib.request.Request(url, data=data, method=method)
    try:
        with OPENER.open(req, timeout=10) as r:
            status, headers, body = r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        status, headers, body = e.code, dict(e.headers), e.read()
    except OSError as e:
        rep.info(f"ERROR {e}")
        rep.fail(step, str(e))
        return None
    loc = headers.get("Location")
    rep.info(f"{method} {url} -> {status}" + (f" Location: {loc}" if loc else ""))
    rep.raw(body)
    if expect is not None and status != expect:
        rep.fail(step, f"expected HTTP {expect}, got {status}")
    return status, headers, body


def run_http(rep: Reporter, host: str, port: int, user: str, password: str) -> None:
    base = f"http://{host}:{port}"

    res = http_request(rep, "http.get /", "GET", f"{base}/", expect=302)
    if res and res[1].get("Location") != "/login":
        rep.fail("http.get /", f"expected Location: /login, got {res[1].get('Location')}")

    http_request(rep, "http.get /login", "GET", f"{base}/login", expect=200)

    bad = urllib.parse.urlencode({"username": "baduser", "password": "badpass"}).encode()
    good = urllib.parse.urlencode({"username": user, "password": password}).encode()
    fail_res = http_request(rep, "http.post /login bad-credentials", "POST",
                            f"{base}/login", data=bad, expect=200)
    ok_res = http_request(rep, "http.post /login", "POST",
                          f"{base}/login", data=good, expect=200)
    if fail_res and ok_res and ok_res[2] == fail_res[2]:
        rep.fail("http.post /login", "success page identical to failure page")

    http_request(rep, "http.get /admin", "GET", f"{base}/admin", expect=200)
    http_request(rep, "http.get /does-not-exist", "GET",
                 f"{base}/does-not-exist", expect=404)


def run_ssh(rep: Reporter, host: str, port: int) -> None:
    rep.step(f"ssh.connect {host}:{port}")
    try:
        s = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        rep.info(f"ERROR {e}")
        rep.info("ssh service not available, skipping")
        return
    with s:
        s.settimeout(5)
        banner = b""
        try:
            while not banner.endswith(b"\n") and len(banner) < 256:
                chunk = s.recv(256)
                if not chunk:
                    break
                banner += chunk
        except OSError as e:
            rep.info(f"ERROR {e}")
            return
        rep.raw(banner)
        if not banner.startswith(b"SSH-2.0"):
            rep.info("no SSH banner received, skipping")
            return
        rep.info("> SSH-2.0-OpenSSH_8.9p1")
        s.sendall(b"SSH-2.0-OpenSSH_8.9p1\r\n")
        reply = drain(s, 2.0)
        if reply:
            rep.raw(reply)
        else:
            rep.info("(no further data)")


def main() -> int:
    parser = argparse.ArgumentParser(description="MicroPot-C5 mock attacker")
    parser.add_argument("--host", required=True)
    parser.add_argument("--telnet-port", type=int, default=23)
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--mode", choices=["telnet", "http", "both", "ssh", "all"],
                        default="both")
    parser.add_argument("--persona", choices=sorted(PERSONAS), default="camera",
                        help="select default credentials and expectations")
    parser.add_argument("--user", default=None, help="override persona default username")
    parser.add_argument("--password", default=None, help="override persona default password")
    args = parser.parse_args()

    creds = PERSONAS[args.persona]
    user = args.user if args.user is not None else creds["user"]
    password = args.password if args.password is not None else creds["password"]

    rep = Reporter()
    print(f"# micropot mock client persona={args.persona} host={args.host} mode={args.mode}")

    if args.mode in ("telnet", "both", "all"):
        run_telnet(rep, args.host, args.telnet_port, user, password,
                   creds["fail_hint"], creds["cmds"])
    if args.mode in ("http", "both", "all"):
        run_http(rep, args.host, args.http_port, user, password)
    if args.mode in ("ssh", "all"):
        run_ssh(rep, args.host, args.ssh_port)

    if rep.failures:
        print("\nTRANSCRIPT FAIL")
        for failure in rep.failures:
            print(f"  - {failure}")
        return 1
    print("\nTRANSCRIPT OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
