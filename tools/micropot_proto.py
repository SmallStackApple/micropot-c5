#!/usr/bin/env python3
"""Shared control-plane protocol helpers for micropot-c5 tools.

Implements the HMAC-SHA256-signed line protocol spoken by the device's
mp_ctl component:

    id=1 ts=1730000000 cmd=set k=log.port v=514 mac=<hmac-sha256 hex>

Replies are JSON: {"id":N,"ok":true,"result":...} or
{"id":N,"ok":false,"err":"..."}.

Used by micropotctl.py (CLI) and micropot_web.py (web UI).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import time

_id = 0
_last_ts = 0
_lock = threading.Lock()


class CtlError(Exception):
    """Transport failure or device-side error reply."""


def build_line(psk: str, cmd: str, key: str | None = None,
               value: str | None = None) -> bytes:
    global _id, _last_ts
    # Millisecond ts: the device demands strictly increasing ts per boot.
    # Same-millisecond calls (web UI poller + user command) and wall-clock
    # steps must not produce a duplicate or backward ts, so serialize the
    # counter and force monotonicity. Separate client processes can still
    # collide; that is a device-side policy limitation.
    with _lock:
        _id += 1
        req_id = _id
        now_ms = int(time.time() * 1000)
        _last_ts = max(_last_ts + 1, now_ms)
        ts = _last_ts
    parts = [f"id={req_id}", f"ts={ts}", f"cmd={cmd}"]
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


def exchange(host: str, port: int, psk: str, cmd: str,
             key: str | None = None, value: str | None = None,
             tcp: bool = False, timeout: float = 5.0) -> bytes:
    """Send one signed command, return the raw reply line."""
    payload = build_line(psk, cmd, key, value)
    fn = exchange_tcp if tcp else exchange_udp
    return fn(host, port, payload, timeout)


def call(host: str, port: int, psk: str, cmd: str,
         key: str | None = None, value: str | None = None,
         tcp: bool = False, timeout: float = 5.0):
    """Send one signed command and return the parsed result.

    Raises CtlError on timeout, transport error, malformed reply, or a
    device-side error.
    """
    try:
        reply = exchange(host, port, psk, cmd, key, value, tcp, timeout)
    except (socket.timeout, TimeoutError):
        raise CtlError("no reply (timeout)") from None
    except OSError as e:
        raise CtlError(str(e)) from None
    try:
        obj = json.loads(reply)
    except json.JSONDecodeError:
        raise CtlError("bad reply: "
                       + reply.decode(errors="replace")[:200]) from None
    if obj.get("ok"):
        return obj.get("result")
    raise CtlError(str(obj.get("err", "unknown error")))
