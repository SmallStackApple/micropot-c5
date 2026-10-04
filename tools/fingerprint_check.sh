#!/usr/bin/env bash
#
# Linux 4.19 persona fingerprint self-check.
#
# Flashes nothing; point it at a running device and it reports what nmap
# sees for the Linux 4.19 services and how close the OS guess is.
#
# Usage:
#   tools/fingerprint_check.sh <device-ip> [ports]
# Defaults: ports 22,23,80
#
# Only use on your own isolated lab network.

set -u

HOST="${1:-}"
PORTS="${2:-22,23,80}"

if [ -z "$HOST" ]; then
    echo "usage: $0 <device-ip> [ports]" >&2
    exit 2
fi

if ! command -v nmap >/dev/null 2>&1; then
    echo "nmap not found in PATH" >&2
    exit 127
fi

echo "=== service/version scan (expect OpenSSH_7.9p1, Apache/2.4.38) ==="
nmap -sV -Pn -p "$PORTS" "$HOST"

echo
echo "=== OS detection (best effort; see sdkconfig lwIP tuning) ==="
nmap -O --osscan-guess -Pn -p "$PORTS" "$HOST"

echo
echo "=== raw TCP SYN reply (TTL should be ~64, MSS 1460, window 0xFAF0) ==="
nmap --packet-trace -p "${PORTS%%,*}" "$HOST" 2>&1 | grep -Ei "ttl|win|mss|flags" | head -20
