#!/usr/bin/env bash
#
# Fetch and prepare third-party components.
#
# managed_components/ is not tracked by git, and wolfSSL 5.8.2 has no
# ESP32-C5 port. This script runs the component manager (idf.py
# reconfigure) and then applies the minimal C5 patch. Run it after a clean
# checkout or after `rm -rf managed_components/`.
#
# Usage:
#   source <idf-activate>
#   tools/setup_deps.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
proj="$(dirname "$here")"

echo "== fetching managed components =="
( cd "$proj" && idf.py reconfigure >/dev/null )

echo "== patching wolfSSL for ESP32-C5 =="
python3 "$here/patches/wolfssl-esp32c5.py" "$proj/managed_components/wolfssl__wolfssl"

echo "== done; now: idf.py build =="
