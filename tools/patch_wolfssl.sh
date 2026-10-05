#!/bin/sh
# Patch the vendored wolfSSL/wolfSSH user_settings.h to keep RSA enabled.
#
# managed_components/ is gitignored and re-fetched by idf.py; the registry
# build flips MY_USE_RSA to 0 on every target except ESP8266/C2, which makes
# wolfSSH define WOLFSSH_NO_RSA and reject RSA host keys with
# WS_UNIMPLEMENTED_E (-1017). Re-run this after deleting managed_components/.
set -e
cd "$(dirname "$0")/.."

for f in managed_components/wolfssl__wolfssl/include/user_settings.h \
         managed_components/wolfssl__wolfssh/include/user_settings.h; do
    if [ -f "$f" ]; then
        sed -i 's/#define MY_USE_RSA 0/#define MY_USE_RSA 1/' "$f"
        echo "patched: $f"
    fi
done

# Temporary diagnostics: wolfSSH WLOG to the console while we chase the
# WS_MATCH_KEY_ALGO_E (-1051) negotiation failure. Remove once resolved.
if ! grep -q 'define DEBUG_WOLFSSH' \
        managed_components/wolfssl__wolfssl/include/user_settings.h; then
    sed -i '1i #define DEBUG_WOLFSSH' \
        managed_components/wolfssl__wolfssl/include/user_settings.h
    echo "patched: DEBUG_WOLFSSH on"
fi
