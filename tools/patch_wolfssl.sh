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

# wolfSSH 1.4.20 hard-disables rsa-sha2-512 ("not ready") unless this is
# defined; without the name mapping, KEX host-key negotiation misfires
# (see mp_sshd.c s_key_list comment).
if ! grep -q 'define WOLFSSH_YES_RSA_SHA2_512' \
        managed_components/wolfssl__wolfssl/include/user_settings.h; then
    sed -i '1i #define WOLFSSH_YES_RSA_SHA2_512' \
        managed_components/wolfssl__wolfssl/include/user_settings.h
    echo "patched: WOLFSSH_YES_RSA_SHA2_512 on"
fi

# ... and enabling it exposes an upstream typo in the canned key-algo
# string: the trailing comma sits OUTSIDE the rsa-sha2-512 literal
# (never compiled upstream), which breaks the build.
sed -i 's|    "rsa-sha2-512",|    "rsa-sha2-512,"|' \
    managed_components/wolfssl__wolfssh/src/internal.c
echo "patched: rsa-sha2-512 string literal comma"
