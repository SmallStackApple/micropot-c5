#!/bin/sh
# Regenerate the linux_419 persona's SSH host keys.
#
# The PEM files are the human-readable source; the firmware embeds the DER
# forms because the vendored wolfSSH build has no WOLFSSH_CERTS (its PEM
# decoding path is compiled out). wolfSSH identifies keys with
# wc_RsaPrivateKeyDecode / wc_EccPrivateKeyDecode, so the DER must be the
# traditional PKCS#1 (RSA) / SEC1 (EC) encodings.
set -e
cd "$(dirname "$0")/../components/brands/mp_brand_linux419/keys"

ssh-keygen -t rsa -b 2048 -m PEM -f ssh_host_rsa_key -N "" -C "root@linux" -q
ssh-keygen -t ecdsa -b 256 -m PEM -f ssh_host_ecdsa_key -N "" -C "root@linux" -q
openssl rsa -in ssh_host_rsa_key -traditional -outform DER -out ssh_host_rsa_key.der
openssl ec -in ssh_host_ecdsa_key -outform DER -out ssh_host_ecdsa_key.der
echo "regenerated; note: host keys change => existing clients will warn"
