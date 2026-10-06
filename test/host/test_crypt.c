#include <stdbool.h>

/*
 * Host test for mp_crypt_sha512 against reference vectors produced by
 * `openssl passwd -6 -salt <salt> <pass>` (glibc-compatible).
 */
#include <string.h>

#include "mp_crypt.h"
#include "test_util.h"

int main(void)
{
    char out[128];

    /* reference: openssl passwd -6 -salt dQw4w9WgXcQ toor */
    CHECK(mp_crypt_sha512("toor", "dQw4w9WgXcQ", out, sizeof(out)));
    CHECK_STR(out,
        "$6$dQw4w9WgXcQ$3DMxPHyU8RNWcAE2zGUcDSdoR0lZo76uNi/osxPiOuAEoVUjUZ59ixE7UtAVIJNDBIYNzyN4UencdDcLHCZhP.");

    /* reference: openssl passwd -6 -salt g1v3y0uup admin */
    CHECK(mp_crypt_sha512("admin", "g1v3y0uup", out, sizeof(out)));
    CHECK_STR(out,
        "$6$g1v3y0uup$5bJUmpHR/KFyTE0y9m78/Fr5bt..Y7W6S4UZiBzwI5aMOfdeZ4pG3BI1HXBrQpr.fr40prxWAbn2.h5TqpThW0");

    /* reference: openssl passwd -6 -salt abcdefgh password */
    CHECK(mp_crypt_sha512("password", "abcdefgh", out, sizeof(out)));
    CHECK_STR(out,
        "$6$abcdefgh$yVfUwsw5T.JApa8POvClA1pQ5peiq97DUNyXCZN5IrF.BMSkiaLQ5kvpuEm/VQ1Tvh/KV2TcaWh8qinoW5dhA1");

    /* salt longer than 16 chars is truncated (glibc behavior): output
     * carries the 16-char prefix and equals hashing with that prefix */
    CHECK(mp_crypt_sha512("toor", "dQw4w9WgXcQEXTRACHARS", out, sizeof(out)));
    CHECK(strncmp(out, "$6$dQw4w9WgXcQEXTRA$", 20) == 0);
    char out2[128];
    CHECK(mp_crypt_sha512("toor", "dQw4w9WgXcQEXTRA", out2, sizeof(out2)));
    CHECK_STR(out, out2);

    /* buffer too small rejected */
    CHECK(mp_crypt_sha512("toor", "salt", out, 10) == false);

    TEST_SUMMARY("test_crypt");
}
