/*
 * sha512crypt ($6$) — Drepper's "Unix crypt using SHA-256 and SHA-512".
 *
 * SHA-512 comes from wolfSSL on device and OpenSSL in host tests; the
 * algorithm here is the spec, verified against reference vectors.
 */
#include <stdbool.h>
#include <string.h>

#include "mp_crypt.h"

#ifdef MP_CRYPT_HOST
#include <openssl/sha.h>
typedef SHA512_CTX sha512_t;
#define SHA512_INIT(c)      SHA512_Init(c)
#define SHA512_UPDATE(c, d, n) SHA512_Update(c, d, n)
#define SHA512_FINAL(c, o)  SHA512_Final(o, c)
#else
#include "wolfssl/wolfcrypt/sha512.h"
typedef wc_Sha512 sha512_t;
#define SHA512_INIT(c)      ((void)wc_InitSha512(c))
#define SHA512_UPDATE(c, d, n) ((void)wc_Sha512Update(c, (const byte *)(d), (word32)(n)))
#define SHA512_FINAL(c, o)  ((void)wc_Sha512Final(c, o))
#endif

#define SHA512_LEN 64

static const char s_b64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void b64_from_24bit(char **o, unsigned b2, unsigned b1, unsigned b0,
                           int n)
{
    unsigned w = (b2 << 16) | (b1 << 8) | b0;
    while (n-- > 0) {
        *(*o)++ = s_b64[w & 0x3f];
        w >>= 6;
    }
}

bool mp_crypt_sha512(const char *pass, const char *salt, char *out, size_t cap)
{
    if (!pass || !salt || !out || cap < 3 + 16 + 1 + 86 + 1) {
        return false;
    }
    size_t pw_len = strlen(pass);
    size_t salt_len = strlen(salt);
    if (salt_len > 16) {
        salt_len = 16;
    }

    sha512_t ctx, alt;
    uint8_t res[SHA512_LEN], altres[SHA512_LEN];
    uint8_t pbytes[SHA512_LEN], sbytes[SHA512_LEN];

    /* A = sha512(pw, salt, pw, then pw_len bytes of alt interleaved) */
    SHA512_INIT(&ctx);
    SHA512_UPDATE(&ctx, pass, pw_len);
    SHA512_UPDATE(&ctx, salt, salt_len);

    SHA512_INIT(&alt);
    SHA512_UPDATE(&alt, pass, pw_len);
    SHA512_UPDATE(&alt, salt, salt_len);
    SHA512_UPDATE(&alt, pass, pw_len);
    SHA512_FINAL(&alt, altres);

    for (size_t cnt = pw_len; cnt > SHA512_LEN; cnt -= SHA512_LEN) {
        SHA512_UPDATE(&ctx, altres, SHA512_LEN);
    }
    SHA512_UPDATE(&ctx, altres, pw_len % SHA512_LEN);

    for (size_t i = pw_len; i > 0; i >>= 1) {
        if (i & 1) {
            SHA512_UPDATE(&ctx, altres, SHA512_LEN);
        } else {
            SHA512_UPDATE(&ctx, pass, pw_len);
        }
    }
    SHA512_FINAL(&ctx, res);

    /* P: sha512 of pw repeated pw_len times */
    SHA512_INIT(&ctx);
    for (size_t i = 0; i < pw_len; i++) {
        SHA512_UPDATE(&ctx, pass, pw_len);
    }
    SHA512_FINAL(&ctx, pbytes);

    /* S: sha512 of salt repeated 16 + res[0] times */
    SHA512_INIT(&ctx);
    for (unsigned i = 0; i < 16u + res[0]; i++) {
        SHA512_UPDATE(&ctx, salt, salt_len);
    }
    SHA512_FINAL(&ctx, sbytes);

    /* 5000 rounds */
    for (int i = 0; i < 5000; i++) {
        SHA512_INIT(&ctx);
        if (i & 1) {
            SHA512_UPDATE(&ctx, pbytes, pw_len);
        } else {
            SHA512_UPDATE(&ctx, res, SHA512_LEN);
        }
        if (i % 3) {
            SHA512_UPDATE(&ctx, sbytes, salt_len);
        }
        if (i % 7) {
            SHA512_UPDATE(&ctx, pbytes, pw_len);
        }
        if (i & 1) {
            SHA512_UPDATE(&ctx, res, SHA512_LEN);
        } else {
            SHA512_UPDATE(&ctx, pbytes, pw_len);
        }
        SHA512_FINAL(&ctx, res);
    }

    /* custom base64 with the spec's byte permutation */
    char *o = out;
    memcpy(o, "$6$", 3); o += 3;
    memcpy(o, salt, salt_len); o += salt_len;
    *o++ = '$';

    static const uint8_t perm[][3] = {
        { 0, 21, 42 }, { 22, 43, 1 }, { 44, 2, 23 }, { 3, 24, 45 },
        { 25, 46, 4 }, { 47, 5, 26 }, { 6, 27, 48 }, { 28, 49, 7 },
        { 50, 8, 29 }, { 9, 30, 51 }, { 31, 52, 10 }, { 53, 11, 32 },
        { 12, 33, 54 }, { 34, 55, 13 }, { 56, 14, 35 }, { 15, 36, 57 },
        { 37, 58, 16 }, { 59, 17, 38 }, { 18, 39, 60 }, { 40, 61, 19 },
        { 62, 20, 41 },
    };
    for (size_t i = 0; i < sizeof(perm) / sizeof(perm[0]); i++) {
        b64_from_24bit(&o, res[perm[i][0]], res[perm[i][1]], res[perm[i][2]], 4);
    }
    b64_from_24bit(&o, 0, 0, res[63], 2);
    *o = '\0';
    return true;
}
