/*
 * SipHash-2-4, reference implementation following the kernel's
 * lib/siphash.c semantics (little-endian loads, 64-bit output).
 */
#include <string.h>

#include "s419_siphash.h"

#define ROTL(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define SIPROUND                                   \
    do {                                           \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0;     \
        v0 = ROTL(v0, 32);                         \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;     \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;     \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2;     \
        v2 = ROTL(v2, 32);                         \
    } while (0)

static uint64_t load64_le(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap64(v);
#endif
    return v;
}

uint64_t s419_siphash_2_4(const void *data, size_t len, const uint8_t key[16])
{
    const uint8_t *p = (const uint8_t *)data;
    uint64_t k0 = load64_le(key);
    uint64_t k1 = load64_le(key + 8);
    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;
    uint64_t b = (uint64_t)len << 56;

    size_t full = len / 8;
    for (size_t i = 0; i < full; i++, p += 8) {
        uint64_t m = load64_le(p);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }
    for (size_t i = 0; i < (len & 7); i++) {
        b |= (uint64_t)p[i] << (8 * i);
    }

    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}
