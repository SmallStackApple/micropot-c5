#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Exact wolfSSL/wolfSSH heap usage in payload bytes, kept by the XMALLOC
 * shim in mp_wolfmem.c (every allocation carries an 8-byte size header).
 * cur = bytes live right now, peak = high-water mark since boot,
 * allocs = lifetime allocation count. Any pointer may be NULL.
 */
void mp_wolfmem_stats(uint32_t *cur, uint32_t *peak, uint32_t *allocs);

#ifdef __cplusplus
}
#endif
