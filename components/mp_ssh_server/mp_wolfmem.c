/*
 * wolfSSL/wolfSSH allocator override (XMALLOC_USER).
 *
 * On ESP-IDF the vendored wolfSSL defaults XMALLOC to pvPortMalloc(), i.e.
 * the wolfSSH KEX working set (RSA bignums, IO buffers, the 16 KiB channel
 * window) all lands in scarce HP SRAM, which is what forced the
 * PREAUTH_MAX=3 cap in mp_sshd. Defining XMALLOC_USER (see the component
 * CMakeLists) routes those allocations through the functions below: large
 * blocks go to PSRAM, small ones stay in internal memory. Allocation size
 * is not known at XFREE time, but heap_caps_free()/heap_caps_realloc()
 * resolve the owning heap, so both kinds can be freed/reallocated safely.
 *
 * Exact byte accounting lives here too: every allocation carries an
 * 8-byte header (magic + size) so XFREE can subtract without knowing the
 * size. wolf_cur/wolf_peak feed the perf event and mgmt status, turning
 * ssh.preauth_max tuning from guesswork into reading numbers.
 *
 * This file deliberately includes no wolfSSL headers: XMALLOC/XFREE are
 * plain function names here, not the macros the library headers define.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "esp_heap_caps.h"

#include "mp_wolfmem.h"

/* Blocks at least this large try PSRAM first. Below it, internal memory
 * still wins (cache-friendly, avoids PSRAM fragmentation by many tiny
 * bignum allocations). */
#define MP_WOLFMEM_PSRAM_MIN 2048

/* 8 bytes keeps the returned pointer in the same alignment class as the
 * raw heap pointer (both heaps hand out >=4-byte aligned blocks). */
#define MP_WOLFMEM_MAGIC 0x574C464Du /* "WLFM" */

typedef struct {
    uint32_t magic;
    uint32_t size; /* payload bytes, header excluded */
} wolfmem_hdr_t;

static volatile uint32_t s_cur;
static volatile uint32_t s_peak;
static volatile uint32_t s_allocs;

void XFREE(void *p, void *heap, int type); /* XREALLOC uses it below */

static void acct_add(uint32_t n)
{
    uint32_t c = __sync_add_and_fetch(&s_cur, n);
    __sync_add_and_fetch(&s_allocs, 1);
    uint32_t p = s_peak;
    while (c > p && !__sync_bool_compare_and_swap(&s_peak, p, c)) {
        p = s_peak;
    }
}

static void acct_sub(uint32_t n)
{
    __sync_sub_and_fetch(&s_cur, n);
}

void mp_wolfmem_stats(uint32_t *cur, uint32_t *peak, uint32_t *allocs)
{
    if (cur) {
        *cur = s_cur;
    }
    if (peak) {
        *peak = s_peak;
    }
    if (allocs) {
        *allocs = s_allocs;
    }
}

/* Referenced by mp_sshd.c. The linker resolves XMALLOC/XFREE against the
 * wolfSSL archive *after* this object has already been scanned, so without
 * a live reference from an object that is definitely linked, the archive
 * member would be dropped and the link would fail with "undefined
 * reference to XMALLOC". */
void mp_wolfmem_anchor(void)
{
}

void *XMALLOC(size_t n, void *heap, int type)
{
    (void)heap;
    (void)type;
    if (n == 0) {
        return NULL;
    }
    void *base;
    if (n >= MP_WOLFMEM_PSRAM_MIN) {
        base = heap_caps_malloc(sizeof(wolfmem_hdr_t) + n,
                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (base) {
            goto got;
        }
    }
    base = malloc(sizeof(wolfmem_hdr_t) + n);
    if (!base) {
        return NULL;
    }
got:;
    wolfmem_hdr_t *h = base;
    h->magic = MP_WOLFMEM_MAGIC;
    h->size = (uint32_t)n;
    acct_add((uint32_t)n);
    return h + 1;
}

void *XREALLOC(void *p, size_t n, void *heap, int type)
{
    (void)heap;
    (void)type;
    if (!p) {
        return XMALLOC(n, heap, type);
    }
    if (n == 0) {
        XFREE(p, heap, type);
        return NULL;
    }
    wolfmem_hdr_t *h = ((wolfmem_hdr_t *)p) - 1;
    if (h->magic != MP_WOLFMEM_MAGIC) {
        return NULL; /* foreign pointer: refuse rather than corrupt */
    }
    uint32_t old = h->size;
    /* MALLOC_CAP_8BIT is satisfied by both heaps, so this keeps the block
     * where it already lives instead of forcing a cross-heap move. */
    void *nb = heap_caps_realloc(h, sizeof(wolfmem_hdr_t) + n,
                                 MALLOC_CAP_8BIT);
    if (!nb) {
        return NULL;
    }
    h = nb;
    h->size = (uint32_t)n;
    if (n > old) {
        acct_add((uint32_t)n - old);
        __sync_sub_and_fetch(&s_allocs, 1); /* realloc isn't a new alloc */
    } else {
        acct_sub(old - (uint32_t)n);
    }
    return h + 1;
}

void XFREE(void *p, void *heap, int type)
{
    (void)heap;
    (void)type;
    if (!p) {
        return;
    }
    wolfmem_hdr_t *h = ((wolfmem_hdr_t *)p) - 1;
    if (h->magic == MP_WOLFMEM_MAGIC) {
        acct_sub(h->size);
        h->magic = 0;
    }
    heap_caps_free(h);
}
