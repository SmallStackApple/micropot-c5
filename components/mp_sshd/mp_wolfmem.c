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
 * This file deliberately includes no wolfSSL headers: XMALLOC/XFREE are
 * plain function names here, not the macros the library headers define.
 */
#include <stddef.h>
#include <stdlib.h>

#include "esp_heap_caps.h"

/* Blocks at least this large try PSRAM first. Below it, internal memory
 * still wins (cache-friendly, avoids PSRAM fragmentation by many tiny
 * bignum allocations). */
#define MP_WOLFMEM_PSRAM_MIN 2048

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
    if (n >= MP_WOLFMEM_PSRAM_MIN) {
        void *p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (p) {
            return p;
        }
    }
    return malloc(n);
}

void *XREALLOC(void *p, size_t n, void *heap, int type)
{
    (void)heap;
    (void)type;
    if (!p) {
        return XMALLOC(n, heap, type);
    }
    if (n == 0) {
        if (p) {
            heap_caps_free(p);
        }
        return NULL;
    }
    /* MALLOC_CAP_8BIT is satisfied by both heaps, so this keeps the block
     * where it already lives instead of forcing a cross-heap move. */
    return heap_caps_realloc(p, n, MALLOC_CAP_8BIT);
}

void XFREE(void *p, void *heap, int type)
{
    (void)heap;
    (void)type;
    if (p) {
        heap_caps_free(p);
    }
}
