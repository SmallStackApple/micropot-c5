#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Address a honeypot service is bound to.
 *
 * Phase 1: @c vaddr is 0 (INADDR_ANY) — the single device IP.
 * Phase 2: @c vaddr carries the virtual device IPv4 address (network byte
 *          order) so multiple personas can each own an IP on one NIC.
 */
typedef struct {
    uint32_t vaddr; /* network byte order; 0 = any */
    uint16_t port;  /* host byte order */
} mp_bind_t;

static inline mp_bind_t mp_bind_any(uint16_t port)
{
    mp_bind_t b = { .vaddr = 0, .port = port };
    return b;
}

#ifdef __cplusplus
}
#endif
