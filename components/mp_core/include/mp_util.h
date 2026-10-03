#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Format a network-byte-order IPv4 word as "a.b.c.d". */
void     mp_ip4_str(uint32_t addr_nbo, char *out, size_t out_len);

/** Monotonic process-wide session id (thread-safe, starts at 1). */
uint32_t mp_session_next_id(void);

#ifdef __cplusplus
}
#endif
