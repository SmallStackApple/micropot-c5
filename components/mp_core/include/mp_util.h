#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Format a network-byte-order IPv4 word as "a.b.c.d". */
void     mp_ip4_str(uint32_t addr_nbo, char *out, size_t out_len);

/** Parse "aa:bb:cc:dd:ee:ff" (hex, any case) into out[6].
 *  Returns false on any syntax error; a multicast/group address
 *  (low bit of first octet set) is syntactically valid but rejected. */
bool     mp_parse_mac(const char *s, uint8_t out[6]);

/** Monotonic process-wide session id (thread-safe, starts at 1). */
uint32_t mp_session_next_id(void);

#ifdef __cplusplus
}
#endif
