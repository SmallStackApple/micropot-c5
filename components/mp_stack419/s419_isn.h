#pragma once

#include <stdint.h>

/** Seed the per-boot secret (net_secret in Linux). */
void     s419_isn_init(void);

/** Initial send sequence number for a connection, computed exactly like
 *  Linux 4.19 secure_tcp_sequence_number() (net/core/secure_seq.c):
 *  siphash over the 4-tuple with a per-boot key, plus a 64 ns wall clock
 *  (seq_scale: ktime_get_real_ns() >> 6).
 *
 *  All fields in the same byte order they have on the wire. */
uint32_t s419_isn(uint32_t saddr_nbo, uint32_t daddr_nbo,
                  uint16_t sport_nbo, uint16_t dport_nbo);
