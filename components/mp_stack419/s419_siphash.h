#pragma once

#include <stddef.h>
#include <stdint.h>

/* SipHash-2-4 (Aumasson & Bernstein), the primitive the Linux kernel uses
 * for secure sequence numbers (net/core/secure_seq.c, lib/siphash.c). */
uint64_t s419_siphash_2_4(const void *data, size_t len, const uint8_t key[16]);
