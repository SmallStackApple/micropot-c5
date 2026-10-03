#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Length-prefixed byte string.
 *
 * Text protocols use NUL-terminated C strings, but binary protocols
 * (Modbus, MQTT, SSH key exchange) embed '\\0' bytes. mp_blob_t covers
 * both: text is just the degenerate case.
 */
typedef struct {
    const uint8_t *p;
    size_t         n;
} mp_blob_t;

/** Blob over a string literal (excludes the NUL terminator). */
#define MP_STR(lit) ((mp_blob_t){ (const uint8_t *)(lit), sizeof(lit) - 1 })

/** Blob over a byte array. */
#define MP_BYTES(arr) ((mp_blob_t){ (const uint8_t *)(arr), sizeof(arr) })

/** Blob over a runtime C string (NULL-safe: NULL maps to an empty blob). */
static inline mp_blob_t mp_blob_str(const char *s)
{
    mp_blob_t b = { (const uint8_t *)s, s ? strlen(s) : 0 };
    return b;
}

#ifdef __cplusplus
}
#endif
