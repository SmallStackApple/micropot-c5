#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Runtime configuration store
 *
 * A typed key registry with pluggable storage: components register their
 * keys (with Kconfig-derived defaults) at init; values are read through a
 * RAM shadow that lazily loads overrides from the storage backend (NVS on
 * device, RAM stub in host tests). Effective value = NVS override, else the
 * registered default.
 *
 * This file is ESP-free on purpose so the registry logic is host-testable.
 * ---------------------------------------------------------------------- */

#define MP_CFG_KEY_MAX  15 /* NVS namespace key limit */
#define MP_CFG_STR_MAX  63
#define MP_CFG_MAX_KEYS 48

typedef enum {
    MP_CFG_T_STR = 0,
    MP_CFG_T_U32,
    MP_CFG_T_BOOL,
    MP_CFG_T_IP, /* stored as a dotted-quad string, syntax-validated */
} mp_cfg_type_t;

typedef struct {
    union {
        char     str[MP_CFG_STR_MAX + 1];
        uint32_t u32;
        bool     b;
    } u;
} mp_cfg_value_t;

typedef struct {
    const char  *key;
    mp_cfg_type_t type;
    mp_cfg_value_t dflt;
    uint32_t      u32_min;   /* T_U32 only: inclusive range check */
    uint32_t      u32_max;
    bool        (*validate)(const mp_cfg_value_t *v); /* optional extra check */
    bool          secret;   /* value redacted in audits and listings */
    /* called after a successful set/unset (value already stored), e.g. to
     * regenerate derived state like /etc/shadow */
    void        (*on_change)(const char *key);
    /* value only takes effect after a reboot (listener rebind, WiFi) */
    bool          needs_reboot;
} mp_cfg_key_t;

/* Storage backend: return 1 value found, 0 not found, <0 error. */
typedef struct {
    int (*load)(const char *key, mp_cfg_type_t type, mp_cfg_value_t *out);
    int (*save)(const char *key, mp_cfg_type_t type, const mp_cfg_value_t *v);
    int (*erase)(const char *key);
    int (*erase_all)(void);
} mp_cfg_storage_t;

/* Called after every successful set/unset; values are pre-stringified and
 * already redacted when the key is secret. @p src identifies the caller
 * ("udp:192.168.1.10", "serial", ...). */
typedef void (*mp_cfg_audit_hook)(const char *key, const char *oldv,
                                  const char *newv, const char *src);

/* Register key definitions. Fails on duplicates, overlong keys, a full
 * registry, or an invalid default. Returns 0 on success. */
int mp_cfg_register(const mp_cfg_key_t *keys, size_t n);

void mp_cfg_use_storage(const mp_cfg_storage_t *st);
void mp_cfg_set_audit_hook(mp_cfg_audit_hook fn);

/* Read the effective value (override if set, else default). */
bool mp_cfg_get(const char *key, mp_cfg_value_t *out); /* false: unknown key */

/* Store an override. 0 ok, -1 unknown key, -2 validation failed,
 * -3 storage backend missing, -4 storage error. */
int mp_cfg_set(const char *key, const mp_cfg_value_t *v, const char *src);

/* Drop the override (back to the registered default). */
int mp_cfg_unset(const char *key, const char *src);
int mp_cfg_unset_all(const char *src);

/* Typed conveniences; an unknown key yields the fallback. */
const char *mp_cfg_str(const char *key, char *buf, size_t cap);
uint32_t    mp_cfg_u32(const char *key, uint32_t fallback);
bool        mp_cfg_bool(const char *key, bool fallback);

size_t             mp_cfg_count(void);
const mp_cfg_key_t *mp_cfg_at(size_t i);
bool               mp_cfg_is_overridden(const char *key);

void mp_cfg_value_str(mp_cfg_type_t t, const mp_cfg_value_t *v,
                      char *out, size_t cap);

#ifdef __cplusplus
}
#endif
