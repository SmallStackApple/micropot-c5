#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "mp_bind.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MP_MAX_SERVICES 4

/**
 * A persona is one virtual device instance: it selects a brand and the set of
 * protocol services it exposes.
 *
 * Phase 1: exactly one persona is active, bound to the single device IP.
 * Phase 2: a table of personas is indexed by virtual IP.
 */
typedef struct {
    const char *id;
    const char *brand_id;
    mp_bind_t   bind;                 /* phase 2: virtual IP */
    const char *services[MP_MAX_SERVICES];
    uint8_t     n_services;
    const char *hostname;
} mp_persona_t;

/** Currently selected persona (chosen by Kconfig). */
const mp_persona_t *mp_persona_active(void);

const mp_persona_t *mp_persona_by_index(size_t index);
size_t              mp_persona_count(void);

bool                mp_persona_has_service(const mp_persona_t *p, const char *name);

#ifdef __cplusplus
}
#endif
