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
    const char *transport;            /* xport backend: NULL/"lwip" or "s419" */
} mp_persona_t;

/** Currently selected persona (chosen by Kconfig, or a runtime override). */
const mp_persona_t *mp_persona_active(void);

/**
 * Override the active persona at runtime (NULL clears the override and
 * restores the Kconfig default). Phase 2 uses this to select a persona
 * from NVS/JSON instead of the compile-time choice.
 */
void mp_persona_set_active(const mp_persona_t *persona);

/**
 * Persona bound to a virtual IPv4 address (network byte order), or NULL.
 * Phase 1 leaves every @c bind.vaddr zero (the single device IP); phase 2
 * assigns one address per persona and indexes the table with this.
 */
const mp_persona_t *mp_persona_by_vaddr(uint32_t vaddr);

const mp_persona_t *mp_persona_by_index(size_t index);
size_t              mp_persona_count(void);

bool                mp_persona_has_service(const mp_persona_t *p, const char *name);

#ifdef __cplusplus
}
#endif
