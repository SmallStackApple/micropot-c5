#pragma once

#include "esp_err.h"
#include "mp_xport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Wire profiles
 *
 * A wire profile is the L3/L4 personality of a virtual device — IP/TCP
 * behaviour parameters plus the engine that plays them. It is deliberately
 * separate from brands (L7 persona data: banners, filesystems, creds): a
 * brand never knows which TCP/IP stack it is talking over, and an engine
 * never knows which brand it is serving. Virtual devices (mp_persona.wire,
 * later per-vdev) bind the two axes by profile id.
 * ---------------------------------------------------------------------- */

typedef struct {
    const char *id;                     /* "linux419" */
    esp_err_t (*init)(const void *params);       /* engine init thunk */
    const void *params;                 /* engine-specific parameter block */
    const mp_xport_backend_t *xport;    /* backend services run on */
} mp_wprof_t;

/** Register a wire profile (idempotent per id). */
esp_err_t mp_wprof_register(const mp_wprof_t *prof);

/** Look up a profile by id; NULL when unknown. */
const mp_wprof_t *mp_wprof_find(const char *id);

#ifdef __cplusplus
}
#endif
