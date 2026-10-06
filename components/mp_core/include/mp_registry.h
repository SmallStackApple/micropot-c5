#pragma once

#include <stddef.h>

#include "esp_err.h"
#include "mp_service.h"
#include "mp_persona.h"
#include "mp_xport.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register a protocol service together with the address it should bind to.
 * Registration by itself does not start anything.
 */
esp_err_t mp_registry_register(const mp_service_ops_t *ops, mp_bind_t bind);

/** Backend a service instance should listen through: the persona's wire
 *  profile backend, or NULL for the active default. */
const mp_xport_backend_t *mp_service_xport(const mp_service_t *svc);

/**
 * Start one service instance per (vdev, persona service) pair. Persona,
 * brand and wire profile are resolved per vdev; a failing instance is
 * skipped (logged) instead of aborting the rest.
 */
esp_err_t mp_registry_start_all(void);

void      mp_registry_stop_all(void);

size_t       mp_registry_count(void);
mp_service_t *mp_registry_at(size_t index);

#ifdef __cplusplus
}
#endif
