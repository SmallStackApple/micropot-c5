#pragma once

#include <stddef.h>

#include "esp_err.h"
#include "mp_service.h"
#include "mp_persona.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register a protocol service together with the address it should bind to.
 * Registration by itself does not start anything.
 */
esp_err_t mp_registry_register(const mp_service_ops_t *ops, mp_bind_t bind);

/**
 * Start every registered service whose name is listed in @p persona.
 * If the persona lists no services, all registered services are started.
 * @p brand is handed to each service so it can read vendor behaviour.
 */
esp_err_t mp_registry_start_all(const mp_persona_t *persona, const mp_brand_t *brand);

void      mp_registry_stop_all(void);

size_t       mp_registry_count(void);
mp_service_t *mp_registry_at(size_t index);

#ifdef __cplusplus
}
#endif
