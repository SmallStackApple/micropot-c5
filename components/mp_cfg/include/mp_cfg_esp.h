#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Open the NVS backend (namespace "mpc") and install it. Call once after
 *  nvs_flash_init(), before any component registers or reads keys. */
esp_err_t mp_cfg_init(void);

#ifdef __cplusplus
}
#endif
