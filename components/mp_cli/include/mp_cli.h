#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Start the serial management REPL (same config surface as mp_ctl, no
 *  HMAC — physical access is trusted; changes are audited as "serial"). */
esp_err_t mp_cli_start(void);

#ifdef __cplusplus
}
#endif
