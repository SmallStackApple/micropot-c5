#pragma once

#include "mp_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** mp_httpd service ops (name "httpd"), registered by main like any other
 *  service; it routes through the active mp_xport backend. */
const mp_service_ops_t *mp_httpd_get_ops(void);

#ifdef __cplusplus
}
#endif
