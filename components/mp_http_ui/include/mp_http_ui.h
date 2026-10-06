#pragma once

#include "mp_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Protocol service ops for the brand-agnostic HTTP management honeypot. */
const mp_service_ops_t *mp_http_ui_get_ops(void);

#ifdef __cplusplus
}
#endif
