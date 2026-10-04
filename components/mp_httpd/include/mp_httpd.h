#pragma once

#include "mp_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Apache-style HTTP honeypot on mp_xport (see mp_httpd.c). */
const mp_service_ops_t *mp_httpd_get_ops(void);

#ifdef __cplusplus
}
#endif
