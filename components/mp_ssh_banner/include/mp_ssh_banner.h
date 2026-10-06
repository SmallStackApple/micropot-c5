#pragma once

#include "mp_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Protocol service ops for the banner-level SSH honeypot. */
const mp_service_ops_t *mp_ssh_banner_get_ops(void);

#ifdef __cplusplus
}
#endif
