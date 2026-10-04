#pragma once

#include "mp_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** vsftpd-3.0.3-style FTP honeypot service (name "ftpd"). */
const mp_service_ops_t *mp_ftpd_get_ops(void);

#ifdef __cplusplus
}
#endif
