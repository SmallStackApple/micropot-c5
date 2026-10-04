#pragma once

#include "mp_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** vsftpd-style FTP honeypot on mp_xport (see mp_ftpd.c). */
const mp_service_ops_t *mp_ftpd_get_ops(void);

#ifdef __cplusplus
}
#endif
