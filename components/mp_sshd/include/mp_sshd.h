#pragma once

#include "mp_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/** OpenSSH-style SSH honeypot with real KEX (wolfSSH, see mp_sshd.c). */
const mp_service_ops_t *mp_sshd_get_ops(void);

#ifdef __cplusplus
}
#endif
