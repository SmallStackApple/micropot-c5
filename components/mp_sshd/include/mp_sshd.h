#pragma once

#include <stdint.h>

#include "mp_brand.h"
#include "mp_service.h"
#include "mp_shell.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Real-SSH honeypot behaviour.
 *
 * wolfSSH completes the key exchange against the client (the whole binary
 * protocol runs, so scanners and brute-forcers see a live sshd), the
 * password auth callback captures every credential attempt, and a
 * successful login lands in the persona shell. The advertised protocol id
 * is a plain upstream OpenSSH string (no distro suffix).
 * ---------------------------------------------------------------------- */

typedef struct {
    const char *proto_id;      /* "SSH-2.0-OpenSSH_7.9p1" */
    const mp_cred_t *creds;
    uint8_t     n_creds;
    const mp_shell_cfg_t *shell; /* NULL: capture only, then close */
    uint32_t    handshake_timeout_ms;
} mp_sshd_behavior_t;

const mp_service_ops_t *mp_sshd_get_ops(void);

#ifdef __cplusplus
}
#endif
