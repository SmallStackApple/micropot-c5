#pragma once

#include <stdint.h>

#include "mp_brand.h"
#include "mp_session.h"
#include "mp_xport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Behaviour table for mp_sshd, the OpenSSH-style SSH server (wolfSSH).
 * ---------------------------------------------------------------------- */

typedef struct {
    const char *banner;       /* protocol id, e.g. "SSH-2.0-OpenSSH_7.9p1" */
    const mp_cred_t *creds;
    uint8_t      n_creds;

    /* PEM host keys (brand data, stable across boots like a real host) */
    const uint8_t *key_rsa;
    uint32_t       key_rsa_len;
    const uint8_t *key_ecdsa;
    uint32_t       key_ecdsa_len;

    /* Post-auth interactive shell (same hook shape as mp_telnet). */
    const char *(*shell)(mp_conn_t *conn, const mp_session_t *sess,
                         const void *ctx, const char *user, const char *proto);
    const void *shell_ctx;
} mp_sshd_behavior_t;

#ifdef __cplusplus
}
#endif
