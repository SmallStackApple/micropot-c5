#pragma once

/*
 * Shared internals of the vsftpd-style FTP honeypot, split across:
 *   mp_ftpd.c       session, replies, command dispatch, lifecycle
 *   mp_ftpd_data.c  PASV data-channel pool + connection limits
 *
 * Not part of the public component API.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mp_core.h"
#include "mp_ftpd_behavior.h"
#include "mp_session.h"
#include "mp_xport.h"

#define CTRL_TIMEOUT_MS 300000 /* vsftpd idle_session_timeout default */
#define PASV_SLOTS      4
#define PASV_PORT_BASE  40021
#define PASV_WAIT_MS    60000

/** One control session. */
typedef struct {
    mp_conn_t                 *conn;
    const mp_session_t        *sess;
    const mp_ftpd_behavior_t  *b;
    char                       cwd[128];
    char                       user[64];
    bool                       has_user;
    bool                       authed;
    int                        pasv; /* claimed slot index, -1 = none */
} ftp_t;

/* ---- mp_ftpd_data.c ---- */

/** Pre-register the PASV listener pool (no unlisten API; slots reuse). */
esp_err_t mp_ftpd_pasv_pool_start(uint32_t vaddr);

/** 0 admit (counters claimed), 1 refuse global, 2 refuse per-IP. */
int  mp_ftpd_limit_admit(const mp_ftpd_behavior_t *b, uint32_t ip);
void mp_ftpd_limit_release(uint32_t ip);

/** Claim a free PASV slot; -1 when all are busy. */
int  mp_ftpd_pasv_claim(void);
/** Wait for the peer's data connection; NULL on timeout. */
mp_conn_t *mp_ftpd_pasv_accept(ftp_t *f);
/** Hand the data connection back to the pool (idempotent). */
void       mp_ftpd_pasv_finish(ftp_t *f);
