#pragma once

#include "mp_linekit.h"
#include "mp_linuxfs.h"
#include "mp_session.h"
#include "mp_xport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Generic bash-style shell interpreter.
 *
 * Used by telnet and (soon) sshd once a login succeeds. Filesystem reads
 * go to mp_linuxfs; network facts (ifconfig/ip/route) are generated from
 * the live device state so the shell story matches the wire.
 * ---------------------------------------------------------------------- */

typedef enum {
    MP_SHELL_LOGOUT = 0,
    MP_SHELL_REBOOT,
    MP_SHELL_CLOSED,
    MP_SHELL_TIMEOUT,
    MP_SHELL_ERROR,
} mp_shell_exit_t;

typedef struct {
    const mp_lfs_t *fs;
    const char     *hostname;   /* e.g. "linux" */
    const char     *user;       /* "root" */
    const char     *proto;      /* event protocol name, "telnet"/"ssh" */
    /** Called for every command line before execution (may be NULL). */
    void (*on_cmd)(const mp_session_t *sess, const char *proto,
                   const char *cmdline);
} mp_shell_cfg_t;

/** Run the interactive shell until the peer leaves, the shell exits or an
 *  I/O error/timeout occurs. */
mp_shell_exit_t mp_shell_run(mp_conn_t *conn, const mp_shell_cfg_t *cfg,
                             const mp_session_t *sess);

#ifdef __cplusplus
}
#endif
