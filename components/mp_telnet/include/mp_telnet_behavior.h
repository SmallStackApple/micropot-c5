#pragma once

#include <stdint.h>
#include <stddef.h>

#include "mp_brand.h"
#include "mp_linekit.h"
#include "mp_session.h"
#include "mp_xport.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Telnet behaviour table — the brand-owned data that drives the
 * brand-agnostic Telnet interpreter (mp_telnet). Command replies use
 * linekit's generic mp_cmd_t.
 */
typedef struct {
    const char      *banner;          /* pre-login banner, may be NULL */
    const char      *login_prompt;    /* e.g. "IPCAM login: " */
    const char      *password_prompt; /* e.g. "Password: " */
    const char      *login_failed;    /* e.g. "Login incorrect" */
    const char      *shell_prompt;    /* e.g. "# " */
    uint8_t          max_retries;
    const mp_cred_t *creds;
    uint8_t          n_creds;
    const mp_cmd_t  *cmds;
    uint8_t          n_cmds;
    /* Optional dynamic hook. NULL => pure data-table driven matching. */
    const char *(*exec)(const mp_session_t *s, const char *cmdline,
                        char *out, size_t out_len);
    /* Optional full-session shell: when set, the post-login interactive
     * loop is delegated to the brand (e.g. mp_linuxsh). The hook logs
     * commands itself and returns the disconnect reason string. */
    const char *(*shell)(mp_conn_t *conn, const mp_session_t *sess,
                         const void *ctx, const char *user,
                         const char *proto);
    const void *shell_ctx;
} mp_telnet_behavior_t;

#ifdef __cplusplus
}
#endif
