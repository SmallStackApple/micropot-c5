#pragma once

#include <stdint.h>
#include <stddef.h>

#include "mp_brand.h"
#include "mp_linekit.h"
#include "mp_session.h"

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
} mp_telnet_behavior_t;

#ifdef __cplusplus
}
#endif
