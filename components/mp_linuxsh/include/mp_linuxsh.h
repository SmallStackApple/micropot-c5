#pragma once

#include <stddef.h>
#include <stdint.h>

#include "mp_linuxfs.h"
#include "mp_linekit.h"
#include "mp_xport.h"
#include "mp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Generic Linux shell interpreter (bash-flavoured, brand-agnostic).
 *
 * Session state (cwd) is real; filesystem answers come from the brand's
 * mpfs tree; network commands (ifconfig/ip/route) are generated live from
 * mp_net so the shell story matches the wire; everything else (ps, df,
 * free, uptime, ss, ...) is brand-supplied canned data in extra_cmds.
 * ---------------------------------------------------------------------- */

typedef struct {
    const char *hostname;       /* "linux" */
    const char *kernel_release; /* "4.19.0" */
    const char *kernel_version; /* "#1 SMP" */
    const char *machine;        /* "x86_64" */

    const mpfs_node_t *fs;
    size_t             fs_n;

    /** Brand canned replies for non-structural commands (ps, df, free,
     *  ss, netstat, uptime, w, history, env, ...), mp_cmd_lookup rules. */
    const mp_cmd_t *extra_cmds;
    uint8_t         n_extra;
} mp_linuxsh_config_t;

/**
 * Interactive shell loop, matching the telnet/sshd shell hook shape.
 * Logs every command line as <proto>.command; wget/curl additionally
 * raise <proto>.download events with the requested URL.
 *
 * @return disconnect reason: "logout", "reboot", "timeout", "closed",
 *         "send_error".
 */
const char *mp_linuxsh_shell(mp_conn_t *conn, const mp_session_t *sess,
                             const void *ctx, const char *user,
                             const char *proto);

#ifdef __cplusplus
}
#endif
