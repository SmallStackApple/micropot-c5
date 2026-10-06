#pragma once

/*
 * Shared internals for the bash-flavoured shell, split across:
 *   mp_linuxsh.c            core: helpers, dispatch, builtins, shell loop
 *   mp_linuxsh_cmd_fs.c     pwd/cd/ls/cat/grep/echo
 *   mp_linuxsh_cmd_net.c    ifconfig/ip/route + wget/curl harvest
 *   mp_linuxsh_cmd_misc.c   uname/id/noop + date/uptime/w
 *
 * Not a public header: only the mp_linuxsh sources include it.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mp_linuxsh.h"
#include "mp_session.h"
#include "mp_xport.h"

typedef struct {
    mp_conn_t                 *conn;
    const mp_session_t        *sess;
    const mp_linuxsh_config_t *cfg;
    char                       cwd[128];
    const char                *user;
    const char                *proto; /* event namespace: "telnet" or "ssh" */
    bool                       root;
    int64_t                    login_us; /* shell entry, for w's LOGIN@ */
} sh_t;

/* Command results: >= 0 is a shell exit status, negatives end the session. */
#define SH_R_LOGOUT (-2)
#define SH_R_REBOOT (-3)
#define SH_R_SEND   (-4)

/* shell clock: fixed base + uptime (a plausible "RTC drifted" story) */
#define SH_CLOCK_BASE_EPOCH 1767225600L /* 2026-01-01 UTC */

/* ---- core helpers (mp_linuxsh.c) ---- */
int  sh_out(sh_t *sh, const char *str);
int  sh_outf(sh_t *sh, const char *fmt, ...);
int  sh_split(char *line, char *argv[], int max);
bool sh_resolve(sh_t *sh, const char *arg, char *out, size_t len);
void sh_log_command(sh_t *sh, const char *cmd);

/* ---- fs commands (mp_linuxsh_cmd_fs.c) ---- */
int sh_cmd_pwd(sh_t *sh);
int sh_cmd_cd(sh_t *sh, int argc, char **argv);
int sh_cmd_ls(sh_t *sh, int argc, char **argv);
int sh_cmd_cat(sh_t *sh, int argc, char **argv);
int sh_cmd_grep(sh_t *sh, int argc, char **argv);
int sh_cmd_echo(sh_t *sh, int argc, char **argv);

/* ---- network commands (mp_linuxsh_cmd_net.c) ---- */
int  sh_cmd_ifconfig(sh_t *sh, int argc, char **argv);
int  sh_cmd_ip(sh_t *sh, int argc, char **argv);
int  sh_cmd_route(sh_t *sh, int argc, char **argv);
int  sh_cmd_download(sh_t *sh, const char *tool, int argc, char **argv);

/* ---- misc commands (mp_linuxsh_cmd_misc.c) ---- */
int  sh_cmd_uname(sh_t *sh, int argc, char **argv);
int  sh_cmd_id(sh_t *sh, int argc, char **argv);
int  sh_cmd_noop(sh_t *sh, int argc, char **argv);
int  sh_cmd_date(sh_t *sh, int argc, char **argv);
int  sh_cmd_uptime(sh_t *sh, int argc, char **argv);
int  sh_cmd_w(sh_t *sh, int argc, char **argv);
