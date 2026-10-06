/*
 * bash-flavoured shell for the Linux persona — core.
 *
 * Holds the session helpers, the builtin dispatch table, command-line
 * separator handling and the interactive loop. Command bodies live in
 * mp_linuxsh_cmd_{fs,net,misc}.c; shared internals in
 * mp_linuxsh_internal.h.
 *
 * Structural commands work against the brand's mpfs tree with a real cwd;
 * network commands render live state from mp_net; the rest falls back to
 * brand canned data, then to bash's "command not found".
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "esp_timer.h"

#include "mp_linuxsh.h"
#include "mp_linuxsh_internal.h"
#include "mp_log.h"

#define SHELL_TIMEOUT_MS 120000

/* ------------------------------------------------------------ helpers */

int sh_out(sh_t *sh, const char *str)
{
    return mp_send_str(sh->conn, str);
}

int sh_outf(sh_t *sh, const char *fmt, ...)
{
    char buf[640];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return sh_out(sh, buf);
}

/* split a command line into argv (in place, quotes stripped, no escapes) */
int sh_split(char *line, char *argv[], int max)
{
    int argc = 0;
    char *p = line;
    while (*p && argc < max) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (!*p) {
            break;
        }
        char quote = 0;
        if (*p == '"' || *p == '\'') {
            quote = *p++;
        }
        argv[argc++] = p;
        while (*p && ((quote && *p != quote) ||
                      (!quote && *p != ' ' && *p != '\t'))) {
            p++;
        }
        if (*p) {
            *p++ = '\0';
        }
    }
    return argc;
}

/* resolve arg against cwd; returns false when the path overflows */
bool sh_resolve(sh_t *sh, const char *arg, char *out, size_t len)
{
    return mpfs_normalize(sh->cwd, arg, out, len);
}

/* log a command line as <proto>.command */
void sh_log_command(sh_t *sh, const char *cmd)
{
    char evt[24];
    snprintf(evt, sizeof(evt), "%s.command", sh->proto);
    mp_evt_t e;
    mp_evt_begin(&e, sh->sess, sh->proto, evt);
    mp_evt_str(&e, "cmd", cmd);
    mp_evt_send(&e);
}

/* ------------------------------------------------------------ dispatch */

typedef int (*sh_cmd_fn)(sh_t *sh, int argc, char **argv);

typedef struct {
    const char *name;
    sh_cmd_fn  fn;
} sh_builtin_t;

static const sh_builtin_t s_builtins[]; /* defined below, used by which */

static int wrap_pwd(sh_t *s, int a, char **v)      { (void)a; (void)v; return sh_cmd_pwd(s); }
static int wrap_ifconfig(sh_t *s, int a, char **v) { return sh_cmd_ifconfig(s, a, v); }
static int wrap_ip(sh_t *s, int a, char **v)       { return sh_cmd_ip(s, a, v); }
static int wrap_route(sh_t *s, int a, char **v)    { return sh_cmd_route(s, a, v); }
static int wrap_cd(sh_t *s, int a, char **v)       { return sh_cmd_cd(s, a, v); }
static int wrap_ls(sh_t *s, int a, char **v)       { return sh_cmd_ls(s, a, v); }
static int wrap_cat(sh_t *s, int a, char **v)      { return sh_cmd_cat(s, a, v); }
static int wrap_grep(sh_t *s, int a, char **v)     { return sh_cmd_grep(s, a, v); }
static int wrap_echo(sh_t *s, int a, char **v)     { return sh_cmd_echo(s, a, v); }
static int wrap_uname(sh_t *s, int a, char **v)    { return sh_cmd_uname(s, a, v); }
static int wrap_id(sh_t *s, int a, char **v)       { return sh_cmd_id(s, a, v); }
static int wrap_whoami(sh_t *s, int a, char **v)   { (void)a; (void)v; return sh_outf(s, "%s\r\n", s->user); }
static int wrap_hostname(sh_t *s, int a, char **v) { (void)a; (void)v; return sh_outf(s, "%s\r\n", s->cfg->hostname); }
static int wrap_wget(sh_t *s, int a, char **v)     { return sh_cmd_download(s, "wget", a, v); }
static int wrap_curl(sh_t *s, int a, char **v)     { return sh_cmd_download(s, "curl", a, v); }
static int wrap_date(sh_t *s, int a, char **v)     { return sh_cmd_date(s, a, v); }
static int wrap_uptime(sh_t *s, int a, char **v)   { return sh_cmd_uptime(s, a, v); }
static int wrap_w(sh_t *s, int a, char **v)        { return sh_cmd_w(s, a, v); }

static int wrap_which(sh_t *s, int a, char **v)
{
    if (a < 2) {
        return 0;
    }
    static const char *const sbin[] = {
        "init", "sshd", "vsftpd", "apache2", "inetd", "fdisk", "fsck",
        "iptables", "ip6tables", "reboot", "shutdown",
    };
    for (int i = 1; i < a; i++) {
        bool found = false, in_sbin = false;
        for (size_t j = 0; j < sizeof(sbin) / sizeof(sbin[0]); j++) {
            if (strcmp(v[i], sbin[j]) == 0) {
                found = in_sbin = true;
                break;
            }
        }
        if (!found) {
            for (size_t j = 0; s_builtins[j].name; j++) {
                if (strcmp(v[i], s_builtins[j].name) == 0) {
                    found = true;
                    break;
                }
            }
        }
        if (!found && mp_cmd_lookup(s->cfg->extra_cmds, s->cfg->n_extra, v[i])) {
            found = true;
        }
        if (found) {
            if (sh_outf(s, "/usr/%s/%s\r\n", in_sbin ? "sbin" : "bin", v[i]) < 0) {
                return -1;
            }
        }
    }
    return 0;
}

static const sh_builtin_t s_builtins[] = {
    { "pwd", wrap_pwd },
    { "cd", wrap_cd },
    { "ls", wrap_ls },
    { "dir", wrap_ls },
    { "cat", wrap_cat },
    { "grep", wrap_grep },
    { "echo", wrap_echo },
    { "uname", wrap_uname },
    { "id", wrap_id },
    { "whoami", wrap_whoami },
    { "hostname", wrap_hostname },
    { "ifconfig", wrap_ifconfig },
    { "ip", wrap_ip },
    { "route", wrap_route },
    { "wget", wrap_wget },
    { "curl", wrap_curl },
    { "date", wrap_date },
    { "uptime", wrap_uptime },
    { "w", wrap_w },
    { "which", wrap_which },
    { "mkdir", sh_cmd_noop },
    { "touch", sh_cmd_noop },
    { "rm", sh_cmd_noop },
    { "rmdir", sh_cmd_noop },
    { "chmod", sh_cmd_noop },
    { "chown", sh_cmd_noop },
    { "cp", sh_cmd_noop },
    { "mv", sh_cmd_noop },
    { "ln", sh_cmd_noop },
    { "kill", sh_cmd_noop },
    { "clear", sh_cmd_noop },
    { "sync", sh_cmd_noop },
    { NULL, NULL }, /* which() iterates to the sentinel */
};

static bool is_exit_cmd(const char *cmd)
{
    return strcmp(cmd, "exit") == 0 || strcmp(cmd, "logout") == 0 ||
           strcmp(cmd, "quit") == 0;
}

static bool is_reboot_cmd(const char *cmd)
{
    return strcmp(cmd, "reboot") == 0 || strcmp(cmd, "shutdown") == 0 ||
           strcmp(cmd, "poweroff") == 0 || strcmp(cmd, "halt") == 0;
}

static const char *shell_loop(sh_t *sh);

const char *mp_linuxsh_shell(mp_conn_t *conn, const mp_session_t *sess,
                             const void *ctx, const char *user,
                             const char *proto)
{
    sh_t sh = {
        .conn = conn,
        .sess = sess,
        .cfg = (const mp_linuxsh_config_t *)ctx,
        .cwd = "/root",
        .user = user && *user ? user : "root",
        .proto = proto && *proto ? proto : "telnet",
        .root = !user || strcmp(user, "root") == 0,
        .login_us = esp_timer_get_time(),
    };
    if (!sh.root && strcmp(sh.cwd, "/root") == 0) {
        snprintf(sh.cwd, sizeof(sh.cwd), "/home/%s", sh.user);
    }

    /* login(1) prints the motd and the last-login line before the prompt */
    const mpfs_node_t *motd = mpfs_lookup(sh.cfg->fs, sh.cfg->fs_n, "/etc/motd");
    if (motd && motd->content) {
        for (const char *p = motd->content; *p;) {
            const char *nl = strchr(p, '\n');
            if (nl) {
                mp_conn_send(conn, p, (size_t)(nl - p));
                sh_out(&sh, "\r\n");
                p = nl + 1;
            } else {
                sh_out(&sh, p);
                sh_out(&sh, "\r\n");
                break;
            }
        }
    }
    {
        unsigned o0 = (unsigned)(sess->src_ip & 0xff);
        unsigned o1 = (unsigned)((sess->src_ip >> 8) & 0xff);
        unsigned o2 = (unsigned)((sess->src_ip >> 16) & 0xff);
        unsigned o3 = (unsigned)((sess->src_ip >> 24) & 0xff);
        sh_outf(&sh, "Last login: Sat Oct  3 21:14:09 2026 from %u.%u.%u.%u\r\n",
                o0, o1, o2, o3);
    }

    return shell_loop(&sh);
}

/* Execute one simple command (no separators). MUTATES cmd (split). */
static int run_simple(sh_t *sh, char *cmd)
{
    char *argv[16];
    int argc = sh_split(cmd, argv, 16);
    if (!argc) {
        return 0;
    }
    if (is_exit_cmd(argv[0])) {
        return SH_R_LOGOUT;
    }
    if (is_reboot_cmd(argv[0])) {
        sh_out(sh, "The system is going down NOW!\r\n");
        return SH_R_REBOOT;
    }
    if (strcmp(argv[0], "sudo") == 0) {
        /* already root: sudo just runs the rest of the line */
        if (argc < 2) {
            sh_out(sh, "usage: sudo command\r\n");
            return 0;
        }
        memmove(argv, argv + 1, sizeof(char *) * (size_t)(argc - 1));
        argc--;
    }

    for (size_t i = 0; s_builtins[i].name; i++) { /* table is NULL-terminated */
        if (strcmp(argv[0], s_builtins[i].name) == 0) {
            return s_builtins[i].fn(sh, argc, argv) < 0 ? SH_R_SEND : 0;
        }
    }

    /* brand canned data (ps, df, free, ss, top, ...) */
    char line[256] = { 0 };
    for (int i = 0; i < argc; i++) {
        strlcat(line, argv[i], sizeof(line));
        if (i + 1 < argc) {
            strlcat(line, " ", sizeof(line));
        }
    }
    const mp_cmd_t *c = mp_cmd_lookup(sh->cfg->extra_cmds,
                                      sh->cfg->n_extra, line);
    if (c) {
        /* canned bodies use \n; terminal wants \r\n */
        for (const char *p = c->response; *p;) {
            const char *nl = strchr(p, '\n');
            if (nl) {
                mp_conn_send(sh->conn, p, (size_t)(nl - p));
                sh_out(sh, "\r\n");
                p = nl + 1;
            } else {
                sh_out(sh, p);
                sh_out(sh, "\r\n");
                break;
            }
        }
        return 0;
    }
    sh_outf(sh, "bash: %s: command not found\r\n", argv[0]);
    return 127;
}

/* Execute a line of commands joined by ';', '&&', '||' (quotes honored).
 * bash runs them left to right; && skips on failure, || on success. */
static int run_line(sh_t *sh, char *line)
{
    int status = 0;
    int cond = 0; /* 0: always (';' / first), 1: &&, 2: || */
    char *p = line;

    while (*p) {
        char *sep = p;
        char quote = 0;
        while (*sep) {
            if (quote) {
                if (*sep == quote) {
                    quote = 0;
                }
            } else if (*sep == '"' || *sep == '\'') {
                quote = *sep;
            } else if (*sep == ';') {
                break;
            } else if (*sep == '&' && sep[1] == '&') {
                break;
            } else if (*sep == '|' && sep[1] == '|') {
                break;
            }
            sep++;
        }
        int next = 0;
        if (*sep == ';') {
            *sep = '\0';
            sep++;
        } else if (*sep == '&' && sep[1] == '&') {
            next = 1;
            *sep = '\0';
            sep += 2;
        } else if (*sep == '|' && sep[1] == '|') {
            next = 2;
            *sep = '\0';
            sep += 2;
        }

        bool run = cond == 0 || (cond == 1 && status == 0) ||
                   (cond == 2 && status != 0);
        if (run && *p) {
            int r = run_simple(sh, p);
            if (r < 0) {
                return r;
            }
            status = r;
        }
        cond = next;
        p = sep;
    }
    return 0;
}

static const char *shell_loop(sh_t *sh)
{
    const char *reason = "closed";
    char cmd[256];

    for (;;) {
        /* bash PS1: user@host:cwd# (or $ for non-root) */
        if (sh_outf(sh, "%s@%s:%s%s ", sh->user, sh->cfg->hostname, sh->cwd,
                    sh->root ? "#" : "$") < 0) {
            reason = "send_error";
            break;
        }
        int n = mp_line_read(sh->conn, cmd, sizeof(cmd), SHELL_TIMEOUT_MS,
                             true, MP_LINE_ECHO_ON);
        if (n < 0) {
            reason = (n == -2) ? "timeout" : "closed";
            break;
        }
        if (n == 0) {
            continue;
        }

        sh_log_command(sh, cmd);

        switch (run_line(sh, cmd)) {
        case SH_R_LOGOUT:
            reason = "logout";
            goto out;
        case SH_R_REBOOT:
            reason = "reboot";
            goto out;
        case SH_R_SEND:
            reason = "send_error";
            goto out;
        default:
            break;
        }
    }
out:
    return reason;
}
