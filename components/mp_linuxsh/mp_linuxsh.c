/*
 * bash-flavoured shell for the Linux persona.
 *
 * Structural commands (ls/cd/pwd/cat/echo/grep) work against the brand's
 * mpfs tree with a real cwd; network commands render live interface state
 * from mp_net (the same IP/MAC the wire shows); the rest falls back to
 * brand canned data, then to bash's "command not found".
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_timer.h"

#include "mp_linuxsh.h"
#include "mp_log.h"
#include "mp_net.h"

#define SHELL_TIMEOUT_MS 120000
#define CAT_IDLE_MS      10000

typedef struct {
    mp_conn_t *conn;
    const mp_session_t *sess;
    const mp_linuxsh_config_t *cfg;
    char cwd[128];
    const char *user;
    const char *proto; /* event namespace: "telnet" or "ssh" */
    bool root;
    int64_t login_us;  /* shell entry, for w's LOGIN@ column */
} sh_t;

/* log a command line as <proto>.command */
static void log_command(sh_t *sh, const char *cmd)
{
    char evt[24];
    snprintf(evt, sizeof(evt), "%s.command", sh->proto);
    mp_evt_t e;
    mp_evt_begin(&e, sh->sess, sh->proto, evt);
    mp_evt_str(&e, "cmd", cmd);
    mp_evt_send(&e);
}

/* ------------------------------------------------------------ helpers */

static int out(sh_t *sh, const char *str)
{
    return mp_send_str(sh->conn, str);
}

static int outf(sh_t *sh, const char *fmt, ...)
{
    char buf[640];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return out(sh, buf);
}

/* split a command line into argv (in place, quotes stripped, no escapes) */
static int split(char *line, char *argv[], int max)
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
static bool resolve(sh_t *sh, const char *arg, char *out, size_t len)
{
    return mpfs_normalize(sh->cwd, arg, out, len);
}

/* -------------------------------------------------- network (live) ---- */

static void net_ip_octets(const mp_session_t *sess, unsigned o[4])
{
    o[0] = (unsigned)(sess->dst_ip & 0xff);
    o[1] = (unsigned)((sess->dst_ip >> 8) & 0xff);
    o[2] = (unsigned)((sess->dst_ip >> 16) & 0xff);
    o[3] = (unsigned)((sess->dst_ip >> 24) & 0xff);
}

static int cmd_ifconfig(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    unsigned o[4];
    net_ip_octets(sh->sess, o);
    uint8_t mac[6];
    mp_net_get_mac(mac);
    return outf(sh,
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
        "        inet %u.%u.%u.%u  netmask 255.255.255.0  broadcast %u.%u.%u.255\r\n"
        "        ether %02x:%02x:%02x:%02x:%02x:%02x  txqueuelen 1000  (Ethernet)\r\n"
        "        RX packets 10231  bytes 1234567 (1.1 MiB)\r\n"
        "        RX errors 0  dropped 0  overruns 0  frame 0\r\n"
        "        TX packets 8842  bytes 765432 (747.4 KiB)\r\n"
        "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n",
        o[0], o[1], o[2], o[3], o[0], o[1], o[2],
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int cmd_ip(sh_t *sh, int argc, char **argv)
{
    unsigned o[4];
    net_ip_octets(sh->sess, o);
    uint8_t mac[6];
    mp_net_get_mac(mac);

    if (argc < 2) {
        return out(sh, "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\r\n");
    }
    if (strcmp(argv[1], "addr") == 0 || strcmp(argv[1], "address") == 0 ||
        strcmp(argv[1], "a") == 0) {
        return outf(sh,
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\r\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n"
            "    inet 127.0.0.1/8 scope host lo\r\n"
            "       valid_lft forever preferred_lft forever\r\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\r\n"
            "    link/ether %02x:%02x:%02x:%02x:%02x:%02x brd ff:ff:ff:ff:ff:ff\r\n"
            "    inet %u.%u.%u.%u/24 brd %u.%u.%u.255 scope global eth0\r\n"
            "       valid_lft forever preferred_lft forever\r\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            o[0], o[1], o[2], o[3], o[0], o[1], o[2]);
    }
    if (strcmp(argv[1], "link") == 0) {
        return outf(sh,
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\r\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\r\n"
            "    link/ether %02x:%02x:%02x:%02x:%02x:%02x brd ff:ff:ff:ff:ff:ff\r\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    if (strcmp(argv[1], "route") == 0 || strcmp(argv[1], "r") == 0) {
        char gw[16] = "0.0.0.0";
        mp_net_get_gw_str(gw, sizeof(gw));
        return outf(sh,
            "default via %s dev eth0 proto static metric 100\r\n"
            "%u.%u.%u.0/24 dev eth0 proto kernel scope link src %u.%u.%u.%u metric 100\r\n",
            gw, o[0], o[1], o[2], o[0], o[1], o[2], o[3]);
    }
    return outf(sh, "Object \"%s\" is unknown, try \"ip help\".\r\n", argv[1]);
}

static int cmd_route(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    unsigned o[4];
    net_ip_octets(sh->sess, o);
    char gw[16] = "0.0.0.0";
    mp_net_get_gw_str(gw, sizeof(gw));
    return outf(sh,
        "Kernel IP routing table\r\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\r\n"
        "0.0.0.0         %-15s 0.0.0.0         UG    100    0        0 eth0\r\n"
        "%u.%u.%u.0      0.0.0.0         255.255.255.0   U     100    0        0 eth0\r\n",
        gw, o[0], o[1], o[2]);
}

/* ------------------------------------------------------- fs commands */

static int cmd_pwd(sh_t *sh)
{
    return outf(sh, "%s\r\n", sh->cwd);
}

static int cmd_cd(sh_t *sh, int argc, char **argv)
{
    const char *target = (argc < 2 || strcmp(argv[1], "~") == 0) ? "/root"
                                                                 : argv[1];
    char path[128];
    if (!resolve(sh, target, path, sizeof(path))) {
        return 0;
    }
    const mpfs_node_t *node = mpfs_lookup(sh->cfg->fs, sh->cfg->fs_n, path);
    if (!node) {
        return outf(sh, "bash: cd: %s: No such file or directory\r\n", target);
    }
    if (node->type != MPFS_DIR) {
        return outf(sh, "bash: cd: %s: Not a directory\r\n", target);
    }
    snprintf(sh->cwd, sizeof(sh->cwd), "%s", path);
    return 0;
}

static void ls_long_line(sh_t *sh, const mpfs_node_t *node, const char *name)
{
    uint32_t size = node->size;
    if (!size) {
        size = node->type == MPFS_DIR ? 4096
                                      : (uint32_t)strlen(node->content);
    }
    outf(sh, "%s 1 %s %s %6u %s %s\r\n",
         node->mode ? node->mode
                    : (node->type == MPFS_DIR ? "drwxr-xr-x" : "-rw-r--r--"),
         node->owner ? node->owner : "root",
         node->group ? node->group : "root",
         (unsigned)size,
         node->date ? node->date : "Oct  1 09:00",
         name);
}

static int cmd_ls(sh_t *sh, int argc, char **argv)
{
    bool long_fmt = false, show_all = false;
    const char *target = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strchr(argv[i], 'l')) {
                long_fmt = true;
            }
            if (strchr(argv[i], 'a')) {
                show_all = true;
            }
        } else {
            target = argv[i];
        }
    }

    char path[128];
    if (!resolve(sh, target ? target : ".", path, sizeof(path))) {
        return 0;
    }
    const mpfs_node_t *node = mpfs_lookup(sh->cfg->fs, sh->cfg->fs_n, path);
    if (!node) {
        return outf(sh, "ls: cannot access '%s': No such file or directory\r\n",
                    target ? target : path);
    }
    if (node->type == MPFS_FILE) {
        if (long_fmt) {
            ls_long_line(sh, node, target ? target : mpfs_basename(path));
        } else {
            outf(sh, "%s\r\n", target ? target : mpfs_basename(path));
        }
        return 0;
    }

    const mpfs_node_t *kids[64];
    size_t n = mpfs_children(sh->cfg->fs, sh->cfg->fs_n, path, kids, 64);
    if (long_fmt) {
        if (show_all) {
            out(sh, "total 8\r\n");
            const mpfs_node_t *self = node;
            ls_long_line(sh, self, ".");
            static const mpfs_node_t parent = {
                "", MPFS_DIR, NULL, "drwxr-xr-x", "root", "root", 4096, NULL
            };
            ls_long_line(sh, &parent, "..");
        } else {
            out(sh, "total 4\r\n");
        }
        for (size_t i = 0; i < n; i++) {
            ls_long_line(sh, kids[i], mpfs_basename(kids[i]->path));
        }
    } else {
        for (size_t i = 0; i < n; i++) {
            out(sh, mpfs_basename(kids[i]->path));
            out(sh, (i + 1 < n) ? "  " : "\r\n");
        }
        if (!n) {
            out(sh, "\r\n");
        }
    }
    return 0;
}

static int cat_file(sh_t *sh, const char *path, const char *shown)
{
    const mpfs_node_t *node = mpfs_lookup(sh->cfg->fs, sh->cfg->fs_n, path);
    if (!node) {
        return outf(sh, "cat: %s: No such file or directory\r\n", shown);
    }
    if (node->type == MPFS_DIR) {
        return outf(sh, "cat: %s: Is a directory\r\n", shown);
    }
    /* file bodies use \n; the terminal wants \r\n */
    for (const char *p = node->content; *p;) {
        const char *nl = strchr(p, '\n');
        if (nl) {
            mp_conn_send(sh->conn, p, (size_t)(nl - p));
            out(sh, "\r\n");
            p = nl + 1;
        } else {
            out(sh, p);
            out(sh, "\r\n");
            break;
        }
    }
    return 0;
}

static int cmd_cat(sh_t *sh, int argc, char **argv)
{
    if (argc < 2) {
        /* bare cat reads stdin: echo lines back until the peer goes quiet */
        char line[256];
        for (;;) {
            int n = mp_line_read(sh->conn, line, sizeof(line), CAT_IDLE_MS,
                                 false, MP_LINE_ECHO_ON);
            if (n < 0) {
                break;
            }
            out(sh, line);
            out(sh, "\r\n");
        }
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        char path[128];
        if (resolve(sh, argv[i], path, sizeof(path))) {
            cat_file(sh, path, argv[i]);
        }
    }
    return 0;
}

static int cmd_grep(sh_t *sh, int argc, char **argv)
{
    if (argc < 3) {
        return out(sh, "Usage: grep [OPTION]... PATTERNS [FILE]...\r\n");
    }
    const char *pat = argv[1];
    char path[128];
    if (!resolve(sh, argv[2], path, sizeof(path))) {
        return 0;
    }
    const mpfs_node_t *node = mpfs_lookup(sh->cfg->fs, sh->cfg->fs_n, path);
    if (!node || node->type == MPFS_DIR) {
        return outf(sh, "grep: %s: No such file or directory\r\n", argv[2]);
    }
    /* fixed-string, line oriented: enough for "grep root /etc/passwd" */
    char *copy = strdup(node->content);
    if (!copy) {
        return -1;
    }
    for (char *line = strtok(copy, "\n"); line; line = strtok(NULL, "\n")) {
        if (strstr(line, pat)) {
            out(sh, line);
            out(sh, "\r\n");
        }
    }
    free(copy);
    return 0;
}

static int cmd_echo(sh_t *sh, int argc, char **argv)
{
    int i = 1;
    bool newline = true;
    if (i < argc && strcmp(argv[i], "-n") == 0) {
        newline = false;
        i++;
    }
    for (; i < argc; i++) {
        out(sh, argv[i]);
        out(sh, (i + 1 < argc) ? " " : (newline ? "\r\n" : ""));
    }
    if (argc <= 1 && newline) {
        out(sh, "\r\n");
    }
    return 0;
}

/* -------------------------------------------------------- misc commands */

static int cmd_uname(sh_t *sh, int argc, char **argv)
{
    const mp_linuxsh_config_t *c = sh->cfg;
    if (argc < 2) {
        return out(sh, "Linux\r\n");
    }
    if (strcmp(argv[1], "-a") == 0) {
        return outf(sh, "Linux %s %s %s %s GNU/Linux\r\n",
                    c->hostname, c->kernel_release, c->kernel_version,
                    c->machine);
    }
    if (strcmp(argv[1], "-r") == 0) {
        return outf(sh, "%s\r\n", c->kernel_release);
    }
    if (strcmp(argv[1], "-m") == 0) {
        return outf(sh, "%s\r\n", c->machine);
    }
    if (strcmp(argv[1], "-n") == 0) {
        return outf(sh, "%s\r\n", c->hostname);
    }
    return out(sh, "Linux\r\n");
}

static int cmd_id(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    if (sh->root) {
        return out(sh, "uid=0(root) gid=0(root) groups=0(root)\r\n");
    }
    return outf(sh, "uid=1000(%s) gid=1000(%s) groups=1000(%s),27(sudo)\r\n",
                sh->user, sh->user, sh->user);
}

static int cmd_download(sh_t *sh, const char *tool, int argc, char **argv)
{
    const char *url = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            url = argv[i];
        }
    }
    if (!url) {
        return outf(sh, "%s: missing URL\r\n", tool);
    }

    /* the point of the honeypot: harvest the payload URL */
    char evt[24];
    snprintf(evt, sizeof(evt), "%s.download", sh->proto);
    mp_evt_t e;
    mp_evt_begin(&e, sh->sess, sh->proto, evt);
    mp_evt_str(&e, "tool", tool);
    mp_evt_str(&e, "url", url);
    mp_evt_send(&e);

    const char *file = strrchr(url, '/');
    file = file ? file + 1 : "index.html";
    if (!*file) {
        file = "index.html";
    }

    char host[128] = { 0 };
    const char *h = strstr(url, "://");
    h = h ? h + 3 : url;
    size_t hl = strcspn(h, "/:");
    if (hl >= sizeof(host)) {
        hl = sizeof(host) - 1;
    }
    memcpy(host, h, hl);

    outf(sh,
         "--2026-10-04 09:42:11--  %s\r\n"
         "Connecting to %s:80... connected.\r\n"
         "HTTP request sent, awaiting response... 200 OK\r\n"
         "Length: 20421 (20K) [application/x-sh]\r\n"
         "Saving to: '%s'\r\n"
         "\r\n"
         "%-16s 100%%[===================>]  19.94K  --.-KB/s    in 0s\r\n"
         "\r\n"
         "2026-10-04 09:42:11 (164 MB/s) - '%s' saved [20421/20421]\r\n",
         url, host, file, file, file);
    return 0;
}

static int cmd_noop(sh_t *sh, int argc, char **argv)
{
    (void)sh; (void)argc; (void)argv;
    return 0; /* mkdir/touch/rm/chmod/chown/cp/mv/ln/kill/clear: pretend ok */
}

/* ------------------------------------------------------------ dispatch */

typedef int (*sh_cmd_fn)(sh_t *sh, int argc, char **argv);

typedef struct {
    const char *name;
    sh_cmd_fn  fn;
} sh_builtin_t;

static const sh_builtin_t s_builtins[]; /* defined below, used by which */

static int wrap_pwd(sh_t *s, int a, char **v)      { (void)a; (void)v; return cmd_pwd(s); }
static int wrap_ifconfig(sh_t *s, int a, char **v) { return cmd_ifconfig(s, a, v); }
static int wrap_ip(sh_t *s, int a, char **v)       { return cmd_ip(s, a, v); }
static int wrap_route(sh_t *s, int a, char **v)    { return cmd_route(s, a, v); }
static int wrap_cd(sh_t *s, int a, char **v)       { return cmd_cd(s, a, v); }
static int wrap_ls(sh_t *s, int a, char **v)       { return cmd_ls(s, a, v); }
static int wrap_cat(sh_t *s, int a, char **v)      { return cmd_cat(s, a, v); }
static int wrap_grep(sh_t *s, int a, char **v)     { return cmd_grep(s, a, v); }
static int wrap_echo(sh_t *s, int a, char **v)     { return cmd_echo(s, a, v); }
static int wrap_uname(sh_t *s, int a, char **v)    { return cmd_uname(s, a, v); }
static int wrap_id(sh_t *s, int a, char **v)       { return cmd_id(s, a, v); }
static int wrap_whoami(sh_t *s, int a, char **v)   { (void)a; (void)v; return outf(s, "%s\r\n", s->user); }
static int wrap_hostname(sh_t *s, int a, char **v) { (void)a; (void)v; return outf(s, "%s\r\n", s->cfg->hostname); }
static int wrap_wget(sh_t *s, int a, char **v)     { return cmd_download(s, "wget", a, v); }
static int wrap_curl(sh_t *s, int a, char **v)     { return cmd_download(s, "curl", a, v); }

/* The box clock: fixed base plus uptime (harmless RTC drift story). */
#define SH_CLOCK_BASE_EPOCH 1767225600L /* 2026-01-01 UTC */

static int wrap_date(sh_t *s, int a, char **v)
{
    (void)a; (void)v;
    time_t t = (time_t)(SH_CLOCK_BASE_EPOCH + esp_timer_get_time() / 1000000);
    struct tm tm;
    gmtime_r(&t, &tm);
    char buf[48];
    strftime(buf, sizeof(buf), "%a %b %e %H:%M:%S UTC %Y", &tm);
    return outf(s, "%s\r\n", buf);
}

/* procps uptime text: "up 2 days, 22:41" / "up  3:17" / "up 3 min" */
static void fmt_uptime(char *buf, size_t cap, uint32_t up_s)
{
    uint32_t d = up_s / 86400, h = (up_s % 86400) / 3600, m = (up_s % 3600) / 60;
    if (d) {
        snprintf(buf, cap, "up %u day%s, %2u:%02u",
                 (unsigned)d, d > 1 ? "s" : "", (unsigned)h, (unsigned)m);
    } else if (h) {
        snprintf(buf, cap, "up %2u:%02u", (unsigned)h, (unsigned)m);
    } else {
        snprintf(buf, cap, "up %u min", (unsigned)(m ? m : 1));
    }
}

/* the header line shared by uptime(1) and w(1) */
static int out_uptime_line(sh_t *s)
{
    time_t now = (time_t)(SH_CLOCK_BASE_EPOCH + esp_timer_get_time() / 1000000);
    struct tm tm;
    gmtime_r(&now, &tm);
    char up[40];
    fmt_uptime(up, sizeof(up), (uint32_t)(esp_timer_get_time() / 1000000));
    return outf(s, " %02d:%02d:%02d %s,  1 user,  load average: 0.00, 0.01, 0.05\r\n",
                tm.tm_hour, tm.tm_min, tm.tm_sec, up);
}

static int wrap_uptime(sh_t *s, int a, char **v)
{
    (void)a; (void)v;
    return out_uptime_line(s);
}

static int wrap_w(sh_t *s, int a, char **v)
{
    (void)a; (void)v;
    if (out_uptime_line(s) < 0) {
        return -1;
    }
    if (out(s, "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n") < 0) {
        return -1;
    }
    /* FROM is the peer we are actually talking to — a canned address is
     * the first thing an attacker checks */
    unsigned o0 = (unsigned)(s->sess->src_ip & 0xff);
    unsigned o1 = (unsigned)((s->sess->src_ip >> 8) & 0xff);
    unsigned o2 = (unsigned)((s->sess->src_ip >> 16) & 0xff);
    unsigned o3 = (unsigned)((s->sess->src_ip >> 24) & 0xff);
    char from[17];
    snprintf(from, sizeof(from), "%u.%u.%u.%u", o0, o1, o2, o3);

    time_t lt = (time_t)(SH_CLOCK_BASE_EPOCH + s->login_us / 1000000);
    struct tm ltm;
    gmtime_r(&lt, &ltm);
    const char *tty = strcmp(s->proto, "ssh") == 0 ? "pts/0" : "pts/1";
    return outf(s, "%-8s %-8s %-16s %02d:%02d    0.00s  0.02s  0.00s w\r\n",
                s->user, tty, from, ltm.tm_hour, ltm.tm_min);
}

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
            if (outf(s, "/usr/%s/%s\r\n", in_sbin ? "sbin" : "bin", v[i]) < 0) {
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
    { "mkdir", cmd_noop },
    { "touch", cmd_noop },
    { "rm", cmd_noop },
    { "rmdir", cmd_noop },
    { "chmod", cmd_noop },
    { "chown", cmd_noop },
    { "cp", cmd_noop },
    { "mv", cmd_noop },
    { "ln", cmd_noop },
    { "kill", cmd_noop },
    { "clear", cmd_noop },
    { "sync", cmd_noop },
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
                out(&sh, "\r\n");
                p = nl + 1;
            } else {
                out(&sh, p);
                out(&sh, "\r\n");
                break;
            }
        }
    }
    {
        unsigned o0 = (unsigned)(sess->src_ip & 0xff);
        unsigned o1 = (unsigned)((sess->src_ip >> 8) & 0xff);
        unsigned o2 = (unsigned)((sess->src_ip >> 16) & 0xff);
        unsigned o3 = (unsigned)((sess->src_ip >> 24) & 0xff);
        outf(&sh, "Last login: Sat Oct  3 21:14:09 2026 from %u.%u.%u.%u\r\n",
             o0, o1, o2, o3);
    }

    return shell_loop(&sh);
}

/* run_simple outcomes: >=0 is a shell exit status, negative ends the
 * session (SH_R_*). "command not found" is status 127 like bash. */
#define SH_R_LOGOUT (-2)
#define SH_R_REBOOT (-3)
#define SH_R_SEND   (-4)

/* Execute one simple command (no separators). MUTATES cmd (split). */
static int run_simple(sh_t *sh, char *cmd)
{
    char *argv[16];
    int argc = split(cmd, argv, 16);
    if (!argc) {
        return 0;
    }
    if (is_exit_cmd(argv[0])) {
        return SH_R_LOGOUT;
    }
    if (is_reboot_cmd(argv[0])) {
        out(sh, "The system is going down NOW!\r\n");
        return SH_R_REBOOT;
    }
    if (strcmp(argv[0], "sudo") == 0) {
        /* already root: sudo just runs the rest of the line */
        if (argc < 2) {
            out(sh, "usage: sudo command\r\n");
            return 0;
        }
        memmove(argv, argv + 1, sizeof(char *) * (size_t)(argc - 1));
        argc--;
    }

    for (size_t i = 0; i < sizeof(s_builtins) / sizeof(s_builtins[0]); i++) {
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
                out(sh, "\r\n");
                p = nl + 1;
            } else {
                out(sh, p);
                out(sh, "\r\n");
                break;
            }
        }
        return 0;
    }
    outf(sh, "bash: %s: command not found\r\n", argv[0]);
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
        if (outf(sh, "%s@%s:%s%s ", sh->user, sh->cfg->hostname, sh->cwd,
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

        log_command(sh, cmd);

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
