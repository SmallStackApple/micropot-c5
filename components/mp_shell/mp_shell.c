/*
 * bash-style shell over mp_linekit + mp_linuxfs.
 *
 * Command coverage targets what attackers actually type after a successful
 * login (identity, users, network, processes, web root, logs) and what a
 * real box would print for it. Network commands are generated from the
 * live device so `ifconfig` and the wire always agree.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_timer.h"

#include "mp_linuxfs.h"
#include "mp_log.h"
#include "mp_net.h"
#include "mp_shell.h"

#define SHELL_TIMEOUT_MS 120000
#define CMD_MAX          256
#define OUT_MAX          1600

static mp_conn_t *s_conn;
static const mp_shell_cfg_t *s_cfg;
static const mp_session_t *s_sess;

#define SHELL_CONTINUE ((mp_shell_exit_t)99)

static int sendf(const char *fmt, ...)
{
    char buf[OUT_MAX];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) {
        return -1;
    }
    if ((size_t)n >= sizeof(buf)) {
        n = sizeof(buf) - 1;
    }
    return mp_send_all(s_conn, buf, (size_t)n);
}

static const char *hn(void)
{
    return s_cfg->hostname ? s_cfg->hostname : "linux";
}

static const char *user(void)
{
    return s_cfg->user ? s_cfg->user : "root";
}

/* --------------------------------------------------------------- helpers */

static void perm_str(const mp_lfs_node_t *n, char out[11])
{
    out[0] = n->kind == MP_LFS_DIR ? 'd' : (n->kind == MP_LFS_LINK ? 'l' : '-');
    static const char rwx[] = "rwxrwxrwx";
    for (int i = 0; i < 9; i++) {
        out[1 + i] = (n->perm & (1 << (8 - i))) ? rwx[i] : '-';
    }
    out[10] = '\0';
}

static uint32_t node_size(const mp_lfs_node_t *n)
{
    if (n->kind == MP_LFS_DIR) {
        return 4096;
    }
    return n->content ? (uint32_t)strlen(n->content) : 0;
}

static void ls_one_long(const mp_lfs_node_t *n, const char *name)
{
    char perms[11];
    perm_str(n, perms);
    sendf("%s %2u %-8s %-8s %6u Oct  1 09:00 %s\r\n",
          perms, n->kind == MP_LFS_DIR ? 2u : 1u,
          n->owner ? n->owner : "root", n->group ? n->group : "root",
          node_size(n), name);
}

struct ls_ctx { bool l, a; int printed; };

static void ls_cb(const char *name, const mp_lfs_node_t *node, void *arg)
{
    struct ls_ctx *c = (struct ls_ctx *)arg;
    if (!c->a && name[0] == '.') {
        return;
    }
    if (c->l) {
        ls_one_long(node, name);
    } else {
        sendf("%s%s", name, "");
        sendf("%s", (++c->printed % 4 == 0) ? "\r\n" : "  ");
    }
}

static int do_ls(const char *cwd, const char *args)
{
    bool l = false, a = false;
    char path[CMD_MAX] = "";
    const char *p = args;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '-') {
            for (const char *f = p + 1; *f && *f != ' '; f++) {
                if (*f == 'l') l = true;
                if (*f == 'a') a = true;
            }
            while (*p && *p != ' ') p++;
        } else {
            size_t n = 0;
            while (p[n] && p[n] != ' ') n++;
            snprintf(path, sizeof(path), "%.*s", (int)n, p);
            break;
        }
    }
    if (!path[0]) {
        snprintf(path, sizeof(path), "%s", cwd);
    }
    char abs[CMD_MAX];
    mp_lfs_join(cwd, path, abs, sizeof(abs));

    if (!mp_lfs_active()) {
        return sendf("ls: cannot access '%s': No such file or directory\r\n", abs);
    }
    const mp_lfs_node_t *n = mp_lfs_lookup(abs);
    if (!n) {
        return sendf("ls: cannot access '%s': No such file or directory\r\n", path);
    }
    if (n->kind != MP_LFS_DIR) {
        if (l) {
            ls_one_long(n, abs);
        } else {
            sendf("%s\r\n", abs);
        }
        return 0;
    }
    if (l) {
        sendf("total %u\r\n", 28u);
    }
    struct ls_ctx c = { .l = l, .a = a };
    mp_lfs_list(abs, ls_cb, &c);
    if (!l && (c.printed % 4) != 0) {
        sendf("\r\n");
    }
    return 0;
}

static int do_cat(const char *cwd, const char *args)
{
    char path[CMD_MAX];
    /* first token only */
    size_t n = 0;
    while (args[n] && args[n] != ' ') n++;
    if (n == 0) {
        return 0;
    }
    snprintf(path, sizeof(path), "%.*s", (int)n, args);
    char abs[CMD_MAX];
    mp_lfs_join(cwd, path, abs, sizeof(abs));

    /* dynamic /proc files */
    if (strcmp(abs, "/proc/uptime") == 0) {
        double up = esp_timer_get_time() / 1e6;
        return sendf("%.2f %.2f\r\n", up, up * 0.8);
    }
    if (strcmp(abs, "/proc/loadavg") == 0) {
        return sendf("0.00 0.01 0.05 1/142 2043\r\n");
    }
    if (strcmp(abs, "/proc/stat") == 0) {
        return sendf("cpu  12345 0 6789 987654 0 0 0 0 0 0\r\n");
    }

    const mp_lfs_node_t *node = mp_lfs_lookup(abs);
    if (node && node->kind == MP_LFS_DIR) {
        return sendf("cat: %s: Is a directory\r\n", path);
    }
    size_t len = 0;
    const char *data = mp_lfs_read(abs, &len);
    if (!data) {
        return sendf("cat: %s: No such file or directory\r\n", path);
    }
    return mp_send_all(s_conn, data, len);
}

/* ------------------------------------------------------------- network */

static void net_ifconfig(const char *iface)
{
    uint8_t mac[6];
    char ip[16], macs[18];
    mp_net_get_ip_str(ip, sizeof(ip));
    mp_net_get_mac_str(macs, sizeof(macs));
    mp_net_get_mac(mac);
    (void)iface;

    sendf("eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n");
    sendf("        inet %s  netmask 255.255.255.0  broadcast %s\r\n", ip, "");
    sendf("        ether %s  txqueuelen 1000  (Ethernet)\r\n", macs);
    sendf("        RX packets 10231  bytes 1234567 (1.1 MiB)\r\n");
    sendf("        TX packets 8842  bytes 765432 (747.4 KiB)\r\n");
    sendf("        RX errors 0  dropped 0  overruns 0  frame 0\r\n");
    sendf("        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n");
}

static void net_ip_link(void)
{
    char macs[18];
    mp_net_get_mac_str(macs, sizeof(macs));
    sendf("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\r\n");
    sendf("    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n");
    sendf("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\r\n");
    sendf("    link/ether %s brd ff:ff:ff:ff:ff:ff\r\n", macs);
}

static void net_ip_addr(void)
{
    char ip[16];
    mp_net_get_ip_str(ip, sizeof(ip));
    sendf("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\r\n");
    sendf("    inet 127.0.0.1/8 scope host lo\r\n");
    sendf("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\r\n");
    sendf("    inet %s/24 brd %s scope global eth0\r\n", ip, ip);
}

static void net_route(void)
{
    char gw[16], ip[16];
    mp_net_get_gw_str(gw, sizeof(gw));
    mp_net_get_ip_str(ip, sizeof(ip));
    unsigned a, b, c, d;
    sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d);
    sendf("Kernel IP routing table\r\n");
    sendf("Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\r\n");
    sendf("0.0.0.0         %-15s 0.0.0.0         UG    0      0        0 eth0\r\n", gw);
    sendf("%u.%u.%u.0      0.0.0.0         255.255.255.0   U     0      0        0 eth0\r\n", a, b, c);
}

static void net_ss(void)
{
    sendf("State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\r\n");
    sendf("LISTEN 0      128          0.0.0.0:22         0.0.0.0:*\r\n");
    sendf("LISTEN 0      128          0.0.0.0:23         0.0.0.0:*\r\n");
    sendf("LISTEN 0      128          0.0.0.0:80         0.0.0.0:*\r\n");
}

static void net_ps(const char *args)
{
    if (strstr(args, "aux") || strstr(args, "-ef")) {
        sendf("USER       PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n");
        sendf("root         1  0.0  0.1 168400 11200 ?        Ss   09:00   0:01 /sbin/init\r\n");
        sendf("root       412  0.0  0.1  72304  6200 ?        Ss   09:00   0:00 /lib/systemd/systemd-journald\r\n");
        sendf("root       520  0.0  0.0  38456  4100 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\r\n");
        sendf("root       655  0.0  0.0  12400  2800 ?        Ss   09:00   0:00 /usr/sbin/apache2 -k start\r\n");
        sendf("www-data   656  0.0  0.0 1243800 7600 ?        S    09:00   0:00 /usr/sbin/apache2 -k start\r\n");
        sendf("root       998  0.0  0.0   8300  1900 pts/0    Ss   09:01   0:00 -bash\r\n");
    } else {
        sendf("  PID TTY          TIME CMD\r\n");
        sendf("    1 ?        00:00:01 systemd\r\n");
        sendf("  412 ?        00:00:00 systemd-journal\r\n");
        sendf("  520 ?        00:00:00 sshd\r\n");
        sendf("  655 ?        00:00:00 apache2\r\n");
        sendf("  998 pts/0    00:00:00 bash\r\n");
    }
}

/* ----------------------------------------------------------- dispatcher */

static void do_uname(const char *args)
{
    if (strstr(args, "-a") || strstr(args, "--all")) {
        sendf("Linux %s 4.19.0 #1 SMP x86_64 GNU/Linux\r\n", hn());
    } else if (strstr(args, "-r")) {
        sendf("4.19.0\r\n");
    } else if (strstr(args, "-m")) {
        sendf("x86_64\r\n");
    } else if (strstr(args, "-s")) {
        sendf("Linux\r\n");
    } else {
        sendf("Linux\r\n");
    }
}

static mp_shell_exit_t run_command(const char *line_in, char *cwd,
                                   size_t cwd_cap)
{
    char line[CMD_MAX];
    snprintf(line, sizeof(line), "%s", line_in);

    /* trim leading spaces */
    char *cmd = line;
    while (*cmd == ' ') cmd++;
    /* strip a "sudo " prefix (attacker habit); no password prompt */
    if (strncmp(cmd, "sudo ", 5) == 0) {
        cmd += 5;
        while (*cmd == ' ') cmd++;
    }
    /* ignore pipes/redirections: keep the left-most simple command */
    for (char *q = cmd; *q; q++) {
        if (*q == '|' || *q == '>' || *q == '<') {
            *q = '\0';
            break;
        }
    }
    /* split command word and args */
    char *args = cmd;
    while (*args && *args != ' ') args++;
    if (*args) {
        *args++ = '\0';
        while (*args == ' ') args++;
    }

    if (!cmd[0]) {
        return SHELL_CONTINUE;
    }

    if (s_cfg->on_cmd) {
        s_cfg->on_cmd(s_sess, s_cfg->proto, cmd);
    }

    if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "logout") == 0 ||
        strcmp(cmd, "quit") == 0) {
        return MP_SHELL_LOGOUT;
    }
    if (strcmp(cmd, "reboot") == 0 || strcmp(cmd, "shutdown") == 0 ||
        strcmp(cmd, "poweroff") == 0 || strcmp(cmd, "halt") == 0) {
        sendf("The system is going down NOW!\r\n");
        return MP_SHELL_REBOOT;
    }
    if (strcmp(cmd, "pwd") == 0) {
        sendf("%s\r\n", cwd);
    } else if (strcmp(cmd, "cd") == 0) {
        char abs[CMD_MAX];
        const char *target = args[0] ? args : "~";
        mp_lfs_join(cwd, target, abs, sizeof(abs));
        if (mp_lfs_is_dir(abs) || strcmp(abs, "/") == 0) {
            snprintf(cwd, cwd_cap, "%s", abs);
        } else {
            sendf("bash: cd: %s: No such file or directory\r\n", target);
        }
    } else if (strcmp(cmd, "ls") == 0) {
        do_ls(cwd, args);
    } else if (strcmp(cmd, "cat") == 0) {
        do_cat(cwd, args);
    } else if (strcmp(cmd, "echo") == 0) {
        sendf("%s\r\n", args[0] ? args : "");
    } else if (strcmp(cmd, "uname") == 0) {
        do_uname(args);
    } else if (strcmp(cmd, "id") == 0) {
        sendf("uid=0(root) gid=0(root) groups=0(root)\r\n");
    } else if (strcmp(cmd, "whoami") == 0) {
        sendf("%s\r\n", user());
    } else if (strcmp(cmd, "hostname") == 0) {
        sendf("%s\r\n", hn());
    } else if (strcmp(cmd, "ps") == 0) {
        net_ps(args);
    } else if (strcmp(cmd, "ss") == 0) {
        net_ss();
    } else if (strcmp(cmd, "netstat") == 0) {
        sendf("Active Internet connections (only servers)\r\n");
        sendf("Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n");
        sendf("tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n");
        sendf("tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\r\n");
        sendf("tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n");
    } else if (strcmp(cmd, "ifconfig") == 0) {
        net_ifconfig(args);
    } else if (strcmp(cmd, "ip") == 0) {
        if (strstr(args, "link")) {
            net_ip_link();
        } else if (strstr(args, "route")) {
            net_route();
        } else {
            net_ip_addr();
        }
    } else if (strcmp(cmd, "route") == 0) {
        net_route();
    } else if (strcmp(cmd, "uptime") == 0) {
        double up = esp_timer_get_time() / 1e6;
        int days = (int)(up / 86400.0), h = (int)(up / 3600.0) % 24,
            m = (int)(up / 60.0) % 60;
        sendf(" 09:42:11 up %d days, %2d:%02d,  1 user,  load average: 0.00, 0.01, 0.05\r\n",
              days, h, m);
    } else if (strcmp(cmd, "date") == 0) {
        time_t now = time(NULL);
        if (now < 1600000000) {
            now = (time_t)1767225600 + (time_t)(esp_timer_get_time() / 1000000);
        }
        struct tm tm;
        char buf[64];
        gmtime_r(&now, &tm);
        strftime(buf, sizeof(buf), "%a %b %e %H:%M:%S UTC %Y", &tm);
        sendf("%s\r\n", buf);
    } else if (strcmp(cmd, "free") == 0) {
        sendf("              total        used        free      shared  buff/cache   available\r\n");
        sendf("Mem:        2013276      534688     1478032        9420      361240     1623588\r\n");
        sendf("Swap:       1048572           0     1048572\r\n");
    } else if (strcmp(cmd, "df") == 0) {
        sendf("Filesystem      Size  Used Avail Use%% Mounted on\r\n");
        sendf("udev            969M     0  969M   0%% /dev\r\n");
        sendf("/dev/sda1        49G  6.2G   40G  14%% /\r\n");
        sendf("tmpfs           197M  1.1M  196M   1%% /run\r\n");
    } else if (strcmp(cmd, "mount") == 0) {
        const char *m = mp_lfs_read("/proc/mounts", NULL);
        if (m) {
            sendf("%s", m);
        }
    } else if (strcmp(cmd, "who") == 0 || strcmp(cmd, "w") == 0) {
        sendf("root     pts/0        2026-10-03 09:42 (192.168.1.50)\r\n");
    } else if (strcmp(cmd, "history") == 0) {
        const char *h = mp_lfs_read("/root/.bash_history", NULL);
        if (h) {
            sendf("%s", h);
        }
    } else if (strcmp(cmd, "env") == 0) {
        sendf("SHELL=/bin/bash\r\nPWD=%s\r\nUSER=root\r\nHOME=/root\r\n"
              "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
              "LANG=en_US.UTF-8\r\n", cwd);
    } else if (strcmp(cmd, "clear") == 0) {
        sendf("\033[H\033[2J");
    } else if (strcmp(cmd, "bash") == 0 || strcmp(cmd, "sh") == 0) {
        /* nested shell: no-op */
    } else if (strcmp(cmd, "which") == 0 && args[0]) {
        sendf("/usr/bin/%s\r\n", args);
    } else if (strcmp(cmd, "help") == 0) {
        sendf("GNU bash, version 5.0.3(1)-release (x86_64-pc-linux-gnu)\r\n"
              "Type 'help' for the command list, 'exit' to leave the shell.\r\n");
    } else {
        sendf("bash: %s: command not found\r\n", cmd);
    }
    return SHELL_CONTINUE;
}

/* --------------------------------------------------------------- main */

mp_shell_exit_t mp_shell_run(mp_conn_t *conn, const mp_shell_cfg_t *cfg,
                             const mp_session_t *sess)
{
    s_conn = conn;
    s_cfg = cfg;
    s_sess = sess;
    char cwd[CMD_MAX] = "/root";
    char cmd[CMD_MAX];
    mp_shell_exit_t reason = MP_SHELL_CLOSED;

    for (;;) {
        /* prompt: root@host:/path# */
        if (sendf("%s@%s:%s# ", user(), hn(), cwd) < 0) {
            reason = MP_SHELL_ERROR;
            break;
        }
        int n = mp_line_read(conn, cmd, sizeof(cmd), SHELL_TIMEOUT_MS,
                             true, MP_LINE_ECHO_ON);
        if (n < 0) {
            reason = (n == -2) ? MP_SHELL_TIMEOUT
                               : (n == -1 ? MP_SHELL_CLOSED : MP_SHELL_ERROR);
            break;
        }
        if (n == 0) {
            continue;
        }

        mp_shell_exit_t r = run_command(cmd, cwd, sizeof(cwd));
        if (r != SHELL_CONTINUE) {
            reason = r;
            break;
        }
    }
    return reason;
}
