/*
 * Miscellaneous shell commands: uname/id and the no-op mutators, plus the
 * clock-derived date/uptime/w. The box clock is a fixed epoch base plus
 * uptime, i.e. an RTC that "drifted" to a plausible date.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_timer.h"

#include "mp_linuxsh_internal.h"

int sh_cmd_uname(sh_t *sh, int argc, char **argv)
{
    const mp_linuxsh_config_t *c = sh->cfg;
    if (argc < 2) {
        return sh_out(sh, "Linux\r\n");
    }
    if (strcmp(argv[1], "-a") == 0) {
        return sh_outf(sh, "Linux %s %s %s %s GNU/Linux\r\n",
                       c->hostname, c->kernel_release, c->kernel_version,
                       c->machine);
    }
    if (strcmp(argv[1], "-r") == 0) {
        return sh_outf(sh, "%s\r\n", c->kernel_release);
    }
    if (strcmp(argv[1], "-m") == 0) {
        return sh_outf(sh, "%s\r\n", c->machine);
    }
    if (strcmp(argv[1], "-n") == 0) {
        return sh_outf(sh, "%s\r\n", c->hostname);
    }
    return sh_out(sh, "Linux\r\n");
}

int sh_cmd_id(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    if (sh->root) {
        return sh_out(sh, "uid=0(root) gid=0(root) groups=0(root)\r\n");
    }
    return sh_outf(sh, "uid=1000(%s) gid=1000(%s) groups=1000(%s),27(sudo)\r\n",
                   sh->user, sh->user, sh->user);
}

int sh_cmd_noop(sh_t *sh, int argc, char **argv)
{
    (void)sh; (void)argc; (void)argv;
    return 0; /* mkdir/touch/rm/chmod/chown/cp/mv/ln/kill/clear: pretend ok */
}

int sh_cmd_date(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    time_t t = (time_t)(SH_CLOCK_BASE_EPOCH + esp_timer_get_time() / 1000000);
    struct tm tm;
    gmtime_r(&t, &tm);
    char buf[48];
    strftime(buf, sizeof(buf), "%a %b %e %H:%M:%S UTC %Y", &tm);
    return sh_outf(sh, "%s\r\n", buf);
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
    return sh_outf(s,
                   " %02d:%02d:%02d %s,  1 user,  load average: 0.00, 0.01, 0.05\r\n",
                   tm.tm_hour, tm.tm_min, tm.tm_sec, up);
}

int sh_cmd_uptime(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    return out_uptime_line(sh);
}

int sh_cmd_w(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    if (out_uptime_line(sh) < 0) {
        return -1;
    }
    if (sh_out(sh, "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n") < 0) {
        return -1;
    }
    /* FROM is the peer we are actually talking to — a canned address is
     * the first thing an attacker checks */
    unsigned o0 = (unsigned)(sh->sess->src_ip & 0xff);
    unsigned o1 = (unsigned)((sh->sess->src_ip >> 8) & 0xff);
    unsigned o2 = (unsigned)((sh->sess->src_ip >> 16) & 0xff);
    unsigned o3 = (unsigned)((sh->sess->src_ip >> 24) & 0xff);
    char from[17];
    snprintf(from, sizeof(from), "%u.%u.%u.%u", o0, o1, o2, o3);

    time_t lt = (time_t)(SH_CLOCK_BASE_EPOCH + sh->login_us / 1000000);
    struct tm ltm;
    gmtime_r(&lt, &ltm);
    const char *tty = strcmp(sh->proto, "ssh") == 0 ? "pts/0" : "pts/1";
    return sh_outf(sh,
                   "%-8s %-8s %-16s %02d:%02d    0.00s  0.02s  0.00s w\r\n",
                   sh->user, tty, from, ltm.tm_hour, ltm.tm_min);
}
