/*
 * Generic Linux 4.19 server brand.
 *
 * Presents a plain x86_64 Linux 4.19 host: OpenSSH 7.9 banner, Apache-style
 * web server and a root shell whose canned output is consistent with a real
 * Debian/Ubuntu-era 4.19 box. Kernel strings come from the v4.19 kernel tree;
 * the network replies (ifconfig / ip / route) are generated live from mp_net
 * so the shell story matches the wire (same IP and spoofed MAC as ARP).
 */
#include <stdio.h>
#include <string.h>

#include "mp_brand_linux419.h"
#include "mp_http_behavior.h"
#include "mp_httpd_behavior.h"
#include "mp_linuxfs.h"
#include "mp_net.h"
#include "mp_s419_params.h"
#include "mp_shell.h"
#include "mp_ssh_behavior.h"
#include "mp_sshd.h"
#include "mp_telnet_behavior.h"

/* Embedded page resources (see EMBED_TXTFILES in CMakeLists.txt). */
extern const uint8_t linux_login_html_start[] asm("_binary_linux_login_html_start");
extern const uint8_t linux_fail_html_start[]  asm("_binary_linux_fail_html_start");
extern const uint8_t linux_admin_html_start[] asm("_binary_linux_admin_html_start");

/* ------------------------------------------------------- weak credentials */

/* Servers are usually brute-forced on root; keep a small plausible set. */
static const mp_cred_t s_creds[] = {
    { .user = "root",  .pass = "toor" },
    { .user = "root",  .pass = "root" },
    { .user = "root",  .pass = "password" },
    { .user = "admin", .pass = "admin" },
};

/* ----------------------------------------------------------- canned shell */

static const mp_cmd_t s_cmds[] = {
    { "help",
      "GNU bash, version 5.0.3(1)-release (x86_64-pc-linux-gnu)\r\n"
      "These shell commands are defined internally.  Type `help' to see this list.\r\n"
      " help      show this help\r\n"
      " ls        list directory contents\r\n"
      " cat       print a file\r\n"
      " ps        report process status\r\n"
      " ip        show / manipulate routing, network devices\r\n"
      " uname     print system information\r\n"
      " id        print real and effective user and group IDs\r\n"
      " reboot    restart the system\r\n"
      " exit      close session\r\n" },
    { "ls",
      "bin   boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root\r\n"
      "run   sbin  srv  sys  tmp  usr  var\r\n" },
    { "ls /",
      "bin   boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root\r\n"
      "run   sbin  srv  sys  tmp  usr  var\r\n" },
    { "ls -l",
      "total 28\r\n"
      "drwxr-xr-x   2 root root  4096 Oct  1 09:00 bin\r\n"
      "drwxr-xr-x   3 root root  4096 Oct  1 09:00 boot\r\n"
      "drwxr-xr-x  14 root root  3360 Oct  1 09:01 dev\r\n"
      "drwxr-xr-x  90 root root  4096 Oct  1 09:01 etc\r\n"
      "drwxr-xr-x   3 root root  4096 Oct  1 09:00 home\r\n"
      "drwxr-xr-x  17 root root  4096 Sep 30 18:22 usr\r\n"
      "drwxr-xr-x  12 root root  4096 Sep 30 18:22 var\r\n" },
    { "ls -la",
      "total 32\r\n"
      "drwxr-xr-x  20 root root 4096 Oct  1 09:00 .\r\n"
      "drwxr-xr-x  20 root root 4096 Oct  1 09:00 ..\r\n"
      "drwxr-xr-x   2 root root 4096 Oct  1 09:00 bin\r\n"
      "drwxr-xr-x  90 root root 4096 Oct  1 09:01 etc\r\n"
      "drwx------   2 root root 4096 Oct  1 09:01 root\r\n" },
    { "pwd", "/root\r\n" },
    { "uname", "Linux\r\n" },
    { "uname -a", "Linux linux 4.19.0 #1 SMP x86_64 GNU/Linux\r\n" },
    { "uname -r", "4.19.0\r\n" },
    { "uname -s", "Linux\r\n" },
    { "uname -m", "x86_64\r\n" },
    { "id", "uid=0(root) gid=0(root) groups=0(root)\r\n" },
    { "whoami", "root\r\n" },
    { "cat /etc/passwd",
      "root:x:0:0:root:/root:/bin/bash\r\n"
      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
      "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
      "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
      "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\r\n"
      "admin:x:1000:1000:admin:/home/admin:/bin/bash\r\n" },
    { "cat /etc/group",
      "root:x:0:\r\n"
      "daemon:x:1:\r\n"
      "sudo:x:27:admin\r\n"
      "www-data:x:33:\r\n"
      "admin:x:1000:\r\n" },
    { "cat /etc/hostname", "linux\r\n" },
    { "cat /etc/issue", "Linux 4.19 \\n \\l\r\n" },
    { "cat /etc/os-release",
      "PRETTY_NAME=\"Linux 4.19\"\r\n"
      "NAME=\"Linux\"\r\n"
      "VERSION_ID=\"4.19\"\r\n"
      "VERSION=\"4.19\"\r\n"
      "ID=linux\r\n"
      "HOME_URL=\"https://www.kernel.org/\"\r\n" },
    { "cat /proc/version",
      "Linux version 4.19.0 (gcc version 8.3.0 (GCC)) #1 SMP x86_64 GNU/Linux\r\n" },
    { "cat /proc/cpuinfo",
      "processor\t: 0\r\n"
      "vendor_id\t: GenuineIntel\r\n"
      "cpu family\t: 6\r\n"
      "model\t\t: 85\r\n"
      "model name\t: Intel(R) Xeon(R) Gold 6152 CPU @ 2.10GHz\r\n"
      "stepping\t: 4\r\n"
      "cpu MHz\t\t: 2095.078\r\n"
      "cache size\t: 30976 KB\r\n"
      "cpu cores\t: 2\r\n"
      "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov\r\n" },
    { "cat /proc/meminfo",
      "MemTotal:        2013276 kB\r\n"
      "MemFree:         1478032 kB\r\n"
      "MemAvailable:    1623588 kB\r\n"
      "Buffers:           42316 kB\r\n"
      "Cached:           361240 kB\r\n"
      "SwapTotal:       1048572 kB\r\n" },
    { "ps",
      "  PID TTY          TIME CMD\r\n"
      "    1 ?        00:00:01 systemd\r\n"
      "  412 ?        00:00:00 systemd-journal\r\n"
      "  520 ?        00:00:00 sshd\r\n"
      "  655 ?        00:00:00 apache2\r\n"
      "  998 pts/0    00:00:00 bash\r\n" },
    { "ps aux",
      "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
      "root         1  0.0  0.1 168400 11200 ?        Ss   09:00   0:01 /sbin/init\r\n"
      "root       412  0.0  0.1  72304  6200 ?        Ss   09:00   0:00 /lib/systemd/systemd-journald\r\n"
      "root       520  0.0  0.0  38456  4100 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\r\n"
      "root       655  0.0  0.0  12400  2800 ?        Ss   09:00   0:00 /usr/sbin/apache2 -k start\r\n"
      "www-data   656  0.0  0.0 1243800 7600 ?        S    09:00   0:00 /usr/sbin/apache2 -k start\r\n"
      "root       998  0.0  0.0   8300  1900 pts/0    Ss   09:01   0:00 -bash\r\n" },
    { "ps -ef",
      "UID        PID  PPID  C STIME TTY          TIME CMD\r\n"
      "root         1     0  0 09:00 ?        00:00:01 /sbin/init\r\n"
      "root       520     1  0 09:00 ?        00:00:00 /usr/sbin/sshd -D\r\n"
      "root       655     1  0 09:00 ?        00:00:00 /usr/sbin/apache2 -k start\r\n" },
    { "uptime",
      " 09:42:11 up 12 days,  3:11,  1 user,  load average: 0.00, 0.01, 0.05\r\n" },
    { "free", "              total        used        free      shared  buff/cache   available\r\n"
              "Mem:        2013276      534688     1478032        9420      361240     1623588\r\n"
              "Swap:       1048572           0     1048572\r\n" },
    { "free -m", "              total        used        free      shared  buff/cache   available\r\n"
                 "Mem:           1966         522        1443           9         352        1585\r\n"
                 "Swap:          1023           0        1023\r\n" },
    { "df -h",
      "Filesystem      Size  Used Avail Use% Mounted on\r\n"
      "udev            969M     0  969M   0% /dev\r\n"
      "/dev/sda1        49G  6.2G   40G  14% /\r\n"
      "tmpfs           197M  1.1M  196M   1% /run\r\n" },
    { "ss -tlnp",
      "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\r\n"
      "LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=520,fd=3))\r\n"
      "LISTEN 0      128          0.0.0.0:23         0.0.0.0:*     users:((\"inetd\",pid=530,fd=4))\r\n"
      "LISTEN 0      128          0.0.0.0:80         0.0.0.0:*     users:((\"apache2\",pid=655,fd=4))\r\n" },
    { "netstat -tlnp",
      "Active Internet connections (only servers)\r\n"
      "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\r\n"
      "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      520/sshd\r\n"
      "tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      530/inetd\r\n"
      "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      655/apache2\r\n" },
    { "date", "Mon Oct  3 09:42:11 UTC 2026\r\n" },
    { "reboot", "The system is going down NOW!\r\n" },
};

/* ------------------------------------------------------------- HTTP pages */

static const mp_http_behavior_t s_http = {
    .server_hdr = "Apache/2.4.38",
    .realm = "Restricted Area",
    .login_html = (const char *)linux_login_html_start,
    .fail_html = (const char *)linux_fail_html_start,
    .admin_html = (const char *)linux_admin_html_start,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .routes = NULL,
    .n_routes = 0,
};

/* Apache 2.4.38 style, generic (no distro suffix). The mp_httpd service
 * implements the protocol; these are the persona's pages and credentials. */
static const mp_httpd_behavior_t s_httpd = {
    .server_hdr = "Apache/2.4.38",
    .realm = "Restricted Area",
    .hostname = "linux",
    .login_html = (const char *)linux_login_html_start,
    .fail_html = (const char *)linux_fail_html_start,
    .admin_html = (const char *)linux_admin_html_start,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .keepalive_ms = 5000,
    .max_requests = 100,
};

/* -------------------------------------------------------------- metadata */

static const mp_brand_meta_t s_meta = {
    .id = "linux_419",
    .vendor = "Linux",
    .model = "4.19",
    .firmware = "#1 SMP",
    .hostname = "linux",
    /* QEMU/KVM virtual NIC: a generic "Linux 4.19" host is usually a VM. */
    .mac_oui = { 0x52, 0x54, 0x00 },
};

/* Optional dynamic hook: generate interface/routing output from the live
 * device state so the shell story agrees with the wire. */
static const char *linux_exec(const mp_session_t *s, const char *cmdline,
                              char *out, size_t out_len)
{
    unsigned a = (unsigned)(s->dst_ip & 0xff);
    unsigned b = (unsigned)((s->dst_ip >> 8) & 0xff);
    unsigned c = (unsigned)((s->dst_ip >> 16) & 0xff);
    unsigned d = (unsigned)((s->dst_ip >> 24) & 0xff);

    if (strcmp(cmdline, "ifconfig") == 0 || strcmp(cmdline, "ifconfig eth0") == 0 ||
        strcmp(cmdline, "ip a") == 0 || strcmp(cmdline, "ip addr") == 0 ||
        strcmp(cmdline, "ip address") == 0 || strcmp(cmdline, "ip addr show") == 0) {
        uint8_t mac[6];
        mp_net_get_mac(mac);
        snprintf(out, out_len,
                 "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                 "        inet %u.%u.%u.%u  netmask 255.255.255.0  broadcast %u.%u.%u.255\r\n"
                 "        ether %02x:%02x:%02x:%02x:%02x:%02x  txqueuelen 1000  (Ethernet)\r\n"
                 "        RX packets 10231  bytes 1234567 (1.1 MiB)\r\n"
                 "        TX packets 8842  bytes 765432 (747.4 KiB)\r\n"
                 "        RX errors 0  dropped 0  overruns 0  frame 0\r\n"
                 "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\r\n",
                 a, b, c, d, a, b, c,
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return out;
    }
    if (strcmp(cmdline, "ip link") == 0 || strcmp(cmdline, "ip link show") == 0) {
        uint8_t mac[6];
        mp_net_get_mac(mac);
        snprintf(out, out_len,
                 "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\r\n"
                 "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n"
                 "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\r\n"
                 "    link/ether %02x:%02x:%02x:%02x:%02x:%02x brd ff:ff:ff:ff:ff:ff\r\n",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return out;
    }
    if (strcmp(cmdline, "route") == 0 || strcmp(cmdline, "route -n") == 0 ||
        strcmp(cmdline, "ip route") == 0) {
        char gw[16] = "0.0.0.0";
        mp_net_get_gw_str(gw, sizeof(gw));
        snprintf(out, out_len,
                 "Kernel IP routing table\r\n"
                 "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\r\n"
                 "0.0.0.0         %-15s 0.0.0.0         UG    0      0        0 eth0\r\n"
                 "%u.%u.%u.0      0.0.0.0         255.255.255.0   U     0      0        0 eth0\r\n",
                 gw, a, b, c);
        return out;
    }
    if (strcmp(cmdline, "hostname") == 0) {
        snprintf(out, out_len, "linux\r\n");
        return out;
    }
    if (strcmp(cmdline, "ip -4 addr") == 0) {
        snprintf(out, out_len,
                 "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\r\n"
                 "    inet %u.%u.%u.%u/24 brd %u.%u.%u.255 scope global eth0\r\n",
                 a, b, c, d, a, b, c);
        return out;
    }
    return NULL;
}

/* bash-style shell over the persona's fake filesystem */
static const mp_shell_cfg_t s_shell = {
    .fs = &mp_lfs_linux419,
    .hostname = "linux",
    .user = "root",
    .proto = "telnet",
};

static const mp_telnet_behavior_t s_telnet = {
    .banner = "Linux 4.19\r\n"
              "Welcome to the Linux 4.19 server",
    .login_prompt = "\r\nlinux login: ",
    .password_prompt = "Password: ",
    .login_failed = "Login incorrect",
    .shell_prompt = "root@linux:~# ",
    .max_retries = 3,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .cmds = s_cmds,
    .n_cmds = sizeof(s_cmds) / sizeof(s_cmds[0]),
    .exec = linux_exec,
    .shell = &s_shell,
};

/* Banner-level fallback (kept for lightweight personas). */
static const mp_ssh_behavior_t s_ssh = {
    .banner = "SSH-2.0-OpenSSH_7.9p1",
    .linger_ms = 4000,
};

/* Real SSH: wolfSSH completes the handshake and the shell runs over the
 * SSH channel. Upstream 7.9p1 protocol id, generic (no distro suffix). */
static const mp_shell_cfg_t s_shell_ssh = {
    .fs = &mp_lfs_linux419,
    .hostname = "linux",
    .user = "root",
    .proto = "ssh",
};

static const mp_sshd_behavior_t s_sshd = {
    .proto_id = "SSH-2.0-OpenSSH_7.9p1",
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .shell = &s_shell_ssh,
    .handshake_timeout_ms = 30000,
};

static const mp_brand_behavior_entry_t s_behaviors[] = {
    { "telnet",   &s_telnet },
    { "http",     &s_http   },
    { "httpd",    &s_httpd  },
    { "ssh",      &s_ssh    },
    { "sshd",     &s_sshd   },
    /* Drives the mp_stack419 engine when this persona runs on it: the
     * kernel personality (TTL, MSS, window, option layout, ISN, timers)
     * is data, not code. */
    { "stack419", &mp_s419_params_linux419 },
    { NULL, NULL },
};

const mp_brand_t mp_brand_linux419 = {
    .meta = &s_meta,
    .behaviors = s_behaviors,
    .init = NULL,
};
