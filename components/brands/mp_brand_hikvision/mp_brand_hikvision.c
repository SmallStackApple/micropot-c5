#include <stdio.h>
#include <string.h>

#include "mp_brand_hikvision.h"
#include "mp_http_behavior.h"
#include "mp_net.h"
#include "mp_ssh_behavior.h"
#include "mp_telnet_behavior.h"

/* Embedded page resources (see EMBED_TXTFILES in CMakeLists.txt). */
extern const uint8_t hikvision_login_html_start[] asm("_binary_hikvision_login_html_start");
extern const uint8_t hikvision_fail_html_start[]  asm("_binary_hikvision_fail_html_start");
extern const uint8_t hikvision_admin_html_start[] asm("_binary_hikvision_admin_html_start");

/* ------------------------------------------------------- weak credentials */

static const mp_cred_t s_creds[] = {
    { .user = "admin", .pass = "12345" },
    { .user = "admin", .pass = "admin" },
    { .user = "root",  .pass = "12345" },
    { .user = "root",  .pass = "vizxv" },
};

/* ----------------------------------------------------------- canned shell */

static const mp_cmd_t s_cmds[] = {
    { "help",
      "Built-in commands:\r\n"
      " help      show this help\r\n"
      " ls        list files\r\n"
      " cat       print a file\r\n"
      " ps        show processes\r\n"
      " ifconfig  show network interfaces\r\n"
      " uname     show system information\r\n"
      " whoami    print current user\r\n"
      " reboot    restart the device\r\n"
      " exit      close session\r\n" },
    { "ls",
      "bin      dev      etc      home     lib      linuxrc\r\n"
      "mnt      proc     root     sbin     sys      tmp\r\n"
      "usr      var      mnt      ipc     config\r\n" },
    { "ls /",
      "bin      dev      etc      home     lib      linuxrc\r\n"
      "mnt      proc     root     sbin     sys      tmp\r\n"
      "usr      var      mnt      ipc     config\r\n" },
    { "cat /etc/passwd",
      "root:x:0:0:root:/root:/bin/sh\r\n"
      "admin:x:1000:1000:admin:/home/admin:/bin/sh\r\n"
      "nobody:x:65534:65534:nobody:/:/bin/false\r\n" },
    { "cat /proc/cpuinfo",
      "Processor\t: ARMv7 Processor rev 5 (v7l)\r\n"
      "BogoMIPS\t: 1998.84\r\n"
      "Hardware\t: Hi3520D\r\n" },
    { "ps",
      "  PID USER       VSZ STAT COMMAND\r\n"
      "    1 root      1180 S    init\r\n"
      "   68 root      2456 S    /sbin/telnetd\r\n"
      "   91 root      3120 S    /bin/ipcam_main\r\n"
      "  104 root      1288 S    -/bin/sh\r\n" },
    { "uname",
      "Linux\r\n" },
    { "uname -a",
      "Linux IPCAM 3.10.14 #1 PREEMPT Mon Mar 10 11:32:14 CST 2016 armv7l GNU/Linux\r\n" },
    { "pwd",
      "/\r\n" },
    { "id",
      "uid=0(root) gid=0(root)\r\n" },
    { "whoami",
      "root\r\n" },
    { "reboot",
      "The system is going down NOW!\r\n" },
};

/* ------------------------------------------------------------- HTTP pages */

static const mp_http_behavior_t s_http = {
    .server_hdr = "Boa/0.94.14rc21",
    .realm = "HIKVISION",
    .login_html = (const char *)hikvision_login_html_start,
    .fail_html = (const char *)hikvision_fail_html_start,
    .admin_html = (const char *)hikvision_admin_html_start,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .routes = NULL,
    .n_routes = 0,
};

/* -------------------------------------------------------------- metadata */

static const mp_brand_meta_t s_meta = {
    .id = "hikvision_ipcam",
    .vendor = "HIKVISION",
    .model = "DS-2CD2032-I",
    .firmware = "V5.4.5 build 170123",
    .hostname = "IPCAM-01",
    .mac_oui = { 0x44, 0x19, 0xb6 },
};

/* Optional dynamic hook: inject the live device IP and the *actual* spoofed
 * station MAC into ifconfig output, so the shell story matches the ARP table. */
static const char *hik_exec(const mp_session_t *s, const char *cmdline,
                            char *out, size_t out_len)
{
    if (strcmp(cmdline, "ifconfig") == 0) {
        uint8_t mac[6];
        mp_net_get_mac(mac);
        snprintf(out, out_len,
                 "eth0      Link encap:Ethernet  HWaddr %02X:%02X:%02X:%02X:%02X:%02X\r\n"
                 "          inet addr:%u.%u.%u.%u  Bcast:%u.%u.%u.255  Mask:255.255.255.0\r\n"
                 "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n"
                 "          RX packets:10231 errors:0 dropped:0 overruns:0 frame:0\r\n"
                 "          TX packets:8842 errors:0 dropped:0 overruns:0 carrier:0\r\n",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                 (unsigned)(s->dst_ip & 0xff), (unsigned)((s->dst_ip >> 8) & 0xff),
                 (unsigned)((s->dst_ip >> 16) & 0xff), (unsigned)((s->dst_ip >> 24) & 0xff),
                 (unsigned)(s->dst_ip & 0xff), (unsigned)((s->dst_ip >> 8) & 0xff),
                 (unsigned)((s->dst_ip >> 16) & 0xff));
        return out;
    }
    return NULL;
}

static const mp_telnet_behavior_t s_telnet = {
    .banner = "BusyBox v1.19.4 (2016-03-10 11:32:14 CST) built-in shell (ash)\r\n"
              "Enter 'help' for a list of built-in commands.",
    .login_prompt = "\r\nIPCAM login: ",
    .password_prompt = "Password: ",
    .login_failed = "Login incorrect",
    .shell_prompt = "# ",
    .max_retries = 3,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .cmds = s_cmds,
    .n_cmds = sizeof(s_cmds) / sizeof(s_cmds[0]),
    .exec = hik_exec,
};

/* Dropbear is what Hikvision-era embedded firmware actually ships. */
static const mp_ssh_behavior_t s_ssh = {
    .banner = "SSH-2.0-dropbear_2014.63",
    .linger_ms = 4000,
};

static const mp_brand_behavior_entry_t s_behaviors[] = {
    { "telnet", &s_telnet },
    { "http",   &s_http   },
    { "ssh",    &s_ssh    },
    { NULL, NULL },
};

const mp_brand_t mp_brand_hikvision = {
    .meta = &s_meta,
    .behaviors = s_behaviors,
    .init = NULL,
};
