#include <stdio.h>
#include <string.h>

#include "mp_brand_router.h"
#include "mp_http_behavior.h"
#include "mp_net.h"
#include "mp_ssh_behavior.h"
#include "mp_telnet_behavior.h"

extern const uint8_t tplink_login_html_start[] asm("_binary_tplink_login_html_start");
extern const uint8_t tplink_fail_html_start[]  asm("_binary_tplink_fail_html_start");
extern const uint8_t tplink_admin_html_start[] asm("_binary_tplink_admin_html_start");

static const mp_cred_t s_creds[] = {
    { .user = "admin", .pass = "admin" },
    { .user = "admin", .pass = "1234" },
    { .user = "admin", .pass = "password" },
};

static const mp_cmd_t s_cmds[] = {
    { "help",
      "Available commands:\r\n"
      " help      this help\r\n"
      " ifconfig  interface status\r\n"
      " route     routing table\r\n"
      " ps        running processes\r\n"
      " ls        list root\r\n"
      " uname -a  kernel info\r\n"
      " exit      leave\r\n" },
    { "ls",
      "bin   dev   etc   lib   proc   sbin   tmp   usr   var   web\r\n" },
    { "ls /",
      "bin   dev   etc   lib   proc   sbin   tmp   usr   var   web\r\n" },
    { "ps",
      "  PID USER       VSZ STAT COMMAND\r\n"
      "    1 admin     1024 S    init\r\n"
      "   55 admin     1580 S    /usr/sbin/telnetd\r\n"
      "   72 admin     2760 S    /usr/sbin/httpd\r\n"
      "   88 admin     1200 S    -sh\r\n" },
    { "uname",
      "Linux\r\n" },
    { "uname -a",
      "Linux TL-WR841N 2.6.36 #1 Thu Feb 5 20:15:03 CST 2015 mips GNU/Linux\r\n" },
    { "id",
      "uid=0(admin) gid=0(admin)\r\n" },
    { "whoami",
      "admin\r\n" },
    { "reboot",
      "Rebooting system...\r\n" },
};

static const mp_http_behavior_t s_http = {
    .server_hdr = "TP-LINK-WR841N/3.16.9",
    .realm = "TP-LINK Router",
    .login_html = (const char *)tplink_login_html_start,
    .fail_html = (const char *)tplink_fail_html_start,
    .admin_html = (const char *)tplink_admin_html_start,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .routes = NULL,
    .n_routes = 0,
};

static const mp_brand_meta_t s_meta = {
    .id = "tplink_router",
    .vendor = "TP-LINK",
    .model = "TL-WR841N",
    .firmware = "3.16.9 Build 150205 Rel.42982n",
    .hostname = "TP-LINK_WR841N",
    .mac_oui = { 0x00, 0x1d, 0x0f }, /* TP-Link Technologies */
};

static const char *router_exec(const mp_session_t *s, const char *cmdline,
                               char *out, size_t out_len)
{
    if (strcmp(cmdline, "ifconfig") == 0) {
        uint8_t mac[6];
        mp_net_get_mac(mac);
        snprintf(out, out_len,
                 "br0       Link encap:Ethernet  HWaddr %02X:%02X:%02X:%02X:%02X:%02X\r\n"
                 "          inet addr:%u.%u.%u.%u  Bcast:%u.%u.%u.255  Mask:255.255.255.0\r\n"
                 "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                 (unsigned)(s->dst_ip & 0xff), (unsigned)((s->dst_ip >> 8) & 0xff),
                 (unsigned)((s->dst_ip >> 16) & 0xff), (unsigned)((s->dst_ip >> 24) & 0xff),
                 (unsigned)(s->dst_ip & 0xff), (unsigned)((s->dst_ip >> 8) & 0xff),
                 (unsigned)((s->dst_ip >> 16) & 0xff));
        return out;
    }
    if (strcmp(cmdline, "route") == 0) {
        snprintf(out, out_len,
                 "Kernel IP routing table\r\n"
                 "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\r\n"
                 "192.168.0.0     0.0.0.0         255.255.255.0   U     0      0        0 br0\r\n"
                 "0.0.0.0         192.168.0.1     0.0.0.0         UG    0      0        0 br0\r\n");
        return out;
    }
    return NULL;
}

static const mp_telnet_behavior_t s_telnet = {
    .banner = "TP-LINK Wireless Router TL-WR841N\r\n"
              "Login required.",
    .login_prompt = "\r\nUsername: ",
    .password_prompt = "Password: ",
    .login_failed = "Incorrect username or password.",
    .shell_prompt = "TP-LINK> ",
    .max_retries = 3,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .cmds = s_cmds,
    .n_cmds = sizeof(s_cmds) / sizeof(s_cmds[0]),
    .exec = router_exec,
};

static const mp_ssh_behavior_t s_ssh = {
    .banner = "SSH-2.0-dropbear_2012.55",
    .linger_ms = 4000,
};

static const mp_brand_behavior_entry_t s_behaviors[] = {
    { "telnet", &s_telnet },
    { "http",   &s_http   },
    { "ssh",    &s_ssh    },
    { NULL, NULL },
};

const mp_brand_t mp_brand_router = {
    .meta = &s_meta,
    .behaviors = s_behaviors,
    .init = NULL,
};
