/*
 * Network commands for the bash-flavoured shell.
 *
 * ifconfig/ip/route render LIVE device state from mp_net (the same IP and
 * MAC the wire shows) so the shell and ARP tell one story. wget/curl do not
 * fetch anything: they harvest the requested URL as a <proto>.download
 * event and print a plausible wget transcript.
 */
#include <stdio.h>
#include <string.h>

#include "mp_linuxsh_internal.h"
#include "mp_log.h"
#include "mp_net.h"

static void net_ip_octets(const mp_session_t *sess, unsigned o[4])
{
    o[0] = (unsigned)(sess->dst_ip & 0xff);
    o[1] = (unsigned)((sess->dst_ip >> 8) & 0xff);
    o[2] = (unsigned)((sess->dst_ip >> 16) & 0xff);
    o[3] = (unsigned)((sess->dst_ip >> 24) & 0xff);
}

int sh_cmd_ifconfig(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    unsigned o[4];
    net_ip_octets(sh->sess, o);
    uint8_t mac[6];
    mp_net_get_mac(mac);
    return sh_outf(sh,
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

int sh_cmd_ip(sh_t *sh, int argc, char **argv)
{
    unsigned o[4];
    net_ip_octets(sh->sess, o);
    uint8_t mac[6];
    mp_net_get_mac(mac);

    if (argc < 2) {
        return sh_out(sh, "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\r\n");
    }
    if (strcmp(argv[1], "addr") == 0 || strcmp(argv[1], "address") == 0 ||
        strcmp(argv[1], "a") == 0) {
        return sh_outf(sh,
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
        return sh_outf(sh,
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\r\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\r\n"
            "    link/ether %02x:%02x:%02x:%02x:%02x:%02x brd ff:ff:ff:ff:ff:ff\r\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    if (strcmp(argv[1], "route") == 0 || strcmp(argv[1], "r") == 0) {
        char gw[16] = "0.0.0.0";
        mp_net_get_gw_str(gw, sizeof(gw));
        return sh_outf(sh,
            "default via %s dev eth0 proto static metric 100\r\n"
            "%u.%u.%u.0/24 dev eth0 proto kernel scope link src %u.%u.%u.%u metric 100\r\n",
            gw, o[0], o[1], o[2], o[0], o[1], o[2], o[3]);
    }
    return sh_outf(sh, "Object \"%s\" is unknown, try \"ip help\".\r\n", argv[1]);
}

int sh_cmd_route(sh_t *sh, int argc, char **argv)
{
    (void)argc; (void)argv;
    unsigned o[4];
    net_ip_octets(sh->sess, o);
    char gw[16] = "0.0.0.0";
    mp_net_get_gw_str(gw, sizeof(gw));
    return sh_outf(sh,
        "Kernel IP routing table\r\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\r\n"
        "0.0.0.0         %-15s 0.0.0.0         UG    100    0        0 eth0\r\n"
        "%u.%u.%u.0      0.0.0.0         255.255.255.0   U     100    0        0 eth0\r\n",
        gw, o[0], o[1], o[2]);
}

int sh_cmd_download(sh_t *sh, const char *tool, int argc, char **argv)
{
    const char *url = NULL;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            url = argv[i];
        }
    }
    if (!url) {
        return sh_outf(sh, "%s: missing URL\r\n", tool);
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

    sh_outf(sh,
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
