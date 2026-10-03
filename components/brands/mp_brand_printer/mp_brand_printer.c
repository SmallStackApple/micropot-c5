#include <string.h>

#include "mp_brand_printer.h"
#include "mp_http_behavior.h"
#include "mp_ssh_behavior.h"
#include "mp_telnet_behavior.h"

extern const uint8_t printer_login_html_start[] asm("_binary_printer_login_html_start");
extern const uint8_t printer_fail_html_start[]  asm("_binary_printer_fail_html_start");
extern const uint8_t printer_admin_html_start[] asm("_binary_printer_admin_html_start");

static const mp_cred_t s_creds[] = {
    { .user = "admin", .pass = "0000" },
    { .user = "admin", .pass = "admin" },
    { .user = "admin", .pass = "" },
};

static const mp_cmd_t s_cmds[] = {
    { "help",
      "Available commands:\r\n"
      " help     this help\r\n"
      " info     product information\r\n"
      " status   device status\r\n"
      " pages    total page count\r\n"
      " config   network configuration\r\n"
      " exit     close session\r\n" },
    { "info",
      "Product Name:    HP LaserJet Pro MFP M428fdw\r\n"
      "Firmware:        001.2408A\r\n"
      "Serial Number:   CNB1234567\r\n"
      "Service ID:      00000\r\n" },
    { "status",
      "Device Status:   Ready\r\n"
      "Cartridge:       OK\r\n"
      "Tray 1:          Loaded (A4)\r\n"
      "Tray 2:          Loaded (Letter)\r\n" },
    { "pages",
      "Total Pages Printed: 18432\r\n"
      "Mono Pages:          18432\r\n"
      "Color Pages:         0\r\n" },
    { "config",
      "Host Name:       HP-LaserJet-M428\r\n"
      "IP Config:       DHCP\r\n"
      "IP Address:      0.0.0.0\r\n"
      "Subnet Mask:     255.255.255.0\r\n"
      "Default Gateway: 0.0.0.0\r\n"
      "Server:          HP Embedded Web Server\r\n" },
};

static const mp_http_behavior_t s_http = {
    .server_hdr = "HP HTTP Server; HP LaserJet Pro MFP M428fdw",
    .realm = "HP Embedded Web Server",
    .login_html = (const char *)printer_login_html_start,
    .fail_html = (const char *)printer_fail_html_start,
    .admin_html = (const char *)printer_admin_html_start,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .routes = NULL,
    .n_routes = 0,
};

static const mp_brand_meta_t s_meta = {
    .id = "hp_printer",
    .vendor = "HP",
    .model = "HP LaserJet Pro MFP M428fdw",
    .firmware = "001.2408A",
    .hostname = "HP-LaserJet-M428",
    .mac_oui = { 0x00, 0x01, 0xe6 }, /* HP */
};

static const mp_telnet_behavior_t s_telnet = {
    .banner = "HP JetDirect J3113A  010.010.010\r\n"
              "(C) Copyright 2000-2020 HP Development Company, L.P.",
    .login_prompt = "\r\nLogin: ",
    .password_prompt = "Password: ",
    .login_failed = "Login incorrect",
    .shell_prompt = "> ",
    .max_retries = 3,
    .creds = s_creds,
    .n_creds = sizeof(s_creds) / sizeof(s_creds[0]),
    .cmds = s_cmds,
    .n_cmds = sizeof(s_cmds) / sizeof(s_cmds[0]),
    .exec = NULL, /* pure data-table driven brand */
};

static const mp_ssh_behavior_t s_ssh = {
    .banner = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
    .linger_ms = 3000,
};

static const mp_brand_behavior_entry_t s_behaviors[] = {
    { "telnet", &s_telnet },
    { "http",   &s_http   },
    { "ssh",    &s_ssh    },
    { NULL, NULL },
};

const mp_brand_t mp_brand_printer = {
    .meta = &s_meta,
    .behaviors = s_behaviors,
    .init = NULL,
};
