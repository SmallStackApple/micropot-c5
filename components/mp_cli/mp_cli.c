/*
 * Serial management CLI: the same configuration surface as mp_ctl over the
 * UART console (esp_console REPL). Physical access is trusted, so no HMAC;
 * every change still flows through mp_cfg and lands in the audit stream
 * with src="serial".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_console.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "mp_cfg.h"
#include "mp_log.h"
#include "mp_stack419.h"
#include "mp_util.h"
#include "mp_vdev.h"
#include "mp_xport.h"

static const char *TAG = "mp_cli";

static const char *const s_commands =
    "  get <key>            print the effective value\n"
    "  set <key> <value>    override (validated, persisted, audited)\n"
    "  unset <key>          back to the registered default\n"
    "  list                 all keys (secrets redacted, *=overridden)\n"
    "  reset                factory-reset all overrides (ask twice)\n"
    "  status               device snapshot\n"
    "  logstats             log pipeline counters\n"
    "  listeners            dump s419 listener tables\n"
    "  logtest              emit a test event\n"
    "  reboot               restart\n";

static int cmd_help(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("%s", s_commands);
    return 0;
}

static const mp_cfg_key_t *find_key(const char *k)
{
    for (size_t i = 0; i < mp_cfg_count(); i++) {
        if (strcmp(mp_cfg_at(i)->key, k) == 0) {
            return mp_cfg_at(i);
        }
    }
    return NULL;
}

static int cmd_get(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: get <key>\n");
        return 1;
    }
    const mp_cfg_key_t *def = find_key(argv[1]);
    mp_cfg_value_t v;
    if (!def || !mp_cfg_get(argv[1], &v)) {
        printf("unknown key: %s\n", argv[1]);
        return 1;
    }
    if (def->secret) {
        printf("***\n");
        return 0;
    }
    char s[MP_CFG_STR_MAX + 12];
    mp_cfg_value_str(def->type, &v, s, sizeof(s));
    printf("%s%s\n", s, mp_cfg_is_overridden(argv[1]) ? " (override)" : " (default)");
    return 0;
}

static int cmd_set(int argc, char **argv)
{
    if (argc != 3) {
        printf("usage: set <key> <value>\n");
        return 1;
    }
    const mp_cfg_key_t *def = find_key(argv[1]);
    if (!def) {
        printf("unknown key: %s\n", argv[1]);
        return 1;
    }
    mp_cfg_value_t v = { 0 };
    switch (def->type) {
    case MP_CFG_T_STR:
    case MP_CFG_T_IP:
        strlcpy(v.u.str, argv[2], sizeof(v.u.str));
        break;
    case MP_CFG_T_U32:
        v.u.u32 = (uint32_t)strtoul(argv[2], NULL, 10);
        break;
    case MP_CFG_T_BOOL:
        v.u.b = strcmp(argv[2], "true") == 0 || strcmp(argv[2], "1") == 0 ||
                strcmp(argv[2], "yes") == 0 || strcmp(argv[2], "on") == 0;
        break;
    }
    int r = mp_cfg_set(argv[1], &v, "serial");
    if (r == -2) {
        printf("validation failed\n");
        return 1;
    }
    if (r != 0) {
        printf("set failed (%d)\n", r);
        return 1;
    }
    printf("%s\n", def->needs_reboot ? "ok (applies after reboot)" : "ok");
    return 0;
}

static int cmd_unset(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: unset <key>\n");
        return 1;
    }
    if (mp_cfg_unset(argv[1], "serial") != 0) {
        printf("unknown key: %s\n", argv[1]);
        return 1;
    }
    printf("ok\n");
    return 0;
}

static int cmd_list(int argc, char **argv)
{
    (void)argc; (void)argv;
    for (size_t i = 0; i < mp_cfg_count(); i++) {
        const mp_cfg_key_t *def = mp_cfg_at(i);
        const char *mark = mp_cfg_is_overridden(def->key) ? "*" : " ";
        if (def->secret) {
            printf("%s %-16s ***\n", mark, def->key);
            continue;
        }
        mp_cfg_value_t v;
        char s[MP_CFG_STR_MAX + 12];
        if (mp_cfg_get(def->key, &v)) {
            mp_cfg_value_str(def->type, &v, s, sizeof(s));
        } else {
            s[0] = '\0';
        }
        printf("%s %-16s %s\n", mark, def->key, s);
    }
    return 0;
}

static int cmd_reset(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "CONFIRM") != 0) {
        printf("this erases ALL runtime overrides; repeat: reset CONFIRM\n");
        return 1;
    }
    printf("%s\n", mp_cfg_unset_all("serial") == 0 ? "ok" : "failed");
    return 0;
}

static int cmd_status(int argc, char **argv)
{
    (void)argc; (void)argv;
    const esp_app_desc_t *app = esp_app_get_description();
    printf("version   %s (idf %s)\n", app->version, app->idf_ver);
    printf("uptime    %lld s, boot #%lu\n",
           (long long)(esp_timer_get_time() / 1000000),
           (unsigned long)mp_log_boot_count());
    printf("heap      free %u, min-ever %u; psram free %u\n",
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
           (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    printf("sessions  %lu active\n", (unsigned long)mp_xport_active());
    printf("vdevs:\n");
    for (size_t i = 0; i < mp_vdev_count(); i++) {
        const mp_vdev_t *v = mp_vdev_at(i);
        char ip[16];
        if (v->vaddr == 0) {
            snprintf(ip, sizeof(ip), "primary");
        } else {
            mp_ip4_str(v->vaddr, ip, sizeof(ip));
        }
        printf("  %-16s %s\n", ip, v->persona ? v->persona->id : "mgmt");
    }
    return 0;
}

static int cmd_listeners(int argc, char **argv)
{
    (void)argc; (void)argv;
    mp_s419_dump_listeners();
    return 0;
}

static int cmd_logstats(int argc, char **argv)
{
    (void)argc; (void)argv;
    uint32_t dropped, queued;
    mp_log_stats(&dropped, &queued);
    printf("dropped %lu, queued %lu\n",
           (unsigned long)dropped, (unsigned long)queued);
    return 0;
}

static int cmd_logtest(int argc, char **argv)
{
    (void)argc; (void)argv;
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "system", "log.test");
    mp_evt_str(&e, "src", "serial");
    mp_evt_send(&e);
    printf("sent\n");
    return 0;
}

static int cmd_reboot(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("rebooting\n");
    esp_restart();
    return 0;
}

esp_err_t mp_cli_start(void)
{
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_cfg = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_cfg.prompt = "micropot> ";
    repl_cfg.max_cmdline_length = 256;
    repl_cfg.task_stack_size = 4096;

    esp_console_dev_uart_config_t uart_cfg = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    esp_err_t err = esp_console_new_repl_uart(&uart_cfg, &repl_cfg, &repl);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "repl init failed: %s", esp_err_to_name(err));
        return err;
    }

    static const esp_console_cmd_t cmds[] = {
        { .command = "help",     .help = "show commands",            .func = cmd_help },
        { .command = "get",      .help = "get <key>",                .func = cmd_get },
        { .command = "set",      .help = "set <key> <value>",        .func = cmd_set },
        { .command = "unset",    .help = "unset <key>",              .func = cmd_unset },
        { .command = "list",     .help = "list all config keys",     .func = cmd_list },
        { .command = "reset",    .help = "reset CONFIRM",            .func = cmd_reset },
        { .command = "status",   .help = "device snapshot",          .func = cmd_status },
        { .command = "listeners", .help = "dump s419 listener tables", .func = cmd_listeners },
        { .command = "logstats", .help = "log pipeline counters",    .func = cmd_logstats },
        { .command = "logtest",  .help = "emit a test event",        .func = cmd_logtest },
        { .command = "reboot",   .help = "restart the device",       .func = cmd_reboot },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        esp_console_cmd_register(&cmds[i]);
    }
    err = esp_console_start_repl(repl);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "repl start failed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "serial CLI ready (help)");
    return ESP_OK;
}
