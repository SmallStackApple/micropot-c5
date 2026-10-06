/*
 * Management plane: authenticated remote configuration.
 *
 * Wire format (one line per request, UDP datagram or TCP line):
 *     id=1 ts=1730000000 cmd=set k=log.port v=514 mac=<hmac-sha256 hex>
 * HMAC key = ctl.psk, message = the raw line up to " mac=" (so v= may
 * contain spaces). ts must increase monotonically per boot (anti-replay).
 *
 * Reply (one line, JSON):
 *     {"id":1,"ok":true,"result":...}  /  {"id":1,"ok":false,"err":"..."}
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "lwip/ip4_addr.h"

#include "wolfssl/wolfcrypt/hmac.h"

#include "mp_cfg.h"
#include "mp_ctl.h"
#include "mp_linekit.h"
#include "mp_log.h"
#include "mp_stack419.h"
#include "mp_util.h"
#include "mp_vdev.h"
#include "mp_xport.h"

#include "lwip/def.h"

static const char *TAG = "mp_ctl";

#define CTL_LINE_MAX   384
#define CTL_REPLY_MAX  1200
#define CTL_UDP_QUEUE  4
#define CTL_UDP_MAX    640
#define CTL_TASK_STACK 6144

/* ------------------------------------------------------------ config keys */

static const mp_cfg_key_t s_cfg_keys[] = {
    { "mgmt.ip",   MP_CFG_T_IP,  { .u.str = CONFIG_MICROPOT_MGMT_IP }, 0, 0, NULL, false, NULL, true },
    { "ctl.port",  MP_CFG_T_U32, { .u.u32 = CONFIG_MICROPOT_CTL_PORT }, 1, 65535, NULL, false, NULL, true },
    { "ctl.psk",   MP_CFG_T_STR, { .u.str = CONFIG_MICROPOT_CTL_PSK }, 0, 0, NULL, true, NULL, false },
    { "ctl.admin", MP_CFG_T_IP,  { .u.str = CONFIG_MICROPOT_CTL_ADMIN }, 0, 0, NULL, false, NULL, false },
};

static bool ctl_acl(uint32_t src_ip)
{
    char buf[16];
    mp_cfg_str("ctl.admin", buf, sizeof(buf));
    ip4_addr_t admin;
    if (ip4addr_aton(buf, &admin) != 1 || admin.addr == 0) {
        return true; /* no ACL configured: PSK is the gate */
    }
    return src_ip == admin.addr;
}

/* ------------------------------------------------------------------- HMAC */

static uint32_t s_last_ts;

static bool mac_ok(const char *message, size_t msg_len, const char *mac_hex)
{
    char psk[MP_CFG_STR_MAX + 1];
    mp_cfg_str("ctl.psk", psk, sizeof(psk));

    Hmac h;
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    if (wc_HmacInit(&h, NULL, INVALID_DEVID) != 0 ||
        wc_HmacSetKey(&h, WC_SHA256, (const byte *)psk,
                      (word32)strlen(psk)) != 0 ||
        wc_HmacUpdate(&h, (const byte *)message, (word32)msg_len) != 0 ||
        wc_HmacFinal(&h, digest) != 0) {
        wc_HmacFree(&h);
        return false;
    }
    wc_HmacFree(&h);

    char expect[WC_SHA256_DIGEST_SIZE * 2 + 1];
    for (int i = 0; i < WC_SHA256_DIGEST_SIZE; i++) {
        snprintf(expect + 2 * i, 3, "%02x", digest[i]);
    }
    if (strlen(mac_hex) != WC_SHA256_DIGEST_SIZE * 2) {
        return false;
    }
    uint8_t diff = 0;
    for (size_t i = 0; i < WC_SHA256_DIGEST_SIZE * 2; i++) {
        diff |= (uint8_t)(expect[i] ^ mac_hex[i]);
    }
    return diff == 0;
}

/* ------------------------------------------------------------ reply writer */

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    bool   ok;
} jw_t;

static void jw_raw(jw_t *w, const char *s)
{
    if (!w->ok) {
        return;
    }
    int n = snprintf(w->buf + w->len, w->cap - w->len, "%s", s);
    if (n < 0 || (size_t)n >= w->cap - w->len) {
        w->ok = false;
        return;
    }
    w->len += (size_t)n;
}

static void jw_escaped(jw_t *w, const char *s)
{
    for (; *s && w->ok; s++) {
        char esc[8];
        const char *p = esc;
        switch (*s) {
        case '"':  p = "\\\""; break;
        case '\\': p = "\\\\"; break;
        case '\n': p = "\\n"; break;
        case '\r': p = "\\r"; break;
        case '\t': p = "\\t"; break;
        default:
            if ((unsigned char)*s < 0x20) {
                snprintf(esc, sizeof(esc), "\\u%04x", *s);
            } else {
                esc[0] = *s;
                esc[1] = '\0';
            }
        }
        jw_raw(w, p);
    }
}

static void jw_str(jw_t *w, const char *s)
{
    jw_raw(w, "\"");
    jw_escaped(w, s);
    jw_raw(w, "\"");
}

/* ------------------------------------------------------------ cmd handlers */

static void cmd_status(jw_t *w)
{
    const esp_app_desc_t *app = esp_app_get_description();
    jw_raw(w, "{\"uptime_s\":");
    char tmp[24];
    snprintf(tmp, sizeof(tmp), "%lld", (long long)(esp_timer_get_time() / 1000000));
    jw_raw(w, tmp);
    jw_raw(w, ",\"heap_free\":");
    snprintf(tmp, sizeof(tmp), "%u", (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    jw_raw(w, tmp);
    jw_raw(w, ",\"heap_min\":");
    snprintf(tmp, sizeof(tmp), "%u", (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    jw_raw(w, tmp);
    jw_raw(w, ",\"sessions_active\":");
    snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)mp_xport_active());
    jw_raw(w, tmp);
    jw_raw(w, ",\"boot\":");
    snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)mp_log_boot_count());
    jw_raw(w, tmp);
    jw_raw(w, ",\"version\":");
    jw_str(w, app->version);
    jw_raw(w, ",\"vdevs\":[");
    for (size_t i = 0; i < mp_vdev_count(); i++) {
        const mp_vdev_t *v = mp_vdev_at(i);
        if (i) {
            jw_raw(w, ",");
        }
        jw_raw(w, "{\"ip\":");
        if (v->vaddr == 0) {
            jw_str(w, "primary");
        } else {
            char ip[16];
            mp_ip4_str(v->vaddr, ip, sizeof(ip));
            jw_str(w, ip);
        }
        jw_raw(w, ",\"persona\":");
        jw_str(w, v->persona ? v->persona->id : "mgmt");
        jw_raw(w, "}");
    }
    jw_raw(w, "]}");
}

static void cmd_log_stats(jw_t *w)
{
    uint32_t dropped = 0;
    uint32_t queued = 0;
    mp_log_stats(&dropped, &queued);
    char tmp[160];
    snprintf(tmp, sizeof(tmp),
             "{\"dropped\":%lu,\"queued\":%lu}",
             (unsigned long)dropped, (unsigned long)queued);
    jw_raw(w, tmp);
}

static void cmd_list(jw_t *w)
{
    jw_raw(w, "{");
    bool first = true;
    for (size_t i = 0; i < mp_cfg_count(); i++) {
        const mp_cfg_key_t *k = mp_cfg_at(i);
        if (!first) {
            jw_raw(w, ",");
        }
        first = false;
        jw_str(w, k->key);
        jw_raw(w, ":");
        if (k->secret) {
            jw_str(w, "***");
        } else {
            mp_cfg_value_t v;
            char s[MP_CFG_STR_MAX + 12];
            if (mp_cfg_get(k->key, &v)) {
                mp_cfg_value_str(k->type, &v, s, sizeof(s));
            } else {
                s[0] = '\0';
            }
            jw_str(w, s);
        }
    }
    jw_raw(w, "}");
}

/* ------------------------------------------------------------- dispatcher */

/* @return 0 ok, 1 reboot requested (reply already composed) */
static int ctl_exec(const char *line, char *out, size_t cap, const char *src)
{
    long id = 0;
    const char *err = NULL;
    bool reboot = false;
    char result[CTL_REPLY_MAX - 160];
    result[0] = '\0';

    /* split off " mac=" (last occurrence) */
    const char *mac_mark = NULL;
    for (const char *p = line; (p = strstr(p, " mac=")) != NULL;) {
        mac_mark = p;
        p += 5;
    }
    if (!mac_mark) {
        err = "missing mac";
        goto reply;
    }
    const char *mac_hex = mac_mark + 5;
    size_t msg_len = (size_t)(mac_mark - line);
    if (msg_len >= CTL_LINE_MAX) {
        err = "too long";
        goto reply;
    }

    /* tokens id= / ts= / cmd= / k= are space-separated words; v= runs to
     * end of message (may hold spaces) */
    char msg[CTL_LINE_MAX];
    memcpy(msg, line, msg_len);
    msg[msg_len] = '\0';

    char ts_s[16] = { 0 }, cmd[24] = { 0 }, k[24] = { 0 };
    char vbuf[192]; /* stack: TCP sessions run on per-conn tasks */
    const char *v = "";
    {
        char *save = NULL;
        for (char *tok = strtok_r(msg, " ", &save); tok;
             tok = strtok_r(NULL, " ", &save)) {
            if (strncmp(tok, "id=", 3) == 0) {
                id = strtol(tok + 3, NULL, 10);
            } else if (strncmp(tok, "ts=", 3) == 0) {
                snprintf(ts_s, sizeof(ts_s), "%s", tok + 3);
            } else if (strncmp(tok, "cmd=", 4) == 0) {
                snprintf(cmd, sizeof(cmd), "%s", tok + 4);
            } else if (strncmp(tok, "k=", 2) == 0) {
                snprintf(k, sizeof(k), "%s", tok + 2);
            }
        }
        /* v= (if present) is everything between " v=" and the mac mark */
        const char *vp = strstr(line, " v=");
        if (vp && vp < mac_mark) {
            size_t vl = (size_t)(mac_mark - (vp + 3));
            if (vl >= sizeof(vbuf)) {
                vl = sizeof(vbuf) - 1;
            }
            memcpy(vbuf, vp + 3, vl);
            vbuf[vl] = '\0';
            v = vbuf;
        }
    }

    if (!mac_ok(line, msg_len, mac_hex)) {
        err = "auth";
        mp_evt_t e;
        mp_evt_begin(&e, NULL, "system", "ctl.auth_fail");
        mp_evt_str(&e, "src", src);
        mp_evt_str(&e, "cmd", cmd[0] ? cmd : "?");
        mp_evt_send(&e);
        goto reply;
    }
    {
        uint32_t ts = (uint32_t)strtoul(ts_s, NULL, 10);
        if (ts <= s_last_ts) {
            err = "stale ts";
            goto reply;
        }
        s_last_ts = ts;
    }

    /* key lookup helper result for get/set */
    const mp_cfg_key_t *def = NULL;
    if (k[0]) {
        for (size_t i = 0; i < mp_cfg_count(); i++) {
            if (strcmp(mp_cfg_at(i)->key, k) == 0) {
                def = mp_cfg_at(i);
            }
        }
    }

    /* ---- dispatch ---- */
    if (strcmp(cmd, "ping") == 0) {
        snprintf(result, sizeof(result), "\"pong\"");
    } else if (strcmp(cmd, "status") == 0) {
        jw_t rw = { .buf = result, .cap = sizeof(result), .ok = true };
        cmd_status(&rw);
    } else if (strcmp(cmd, "log.stats") == 0) {
        jw_t rw = { .buf = result, .cap = sizeof(result), .ok = true };
        cmd_log_stats(&rw);
    } else if (strcmp(cmd, "log.test") == 0) {
        mp_evt_t e;
        mp_evt_begin(&e, NULL, "system", "log.test");
        mp_evt_str(&e, "src", src);
        mp_evt_send(&e);
        snprintf(result, sizeof(result), "\"sent\"");
    } else if (strcmp(cmd, "list") == 0) {
        jw_t rw = { .buf = result, .cap = sizeof(result), .ok = true };
        cmd_list(&rw);
    } else if (strcmp(cmd, "get") == 0) {
        mp_cfg_value_t val;
        if (!def || !mp_cfg_get(k, &val)) {
            err = "unknown key";
            goto reply;
        }
        char s[MP_CFG_STR_MAX + 12];
        if (def->secret) {
            snprintf(s, sizeof(s), "***");
        } else {
            mp_cfg_value_str(def->type, &val, s, sizeof(s));
        }
        jw_t rw = { .buf = result, .cap = sizeof(result), .ok = true };
        jw_str(&rw, s);
    } else if (strcmp(cmd, "set") == 0) {
        if (!def) {
            err = "unknown key";
            goto reply;
        }
        mp_cfg_value_t val = { 0 };
        switch (def->type) {
        case MP_CFG_T_STR:
        case MP_CFG_T_IP:
            strlcpy(val.u.str, v, sizeof(val.u.str));
            break;
        case MP_CFG_T_U32:
            val.u.u32 = (uint32_t)strtoul(v, NULL, 10);
            break;
        case MP_CFG_T_BOOL:
            val.u.b = strcmp(v, "true") == 0 || strcmp(v, "1") == 0;
            break;
        }
        int r = mp_cfg_set(k, &val, src);
        if (r != 0) {
            err = (r == -2) ? "validation failed" : "storage error";
            goto reply;
        }
        snprintf(result, sizeof(result), "%s",
                 def->needs_reboot ? "\"ok (applies after reboot)\"" : "\"ok\"");
    } else if (strcmp(cmd, "unset") == 0) {
        if (!def || mp_cfg_unset(k, src) != 0) {
            err = "unknown key";
            goto reply;
        }
        snprintf(result, sizeof(result), "\"ok\"");
    } else if (strcmp(cmd, "reset") == 0) {
        if (mp_cfg_unset_all(src) != 0) {
            err = "storage error";
            goto reply;
        }
        snprintf(result, sizeof(result), "\"ok\"");
    } else if (strcmp(cmd, "reboot") == 0) {
        snprintf(result, sizeof(result), "\"rebooting\"");
        reboot = true;
    } else {
        err = "unknown cmd";
    }

reply:
    {
        jw_t w2 = { .buf = out, .cap = cap, .ok = true };
        char tmp[24];
        snprintf(tmp, sizeof(tmp), "{\"id\":%ld,", id);
        jw_raw(&w2, tmp);
        if (err) {
            jw_raw(&w2, "\"ok\":false,\"err\":");
            jw_str(&w2, err);
        } else {
            jw_raw(&w2, "\"ok\":true,\"result\":");
            jw_raw(&w2, result[0] ? result : "null");
        }
        jw_raw(&w2, "}");
    }
    return reboot ? 1 : 0;
}

/* -------------------------------------------------------------- transports */

static void ctl_tcp_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    (void)arg;
    char src[40];
    char ip[16];
    mp_ip4_str(sess->src_ip, ip, sizeof(ip));
    snprintf(src, sizeof(src), "tcp:%s", ip);

    char line[CTL_LINE_MAX];
    char out[CTL_REPLY_MAX];
    for (;;) {
        int n = mp_line_read(conn, line, sizeof(line), 300000, false,
                             MP_LINE_ECHO_OFF);
        if (n <= 0) {
            break;
        }
        if (ctl_exec(line, out, sizeof(out), src) == 1) {
            mp_conn_send(conn, out, strlen(out));
            mp_conn_send(conn, "\n", 1);
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart();
        }
        mp_conn_send(conn, out, strlen(out));
        mp_conn_send(conn, "\n", 1);
    }
}

typedef struct {
    uint32_t lip, rip;
    uint16_t lport, rport;
    size_t   len;
    uint8_t  data[CTL_UDP_MAX];
} udp_req_t;

static QueueHandle_t s_udp_queue;

static void ctl_udp_rx(uint32_t lip, uint32_t rip, uint16_t lport,
                       uint16_t rport, const uint8_t *data, size_t len)
{
    /* tcpip thread: copy + defer */
    udp_req_t req = {
        .lip = lip, .rip = rip, .lport = lport, .rport = rport,
        .len = len > CTL_UDP_MAX ? CTL_UDP_MAX : len,
    };
    memcpy(req.data, data, req.len);
    xQueueSend(s_udp_queue, &req, 0); /* drop on full: UDP is best effort */
}

static void ctl_task(void *arg)
{
    (void)arg;
    udp_req_t req;
    char out[CTL_REPLY_MAX];
    for (;;) {
        if (xQueueReceive(s_udp_queue, &req, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        /* requests are text lines; tolerate a trailing \n */
        char line[CTL_LINE_MAX];
        size_t n = req.len < sizeof(line) - 1 ? req.len : sizeof(line) - 1;
        memcpy(line, req.data, n);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            n--;
        }
        line[n] = '\0';

        char ip[16], src[40];
        mp_ip4_str(PP_HTONL(req.rip), ip, sizeof(ip));
        snprintf(src, sizeof(src), "udp:%s", ip);

        if (ctl_exec(line, out, sizeof(out), src) == 1) {
            mp_s419_udp_send(req.lip, req.rip, req.lport, req.rport,
                          out, strlen(out));
            mp_s419_udp_send(req.lip, req.rip, req.lport, req.rport, "\n", 1);
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart();
        }
        mp_s419_udp_send(req.lip, req.rip, req.lport, req.rport, out, strlen(out));
        mp_s419_udp_send(req.lip, req.rip, req.lport, req.rport, "\n", 1);
    }
}

/* ---------------------------------------------------------------- lifecycle */

esp_err_t mp_ctl_init(void)
{
    return mp_cfg_register(s_cfg_keys, sizeof(s_cfg_keys) / sizeof(s_cfg_keys[0]))
               == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t mp_ctl_start(void)
{
    char ip[16];
    mp_cfg_str("mgmt.ip", ip, sizeof(ip));
    ip4_addr_t mgmt;
    if (!ip[0] || strcmp(ip, "0.0.0.0") == 0 || ip4addr_aton(ip, &mgmt) != 1) {
        ESP_LOGI(TAG, "management plane disabled (mgmt.ip unset)");
        return ESP_OK;
    }
    ESP_ERROR_CHECK(mp_vdev_add(mgmt.addr, NULL));

    char psk[MP_CFG_STR_MAX + 1];
    mp_cfg_str("ctl.psk", psk, sizeof(psk));
    if (strcmp(psk, "change-me") == 0) {
        ESP_LOGW(TAG, "ctl.psk is the default — set it before exposing mgmt");
        mp_evt_t e;
        mp_evt_begin(&e, NULL, "system", "config_warn");
        mp_evt_str(&e, "msg", "default management PSK in use");
        mp_evt_str(&e, "key", "ctl.psk");
        mp_evt_send(&e);
    }

    uint16_t port = (uint16_t)mp_cfg_u32("ctl.port", CONFIG_MICROPOT_CTL_PORT);

    mp_listener_cfg_t cfg = {
        .vaddr = mgmt.addr,
        .port = port,
        .name = "mp_ctl",
        .persona = "mgmt",
        .allow = ctl_acl,
        .handler = ctl_tcp_conn,
        .xport = &mp_xport_s419,
    };
    esp_err_t err = mp_xport_listen(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tcp listen failed: %s", esp_err_to_name(err));
        return err;
    }

    s_udp_queue = xQueueCreate(CTL_UDP_QUEUE, sizeof(udp_req_t));
    if (!s_udp_queue) {
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(ctl_task, "mp_ctl", CTL_TASK_STACK, NULL, 5, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    err = mp_s419_udp_listen(mgmt.addr, port, ctl_acl, ctl_udp_rx);
    if (err != ESP_OK) {
        return err;
    }
    ESP_LOGI(TAG, "management plane on %s:%u (UDP+TCP, HMAC-SHA256)", ip, port);
    return ESP_OK;
}
