/*
 * Logger runtime: bounded queue, UDP/TCP transport with bounded connect
 * times, NVS boot counter, and the phase-1 thin wrappers. The generic
 * event builder lives in mp_evt.c.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_spiffs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "nvs.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mp_cfg.h"
#include "mp_log.h"
#include "mp_util.h"

static const char *TAG = "mp_log";

#define MP_LOG_QUEUE_LEN     24
#define MP_LOG_LINE_MAX      1024
#define MP_LOG_PERSONA_MAX   32
#define MP_LOG_TASK_STACK    6144
#define MP_LOG_TASK_PRIO     5
#define MP_LOG_CONNECT_TIMEOUT_MS 3000
#define MP_LOG_SEND_TIMEOUT_MS    3000

static QueueHandle_t s_queue;
static int           s_sock = -1;
static bool          s_use_tcp;
static bool          s_tcp_connected;
static struct sockaddr_in s_dest;
static uint32_t      s_seq;
static uint32_t      s_boot;
static char          s_persona[MP_LOG_PERSONA_MAX] = "unknown";

static portMUX_TYPE  s_drop_lock = portMUX_INITIALIZER_UNLOCKED;
static uint32_t      s_dropped;

/* Config keys owned by this component; defaults come from Kconfig. */
#if CONFIG_MICROPOT_LOG_PROTO_TCP
#define MP_CFG_DEFAULT_TCP true
#else
#define MP_CFG_DEFAULT_TCP false
#endif
#if CONFIG_MICROPOT_LOG_CONSOLE
#define MP_CFG_DEFAULT_CONSOLE true
#else
#define MP_CFG_DEFAULT_CONSOLE false
#endif

static const mp_cfg_key_t s_cfg_keys[] = {
    { "log.host", MP_CFG_T_IP,  { .u.str = CONFIG_MICROPOT_LOG_HOST }, 0, 0, NULL, false, NULL, true },
    { "log.port", MP_CFG_T_U32, { .u.u32 = CONFIG_MICROPOT_LOG_PORT }, 1, 65535, NULL, false, NULL, true },
    { "log.tcp",  MP_CFG_T_BOOL,{ .u.b = MP_CFG_DEFAULT_TCP }, 0, 0, NULL, false, NULL, true },
    { "log.console", MP_CFG_T_BOOL, { .u.b = MP_CFG_DEFAULT_CONSOLE }, 0, 0, NULL, false, NULL, false },
    /* event queue depth; past it producers drop (counted in logdrop).
     * ~460 B PSRAM per slot. */
    { "log.queue", MP_CFG_T_U32, { .u.u32 = MP_LOG_QUEUE_LEN }, 8, 128, NULL, false, NULL, true },
    /* SPIFFS spillover ring: offline events persist across reboots and
     * replay when the collector returns. false = volatile-only. */
    { "log.ring", MP_CFG_T_BOOL, { .u.b = true }, 0, 0, NULL, false, NULL, true },
};

/* -------------------------------------------------------------- transport */

static void transport_close(void)
{
    if (s_sock >= 0) {
        close(s_sock);
        s_sock = -1;
    }
    s_tcp_connected = false;
}

/* connect() with a bounded wait so an unreachable collector cannot stall
 * the logger task (lwIP's default connect timeout is tens of seconds). */
static bool tcp_connect(int sock, const struct sockaddr_in *dest)
{
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        flags = 0;
    }
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int r = connect(sock, (const struct sockaddr *)dest, sizeof(*dest));
    if (r < 0 && errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv = {
            .tv_sec = MP_LOG_CONNECT_TIMEOUT_MS / 1000,
            .tv_usec = (MP_LOG_CONNECT_TIMEOUT_MS % 1000) * 1000,
        };
        r = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (r > 0) {
            int so_err = 0;
            socklen_t len = sizeof(so_err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &len);
            r = (so_err == 0) ? 0 : -1;
            errno = so_err;
        } else {
            r = -1;
        }
    }
    fcntl(sock, F_SETFL, flags);

    if (r == 0) {
        struct timeval stv = {
            .tv_sec = MP_LOG_SEND_TIMEOUT_MS / 1000,
            .tv_usec = (MP_LOG_SEND_TIMEOUT_MS % 1000) * 1000,
        };
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv));
        return true;
    }
    return false;
}

static esp_err_t transport_open(void)
{
    transport_close();
    s_sock = socket(AF_INET, s_use_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (s_sock < 0) {
        ESP_LOGE(TAG, "socket() failed errno=%d", errno);
        return ESP_FAIL;
    }
    if (s_use_tcp) {
        if (tcp_connect(s_sock, &s_dest)) {
            s_tcp_connected = true;
        } else {
            ESP_LOGW(TAG, "TCP connect failed errno=%d (will retry)", errno);
        }
    } else if (connect(s_sock, (const struct sockaddr *)&s_dest,
                       sizeof(s_dest)) < 0) {
        /* UDP connect() pins the default peer (and on a full-posix stack
         * would enable async error delivery; lwIP has none, so a dead
         * UDP collector stays invisible — see the ring comment). */
        ESP_LOGW(TAG, "UDP connect failed errno=%d", errno);
    }
    return ESP_OK;
}

static bool transport_send(const char *buf, size_t len)
{
    if (s_sock < 0) {
        transport_open();
        if (s_sock < 0) {
            return false;
        }
    }
    if (!s_use_tcp) {
        if (send(s_sock, buf, len, 0) < 0) {
            ESP_LOGD(TAG, "UDP send failed errno=%d", errno);
            return false;
        }
        return true;
    }
    if (!s_tcp_connected) {
        /* A socket whose nonblocking connect failed is in an unspecified
         * state (POSIX); lwIP refuses any further connect() on it. Rebuild
         * the socket for every reconnect attempt or the retry loop never
         * recovers once the collector comes back. */
        transport_close();
        s_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (s_sock < 0) {
            return false;
        }
        if (!tcp_connect(s_sock, &s_dest)) {
            return false;
        }
        s_tcp_connected = true;
    }
    if (send(s_sock, buf, len, 0) < 0) {
        ESP_LOGW(TAG, "TCP send failed errno=%d, reconnecting", errno);
        transport_close();
        return false;
    }
    return true;
}

/* -------------------------------------------------------- SPIFFS ring spill
 *
 * When the transport is down (TCP disconnected, WiFi gone, local socket
 * errors) events append to a two-slot ring in the "storage" partition;
 * when sends succeed again the logger drains oldest-first, tagging each
 * replayed line with "replay":true. UDP caveat: lwIP delivers no async
 * errors to sockets, so a silently-dead UDP collector is undetectable
 * at send time (the connect() only pins the peer) — guaranteed offline
 * capture needs log.tcp=true, where send failure trips the ring.
 * Slot A is the current write file; on overflow it becomes B and a fresh A
 * starts (B is dropped). The logger task is the only writer and reader.
 */
#define MP_LOG_RING_A          "/spiffs/logring.a"
#define MP_LOG_RING_B          "/spiffs/logring.b"
#define MP_LOG_RING_SLOT_BYTES (128 * 1024)
#define MP_LOG_RING_DRAIN_MAX  16 /* lines drained per shipped event */

static bool  s_ring_mounted;
static FILE *s_ring_w;
static FILE *s_ring_r;

static void ring_mount(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "storage",
        .max_files = 5,
        /* first boot on a fresh partition formats it; afterwards mounts
         * are pure reads of existing state */
        .format_if_mount_failed = true,
    };
    if (esp_vfs_spiffs_register(&conf) != ESP_OK) {
        ESP_LOGW(TAG, "spiffs mount failed; ring spillover disabled");
        return;
    }
    /* a stale A from a previous boot becomes the drain slot */
    if (access(MP_LOG_RING_A, F_OK) == 0 && access(MP_LOG_RING_B, F_OK) != 0) {
        rename(MP_LOG_RING_A, MP_LOG_RING_B);
    }
    s_ring_mounted = true;
    struct stat sa, sb;
    long na = stat(MP_LOG_RING_A, &sa) == 0 ? (long)sa.st_size : -1;
    long nb = stat(MP_LOG_RING_B, &sb) == 0 ? (long)sb.st_size : -1;
    ESP_LOGI(TAG, "log ring mounted (A=%ld B=%ld bytes)", na, nb);
}

static void ring_write(const char *line)
{
    if (!s_ring_mounted) {
        return;
    }
    if (!s_ring_w) {
        s_ring_w = fopen(MP_LOG_RING_A, "a");
        if (!s_ring_w) {
            return;
        }
    }
    fputs(line, s_ring_w);
    fflush(s_ring_w); /* power-loss friendliness beats metadata churn here */
    if (ftell(s_ring_w) >= MP_LOG_RING_SLOT_BYTES) {
        fclose(s_ring_w);
        s_ring_w = NULL;
        if (s_ring_r) { /* rotation discards the undrained remainder of B */
            fclose(s_ring_r);
            s_ring_r = NULL;
        }
        remove(MP_LOG_RING_B);
        rename(MP_LOG_RING_A, MP_LOG_RING_B);
    }
}

/* Send up to MP_LOG_RING_DRAIN_MAX backlog lines; stops at the first
 * transport failure, keeping the read position for the next round. */
static void ring_drain(void)
{
    if (!s_ring_mounted) {
        return;
    }
    if (!s_ring_r) {
        if (access(MP_LOG_RING_B, F_OK) != 0) {
            /* B absent: promote the current write slot so spills from THIS
             * boot are drainable too — otherwise anything under the 128 KiB
             * overflow threshold stays stuck in A until a reboot. */
            if (access(MP_LOG_RING_A, F_OK) != 0) {
                if (s_ring_w) {
                    fclose(s_ring_w);
                    s_ring_w = NULL;
                }
                rename(MP_LOG_RING_A, MP_LOG_RING_B);
            } else {
                return;
            }
        }
        s_ring_r = fopen(MP_LOG_RING_B, "r");
        if (!s_ring_r) {
            return;
        }
    }
    char line[MP_LOG_LINE_MAX];
    for (int i = 0; i < MP_LOG_RING_DRAIN_MAX; i++) {
        if (!fgets(line, sizeof(line), s_ring_r)) {
            fclose(s_ring_r);
            s_ring_r = NULL;
            remove(MP_LOG_RING_B);
            /* promote whatever accumulated in A while draining */
            if (s_ring_w) {
                fclose(s_ring_w);
                s_ring_w = NULL;
            }
            rename(MP_LOG_RING_A, MP_LOG_RING_B);
            return;
        }
        /* tag replays: insert right after the opening '{' */
        char tagged[MP_LOG_LINE_MAX + 16];
        if (line[0] == '{') {
            snprintf(tagged, sizeof(tagged), "{\"replay\":true,%s", line + 1);
        } else {
            snprintf(tagged, sizeof(tagged), "%s", line);
        }
        if (!transport_send(tagged, strlen(tagged))) {
            return;
        }
    }
}

/* --------------------------------------------------------------- encoding */

static int format_msg(const mp_evt_t *m, uint32_t seq, const char *persona,
                      char *out, size_t n)
{
    char sip[16], dip[16];
    mp_ip4_str(m->src_ip, sip, sizeof(sip));
    mp_ip4_str(m->dst_ip, dip, sizeof(dip));

    return snprintf(out, n,
                    "{\"v\":1,\"ts\":%lld,\"boot\":%u,\"seq\":%u,\"sid\":%u,"
                    "\"evt\":\"%s\",\"proto\":\"%s\",\"persona\":\"%s\","
                    "\"sip\":\"%s\",\"sport\":%u,\"dip\":\"%s\",\"dport\":%u,"
                    "\"data\":{%s}}",
                    (long long)m->ts_ms, (unsigned)s_boot, (unsigned)seq,
                    (unsigned)m->sid, m->evt, m->proto, persona,
                    sip, (unsigned)m->src_port, dip, (unsigned)m->dst_port,
                    m->data);
}

static void ship(const mp_evt_t *m, uint32_t seq, char *line, size_t line_cap)
{
    /* Per-session persona (phase 2 multi-IP) wins; otherwise the global one
     * set by mp_log_set_persona() for system events. */
    int n = format_msg(m, seq, m->persona ? m->persona : s_persona,
                       line, line_cap);
    if (n < 0 || (size_t)n + 1 >= line_cap) {
        return; /* cannot happen with MP_LOG_LINE_MAX >> MP_EVT_DATA_MAX */
    }
    line[n++] = '\n'; /* newline framing so TCP receivers can split */
    line[n] = '\0';
    if (transport_send(line, (size_t)n)) {
        ring_drain(); /* transport healthy: opportunistically flush backlog */
    } else {
        ring_write(line);
    }
    if (mp_cfg_bool("log.console", MP_CFG_DEFAULT_CONSOLE)) {
        /* Blocking UART write: fine while developing, but under an event
         * flood it keeps this task (and thus the idle task) busy — see the
         * Kconfig help. The collector is the authoritative sink. */
        fputs(line, stdout); /* line already carries its newline */
    }
}

/* ------------------------------------------------------------------ queue */

void mp_evt_send(mp_evt_t *e)
{
    if (!s_queue) {
        return;
    }
    e->ts_ms = esp_timer_get_time() / 1000;
    if (xQueueSend(s_queue, e, 0) != pdTRUE) {
        portENTER_CRITICAL(&s_drop_lock);
        s_dropped++;
        portEXIT_CRITICAL(&s_drop_lock);
    }
}

static void logger_task(void *arg)
{
    (void)arg;
    mp_evt_t m;
    char     line[MP_LOG_LINE_MAX];
    for (;;) {
        if (xQueueReceive(s_queue, &m, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        ship(&m, ++s_seq, line, sizeof(line));

        portENTER_CRITICAL(&s_drop_lock);
        uint32_t dropped = s_dropped;
        s_dropped = 0;
        portEXIT_CRITICAL(&s_drop_lock);
        if (dropped) {
            mp_evt_t d;
            mp_evt_begin(&d, NULL, "system", "log.dropped");
            mp_evt_int(&d, "count", (long long)dropped);
            d.ts_ms = esp_timer_get_time() / 1000;
            ship(&d, ++s_seq, line, sizeof(line));
        }
    }
}

/* ---------------------------------------------------------------- startup */

static void read_boot_counter(void)
{
    nvs_handle_t h;
    uint32_t     v = 0;
    if (nvs_open("mp", NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    if (nvs_get_u32(h, "boot", &v) != ESP_OK) {
        v = 0;
    }
    v++;
    s_boot = v;
    nvs_set_u32(h, "boot", v);
    nvs_commit(h);
    nvs_close(h);
}

/* Installed into mp_cfg: every change becomes a system.config audit event. */
static void cfg_audit(const char *key, const char *oldv, const char *newv,
                      const char *src)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "system", "config");
    mp_evt_str(&e, "key", key);
    mp_evt_str(&e, "old", oldv);
    mp_evt_str(&e, "new", newv);
    mp_evt_str(&e, "src", src);
    mp_evt_send(&e);
}

esp_err_t mp_log_init(void)
{
    /* keys must be registered before ANY mp_cfg_* read here, or an NVS
     * override of that key (e.g. log.ring=false) is invisible */
    mp_cfg_register(s_cfg_keys, sizeof(s_cfg_keys) / sizeof(s_cfg_keys[0]));
    mp_cfg_set_audit_hook(cfg_audit);

    read_boot_counter();
    if (mp_cfg_bool("log.ring", true)) {
        ring_mount();
    }

    char host[16];
    mp_cfg_str("log.host", host, sizeof(host));

    memset(&s_dest, 0, sizeof(s_dest));
    s_dest.sin_family = AF_INET;
    s_dest.sin_port = htons((uint16_t)mp_cfg_u32("log.port", CONFIG_MICROPOT_LOG_PORT));
    if (inet_pton(AF_INET, host, &s_dest.sin_addr) != 1) {
        ESP_LOGE(TAG, "invalid log host '%s'", host);
        return ESP_ERR_INVALID_ARG;
    }

    s_use_tcp = mp_cfg_bool("log.tcp", MP_CFG_DEFAULT_TCP);
    /* Socket is opened lazily on first send: the lwIP/tcpip stack must already
     * be initialised (esp_netif_init) before any socket() call. */

    /* The event queue lives in PSRAM: producers only call
     * xQueueSend from task context (never an ISR), so it is safe there and
     * keeps HP SRAM free. The logger task itself stays internal because it
     * commits the NVS boot counter. */
    s_queue = xQueueCreateWithCaps(mp_cfg_u32("log.queue", MP_LOG_QUEUE_LEN),
                                   sizeof(mp_evt_t), MALLOC_CAP_SPIRAM);
    if (!s_queue) {
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(logger_task, "mp_log", MP_LOG_TASK_STACK, NULL,
                    MP_LOG_TASK_PRIO, NULL) != pdPASS) {
        vQueueDeleteWithCaps(s_queue);
        s_queue = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "logger ready -> %s:%u over %s (boot #%u)",
             host, (unsigned)mp_cfg_u32("log.port", CONFIG_MICROPOT_LOG_PORT),
             s_use_tcp ? "TCP" : "UDP", (unsigned)s_boot);
    return ESP_OK;
}

void mp_log_set_persona(const char *persona_id)
{
    if (!persona_id) {
        return;
    }
    snprintf(s_persona, sizeof(s_persona), "%s", persona_id);
}

void mp_log_stats(uint32_t *dropped, uint32_t *queued)
{
    if (dropped) {
        *dropped = s_dropped;
    }
    if (queued) {
        *queued = s_queue ? uxQueueMessagesWaiting(s_queue) : 0;
    }
}

uint32_t mp_log_boot_count(void)
{
    return s_boot;
}

/* ----------------------------------------------------- phase-1 wrappers */

void mp_log_net_up(const char *ip, const char *gw, const char *mac)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "system", "net.up");
    mp_evt_str(&e, "ip", ip);
    mp_evt_str(&e, "gw", gw);
    mp_evt_str(&e, "mac", mac);
    mp_evt_send(&e);
}

void mp_log_service(const char *service, uint16_t port, bool up)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "system", "svc");
    mp_evt_str(&e, "service", service);
    mp_evt_int(&e, "port", port);
    mp_evt_bool(&e, "up", up);
    mp_evt_send(&e);
}

void mp_log_telnet_connect(const mp_session_t *s)
{
    mp_evt_t e;
    mp_evt_begin(&e, s, "telnet", "telnet.connect");
    mp_evt_str(&e, "service", "telnet");
    mp_evt_send(&e);
}

void mp_log_telnet_login(const mp_session_t *s, const char *user, const char *pass,
                         bool ok, int attempt)
{
    mp_evt_t e;
    mp_evt_begin(&e, s, "telnet", "telnet.login_attempt");
    mp_evt_str(&e, "user", user);
    mp_evt_str(&e, "pass", pass);
    mp_evt_str(&e, "result", ok ? "ok" : "fail");
    mp_evt_int(&e, "attempt", attempt);
    mp_evt_send(&e);
}

void mp_log_telnet_command(const mp_session_t *s, const char *cmd)
{
    mp_evt_t e;
    mp_evt_begin(&e, s, "telnet", "telnet.command");
    mp_evt_str(&e, "cmd", cmd);
    mp_evt_send(&e);
}

void mp_log_telnet_disconnect(const mp_session_t *s, int64_t dur_ms, const char *reason)
{
    mp_evt_t e;
    mp_evt_begin(&e, s, "telnet", "telnet.disconnect");
    mp_evt_int(&e, "dur_ms", (long long)dur_ms);
    mp_evt_str(&e, "reason", reason);
    mp_evt_send(&e);
}

void mp_log_http_request(const mp_session_t *s, const char *method, const char *uri,
                         int code)
{
    mp_evt_t e;
    mp_evt_begin(&e, s, "http", "http.request");
    mp_evt_str(&e, "method", method);
    mp_evt_str(&e, "uri", uri);
    mp_evt_int(&e, "code", code);
    mp_evt_send(&e);
}

void mp_log_http_login(const mp_session_t *s, const char *user, const char *pass, bool ok)
{
    mp_evt_t e;
    mp_evt_begin(&e, s, "http", "http.login_attempt");
    mp_evt_str(&e, "user", user);
    mp_evt_str(&e, "pass", pass);
    mp_evt_str(&e, "result", ok ? "ok" : "fail");
    mp_evt_send(&e);
}

void mp_log_http_notfound(const mp_session_t *s, const char *uri)
{
    mp_evt_t e;
    mp_evt_begin(&e, s, "http", "http.notfound");
    mp_evt_str(&e, "uri", uri);
    mp_evt_send(&e);
}
