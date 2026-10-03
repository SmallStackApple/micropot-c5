/*
 * Banner-level SSH honeypot.
 *
 * A real SSH server sends its version string the moment the TCP connection
 * opens, so that single line is what every scanner (nmap -sV, masscan,
 * Shodan) fingerprints. We send the brand's version, harvest the client's
 * own banner (a great scanner/family indicator), linger like a slow
 * embedded sshd would, then close. All events go straight through the
 * generic event bus — proof that a new protocol needs no core changes.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "mp_core.h"
#include "mp_linekit.h"
#include "mp_log.h"
#include "mp_ssh.h"
#include "mp_ssh_behavior.h"

static const char *TAG = "mp_ssh";

#define SSH_BANNER_TIMEOUT_MS 10000
#define SSH_DEFAULT_LINGER_MS 5000
#define SSH_CLIENT_BANNER_MAX 255 /* RFC 4253 §4.2 */

static mp_tcp_listener_cfg_t s_listener;

static void ssh_conn(int sock, const mp_session_t *sess, void *arg)
{
    mp_service_t *svc = (mp_service_t *)arg;
    const mp_ssh_behavior_t *b =
        svc->brand ? mp_brand_behavior(svc->brand, "ssh") : NULL;
    if (!b || !b->banner) {
        return;
    }

    mp_evt_t e;
    mp_evt_begin(&e, sess, "ssh", "ssh.connect");
    mp_evt_str(&e, "service", "ssh");
    mp_evt_send(&e);

    const char *reason = "closed";
    if (mp_send_str(sock, b->banner) < 0 || mp_send_str(sock, "\r\n") < 0) {
        reason = "send_error";
        goto done;
    }

    /* harvest the client's version string */
    char client[SSH_CLIENT_BANNER_MAX + 1];
    int n = mp_line_read(sock, client, sizeof(client), SSH_BANNER_TIMEOUT_MS,
                         false, MP_LINE_ECHO_OFF);
    if (n >= 0) {
        mp_evt_begin(&e, sess, "ssh", "ssh.banner");
        mp_evt_str(&e, "client", client);
        mp_evt_send(&e);
        reason = "probe";
    } else {
        reason = (n == -2) ? "timeout" : "closed";
    }

    /* a sluggish embedded sshd pauses before the key exchange; scanners
     * get their banner and move on, patient clients wait in vain */
    vTaskDelay(pdMS_TO_TICKS(b->linger_ms ? b->linger_ms
                                          : SSH_DEFAULT_LINGER_MS));

done:
    {
        int64_t dur = (esp_timer_get_time() - sess->start_us) / 1000;
        mp_evt_begin(&e, sess, "ssh", "ssh.disconnect");
        mp_evt_int(&e, "dur_ms", (long long)dur);
        mp_evt_str(&e, "reason", reason);
        mp_evt_send(&e);
    }
}

static esp_err_t ssh_start(mp_service_t *svc)
{
    if (!svc->brand || !mp_brand_behavior(svc->brand, "ssh")) {
        ESP_LOGE(TAG, "brand '%s' has no ssh behaviour",
                 svc->brand ? svc->brand->meta->id : "(null)");
        return ESP_ERR_NOT_SUPPORTED;
    }
    memset(&s_listener, 0, sizeof(s_listener));
    s_listener.vaddr = svc->bind.vaddr;
    s_listener.port = svc->bind.port;
    s_listener.name = "ssh";
    s_listener.handler = ssh_conn;
    s_listener.arg = svc;
    return mp_tcp_listener_start(&s_listener);
}

static const mp_service_ops_t s_ops = {
    .name = "ssh",
    .proto = MP_PROTO_TCP,
    .default_port = 22,
    .start = ssh_start,
    .stop = NULL,
};

const mp_service_ops_t *mp_ssh_get_ops(void)
{
    return &s_ops;
}
