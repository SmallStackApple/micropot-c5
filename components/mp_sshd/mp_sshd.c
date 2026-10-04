/*
 * Real SSH honeypot on mp_xport, driven by wolfSSH.
 *
 * The SSH-2 transport (KEX, host key, encryption, auth) is handled by
 * wolfSSH; this file supplies the transport glue and the honeypot policy:
 *  - custom I/O callbacks bound to the mp_conn_t, so the service runs on
 *    whichever stack the persona selected (lwIP or mp_stack419);
 *  - a password auth callback that records every attempt and accepts only
 *    the persona's weak credentials;
 *  - a handed-off shell (mp_shell) over the SSH channel.
 *
 * The protocol id is set to upstream "SSH-2.0-OpenSSH_7.9p1" — the exact
 * string `ssh -V` on a 7.9p1 build reports, with no distro suffix.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "mp_core.h"
#include "mp_log.h"
#include "mp_sshd.h"

/* wolfSSH expects the wolfSSL user_settings.h build (the managed
 * component does not ship a generated wolfssl/options.h). */
#define WOLFSSL_USER_SETTINGS 1
#include "wolfssh/ssh.h"

#include "esp_random.h"

/* wolfSSL's RNG seed hook (see CUSTOM_RAND_GENERATE_SEED in the project
 * CMakeLists): the ESP32-C5 hardware RNG. */
int mp_wolfssl_rand_seed(unsigned char *output, unsigned int sz)
{
    esp_fill_random(output, sz);
    return 0;
}

static const char *TAG = "mp_sshd";

#define SSHD_TASK_STACK    16384
#define SSHD_TASK_PRIO     5
#define SSHD_IO_TIMEOUT_MS 10000

/* ECDSA P-256 host key (DPP; the wolfSSL configuration disables RSA). */
extern const uint8_t ssh_host_ecdsa_key_der_start[] asm(
    "_binary_ssh_host_ecdsa_key_der_start");
extern const uint8_t ssh_host_ecdsa_key_der_end[] asm(
    "_binary_ssh_host_ecdsa_key_der_end");

static WOLFSSH_CTX *s_ctx;

typedef struct {
    const mp_sshd_behavior_t *beh;
    mp_conn_t                *conn;
    mp_session_t              sess;
    int                       attempts;
} sshd_conn_t;

/* ------------------------------------------------------------- wolfSSH IO */

static int ws_io_recv(WOLFSSH *ssh, void *buf, word32 sz, void *ctx)
{
    (void)ssh;
    sshd_conn_t *c = (sshd_conn_t *)ctx;
    int n = mp_conn_recv(c->conn, buf, sz, SSHD_IO_TIMEOUT_MS);
    if (n > 0) {
        return n;
    }
    if (n == MP_CONN_TIMEOUT) {
        return WS_CBIO_ERR_WANT_READ;
    }
    return WS_CBIO_ERR_CONN_CLOSE;
}

static int ws_io_send(WOLFSSH *ssh, void *buf, word32 sz, void *ctx)
{
    (void)ssh;
    sshd_conn_t *c = (sshd_conn_t *)ctx;
    if (mp_conn_send(c->conn, buf, sz) != 0) {
        return WS_CBIO_ERR_CONN_CLOSE;
    }
    return (int)sz;
}

/* --------------------------------------------------------------- auth */

/* Every password attempt is an intelligence win: record it. Only the
 * persona's weak credentials actually authenticate. */
static int ws_user_auth(byte authType, WS_UserAuthData *data, void *ctx)
{
    sshd_conn_t *c = (sshd_conn_t *)ctx;
    if (!c || !c->beh) {
        return WOLFSSH_USERAUTH_FAILURE;
    }

    const char *user = (const char *)data->username;
    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        const char *pass = (const char *)data->sf.password.password;
        bool ok = mp_creds_match(c->beh->creds, c->beh->n_creds,
                                 user ? user : "", pass ? pass : "");
        c->attempts++;

        mp_evt_t e;
        mp_evt_begin(&e, &c->sess, "ssh", "ssh.auth_attempt");
        mp_evt_str(&e, "user", user ? user : "");
        mp_evt_str(&e, "pass", pass ? pass : "");
        mp_evt_bool(&e, "result", ok);
        mp_evt_int(&e, "attempt", c->attempts);
        mp_evt_send(&e);

        return ok ? WOLFSSH_USERAUTH_SUCCESS : WOLFSSH_USERAUTH_FAILURE;
    }

    if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        mp_evt_t e;
        mp_evt_begin(&e, &c->sess, "ssh", "ssh.auth_attempt");
        mp_evt_str(&e, "user", user ? user : "");
        mp_evt_str(&e, "method", "publickey");
        mp_evt_bool(&e, "result", false);
        mp_evt_send(&e);
    }
    return WOLFSSH_USERAUTH_FAILURE;
}

/* ------------------------------------------------- shell over SSH stream */

typedef struct {
    WOLFSSH *ssh;
} stream_t;

static int stream_recv(mp_conn_t *c, void *buf, size_t len, uint32_t timeout_ms)
{
    stream_t *s = (stream_t *)c->ctx;
    int64_t deadline = esp_timer_get_time() / 1000 + timeout_ms;
    for (;;) {
        int r = wolfSSH_stream_read(s->ssh, (byte *)buf, (word32)len);
        if (r > 0) {
            return r;
        }
        if (r == WS_EOF) {
            return 0;
        }
        int err = wolfSSH_get_error(s->ssh);
        if (err == WS_WANT_READ || err == WS_WANT_WRITE) {
            if (esp_timer_get_time() / 1000 >= deadline) {
                return MP_CONN_TIMEOUT;
            }
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        return MP_CONN_ABORTED;
    }
}

static int stream_send(mp_conn_t *c, const void *buf, size_t len)
{
    stream_t *s = (stream_t *)c->ctx;
    int r = wolfSSH_stream_send(s->ssh, (byte *)buf, (word32)len);
    return r < 0 ? -1 : 0;
}

static void stream_shutdown(mp_conn_t *c)
{
    (void)c;
    /* the SSH channel is closed when the shell session ends */
}

static void stream_release(mp_conn_t *c)
{
    (void)c;
}

static const mp_conn_ops_t s_stream_ops = {
    .recv = stream_recv,
    .send = stream_send,
    .shutdown = stream_shutdown,
    .release = stream_release,
};

static void ssh_cmd_evt(const mp_session_t *sess, const char *proto,
                        const char *cmd)
{
    mp_evt_t e;
    mp_evt_begin(&e, sess, proto ? proto : "ssh", "ssh.command");
    mp_evt_str(&e, "cmd", cmd);
    mp_evt_send(&e);
}

/* ----------------------------------------------------------- connection */

static void sshd_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    mp_service_t *svc = (mp_service_t *)arg;
    const mp_sshd_behavior_t *beh =
        svc->brand ? mp_brand_behavior(svc->brand, "sshd") : NULL;
    if (!beh || !s_ctx) {
        return;
    }

    sshd_conn_t c = {
        .beh = beh,
        .conn = conn,
        .sess = *sess,
    };

    mp_evt_t e;
    mp_evt_begin(&e, sess, "ssh", "ssh.connect");
    mp_evt_send(&e);

    const char *reason = "closed";
    WOLFSSH *ssh = wolfSSH_new(s_ctx);
    if (!ssh) {
        ESP_LOGE(TAG, "wolfSSH_new failed");
        return;
    }
    wolfSSH_SetIOReadCtx(ssh, &c);
    wolfSSH_SetIOWriteCtx(ssh, &c);
    wolfSSH_SetUserAuthCtx(ssh, &c);

    /* Handshake, bounded: idle scanners must not pin the session. */
    int64_t deadline = esp_timer_get_time() / 1000 +
                       (beh->handshake_timeout_ms ? beh->handshake_timeout_ms
                                                  : 30000);
    int ret;
    do {
        ret = wolfSSH_accept(ssh);
        if (ret == WS_SUCCESS) {
            break;
        }
        int err = wolfSSH_get_error(ssh);
        if (err != WS_WANT_READ && err != WS_WANT_WRITE) {
            reason = (err == WS_USER_AUTH_E) ? "auth_failed" : "error";
            break;
        }
        if (esp_timer_get_time() / 1000 >= deadline) {
            reason = "timeout";
            break;
        }
    } while (ret != WS_SUCCESS);

    if (ret == WS_SUCCESS && beh->shell) {
        mp_shell_cfg_t sc = *beh->shell;
        if (!sc.on_cmd) {
            sc.on_cmd = ssh_cmd_evt;
        }
        stream_t st = { .ssh = ssh };
        mp_conn_t shim = { .ops = &s_stream_ops, .ctx = &st };
        mp_shell_exit_t r = mp_shell_run(&shim, &sc, sess);
        reason = (r == MP_SHELL_LOGOUT) ? "logout"
               : (r == MP_SHELL_REBOOT) ? "reboot"
               : (r == MP_SHELL_TIMEOUT) ? "timeout"
               : (r == MP_SHELL_CLOSED) ? "closed" : "error";
    }

    wolfSSH_free(ssh);

    int64_t dur = (esp_timer_get_time() - sess->start_us) / 1000;
    mp_evt_begin(&e, sess, "ssh", "ssh.disconnect");
    mp_evt_int(&e, "dur_ms", (long long)dur);
    mp_evt_str(&e, "reason", reason);
    mp_evt_int(&e, "auth_attempts", c.attempts);
    mp_evt_send(&e);
}

/* -------------------------------------------------------------- lifecycle */

static mp_listener_cfg_t s_listener;

static esp_err_t sshd_start(mp_service_t *svc)
{
    const mp_sshd_behavior_t *beh =
        svc->brand ? mp_brand_behavior(svc->brand, "sshd") : NULL;
    if (!beh) {
        ESP_LOGE(TAG, "brand '%s' has no sshd behaviour",
                 svc->brand ? svc->brand->meta->id : "(null)");
        return ESP_ERR_NOT_SUPPORTED;
    }

    if (!s_ctx) {
        s_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
        if (!s_ctx) {
            return ESP_FAIL;
        }
        /* upstream OpenSSH version string, no distro suffix */
        wolfSSH_CTX_SetSshProtoIdStr(s_ctx,
            beh->proto_id ? beh->proto_id : "SSH-2.0-OpenSSH_7.9p1");
        wolfSSH_SetUserAuth(s_ctx, ws_user_auth);
        wolfSSH_SetIORecv(s_ctx, ws_io_recv);
        wolfSSH_SetIOSend(s_ctx, ws_io_send);

        size_t key_len = (size_t)(ssh_host_ecdsa_key_der_end -
                                  ssh_host_ecdsa_key_der_start);
        if (wolfSSH_CTX_UsePrivateKey_buffer(s_ctx, ssh_host_ecdsa_key_der_start,
                                             (word32)key_len,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
            ESP_LOGE(TAG, "failed to load host key");
            wolfSSH_CTX_free(s_ctx);
            s_ctx = NULL;
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "wolfSSH server ready (%s)", beh->proto_id);
    }

    memset(&s_listener, 0, sizeof(s_listener));
    s_listener.vaddr = svc->bind.vaddr;
    s_listener.port = svc->bind.port;
    s_listener.name = "sshd";
    s_listener.handler = sshd_conn;
    s_listener.arg = svc;
    s_listener.stack_size = SSHD_TASK_STACK;
    return mp_xport_listen(&s_listener);
}

static const mp_service_ops_t s_ops = {
    .name = "sshd",
    .proto = MP_PROTO_TCP,
    .default_port = 22,
    .start = sshd_start,
    .stop = NULL,
};

const mp_service_ops_t *mp_sshd_get_ops(void)
{
    return &s_ops;
}
