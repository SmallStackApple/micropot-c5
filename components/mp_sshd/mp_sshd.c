/*
 * OpenSSH-style SSH honeypot with real SSH-2.0 transport (wolfSSH).
 *
 * Unlike the old canned-banner service this runs a genuine key exchange,
 * so ssh clients, hydra and nmap's ssh2-enum-algos all see a real server:
 *  - protocol id / KEXINIT proposal lists trimmed from OpenSSH 7.9p1
 *    (myproposal.h, tag V_7_9_P1) down to what wolfSSL implements
 *    (chacha20-poly1305, umac, curve25519@libssh.org, group18 dropped —
 *    indistinguishable from a hardened sshd_config)
 *  - stable RSA + ECDSA host keys (brand data) like a real installed host
 *  - password attempts are captured as ssh.auth_attempt events; valid
 *    credentials open the same interactive shell as telnet, channel data
 *    piped through an mp_conn shim over wolfSSH_read/write
 */
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"

#include <wolfssl/ssl.h>
#include <wolfssh/ssh.h>

#include "mp_core.h"
#include "mp_log.h"
#include "mp_sshd.h"
#include "mp_sshd_behavior.h"

static const char *TAG = "mp_sshd";

/* wolfSSL's ESP user_settings.h delegates the RNG seed to us
 * (CUSTOM_RAND_GENERATE_SEED): feed it the C5 hardware entropy source. */
int mp_wolfssl_rand_seed(unsigned char *output, unsigned int sz)
{
    esp_fill_random(output, sz);
    return 0;
}

#define IO_RECV_TIMEOUT_MS 30000
#define PREAUTH_GRACE_MS   120000 /* OpenSSH LoginGraceTime default */
#define SHELL_BUF          512

/* OpenSSH 7.9p1 proposal lists minus what wolfSSL cannot implement.
 * Client-side first-match negotiation lands on curve25519-sha256 /
 * aes128-ctr / hmac-sha2-256 with stock OpenSSH clients. */
static const char s_kex_list[] =
    "curve25519-sha256,"
    "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
    "diffie-hellman-group-exchange-sha256,"
    "diffie-hellman-group16-sha512,"
    "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1";
static const char s_cipher_list[] =
    "aes128-ctr,aes192-ctr,aes256-ctr,"
    "aes128-gcm@openssh.com,aes256-gcm@openssh.com";
static const char s_mac_list[] =
    "hmac-sha2-256,hmac-sha2-512,hmac-sha1";
static const char s_key_list[] =
    "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256";

static mp_listener_cfg_t s_listener;
static WOLFSSH_CTX *s_ctx;

/* -------------------------------------------------------- per-connection */

typedef struct {
    mp_conn_t *raw;                    /* transport connection */
    const mp_session_t *sess;
    const mp_sshd_behavior_t *b;
    WOLFSSH *ssh;
    char user[64];
} sshd_conn_t;

/* ---------------------------------------------------------- IO callbacks */

static int io_recv(WOLFSSH *ssh, void *buf, word32 sz, void *ctx)
{
    (void)ssh;
    sshd_conn_t *c = (sshd_conn_t *)ctx;
    int r = mp_conn_recv(c->raw, buf, sz, IO_RECV_TIMEOUT_MS);
    if (r > 0) {
        return r;
    }
    if (r == MP_CONN_TIMEOUT) {
        return WS_CBIO_ERR_WANT_READ;
    }
    if (r == MP_CONN_ABORTED) {
        return WS_CBIO_ERR_CONN_RST;
    }
    return WS_CBIO_ERR_CONN_CLOSE;
}

static int io_send(WOLFSSH *ssh, void *buf, word32 sz, void *ctx)
{
    (void)ssh;
    sshd_conn_t *c = (sshd_conn_t *)ctx;
    return mp_conn_send(c->raw, buf, sz) == 0 ? (int)sz : WS_CBIO_ERR_CONN_RST;
}

/* ------------------------------------------------------------ user auth */

static int user_auth(byte type, WS_UserAuthData *data, void *vctx)
{
    sshd_conn_t *c = (sshd_conn_t *)vctx;
    char user[64], pass[64];

    size_t usz = data->usernameSz < sizeof(user) - 1 ? data->usernameSz
                                                     : sizeof(user) - 1;
    memcpy(user, data->username, usz);
    user[usz] = '\0';

    if (type != WOLFSSH_USERAUTH_PASSWORD) {
        /* pubkey probes get a plain failure, like a PasswordAuthentication-
         * only server; the offered key type is still worth logging */
        mp_evt_t e;
        mp_evt_begin(&e, c->sess, "ssh", "ssh.auth_attempt");
        mp_evt_str(&e, "user", user);
        mp_evt_str(&e, "method", "publickey");
        mp_evt_str(&e, "result", "fail");
        mp_evt_send(&e);
        return WOLFSSH_USERAUTH_FAILURE;
    }

    size_t psz = data->sf.password.passwordSz < sizeof(pass) - 1
                     ? data->sf.password.passwordSz : sizeof(pass) - 1;
    memcpy(pass, data->sf.password.password, psz);
    pass[psz] = '\0';

    bool ok = mp_creds_match(c->b->creds, c->b->n_creds, user, pass);

    mp_evt_t e;
    mp_evt_begin(&e, c->sess, "ssh", "ssh.auth_attempt");
    mp_evt_str(&e, "user", user);
    mp_evt_str(&e, "pass", pass);
    mp_evt_str(&e, "result", ok ? "success" : "fail");
    mp_evt_send(&e);

    if (ok) {
        snprintf(c->user, sizeof(c->user), "%s", user);
        return WOLFSSH_USERAUTH_SUCCESS;
    }
    return WOLFSSH_USERAUTH_FAILURE;
}

/* ------------------------------------------- channel data as mp_conn_t */

typedef struct {
    sshd_conn_t *c;
    bool released;
} shim_t;

static int shim_recv(mp_conn_t *conn, void *buf, size_t cap, uint32_t timeout_ms)
{
    shim_t *sh = (shim_t *)conn->ctx;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    for (;;) {
        int r = wolfSSH_stream_read(sh->c->ssh, buf, (word32)cap);
        if (r > 0) {
            return r;
        }
        int err = wolfSSH_get_error(sh->c->ssh);
        if (err == WS_WANT_READ || err == WS_WANT_WRITE) {
            if (timeout_ms == 0 || esp_timer_get_time() >= deadline) {
                return MP_CONN_TIMEOUT;
            }
            continue; /* IORecv enforces its own pacing */
        }
        if (err == WS_CHANNEL_CLOSED || err == WS_EOF) {
            return 0;
        }
        return MP_CONN_ABORTED;
    }
}

static int shim_send(mp_conn_t *conn, const void *data, size_t len)
{
    shim_t *sh = (shim_t *)conn->ctx;
    const uint8_t *p = (const uint8_t *)data;
    while (len) {
        int r = wolfSSH_stream_send(sh->c->ssh, (void *)p, (word32)len);
        if (r > 0) {
            p += r;
            len -= (size_t)r;
            continue;
        }
        int err = wolfSSH_get_error(sh->c->ssh);
        if (err == WS_WANT_READ || err == WS_WANT_WRITE) {
            continue;
        }
        return -1;
    }
    return 0;
}

static void shim_shutdown(mp_conn_t *conn)
{
    shim_t *sh = (shim_t *)conn->ctx;
    wolfSSH_shutdown(sh->c->ssh);
}

static void shim_release(mp_conn_t *conn)
{
    shim_t *sh = (shim_t *)conn->ctx;
    sh->released = true; /* ssh itself is freed by the service task */
}

static const mp_conn_ops_t s_shim_ops = {
    .recv = shim_recv,
    .send = shim_send,
    .shutdown = shim_shutdown,
    .release = shim_release,
};

static void log_evt(const mp_session_t *sess, const char *evt,
                    const char *key, const char *val)
{
    mp_evt_t e;
    mp_evt_begin(&e, sess, "ssh", evt);
    if (key && val) {
        mp_evt_str(&e, key, val);
    }
    mp_evt_send(&e);
}

/* ------------------------------------------------------------ connection */

static void sshd_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    mp_service_t *svc = (mp_service_t *)arg;
    const mp_sshd_behavior_t *b =
        svc->brand ? mp_brand_behavior(svc->brand, "sshd") : NULL;
    if (!b) {
        return;
    }

    log_evt(sess, "ssh.connect", NULL, NULL);

    sshd_conn_t c = {
        .raw = conn,
        .sess = sess,
        .b = b,
        .ssh = NULL,
    };

    c.ssh = wolfSSH_new(s_ctx);
    if (!c.ssh) {
        ESP_LOGE(TAG, "wolfSSH_new failed");
        goto done;
    }
    wolfSSH_SetIOReadCtx(c.ssh, &c);
    wolfSSH_SetIOWriteCtx(c.ssh, &c);
    wolfSSH_SetUserAuthCtx(c.ssh, &c);

    /* key exchange + user auth, with OpenSSH's LoginGraceTime pacing */
    {
        int64_t deadline = esp_timer_get_time() +
                           (int64_t)PREAUTH_GRACE_MS * 1000;
        int r;
        for (;;) {
            r = wolfSSH_accept(c.ssh);
            if (r == WS_SUCCESS) {
                break;
            }
            int err = wolfSSH_get_error(c.ssh);
            if (err == WS_WANT_READ || err == WS_WANT_WRITE) {
                if (esp_timer_get_time() >= deadline) {
                    ESP_LOGD(TAG, "login grace time expired");
                    goto done;
                }
                continue;
            }
            ESP_LOGD(TAG, "accept failed: %d", err);
            goto done; /* auth exhausted / protocol error / peer gone */
        }
    }

    log_evt(sess, "ssh.login", "user", c.user);

    /* authenticated: run the brand shell over the channel */
    if (b->shell) {
        shim_t shim = { .c = &c, .released = false };
        mp_conn_t shim_conn = {
            .ops = &s_shim_ops,
            .ctx = &shim,
        };
        const char *reason = b->shell(&shim_conn, sess, b->shell_ctx,
                                      c.user, "ssh");
        log_evt(sess, "ssh.disconnect", "reason", reason);
    }

done:
    if (c.ssh) {
        wolfSSH_free(c.ssh);
    }
}

/* ------------------------------------------------------------- lifecycle */

static esp_err_t sshd_start(mp_service_t *svc)
{
    const mp_sshd_behavior_t *b =
        svc->brand ? mp_brand_behavior(svc->brand, "sshd") : NULL;
    if (!b || !b->banner) {
        ESP_LOGE(TAG, "brand '%s' has no sshd behaviour",
                 svc->brand ? svc->brand->meta->id : "(null)");
        return ESP_ERR_NOT_SUPPORTED;
    }

    if (!s_ctx) {
        if (wolfSSH_Init() != WS_SUCCESS) {
            ESP_LOGE(TAG, "wolfSSH_Init failed");
            return ESP_FAIL;
        }
        wolfSSH_Debugging_ON(); /* no-op unless built with WOLFSSH_DEBUG */
        s_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
        if (!s_ctx) {
            ESP_LOGE(TAG, "wolfSSH_CTX_new failed");
            return ESP_ERR_NO_MEM;
        }

        char proto_id[64];
        snprintf(proto_id, sizeof(proto_id), "%s\r\n", b->banner);
        /* ctx keeps the pointer: stash it in static storage per banner */
        static char s_proto_id[64];
        snprintf(s_proto_id, sizeof(s_proto_id), "%s", proto_id);
        wolfSSH_CTX_SetSshProtoIdStr(s_ctx, s_proto_id);

        wolfSSH_CTX_SetAlgoListKex(s_ctx, s_kex_list);
        wolfSSH_CTX_SetAlgoListCipher(s_ctx, s_cipher_list);
        wolfSSH_CTX_SetAlgoListMac(s_ctx, s_mac_list);
        wolfSSH_CTX_SetAlgoListKey(s_ctx, s_key_list);
        wolfSSH_CTX_SetAlgoListKeyAccepted(s_ctx, s_key_list);

        wolfSSH_SetIORecv(s_ctx, io_recv);
        wolfSSH_SetIOSend(s_ctx, io_send);
        wolfSSH_SetUserAuth(s_ctx, user_auth);

        if (b->key_rsa) {
            int ret = wolfSSH_CTX_UsePrivateKey_buffer(s_ctx, b->key_rsa,
                                                       b->key_rsa_len,
                                                       WOLFSSH_FORMAT_ASN1);
            if (ret != WS_SUCCESS) {
                ESP_LOGE(TAG, "RSA host key rejected (%d)", ret);
            }
        }
        if (b->key_ecdsa) {
            int ret = wolfSSH_CTX_UsePrivateKey_buffer(s_ctx, b->key_ecdsa,
                                                       b->key_ecdsa_len,
                                                       WOLFSSH_FORMAT_ASN1);
            if (ret != WS_SUCCESS) {
                ESP_LOGE(TAG, "ECDSA host key rejected (%d)", ret);
            }
        }
    }

    memset(&s_listener, 0, sizeof(s_listener));
    s_listener.vaddr = svc->bind.vaddr;
    s_listener.port = svc->bind.port;
    s_listener.name = "sshd";
    s_listener.handler = sshd_conn;
    s_listener.arg = svc;
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
