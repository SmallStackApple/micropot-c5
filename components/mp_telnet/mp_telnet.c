/*
 * Brand-agnostic Telnet honeypot: login flow, shell loop and Telnet
 * negotiation are interpreted from the brand's behaviour table. All socket
 * mechanics come from mp_linekit.
 */
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "mp_core.h"
#include "mp_linekit.h"
#include "mp_log.h"
#include "mp_telnet.h"
#include "mp_telnet_behavior.h"

static const char *TAG = "mp_telnet";

#define TELNET_IAC 255

#define LOGIN_TIMEOUT_MS   60000
#define SHELL_TIMEOUT_MS   120000
#define REBOOT_LINGER_MS   1000

static mp_listener_cfg_t s_listener;

/* --------------------------------------------------------- session logic */

static bool is_exit_cmd(const char *cmd)
{
    return strcmp(cmd, "exit") == 0 || strcmp(cmd, "logout") == 0 ||
           strcmp(cmd, "quit") == 0;
}

static bool is_reboot_cmd(const char *cmd)
{
    return strcmp(cmd, "reboot") == 0 || strcmp(cmd, "shutdown") == 0 ||
           strcmp(cmd, "poweroff") == 0;
}

/** Resolve a command line to a reply, brand hook first then the table.
 *  NULL when the command is unknown. */
static const char *find_response(const mp_telnet_behavior_t *b,
                                 const mp_session_t *sess, const char *cmdline,
                                 char *out, size_t out_len)
{
    if (b->exec) {
        const char *r = b->exec(sess, cmdline, out, out_len);
        if (r) {
            return r;
        }
    }
    const mp_cmd_t *c = mp_cmd_lookup(b->cmds, b->n_cmds, cmdline);
    return c ? c->response : NULL;
}

static void telnet_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    mp_service_t *svc = (mp_service_t *)arg;
    const mp_telnet_behavior_t *b =
        svc->brand ? mp_brand_behavior(svc->brand, "telnet") : NULL;
    if (!b) {
        return;
    }

    mp_log_telnet_connect(sess);

    /* BSD/inetutils telnetd opens with option REQUESTS and then waits
     * for the answers before printing anything (its negotiation timer
     * outlasts a silent peer). This exact 12-byte burst, anchored, is
     * what nmap's service DB calls "Linux telnetd" — our old greeting
     * (WILL ECHO, WILL SGA, then straight into the banner) anchored to
     * "Pocket CMD telnetd" instead. */
    const unsigned char init[] = {
        TELNET_IAC, 253, 24, /* DO TERMINAL-TYPE */
        TELNET_IAC, 253, 32, /* DO TSPEED */
        TELNET_IAC, 253, 35, /* DO XDISPLOC */
        TELNET_IAC, 253, 39, /* DO NEW-ENVIRON */
    };
    mp_send_all(conn, init, sizeof(init));
    {
        /* Drain the client's WILL/DO answers: a real client replies in
         * one segment within ms; a silent peer (nmap's NULL probe) hits
         * the negotiation timer, like against stock telnetd. */
        unsigned char junk[96];
        int r = mp_conn_recv(conn, junk, sizeof(junk), 10000);
        while (r > 0) {
            r = mp_conn_recv(conn, junk, sizeof(junk), 200);
        }
    }

    /* IAC WILL ECHO, IAC WILL SUPPRESS-GO-AHEAD */
    const unsigned char will[] = { TELNET_IAC, 251, 1, TELNET_IAC, 251, 3 };
    mp_send_all(conn, will, sizeof(will));

    if (b->banner) {
        mp_send_str(conn, b->banner);
        mp_send_str(conn, "\r\n");
    }

    const char *reason = "auth_failed";
    char        user[64] = { 0 };
    char        pass[64] = { 0 };
    bool        authed = false;
    int         attempt = 0;
    int         max_attempts = b->max_retries ? b->max_retries : 3;

    while (attempt < max_attempts) {
        /* busybox behaviour: username is echoed, the password is not */
        if (mp_send_str(conn, b->login_prompt) < 0) {
            reason = "send_error";
            goto done;
        }
        int n = mp_line_read(conn, user, sizeof(user), LOGIN_TIMEOUT_MS,
                             true, MP_LINE_ECHO_ON);
        if (n < 0) {
            reason = (n == -2) ? "timeout" : "closed";
            goto done;
        }
        if (mp_send_str(conn, b->password_prompt) < 0) {
            reason = "send_error";
            goto done;
        }
        n = mp_line_read(conn, pass, sizeof(pass), LOGIN_TIMEOUT_MS,
                         true, MP_LINE_ECHO_OFF);
        if (n < 0) {
            reason = (n == -2) ? "timeout" : "closed";
            goto done;
        }
        mp_send_str(conn, "\r\n");

        attempt++;
        authed = mp_creds_match(b->creds, b->n_creds, user, pass);
        mp_log_telnet_login(sess, user, pass, authed, attempt);
        if (authed) {
            break;
        }
        mp_send_str(conn, b->login_failed);
        mp_send_str(conn, "\r\n");
    }

    if (!authed) {
        reason = "auth_failed";
        goto done;
    }

    /* brand-provided interactive shell (Linux persona) takes over */
    if (b->shell) {
        reason = b->shell(conn, sess, b->shell_ctx, user, "telnet");
        goto done;
    }

    reason = "closed";
    char cmd[128];
    for (;;) {
        if (mp_send_str(conn, b->shell_prompt) < 0) {
            reason = "send_error";
            break;
        }
        int n = mp_line_read(conn, cmd, sizeof(cmd), SHELL_TIMEOUT_MS,
                             true, MP_LINE_ECHO_ON);
        if (n < 0) {
            reason = (n == -2) ? "timeout" : "closed";
            break;
        }
        if (n == 0) {
            continue;
        }
        mp_log_telnet_command(sess, cmd);
        if (is_exit_cmd(cmd)) {
            reason = "logout";
            break;
        }
        char out[512];
        const char *resp = find_response(b, sess, cmd, out, sizeof(out));
        bool known = resp != NULL;
        if (!known) {
            snprintf(out, sizeof(out), "sh: %s: not found", cmd);
            resp = out;
        }
        if (mp_send_str(conn, resp) < 0 || mp_send_str(conn, "\r\n") < 0) {
            reason = "send_error";
            break;
        }
        if (known && is_reboot_cmd(cmd)) {
            /* sell the reboot: linger briefly, then drop the session */
            vTaskDelay(pdMS_TO_TICKS(REBOOT_LINGER_MS));
            reason = "reboot";
            break;
        }
    }

done:
    {
        int64_t dur = (esp_timer_get_time() - sess->start_us) / 1000;
        mp_log_telnet_disconnect(sess, dur, reason);
    }
}

/* -------------------------------------------------------------- lifecycle */

static esp_err_t telnet_start(mp_service_t *svc)
{
    if (!svc->brand || !mp_brand_behavior(svc->brand, "telnet")) {
        ESP_LOGE(TAG, "brand '%s' has no telnet behaviour",
                 svc->brand ? svc->brand->meta->id : "(null)");
        return ESP_ERR_NOT_SUPPORTED;
    }
    memset(&s_listener, 0, sizeof(s_listener));
    s_listener.vaddr = svc->bind.vaddr;
    s_listener.port = svc->bind.port;
    s_listener.name = "telnet";
    s_listener.persona = svc->persona ? svc->persona->id : NULL;
    s_listener.handler = telnet_conn;
    s_listener.arg = svc;
    return mp_xport_listen(&s_listener);
}

static const mp_service_ops_t s_ops = {
    .name = "telnet",
    .proto = MP_PROTO_TCP,
    .default_port = 23,
    .start = telnet_start,
    .stop = NULL,
};

const mp_service_ops_t *mp_telnet_get_ops(void)
{
    return &s_ops;
}
