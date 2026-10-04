/*
 * vsftpd 3.0.3 style FTP honeypot on mp_xport.
 *
 * Control channel: greeting and reply codes follow ftpcodes.h of the real
 * 3.0.3 tree; unknown input gets a plain "500 Unknown command." like the
 * original's permissive parser. Credentials are captured; passive mode is
 * served from one fixed data port (enough for scanners and lftp).
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "mp_core.h"
#include "mp_linekit.h"
#include "mp_linuxfs.h"
#include "mp_log.h"
#include "mp_net.h"

#include "mp_ftpd.h"
#include "mp_ftpd_behavior.h"

static const char *TAG = "mp_ftpd";

#define FTP_TASK_STACK 4096
#define FTP_LINE_MAX   512
#define FTP_LIST_MAX   2048

static mp_listener_cfg_t s_ctrl_listener;

/* Listing handed from the control channel to the passive data listener. */
static char   s_listing[FTP_LIST_MAX];
static size_t s_listing_len;
static bool   s_listing_ready;

/* ---------------------------------------------------------- data channel */

static void ftp_data_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    (void)sess;
    (void)arg;
    if (s_listing_ready && s_listing_len) {
        mp_conn_send(conn, s_listing, s_listing_len);
    }
    s_listing_ready = false;
}

/* Build a Unix `ls -l` style listing of the behaviour's root directory. */
static void build_listing(const mp_ftpd_behavior_t *beh)
{
    s_listing_len = 0;
    s_listing[0] = '\0';

    const mp_lfs_t *fs = mp_lfs_active();
    if (!fs) {
        s_listing_len = 0;
        s_listing_ready = true;
        return;
    }
    const char *root = beh->root ? beh->root : "/";

    struct { char *out; size_t cap, len; } w = { s_listing, sizeof(s_listing), 0 };
    /* one-line-per-entry long listing, vsftpd sends CRLF */
    for (size_t i = 0; i < fs->n; i++) {
        const mp_lfs_node_t *n = &fs->nodes[i];
        if (!n->path || strcmp(n->path, root) == 0) {
            continue;
        }
        size_t rl = strlen(root);
        bool child = false;
        if (strcmp(root, "/") == 0) {
            child = n->path[0] == '/' && !strchr(n->path + 1, '/');
        } else {
            child = strncmp(n->path, root, rl) == 0 && n->path[rl] == '/' &&
                    !strchr(n->path + rl + 1, '/');
        }
        if (!child) {
            continue;
        }
        const char *name = strrchr(n->path, '/');
        name = name ? name + 1 : n->path;
        char perms[11] = "-rw-r--r--";
        perms[0] = n->kind == MP_LFS_DIR ? 'd' : '-';
        char line[128];
        int ln = snprintf(line, sizeof(line),
                          "%s    1 %-8s %-8s %8u Oct  1 09:00 %s\r\n",
                          perms, n->owner ? n->owner : "root",
                          n->group ? n->group : "root",
                          n->kind == MP_LFS_DIR ? 4096u
                                                : (unsigned)(n->content ? strlen(n->content) : 0),
                          name);
        if (ln > 0 && w.len + (size_t)ln < w.cap) {
            memcpy(w.out + w.len, line, (size_t)ln);
            w.len += (size_t)ln;
        }
    }
    s_listing_len = w.len;
    s_listing_ready = true;
}

/* -------------------------------------------------------- control channel */

static void ftp_reply(mp_conn_t *c, const char *fmt, ...)
{
    char buf[320];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
        mp_send_all(c, buf, (size_t)n);
    }
}

static void ftp_ctrl_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    mp_service_t *svc = (mp_service_t *)arg;
    const mp_ftpd_behavior_t *beh =
        svc->brand ? mp_brand_behavior(svc->brand, "ftpd") : NULL;
    if (!beh) {
        return;
    }

    mp_evt_t e;
    mp_evt_begin(&e, sess, "ftp", "ftp.connect");
    mp_evt_send(&e);

    ftp_reply(conn, beh->banner ? beh->banner : "220 (vsFTPd 3.0.3)\r\n");

    char user[64] = { 0 };
    bool have_user = false;
    bool logged_in = false;
    char line[FTP_LINE_MAX];
    const char *reason = "closed";

    for (;;) {
        int n = mp_line_read(conn, line, sizeof(line), 120000, false,
                             MP_LINE_ECHO_OFF);
        if (n < 0) {
            reason = (n == -2) ? "timeout" : "closed";
            break;
        }
        if (n == 0) {
            continue;
        }

        /* split command / argument (vsftpd is case-insensitive on verbs) */
        char *arg = line;
        while (*arg && *arg != ' ') arg++;
        if (*arg) {
            *arg++ = '\0';
        }
        for (char *p = line; *p; p++) {
            if (*p >= 'a' && *p <= 'z') {
                *p -= 32;
            }
        }

        mp_evt_begin(&e, sess, "ftp", "ftp.command");
        mp_evt_str(&e, "cmd", line);
        if (arg[0]) {
            mp_evt_str(&e, "arg", arg);
        }
        mp_evt_send(&e);

        if (strcmp(line, "USER") == 0) {
            snprintf(user, sizeof(user), "%.63s", arg);
            have_user = true;
            ftp_reply(conn, "331 Please specify the password.\r\n");
        } else if (strcmp(line, "PASS") == 0) {
            bool ok = mp_creds_match(beh->creds, beh->n_creds,
                                     have_user ? user : "", arg);
            mp_log_ftp_login(sess, have_user ? user : "", arg, ok);
            if (ok) {
                logged_in = true;
                ftp_reply(conn, "230 Login successful.\r\n");
            } else {
                ftp_reply(conn, "530 Login incorrect.\r\n");
            }
        } else if (strcmp(line, "QUIT") == 0) {
            ftp_reply(conn, "221 Goodbye.\r\n");
            reason = "logout";
            break;
        } else if (strcmp(line, "FEAT") == 0) {
            ftp_reply(conn,
                "211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n"
                " SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n");
        } else if (strcmp(line, "SYST") == 0) {
            ftp_reply(conn, "215 UNIX Type: L8\r\n");
        } else if (strcmp(line, "NOOP") == 0) {
            ftp_reply(conn, "200 NOOP ok.\r\n");
        } else if (!logged_in) {
            ftp_reply(conn, "530 Please login with USER and PASS.\r\n");
        } else if (strcmp(line, "PWD") == 0 || strcmp(line, "XPWD") == 0) {
            ftp_reply(conn, "257 \"%s\"\r\n", beh->root ? beh->root : "/");
        } else if (strcmp(line, "TYPE") == 0) {
            ftp_reply(conn, "200 Switching to Binary mode.\r\n");
        } else if (strcmp(line, "CWD") == 0) {
            ftp_reply(conn, "250 Directory successfully changed.\r\n");
        } else if (strcmp(line, "PASV") == 0) {
            char ip[16];
            mp_net_get_ip_str(ip, sizeof(ip));
            unsigned a, b, c, d;
            if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
                a = b = c = d = 0;
            }
            uint16_t p = beh->data_port;
            build_listing(beh);
            ftp_reply(conn,
                "227 Entering Passive Mode (%u,%u,%u,%u,%u,%u).\r\n",
                a, b, c, d, (unsigned)(p >> 8), (unsigned)(p & 0xff));
        } else if (strcmp(line, "LIST") == 0 || strcmp(line, "NLST") == 0) {
            if (!s_listing_ready) {
                ftp_reply(conn, "425 Use PASV first.\r\n");
            } else {
                ftp_reply(conn, "150 Here comes the directory listing.\r\n");
                ftp_reply(conn, "226 Directory send OK.\r\n");
            }
        } else if (strcmp(line, "RETR") == 0) {
            ftp_reply(conn, "550 Failed to open file.\r\n");
        } else if (strcmp(line, "SIZE") == 0) {
            ftp_reply(conn, "550 Could not get file size.\r\n");
        } else if (strcmp(line, "OPTS") == 0) {
            ftp_reply(conn, "200 Always in UTF8 mode.\r\n");
        } else {
            ftp_reply(conn, "500 Unknown command.\r\n");
        }
    }

    int64_t dur = (esp_timer_get_time() - sess->start_us) / 1000;
    mp_evt_begin(&e, sess, "ftp", "ftp.disconnect");
    mp_evt_int(&e, "dur_ms", (long long)dur);
    mp_evt_str(&e, "reason", reason);
    mp_evt_send(&e);
}

/* -------------------------------------------------------------- lifecycle */

static mp_listener_cfg_t s_data_listener;

static esp_err_t ftpd_start(mp_service_t *svc)
{
    const mp_ftpd_behavior_t *beh =
        svc->brand ? mp_brand_behavior(svc->brand, "ftpd") : NULL;
    if (!beh) {
        ESP_LOGE(TAG, "brand '%s' has no ftpd behaviour",
                 svc->brand ? svc->brand->meta->id : "(null)");
        return ESP_ERR_NOT_SUPPORTED;
    }

    /* passive data listener (one fixed port: honeypot-grade simplicity) */
    if (beh->data_port) {
        memset(&s_data_listener, 0, sizeof(s_data_listener));
        s_data_listener.port = beh->data_port;
        s_data_listener.name = "ftp-data";
        s_data_listener.handler = ftp_data_conn;
        s_data_listener.arg = svc;
        s_data_listener.stack_size = FTP_TASK_STACK;
        if (mp_xport_listen(&s_data_listener) != ESP_OK) {
            ESP_LOGW(TAG, "passive data port %u unavailable", beh->data_port);
        }
    }

    memset(&s_ctrl_listener, 0, sizeof(s_ctrl_listener));
    s_ctrl_listener.vaddr = svc->bind.vaddr;
    s_ctrl_listener.port = svc->bind.port;
    s_ctrl_listener.name = "ftpd";
    s_ctrl_listener.handler = ftp_ctrl_conn;
    s_ctrl_listener.arg = svc;
    s_ctrl_listener.stack_size = FTP_TASK_STACK;
    return mp_xport_listen(&s_ctrl_listener);
}

static const mp_service_ops_t s_ops = {
    .name = "ftpd",
    .proto = MP_PROTO_TCP,
    .default_port = 21,
    .start = ftpd_start,
    .stop = NULL,
};

const mp_service_ops_t *mp_ftpd_get_ops(void)
{
    return &s_ops;
}
