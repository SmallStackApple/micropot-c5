/*
 * vsftpd-style FTP honeypot (3.0.3 protocol behaviour).
 *
 * Reply texts and sequencing follow ~/vsftpd-3.0.3 (prelogin.c /
 * postlogin.c / features.c): 220 greeting, USER/PASS flow, FEAT list,
 * SYST, PWD/CWD over the persona's fake filesystem, PASV data channel
 * served through a small pool of pre-registered listeners, read-only
 * RETR/LIST and 550 for writes. Past max_clients control sessions the
 * server answers 421 like a saturated vsftpd (CVE-2021-30047's
 * connection-limit DoS signature, reproduced without the crash).
 *
 * Events: ftp.login_attempt, ftp.command, ftp.download, ftp.disconnect.
 */
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"

#include "mp_core.h"
#include "mp_ftpd.h"
#include "mp_ftpd_behavior.h"
#include "mp_linekit.h"
#include "mp_log.h"

static const char *TAG = "mp_ftpd";

#define CTRL_TIMEOUT_MS  300000 /* vsftpd idle_session_timeout default */
#define PASV_SLOTS       4
#define PASV_PORT_BASE   40021
#define PASV_WAIT_MS     60000
#define FTP_LINE_MAX     512

/* --------------------------------------------------------- PASV pool ---- */

typedef struct {
    SemaphoreHandle_t conn_ready; /* data task -> control: conn arrived */
    SemaphoreHandle_t xfr_done;   /* control -> data task: release conn */
    mp_conn_t *conn;
    const mp_session_t *sess;
    bool in_use;
} pasv_slot_t;

static pasv_slot_t s_pasv[PASV_SLOTS];
static mp_listener_cfg_t s_pasv_listeners[PASV_SLOTS];
static mp_listener_cfg_t s_listener;
static uint8_t s_active; /* control sessions (421 past max_clients) */
/* per-source-IP session counts (421 past max_per_ip); the table can never
 * outgrow the global session budget, so a fixed small array suffices */
#define PERIP_SLOTS 8
static struct { uint32_t ip; uint8_t n; } s_perip[PERIP_SLOTS];
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

/* found: slot index; new IP with room: -(slot)-1; table full: -100
 * (only reachable if max_clients >= PERIP_SLOTS, which the brand
 * values below the session budget prevent) */
static int perip_find(uint32_t ip)
{
    int empty = -1;
    for (int i = 0; i < PERIP_SLOTS; i++) {
        if (s_perip[i].n && s_perip[i].ip == ip) {
            return i;
        }
        if (!s_perip[i].n && empty < 0) {
            empty = i;
        }
    }
    return empty >= 0 ? -1 - empty : -100;
}

/* Returns: 0 admit, 1 refuse (global), 2 refuse (per-ip). Caller holds
 * no lock; on 0 the counters are already claimed. */
static int limit_admit(const mp_ftpd_behavior_t *b, uint32_t ip)
{
    int ret = 0;
    portENTER_CRITICAL(&s_lock);
    if (s_active >= b->max_clients) {
        ret = 1; /* vsftpd checks max_clients first (prelogin.c) */
    } else {
        int i = perip_find(ip);
        if (i >= 0 && s_perip[i].n >= b->max_per_ip) {
            ret = 2;
        } else {
            if (i < 0 && i != -100) {
                i = -i - 1;
                s_perip[i].ip = ip;
                s_perip[i].n = 0;
            }
            if (i >= 0) {
                s_perip[i].n++;
            }
            s_active++;
        }
    }
    portEXIT_CRITICAL(&s_lock);
    return ret;
}

static void limit_release(uint32_t ip)
{
    portENTER_CRITICAL(&s_lock);
    if (s_active) {
        s_active--;
    }
    int i = perip_find(ip);
    if (i >= 0 && s_perip[i].n) {
        s_perip[i].n--;
    }
    portEXIT_CRITICAL(&s_lock);
}

static void pasv_data_task(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    pasv_slot_t *slot = (pasv_slot_t *)arg;
    slot->conn = conn;
    slot->sess = sess;
    xSemaphoreGive(slot->conn_ready);
    /* the control task transfers over this conn; block until it is done
     * so the backend does not release the connection under our feet */
    xSemaphoreTake(slot->xfr_done, pdMS_TO_TICKS(CTRL_TIMEOUT_MS));
    slot->conn = NULL;
    slot->sess = NULL;
}

/** Claim a free PASV slot. @return slot index or -1. */
static int pasv_claim(void)
{
    int idx = -1;
    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < PASV_SLOTS; i++) {
        if (!s_pasv[i].in_use) {
            s_pasv[i].in_use = true;
            idx = i;
            break;
        }
    }
    portEXIT_CRITICAL(&s_lock);
    return idx;
}

static void pasv_release(int idx)
{
    portENTER_CRITICAL(&s_lock);
    s_pasv[idx].in_use = false;
    portEXIT_CRITICAL(&s_lock);
}

/* --------------------------------------------------------- session ---- */

typedef struct {
    mp_conn_t *conn;
    const mp_session_t *sess;
    const mp_ftpd_behavior_t *b;
    char cwd[128];
    char user[64];
    bool has_user;
    bool authed;
    int pasv; /* claimed slot index, -1 = none */
} ftp_t;

static int reply(ftp_t *f, int code, const char *msg)
{
    char buf[640];
    int n = snprintf(buf, sizeof(buf), "%d %s\r\n", code, msg);
    return mp_conn_send(f->conn, buf, (size_t)n);
}

static void log_cmd(const mp_session_t *sess, const char *cmd)
{
    mp_evt_t e;
    mp_evt_begin(&e, sess, "ftp", "ftp.command");
    mp_evt_str(&e, "cmd", cmd);
    mp_evt_send(&e);
}

/* ------------------------------------------------------ fs rendering ---- */

static bool resolve(ftp_t *f, const char *arg, char *out, size_t len)
{
    return mpfs_normalize(f->cwd, arg, out, len);
}

/* one "ls -l" style line, same rendering as the shell */
static void list_line(mp_conn_t *c, const mpfs_node_t *node, const char *name)
{
    char buf[256];
    uint32_t size = node->size;
    if (!size) {
        size = node->type == MPFS_DIR ? 4096
                                      : (uint32_t)strlen(node->content);
    }
    snprintf(buf, sizeof(buf), "%s 1 %s %s %6u %s %s\r\n",
             node->mode ? node->mode
                        : (node->type == MPFS_DIR ? "drwxr-xr-x" : "-rw-r--r--"),
             node->owner ? node->owner : "root",
             node->group ? node->group : "root",
             (unsigned)size,
             node->date ? node->date : "Oct  1 09:00",
             name);
    mp_conn_send(c, buf, strlen(buf));
}

/* ------------------------------------------------------- data channel ---- */

/** Wait for the peer's data connection on the claimed PASV slot.
 *  @return the data conn (owned by the slot) or NULL on timeout. */
static mp_conn_t *pasv_accept(ftp_t *f)
{
    if (f->pasv < 0) {
        return NULL;
    }
    pasv_slot_t *slot = &s_pasv[f->pasv];
    if (xSemaphoreTake(slot->conn_ready, pdMS_TO_TICKS(PASV_WAIT_MS)) != pdTRUE) {
        return NULL;
    }
    return slot->conn;
}

static void pasv_finish(ftp_t *f)
{
    if (f->pasv >= 0) {
        xSemaphoreGive(s_pasv[f->pasv].xfr_done);
        pasv_release(f->pasv);
        f->pasv = -1;
    }
}

/* ------------------------------------------------------------ commands ---- */

static void cmd_user(ftp_t *f, const char *arg)
{
    snprintf(f->user, sizeof(f->user), "%s", arg ? arg : "");
    f->has_user = true;
    reply(f, 331, "Please specify the password.");
}

static void cmd_pass(ftp_t *f, const char *arg)
{
    const char *pass = arg ? arg : "";
    bool ok = f->has_user &&
              mp_creds_match(f->b->creds, f->b->n_creds, f->user, pass);

    mp_evt_t e;
    mp_evt_begin(&e, f->sess, "ftp", "ftp.login_attempt");
    mp_evt_str(&e, "user", f->has_user ? f->user : "");
    mp_evt_str(&e, "pass", pass);
    mp_evt_str(&e, "result", ok ? "success" : "fail");
    mp_evt_send(&e);

    if (ok) {
        f->authed = true;
        reply(f, 230, "Login successful.");
    } else {
        reply(f, 530, "Login incorrect.");
    }
}

static void cmd_pasv(ftp_t *f)
{
    if (f->pasv < 0) {
        f->pasv = pasv_claim();
    }
    if (f->pasv < 0) {
        reply(f, 421, "Service not available, try later.");
        return;
    }
    unsigned o0 = (unsigned)(f->sess->dst_ip & 0xff);
    unsigned o1 = (unsigned)((f->sess->dst_ip >> 8) & 0xff);
    unsigned o2 = (unsigned)((f->sess->dst_ip >> 16) & 0xff);
    unsigned o3 = (unsigned)((f->sess->dst_ip >> 24) & 0xff);
    unsigned port = PASV_PORT_BASE + (unsigned)f->pasv;
    char msg[96];
    snprintf(msg, sizeof(msg), "Entering Passive Mode (%u,%u,%u,%u,%u,%u).",
             o0, o1, o2, o3, port >> 8, port & 0xff);
    reply(f, 227, msg);
}

static void cmd_list(ftp_t *f, const char *arg, bool names_only)
{
    char path[128];
    if (!resolve(f, arg && *arg ? arg : ".", path, sizeof(path))) {
        return;
    }
    const mpfs_node_t *node = mpfs_lookup(f->b->fs, f->b->fs_n, path);
    if (!node) {
        reply(f, 550, "Failed to open directory.");
        return;
    }

    mp_conn_t *data = pasv_accept(f);
    if (!data) {
        reply(f, 425, "Failed to establish connection.");
        pasv_finish(f);
        return;
    }
    reply(f, 150, "Here comes the directory listing.");

    if (node->type == MPFS_FILE) {
        if (names_only) {
            mp_conn_send(data, mpfs_basename(path), strlen(mpfs_basename(path)));
            mp_conn_send(data, "\r\n", 2);
        } else {
            list_line(data, node, mpfs_basename(path));
        }
    } else {
        const mpfs_node_t *kids[32];
        size_t n = mpfs_children(f->b->fs, f->b->fs_n, path, kids, 32);
        for (size_t i = 0; i < n; i++) {
            if (names_only) {
                mp_conn_send(data, mpfs_basename(kids[i]->path),
                             strlen(mpfs_basename(kids[i]->path)));
                mp_conn_send(data, "\r\n", 2);
            } else {
                list_line(data, kids[i], mpfs_basename(kids[i]->path));
            }
        }
    }
    mp_conn_shutdown(data);
    reply(f, 226, "Directory send OK.");
    pasv_finish(f);
}

static void cmd_retr(ftp_t *f, const char *arg)
{
    char path[128];
    if (!arg || !resolve(f, arg, path, sizeof(path))) {
        reply(f, 550, "Failed to open file.");
        return;
    }
    const mpfs_node_t *node = mpfs_lookup(f->b->fs, f->b->fs_n, path);
    if (!node || node->type != MPFS_FILE) {
        reply(f, 550, "Failed to open file.");
        return;
    }
    mp_conn_t *data = pasv_accept(f);
    if (!data) {
        reply(f, 425, "Failed to establish connection.");
        pasv_finish(f);
        return;
    }
    uint32_t size = node->size ? node->size : (uint32_t)strlen(node->content);
    char msg[192];
    snprintf(msg, sizeof(msg),
             "Opening BINARY mode data connection for %s (%u bytes).",
             path, (unsigned)size);
    reply(f, 150, msg);
    mp_conn_send(data, node->content, strlen(node->content));
    mp_conn_shutdown(data);
    reply(f, 226, "Transfer complete.");

    mp_evt_t e;
    mp_evt_begin(&e, f->sess, "ftp", "ftp.download");
    mp_evt_str(&e, "path", path);
    mp_evt_int(&e, "bytes", size);
    mp_evt_send(&e);

    pasv_finish(f);
}

static void cmd_size(ftp_t *f, const char *arg)
{
    char path[128];
    if (!arg || !resolve(f, arg, path, sizeof(path))) {
        reply(f, 550, "Could not get file size.");
        return;
    }
    const mpfs_node_t *node = mpfs_lookup(f->b->fs, f->b->fs_n, path);
    if (!node || node->type != MPFS_FILE) {
        reply(f, 550, "Could not get file size.");
        return;
    }
    char msg[32];
    snprintf(msg, sizeof(msg), "%u",
             (unsigned)(node->size ? node->size : strlen(node->content)));
    reply(f, 213, msg);
}

static void cmd_cwd(ftp_t *f, const char *arg)
{
    char path[128];
    if (!arg || !resolve(f, arg, path, sizeof(path))) {
        reply(f, 550, "Failed to change directory.");
        return;
    }
    const mpfs_node_t *node = mpfs_lookup(f->b->fs, f->b->fs_n, path);
    if (!node || node->type != MPFS_DIR) {
        reply(f, 550, "Failed to change directory.");
        return;
    }
    snprintf(f->cwd, sizeof(f->cwd), "%s", path);
    reply(f, 250, "Directory successfully changed.");
}

static void cmd_pwd(ftp_t *f)
{
    char msg[160];
    snprintf(msg, sizeof(msg), "\"%s\" is the current directory", f->cwd);
    reply(f, 257, msg);
}

/* -------------------------------------------------------------- dispatch */

/* commands allowed before login (vsftpd prelogin.c) */
static bool prelogin_cmd(const char *cmd)
{
    return strcasecmp(cmd, "USER") == 0 || strcasecmp(cmd, "PASS") == 0 ||
           strcasecmp(cmd, "QUIT") == 0 || strcasecmp(cmd, "FEAT") == 0 ||
           strcasecmp(cmd, "SYST") == 0 || strcasecmp(cmd, "NOOP") == 0 ||
           strcasecmp(cmd, "HELP") == 0;
}

/** @return false when the session should end. */
static bool ftp_dispatch(ftp_t *f, char *line)
{
    char *arg = strchr(line, ' ');
    char *cmd = line;
    if (arg) {
        *arg++ = '\0';
        while (*arg == ' ') {
            arg++;
        }
    }

    if (strcasecmp(cmd, "USER") == 0) {
        cmd_user(f, arg);
    } else if (strcasecmp(cmd, "PASS") == 0) {
        cmd_pass(f, arg);
    } else if (strcasecmp(cmd, "QUIT") == 0) {
        reply(f, 221, "Goodbye.");
        return false;
    } else if (strcasecmp(cmd, "SYST") == 0) {
        reply(f, 215, "UNIX Type: L8");
    } else if (strcasecmp(cmd, "NOOP") == 0) {
        reply(f, 200, "NOOP ok.");
    } else if (strcasecmp(cmd, "FEAT") == 0) {
        mp_send_str(f->conn,
                    "211-Features:\r\n"
                    " EPRT\r\n"
                    " EPSV\r\n"
                    " MDTM\r\n"
                    " PASV\r\n"
                    " REST STREAM\r\n"
                    " SIZE\r\n"
                    " TVFS\r\n"
                    "211 End\r\n");
    } else if (strcasecmp(cmd, "HELP") == 0) {
        mp_send_str(f->conn,
                    "214-The following commands are recognized.\r\n"
                    " ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n"
                    " MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n"
                    " RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n"
                    " XPWD XRMD\r\n"
                    "214 Help OK.\r\n");
    } else if (!f->authed) {
        reply(f, 530, "Please login with USER and PASS.");
    } else if (strcasecmp(cmd, "PWD") == 0 || strcasecmp(cmd, "XPWD") == 0) {
        cmd_pwd(f);
    } else if (strcasecmp(cmd, "CWD") == 0 || strcasecmp(cmd, "XCWD") == 0) {
        cmd_cwd(f, arg);
    } else if (strcasecmp(cmd, "CDUP") == 0 || strcasecmp(cmd, "XCUP") == 0) {
        cmd_cwd(f, "..");
    } else if (strcasecmp(cmd, "TYPE") == 0) {
        if (arg && (arg[0] == 'I' || arg[0] == 'i')) {
            reply(f, 200, "Switching to Binary mode.");
        } else {
            reply(f, 200, "Switching to ASCII mode.");
        }
    } else if (strcasecmp(cmd, "PASV") == 0) {
        cmd_pasv(f);
    } else if (strcasecmp(cmd, "EPSV") == 0) {
        cmd_pasv(f); /* pool slots are IPv4; answer in PASV form anyway */
    } else if (strcasecmp(cmd, "LIST") == 0) {
        cmd_list(f, arg, false);
    } else if (strcasecmp(cmd, "NLST") == 0) {
        cmd_list(f, arg, true);
    } else if (strcasecmp(cmd, "RETR") == 0) {
        cmd_retr(f, arg);
    } else if (strcasecmp(cmd, "SIZE") == 0) {
        cmd_size(f, arg);
    } else if (strcasecmp(cmd, "MDTM") == 0) {
        reply(f, 213, "20261001090000");
    } else if (strcasecmp(cmd, "REST") == 0) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Restart position accepted (%s).",
                 arg ? arg : "0");
        reply(f, 350, msg);
    } else if (strcasecmp(cmd, "STOR") == 0 || strcasecmp(cmd, "STOU") == 0 ||
               strcasecmp(cmd, "APPE") == 0 || strcasecmp(cmd, "DELE") == 0 ||
               strcasecmp(cmd, "MKD") == 0 || strcasecmp(cmd, "XMKD") == 0 ||
               strcasecmp(cmd, "RMD") == 0 || strcasecmp(cmd, "XRMD") == 0 ||
               strcasecmp(cmd, "RNFR") == 0 || strcasecmp(cmd, "RNTO") == 0) {
        /* write_enable=NO */
        reply(f, 550, "Permission denied.");
    } else if (strcasecmp(cmd, "PORT") == 0 || strcasecmp(cmd, "EPRT") == 0) {
        reply(f, 500, "Illegal PORT command.");
    } else if (strcasecmp(cmd, "ABOR") == 0) {
        reply(f, 225, "No transfer to ABOR.");
    } else {
        reply(f, 500, "Unknown command.");
    }
    return true;
}

/* ------------------------------------------------------------ connection */

static void ftpd_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    mp_service_t *svc = (mp_service_t *)arg;
    const mp_ftpd_behavior_t *b =
        svc->brand ? mp_brand_behavior(svc->brand, "ftpd") : NULL;
    if (!b) {
        return;
    }

    /* CVE-2021-30047: past the connection limits vsftpd answers 421
     * (prelogin.c check_limits, verbatim strings) */
    switch (limit_admit(b, sess->src_ip)) {
    case 1:
        mp_send_str(conn, "421 There are too many connected users, "
                          "please try later.\r\n");
        return;
    case 2:
        mp_send_str(conn, "421 There are too many connections from your "
                          "internet address.\r\n");
        return;
    default:
        break;
    }

    ftp_t f = {
        .conn = conn,
        .sess = sess,
        .b = b,
        .cwd = "/",
        .pasv = -1,
    };

    char greet[64];
    snprintf(greet, sizeof(greet), "220 (vsFTPd %s)\r\n", b->version);
    if (mp_conn_send(conn, greet, strlen(greet)) == 0) {
        char line[FTP_LINE_MAX];
        bool open = true;
        while (open) {
            int n = mp_line_read(conn, line, sizeof(line), CTRL_TIMEOUT_MS,
                                 true, MP_LINE_ECHO_OFF);
            if (n < 0) {
                break; /* timeout / closed / aborted */
            }
            if (n == 0) {
                continue;
            }
            log_cmd(sess, line);
            open = ftp_dispatch(&f, line);
        }
    }
    pasv_finish(&f);
    limit_release(sess->src_ip);
}

/* ------------------------------------------------------------- lifecycle */

static esp_err_t ftpd_start(mp_service_t *svc)
{
    const mp_ftpd_behavior_t *b =
        svc->brand ? mp_brand_behavior(svc->brand, "ftpd") : NULL;
    if (!b) {
        ESP_LOGE(TAG, "brand '%s' has no ftpd behaviour",
                 svc->brand ? svc->brand->meta->id : "(null)");
        return ESP_ERR_NOT_SUPPORTED;
    }

    /* pre-register the PASV pool (no unlisten API, slots are reused) */
    for (int i = 0; i < PASV_SLOTS; i++) {
        if (!s_pasv[i].conn_ready) {
            s_pasv[i].conn_ready = xSemaphoreCreateBinary();
            s_pasv[i].xfr_done = xSemaphoreCreateBinary();
        }
        memset(&s_pasv_listeners[i], 0, sizeof(s_pasv_listeners[i]));
        s_pasv_listeners[i].vaddr = svc->bind.vaddr;
        s_pasv_listeners[i].port = PASV_PORT_BASE + (uint16_t)i;
        s_pasv_listeners[i].name = "ftpd-data";
        s_pasv_listeners[i].handler = pasv_data_task;
        s_pasv_listeners[i].arg = &s_pasv[i];
        esp_err_t err = mp_xport_listen(&s_pasv_listeners[i]);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "pasv listener %u failed: %s",
                     PASV_PORT_BASE + i, esp_err_to_name(err));
            return err;
        }
    }

    memset(&s_listener, 0, sizeof(s_listener));
    s_listener.vaddr = svc->bind.vaddr;
    s_listener.port = svc->bind.port;
    s_listener.name = "ftpd";
    s_listener.handler = ftpd_conn;
    s_listener.arg = svc;
    return mp_xport_listen(&s_listener);
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
