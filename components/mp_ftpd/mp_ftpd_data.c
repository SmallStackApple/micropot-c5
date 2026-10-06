/*
 * vsftpd-style FTP honeypot — data channel and connection limits.
 *
 * PASV is served through a small pool of pre-registered listeners so the
 * advertised port range is stable (40021-40024) like a real vsftpd with a
 * configured pasv_min/max_port. The per-source-IP and global session
 * counters reproduce prelogin.c's check_limits (CVE-2021-30047's 421
 * connection-limit signature, without the crash).
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_err.h"
#include "esp_log.h"

#include "mp_ftpd_internal.h"

static const char *TAG = "mp_ftpd";

/* --------------------------------------------------------- PASV pool ---- */

typedef struct {
    SemaphoreHandle_t conn_ready; /* data task -> control: conn arrived */
    SemaphoreHandle_t xfr_done;   /* control -> data task: release conn */
    mp_conn_t *conn;
    const mp_session_t *sess;
    bool in_use;
} pasv_slot_t;

static pasv_slot_t s_pasv[PASV_SLOTS];

/* connection limits: control sessions (421 past max_clients) and per
 * source IP (421 past max_per_ip). The table can never outgrow the global
 * session budget, so a fixed small array suffices. */
static uint8_t s_active;
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

int mp_ftpd_limit_admit(const mp_ftpd_behavior_t *b, uint32_t ip)
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

void mp_ftpd_limit_release(uint32_t ip)
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

/* ------------------------------------------------------- data channel ---- */

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
int mp_ftpd_pasv_claim(void)
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

mp_conn_t *mp_ftpd_pasv_accept(ftp_t *f)
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

void mp_ftpd_pasv_finish(ftp_t *f)
{
    if (f->pasv >= 0) {
        xSemaphoreGive(s_pasv[f->pasv].xfr_done);
        pasv_release(f->pasv);
        f->pasv = -1;
    }
}

/* The pool binds the PASV port range on a wildcard address so every vdev's
 * ftpd can accept data connections; the claiming control session owns the
 * slot, so cross-vdev confusion cannot happen. Started once — subsequent
 * ftpd instances share the pool. */
esp_err_t mp_ftpd_pasv_pool_start(const mp_xport_backend_t *xport)
{
    static bool s_started;
    if (s_started) {
        return ESP_OK;
    }
    s_started = true;
    for (int i = 0; i < PASV_SLOTS; i++) {
        if (!s_pasv[i].conn_ready) {
            s_pasv[i].conn_ready = xSemaphoreCreateBinary();
            s_pasv[i].xfr_done = xSemaphoreCreateBinary();
        }
        mp_listener_cfg_t cfg = {
            .vaddr = 0,
            .port = PASV_PORT_BASE + (uint16_t)i,
            .name = "ftpd-data",
            .handler = pasv_data_task,
            .arg = &s_pasv[i],
            .xport = xport,
        };
        esp_err_t err = mp_xport_listen(&cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "pasv listener %u failed: %s",
                     PASV_PORT_BASE + i, esp_err_to_name(err));
            return err;
        }
    }
    return ESP_OK;
}
