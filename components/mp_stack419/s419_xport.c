/*
 * mp_xport backend on top of the 4.19 engine.
 *
 * Handshake completion (s419_established, tcpip thread) spawns the
 * per-connection task, mirroring the lwIP backend's semantics: the global
 * session budget is taken at accept time, overload is answered with an
 * immediate RST (an open-but-helpless port), and the backend releases the
 * connection once the service handler returns.
 */
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/def.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "mp_util.h"

#include "s419_pkt.h"
#include "s419_priv.h"

static const char *TAG = "s419_xport";

/* Per-connection task stack. mp_httpd nests ~3.5KB of response buffers
 * (hdr/body/canned error pages) across its call chain and picolibc's
 * snprintf adds a fat frame on top — 4KB overflowed under nmap -sV. */
#define S419_CONN_TASK_STACK 8192
#define S419_CONN_TASK_PRIO  5

/* ------------------------------------------------------------ conn ops */

static int xport_recv(mp_conn_t *c, void *buf, size_t len, uint32_t timeout_ms)
{
    return s419_app_recv((s419_tcb *)c->ctx, buf, len, timeout_ms);
}

static int xport_send(mp_conn_t *c, const void *buf, size_t len)
{
    return s419_app_send((s419_tcb *)c->ctx, buf, len);
}

static void xport_shutdown(mp_conn_t *c)
{
    s419_app_shutdown((s419_tcb *)c->ctx);
}

static void xport_release(mp_conn_t *c)
{
    s419_app_release((s419_tcb *)c->ctx);
    free(c);
}

static const mp_conn_ops_t s_s419_conn_ops = {
    .recv = xport_recv,
    .send = xport_send,
    .shutdown = xport_shutdown,
    .release = xport_release,
};

/* ------------------------------------------------------------ conn task */

typedef struct {
    s419_tcb    *tcb;
    mp_conn_t   *conn;
    mp_session_t sess;
} s419_conn_arg_t;

static void conn_task(void *arg)
{
    s419_conn_arg_t *a = (s419_conn_arg_t *)arg;
    const s419_listener_t *lst = a->tcb->listener;

    lst->handler(a->conn, &a->sess, lst->arg);
    a->conn->ops->release(a->conn);
    free(a);
    mp_xport_budget_give();
    vTaskDelete(NULL);
}

/* Handshake complete (tcpip thread). Spawn the connection task, or reset
 * the peer when the session budget is exhausted.
 * @return false when the TCB was destroyed (overload / spawn failure). */
bool s419_established(s419_tcb *tcb)
{
    const s419_listener_t *lst = tcb->listener;

    if (!mp_xport_budget_take()) {
        ESP_LOGW(TAG, "%s: session budget exhausted, resetting %u.%u.%u.%u",
                 lst->name,
                 (unsigned)(tcb->rip & 0xff), (unsigned)((tcb->rip >> 8) & 0xff),
                 (unsigned)((tcb->rip >> 16) & 0xff),
                 (unsigned)((tcb->rip >> 24) & 0xff));
        s419_report_overload(lst);
        s419_tcp_active_reset(tcb);
        s419_tcb_unlink_free(tcb);
        return false;
    }

    tcb->rx_sem = xSemaphoreCreateBinary();
    tcb->tx_sem = xSemaphoreCreateBinary();
    mp_conn_t *conn = calloc(1, sizeof(*conn));
    s419_conn_arg_t *a = calloc(1, sizeof(*a));
    if (!tcb->rx_sem || !tcb->tx_sem || !conn || !a) {
        if (tcb->rx_sem) {
            vSemaphoreDelete(tcb->rx_sem);
            tcb->rx_sem = NULL;
        }
        if (tcb->tx_sem) {
            vSemaphoreDelete(tcb->tx_sem);
            tcb->tx_sem = NULL;
        }
        free(conn);
        free(a);
        mp_xport_budget_give();
        s419_tcp_active_reset(tcb);
        s419_tcb_unlink_free(tcb);
        return false;
    }

    conn->ops = &s_s419_conn_ops;
    conn->ctx = tcb;
    tcb->conn = conn;
    tcb->app_attached = true;

    a->tcb = tcb;
    a->conn = conn;
    a->sess.sock = -1;
    /* TCB addresses are big-endian numerics (packet-read domain); mp_session
     * follows the lwIP convention (first octet in the low byte). */
    a->sess.src_ip = PP_HTONL(tcb->rip);
    a->sess.src_port = tcb->rport;
    a->sess.dst_ip = PP_HTONL(tcb->lip);
    a->sess.dst_port = tcb->lport;
    a->sess.start_us = esp_timer_get_time();
    a->sess.id = mp_session_next_id();

    char task_name[16];
    snprintf(task_name, sizeof(task_name), "%s-%u", lst->name,
             (unsigned)(a->sess.id & 0xff));
    if (xTaskCreate(conn_task, task_name, S419_CONN_TASK_STACK, a,
                    S419_CONN_TASK_PRIO, NULL) != pdPASS) {
        ESP_LOGE(TAG, "%s: failed to spawn connection task", lst->name);
        tcb->conn = NULL;
        tcb->app_attached = false;
        vSemaphoreDelete(tcb->rx_sem);
        tcb->rx_sem = NULL;
        vSemaphoreDelete(tcb->tx_sem);
        tcb->tx_sem = NULL;
        free(conn);
        free(a);
        mp_xport_budget_give();
        s419_tcp_active_reset(tcb);
        s419_tcb_unlink_free(tcb);
        return false;
    }
    return true;
}

static esp_err_t s419_listen(const mp_listener_cfg_t *cfg)
{
    return s419_listener_add(cfg->port, cfg->name, cfg->handler, cfg->arg);
}

const mp_xport_backend_t mp_xport_s419 = {
    .name = "s419",
    .listen = s419_listen,
};
