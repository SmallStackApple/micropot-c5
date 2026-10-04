/*
 * mp_xport backend: services attach to the 4.19 engine through the same
 * listen/accept contract they use on lwIP. The handshake is already done
 * when a connection task is spawned, so the task only sees application
 * data — exactly like accept() on a socket.
 */
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/ip4_addr.h"

#include "mp_util.h"
#include "mp_xport.h"

#include "s419_priv.h"

static const char *TAG = "s419x";

#define S419_CONN_TASK_STACK 4096
#define S419_CONN_TASK_PRIO  5

/* ------------------------------------------------------------- conn ops */

static int conn_recv(mp_conn_t *c, void *buf, size_t len, uint32_t timeout_ms)
{
    return s419_app_recv((s419_tcb *)c->ctx, buf, len, timeout_ms);
}

static int conn_send(mp_conn_t *c, const void *buf, size_t len)
{
    return s419_app_send((s419_tcb *)c->ctx, buf, len);
}

static void conn_shutdown(mp_conn_t *c)
{
    s419_app_shutdown((s419_tcb *)c->ctx);
}

static void conn_release(mp_conn_t *c)
{
    s419_app_release((s419_tcb *)c->ctx);
    free(c);
}

static const mp_conn_ops_t s_conn_ops = {
    .recv = conn_recv,
    .send = conn_send,
    .shutdown = conn_shutdown,
    .release = conn_release,
};

/* ------------------------------------------------------ connection tasks */

typedef struct {
    mp_conn_t               *conn;
    mp_session_t             sess;
    const s419_listener_t   *listener;
} conn_task_arg_t;

static void conn_task(void *arg)
{
    conn_task_arg_t *a = (conn_task_arg_t *)arg;
    a->listener->handler(a->conn, &a->sess, a->listener->arg);
    a->conn->ops->release(a->conn);
    free(a);
    vTaskDelete(NULL);
}

/* Called in the tcpip thread once the three-way handshake completes. */
void s419_established(s419_tcb *tcb)
{
    tcb->app_attached = true;
    tcb->rx_sem = xSemaphoreCreateCounting(S419_RX_CAP, 0);
    tcb->tx_sem = xSemaphoreCreateCounting(64, 0);

    mp_conn_t *conn = tcb->conn = calloc(1, sizeof(*conn));
    conn_task_arg_t *a = calloc(1, sizeof(*a));
    if (!tcb->rx_sem || !tcb->tx_sem || !conn || !a) {
        ESP_LOGE(TAG, "cannot accept %s: out of memory", tcb->listener->name);
        free(conn);
        free(a);
        s419_tcp_abort(tcb);
        return;
    }

    conn->ops = &s_conn_ops;
    conn->ctx = tcb;

    a->conn = conn;
    a->listener = tcb->listener;
    a->sess.sock = -1;
    a->sess.src_ip = tcb->rip;   /* host-order numeric, like the session API */
    a->sess.src_port = tcb->rport;
    a->sess.dst_ip = tcb->lip;
    a->sess.dst_port = tcb->lport;
    a->sess.id = mp_session_next_id();
    a->sess.start_us = esp_timer_get_time();

    char task_name[16];
    snprintf(task_name, sizeof(task_name), "%s-%u", tcb->listener->name,
             (unsigned)(a->sess.id & 0xff));
    if (xTaskCreate(conn_task, task_name, S419_CONN_TASK_STACK, a,
                    S419_CONN_TASK_PRIO, NULL) != pdPASS) {
        ESP_LOGE(TAG, "cannot spawn %s task", tcb->listener->name);
        free(conn);
        free(a);
        s419_tcp_abort(tcb);
    }
}

/* --------------------------------------------------------------- listen */

static esp_err_t s419_listen(const mp_listener_cfg_t *cfg)
{
    /* vaddr filtering (virtual IPs) arrives with phase 2; today the engine
     * answers on the station address only. */
    (void)cfg->vaddr;
    return s419_listener_add(cfg->port, cfg->name, cfg->handler, cfg->arg);
}

const mp_xport_backend_t mp_xport_s419 = {
    .name = "s419",
    .listen = s419_listen,
};
