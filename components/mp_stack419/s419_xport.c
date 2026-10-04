/*
 * mp_xport backend on top of the 4.19 engine.
 *
 * A listener is registered with the engine; the engine completes the
 * three-way handshake itself (that is the point), then calls
 * s419_established() in tcpip context, where a connection task is spawned
 * with an mp_conn_t whose ctx is the TCB. The task reads/writes through
 * the TCB rings; TCP state stays owned by the tcpip thread.
 */
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "mp_util.h"

#include "s419_priv.h"

static const char *TAG = "s419_xport";

#define S419_CONN_TASK_STACK 4096
#define S419_CONN_TASK_PRIO  5

typedef struct {
    mp_conn_t            *conn;
    s419_tcb             *tcb;
    const s419_listener_t *lst;
    mp_session_t          sess;
} conn_task_arg_t;

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

/* ----------------------------------------------------------- task spawn */

static void conn_task(void *arg)
{
    conn_task_arg_t *a = (conn_task_arg_t *)arg;
    a->lst->handler(a->conn, &a->sess, a->lst->arg);
    a->conn->ops->release(a->conn);
    free(a);
    vTaskDelete(NULL);
}

void s419_established(s419_tcb *t)
{
    const s419_listener_t *lst = t->listener;
    if (!lst || !lst->handler) {
        t->dead = true;
        return;
    }

    t->rx_sem = xSemaphoreCreateBinary();
    t->tx_sem = xSemaphoreCreateBinary();
    mp_conn_t *conn = calloc(1, sizeof(*conn));
    conn_task_arg_t *a = calloc(1, sizeof(*a));
    if (!t->rx_sem || !t->tx_sem || !conn || !a) {
        ESP_LOGE(TAG, "%s: out of memory accepting connection", lst->name);
        free(conn);
        free(a);
        t->dead = true; /* tick reaps: no app attached */
        return;
    }

    conn->ops = &s_conn_ops;
    conn->ctx = t;
    t->conn = conn;
    t->app_attached = true;

    a->conn = conn;
    a->tcb = t;
    a->lst = lst;
    a->sess.sock = -1;
    a->sess.src_ip = t->rip;
    a->sess.src_port = (uint16_t)((t->rport >> 8) | (t->rport << 8));
    a->sess.dst_ip = t->lip;
    a->sess.dst_port = (uint16_t)((t->lport >> 8) | (t->lport << 8));
    a->sess.start_us = esp_timer_get_time();
    a->sess.id = mp_session_next_id();

    char task_name[16];
    snprintf(task_name, sizeof(task_name), "%s-%u", lst->name,
             (unsigned)(a->sess.id & 0xff));
    if (xTaskCreate(conn_task, task_name, S419_CONN_TASK_STACK, a,
                    S419_CONN_TASK_PRIO, NULL) != pdPASS) {
        ESP_LOGE(TAG, "%s: failed to spawn connection task", lst->name);
        t->app_attached = false;
        free(conn);
        free(a);
        t->dead = true;
    }
}

/* --------------------------------------------------------------- listen */

static esp_err_t s419_backend_listen(const mp_listener_cfg_t *cfg)
{
    return s419_listener_add(cfg->port, cfg->name, cfg->handler, cfg->arg);
}

const mp_xport_backend_t mp_xport_s419 = {
    .name = "s419",
    .listen = s419_backend_listen,
};
