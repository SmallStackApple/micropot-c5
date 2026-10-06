/*
 * lwIP socket backend for mp_xport.
 *
 * One accept task per listener, one detached task per connection, bounded
 * by the global session budget. This is the phase-1 path: vendor brands
 * (camera/router/printer) keep running on real lwIP sockets unchanged.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "netinet/tcp.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mp_util.h"
#include "mp_xport.h"

static const char *TAG = "mp_xport_lwip";

#define MP_LISTEN_BACKLOG  4
#define MP_CONN_TASK_STACK 4096
#define MP_CONN_TASK_PRIO  5

/* Connection and accept tasks run entirely on sockets/lwIP and never touch
 * flash, so their stacks can live in PSRAM and leave HP SRAM for the
 * logger and lwIP hot paths. xTaskCreateWithCaps pairs with
 * vTaskDeleteWithCaps (which supports self-deletion). */
#define MP_TASK_CAPS MALLOC_CAP_SPIRAM

/* POSIX raises SIGPIPE when writing to a closed peer; lwIP just returns an
 * error. Ask for the error so the honeypot task survives rude clients. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ------------------------------------------------------------ conn ops */

static int xc_recv(mp_conn_t *c, void *buf, size_t len, uint32_t timeout_ms)
{
    int sock = (int)(intptr_t)c->ctx;
    struct timeval tv = {
        .tv_sec = (time_t)(timeout_ms / 1000),
        .tv_usec = (suseconds_t)(timeout_ms % 1000) * 1000,
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int r = recv(sock, buf, len, 0);
    if (r > 0) {
        return r;
    }
    if (r == 0) {
        return 0; /* peer closed */
    }
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? MP_CONN_TIMEOUT
                                                     : MP_CONN_ABORTED;
}

static int xc_send(mp_conn_t *c, const void *buf, size_t len)
{
    int sock = (int)(intptr_t)c->ctx;
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        int r = send(sock, p + sent, len - sent, MSG_NOSIGNAL);
        if (r <= 0) {
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

static void xc_shutdown(mp_conn_t *c)
{
    int sock = (int)(intptr_t)c->ctx;
    shutdown(sock, SHUT_WR);
}

static void xc_release(mp_conn_t *c)
{
    int sock = (int)(intptr_t)c->ctx;
    close(sock);
    free(c);
}

static const mp_conn_ops_t s_lwip_conn_ops = {
    .recv = xc_recv,
    .send = xc_send,
    .shutdown = xc_shutdown,
    .release = xc_release,
};

/* --------------------------------------------------------- accept loop */

typedef struct {
    mp_conn_t                 *conn;
    mp_session_t               sess;
    const mp_listener_cfg_t   *cfg;
} conn_task_arg_t;

static void conn_task(void *arg)
{
    conn_task_arg_t *a = (conn_task_arg_t *)arg;
    a->cfg->handler(a->conn, &a->sess, a->cfg->arg);
    a->conn->ops->release(a->conn);
    free(a);
    mp_xport_budget_give();
    vTaskDeleteWithCaps(NULL);
}

typedef struct {
    int                       sock;
    mp_listener_cfg_t         cfg; /* owned copy — callers may pass stack-locals */
} accept_ctx_t;

static void accept_loop(void *arg)
{
    accept_ctx_t *ctx = (accept_ctx_t *)arg;
    int listen_sock = ctx->sock;
    const mp_listener_cfg_t *cfg = &ctx->cfg;

    for (;;) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int sock = accept(listen_sock, (struct sockaddr *)&peer, &peer_len);
        if (sock < 0) {
            int err = errno;
            if (err == EINTR) {
                continue;
            }
            ESP_LOGW(TAG, "%s: accept failed (%d), retrying", cfg->name, err);
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        /* Over budget: accept then drop at once so the backlog drains and
         * the scanner sees an open-but-helpless port, not a RST storm. */
        if (!mp_xport_budget_take()) {
            ESP_LOGW(TAG, "%s: session budget exhausted, dropping %u.%u.%u.%u",
                     cfg->name,
                     (unsigned)(peer.sin_addr.s_addr & 0xff),
                     (unsigned)((peer.sin_addr.s_addr >> 8) & 0xff),
                     (unsigned)((peer.sin_addr.s_addr >> 16) & 0xff),
                     (unsigned)((peer.sin_addr.s_addr >> 24) & 0xff));
            mp_xport_report_overload(cfg->name, cfg->port);
            close(sock);
            continue;
        }

        conn_task_arg_t *a = calloc(1, sizeof(*a));
        mp_conn_t *conn = calloc(1, sizeof(*conn));
        if (!a || !conn) {
            free(a);
            free(conn);
            mp_xport_budget_give();
            close(sock);
            continue;
        }
        conn->ops = &s_lwip_conn_ops;
        conn->ctx = (void *)(intptr_t)sock;

        a->conn = conn;
        a->cfg = &ctx->cfg;
        a->sess.sock = sock;
        a->sess.src_ip = peer.sin_addr.s_addr;
        a->sess.src_port = ntohs(peer.sin_port);
        a->sess.start_us = esp_timer_get_time();
        a->sess.id = mp_session_next_id();
        a->sess.persona = cfg->persona;

        struct sockaddr_in local;
        socklen_t local_len = sizeof(local);
        if (getsockname(sock, (struct sockaddr *)&local, &local_len) == 0) {
            a->sess.dst_ip = local.sin_addr.s_addr;
            a->sess.dst_port = ntohs(local.sin_port);
        }

        int nodelay = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        char task_name[16];
        snprintf(task_name, sizeof(task_name), "%s-%u", cfg->name,
                 (unsigned)(a->sess.id & 0xff));
        if (xTaskCreateWithCaps(conn_task, task_name, MP_CONN_TASK_STACK, a,
                                MP_CONN_TASK_PRIO, NULL, MP_TASK_CAPS) != pdPASS) {
            ESP_LOGE(TAG, "%s: failed to spawn connection task", cfg->name);
            close(sock);
            free(conn);
            free(a);
            mp_xport_budget_give();
        }
    }
}

static esp_err_t sock_listen(const mp_listener_cfg_t *cfg)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "%s: socket() failed", cfg->name);
        return ESP_FAIL;
    }

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->port);
    addr.sin_addr.s_addr = cfg->vaddr; /* 0 == INADDR_ANY */

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGE(TAG, "%s: bind(:%u) failed errno=%d", cfg->name, cfg->port, errno);
        close(sock);
        return ESP_FAIL;
    }
    if (listen(sock, MP_LISTEN_BACKLOG) != 0) {
        ESP_LOGE(TAG, "%s: listen failed errno=%d", cfg->name, errno);
        close(sock);
        return ESP_FAIL;
    }

    accept_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        close(sock);
        return ESP_ERR_NO_MEM;
    }
    ctx->sock = sock;
    ctx->cfg = *cfg;

    char task_name[16];
    snprintf(task_name, sizeof(task_name), "%s-lstn", cfg->name);
    if (xTaskCreateWithCaps(accept_loop, task_name, MP_CONN_TASK_STACK, ctx,
                            MP_CONN_TASK_PRIO, NULL, MP_TASK_CAPS) != pdPASS) {
        close(sock);
        free(ctx);
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "%s listening on port %u (lwip)", cfg->name, cfg->port);
    return ESP_OK;
}

const mp_xport_backend_t mp_xport_lwip = {
    .name = "lwip",
    .listen = sock_listen,
};
