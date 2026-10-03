#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "netinet/tcp.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "mp_tcp_listener.h"
#include "mp_util.h"

static const char *TAG = "mp_tcp";

#define MP_LISTEN_BACKLOG  4
#define MP_CONN_TASK_STACK 4096
#define MP_CONN_TASK_PRIO  5

/* Global session budget shared by every listener: a flood against one
 * service must not be able to starve the others or exhaust the heap. */
static portMUX_TYPE s_budget_lock = portMUX_INITIALIZER_UNLOCKED;
static uint32_t     s_active;
static mp_overload_hook_t s_overload_hook;

static bool budget_take(void)
{
    bool ok;
    portENTER_CRITICAL(&s_budget_lock);
    ok = s_active < CONFIG_MICROPOT_MAX_SESSIONS;
    if (ok) {
        s_active++;
    }
    portEXIT_CRITICAL(&s_budget_lock);
    return ok;
}

static void budget_give(void)
{
    portENTER_CRITICAL(&s_budget_lock);
    if (s_active) {
        s_active--;
    }
    portEXIT_CRITICAL(&s_budget_lock);
}

uint32_t mp_tcp_listener_active(void)
{
    return s_active;
}

void mp_tcp_listener_set_overload_hook(mp_overload_hook_t hook)
{
    s_overload_hook = hook;
}

typedef struct {
    int                        sock;
    mp_session_t               sess;
    const mp_tcp_listener_cfg_t *cfg;
} conn_task_arg_t;

static void conn_task(void *arg)
{
    conn_task_arg_t *a = (conn_task_arg_t *)arg;
    a->cfg->handler(a->sock, &a->sess, a->cfg->arg);
    close(a->sock);
    free(a);
    budget_give();
    vTaskDelete(NULL);
}

typedef struct {
    int                         sock;
    const mp_tcp_listener_cfg_t *cfg;
} accept_ctx_t;

static void accept_loop(void *arg)
{
    accept_ctx_t *ctx = (accept_ctx_t *)arg;
    int listen_sock = ctx->sock;
    const mp_tcp_listener_cfg_t *cfg = ctx->cfg;

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
        if (!budget_take()) {
            ESP_LOGW(TAG, "%s: session budget exhausted (%u), dropping %u.%u.%u.%u",
                     cfg->name, (unsigned)CONFIG_MICROPOT_MAX_SESSIONS,
                     (unsigned)(peer.sin_addr.s_addr & 0xff),
                     (unsigned)((peer.sin_addr.s_addr >> 8) & 0xff),
                     (unsigned)((peer.sin_addr.s_addr >> 16) & 0xff),
                     (unsigned)((peer.sin_addr.s_addr >> 24) & 0xff));
            if (s_overload_hook) {
                s_overload_hook(cfg->name, cfg->port);
            }
            close(sock);
            continue;
        }

        conn_task_arg_t *a = calloc(1, sizeof(*a));
        if (!a) {
            budget_give();
            close(sock);
            continue;
        }
        a->sock = sock;
        a->cfg = cfg;
        a->sess.sock = sock;
        a->sess.src_ip = peer.sin_addr.s_addr;
        a->sess.src_port = ntohs(peer.sin_port);
        a->sess.start_us = esp_timer_get_time();
        a->sess.id = mp_session_next_id();

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
        if (xTaskCreate(conn_task, task_name, MP_CONN_TASK_STACK, a,
                        MP_CONN_TASK_PRIO, NULL) != pdPASS) {
            ESP_LOGE(TAG, "%s: failed to spawn connection task", cfg->name);
            close(sock);
            free(a);
            budget_give();
        }
    }
}

esp_err_t mp_tcp_listener_start(const mp_tcp_listener_cfg_t *cfg)
{
    if (!cfg || !cfg->handler) {
        return ESP_ERR_INVALID_ARG;
    }

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
    ctx->cfg = cfg;

    char task_name[16];
    snprintf(task_name, sizeof(task_name), "%s-lstn", cfg->name);
    if (xTaskCreate(accept_loop, task_name, MP_CONN_TASK_STACK, ctx,
                    MP_CONN_TASK_PRIO, NULL) != pdPASS) {
        close(sock);
        free(ctx);
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "%s listening on port %u", cfg->name, cfg->port);
    return ESP_OK;
}
