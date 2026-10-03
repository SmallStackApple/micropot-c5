#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "mp_udp_listener.h"
#include "mp_util.h"

static const char *TAG = "mp_udp";

#define MP_UDP_TASK_STACK 4096
#define MP_UDP_TASK_PRIO  5

typedef struct {
    uint32_t src_ip;   /* network byte order */
    uint16_t src_port; /* host byte order */
    uint32_t sid;
    int64_t  last_us;
    bool     used;
} udp_peer_t;

typedef struct {
    int                          sock;
    const mp_udp_listener_cfg_t *cfg;
    udp_peer_t                   peers[MP_UDP_MAX_PEERS];
    uint32_t                     dst_ip;   /* network byte order */
    uint16_t                     dst_port; /* host byte order */
} udp_ctx_t;

/* Find the peer slot for (ip, port), minting or recycling as needed. */
static udp_peer_t *peer_lookup(udp_ctx_t *ctx, uint32_t src_ip, uint16_t src_port)
{
    int64_t now = esp_timer_get_time();
    udp_peer_t *free_slot = NULL;
    udp_peer_t *oldest = &ctx->peers[0];

    for (size_t i = 0; i < MP_UDP_MAX_PEERS; i++) {
        udp_peer_t *p = &ctx->peers[i];
        if (p->used && p->src_ip == src_ip && p->src_port == src_port) {
            if (now - p->last_us > (int64_t)MP_UDP_SESSION_IDLE_MS * 1000) {
                p->sid = mp_session_next_id(); /* idle too long: new session */
            }
            p->last_us = now;
            return p;
        }
        if (!p->used && !free_slot) {
            free_slot = p;
        }
        if (p->used && p->last_us < oldest->last_us) {
            oldest = p;
        }
    }
    udp_peer_t *slot = free_slot ? free_slot : oldest;
    slot->used = true;
    slot->src_ip = src_ip;
    slot->src_port = src_port;
    slot->sid = mp_session_next_id();
    slot->last_us = now;
    return slot;
}

static void udp_loop(void *arg)
{
    udp_ctx_t *ctx = (udp_ctx_t *)arg;
    uint8_t *buf = malloc(MP_UDP_BUF_MAX);
    if (!buf) {
        ESP_LOGE(TAG, "%s: no memory for receive buffer", ctx->cfg->name);
        vTaskDelete(NULL);
    }

    for (;;) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int n = recvfrom(ctx->sock, buf, MP_UDP_BUF_MAX, 0,
                         (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            int err = errno;
            if (err == EINTR) {
                continue;
            }
            ESP_LOGW(TAG, "%s: recvfrom failed (%d), retrying", ctx->cfg->name, err);
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        udp_peer_t *p = peer_lookup(ctx, peer.sin_addr.s_addr,
                                    ntohs(peer.sin_port));
        mp_session_t sess = {
            .sock = ctx->sock,
            .src_ip = peer.sin_addr.s_addr,
            .src_port = ntohs(peer.sin_port),
            .dst_ip = ctx->dst_ip,
            .dst_port = ctx->dst_port,
            .id = p->sid,
            .start_us = p->last_us,
        };
        ctx->cfg->handler(&sess, buf, (size_t)n, ctx->cfg->arg);
    }
}

esp_err_t mp_udp_listener_start(const mp_udp_listener_cfg_t *cfg)
{
    if (!cfg || !cfg->handler) {
        return ESP_ERR_INVALID_ARG;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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

    udp_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        close(sock);
        return ESP_ERR_NO_MEM;
    }
    ctx->sock = sock;
    ctx->cfg = cfg;
    ctx->dst_ip = addr.sin_addr.s_addr; /* 0.0.0.0 when bound to ANY */
    ctx->dst_port = cfg->port;

    char task_name[16];
    snprintf(task_name, sizeof(task_name), "%s-udp", cfg->name);
    if (xTaskCreate(udp_loop, task_name, MP_UDP_TASK_STACK, ctx,
                    MP_UDP_TASK_PRIO, NULL) != pdPASS) {
        close(sock);
        free(ctx);
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "%s listening on UDP port %u", cfg->name, cfg->port);
    return ESP_OK;
}
