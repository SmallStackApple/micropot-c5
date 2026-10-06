/*
 * Virtual interface glue: alias ARP responder + lwIP ip4-input hook feed.
 */
#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"

#include "lwip/err.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"

#include "mp_vdev.h"
#include "mp_vif.h"

static const char *TAG = "mp_vif";

static struct netif      *s_netif;
static netif_input_fn     s_orig_input;
static mp_vif_ip4_feed_fn s_feed;

/* --------------------------------------------------------- ARP responder */

/* 802.11 infrastructure means one MAC: aliases are answered with the
 * station MAC, like IP aliasing on a real host. */
#define ARP_JOBS 4

typedef struct {
    bool    busy;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t vdev_ip[4];
} arp_job_t;

static arp_job_t s_jobs[ARP_JOBS];

static void arp_reply_tx(void *arg)
{
    arp_job_t *job = arg;

    uint8_t mac[6] = { 0 };
    esp_wifi_get_mac(WIFI_IF_STA, mac);

    uint8_t frame[42];
    memset(frame, 0, sizeof(frame));
    memcpy(frame + 0, job->sender_mac, 6);  /* ethernet dst */
    memcpy(frame + 6, mac, 6);              /* ethernet src */
    frame[12] = 0x08; frame[13] = 0x06;     /* ARP */
    frame[14] = 0x00; frame[15] = 0x01;     /* htype ethernet */
    frame[16] = 0x08; frame[17] = 0x00;     /* ptype IPv4 */
    frame[18] = 6;    frame[19] = 4;        /* hlen/plen */
    frame[20] = 0x00; frame[21] = 0x02;     /* op = reply */
    memcpy(frame + 22, mac, 6);             /* sha */
    memcpy(frame + 28, job->vdev_ip, 4);    /* spa */
    memcpy(frame + 32, job->sender_mac, 6); /* tha */
    memcpy(frame + 38, job->sender_ip, 4);  /* tpa */

    struct pbuf *p = pbuf_alloc(PBUF_RAW_TX, sizeof(frame), PBUF_RAM);
    if (p) {
        pbuf_take(p, frame, sizeof(frame));
        s_netif->linkoutput(s_netif, p);
        pbuf_free(p);
    }
    job->busy = false;
}

static err_t vif_input(struct pbuf *p, struct netif *inp)
{
    /* Peek at ARP requests for alias addresses; everything still flows to
     * lwIP untouched (etharp drops alias requests but learns the sender,
     * which our own outbound path benefits from). */
    uint8_t h[42];
    if (pbuf_copy_partial(p, h, sizeof(h), 0) == sizeof(h) &&
        h[12] == 0x08 && h[13] == 0x06 &&                /* ARP */
        h[14] == 0x00 && h[15] == 0x01 &&                /* htype ethernet */
        h[16] == 0x08 && h[17] == 0x00 &&                /* ptype IPv4 */
        h[18] == 6 && h[19] == 4 &&
        h[20] == 0x00 && h[21] == 0x01) {                /* request */
        uint32_t tpa;
        memcpy(&tpa, h + 38, 4); /* lwIP word order, matches mp_vdev */
        if (mp_vdev_by_vaddr(tpa)) {
            for (int i = 0; i < ARP_JOBS; i++) {
                if (!s_jobs[i].busy) {
                    s_jobs[i].busy = true;
                    memcpy(s_jobs[i].sender_mac, h + 22, 6);
                    memcpy(s_jobs[i].sender_ip, h + 28, 4);
                    memcpy(s_jobs[i].vdev_ip, h + 38, 4);
                    if (tcpip_callback(arp_reply_tx, &s_jobs[i]) != ERR_OK) {
                        s_jobs[i].busy = false;
                    }
                    break;
                }
            }
        }
    }
    return s_orig_input(p, inp);
}

/* -------------------------------------------------------------- ip4 hook */

int mp_vif_ip4_input_hook(struct pbuf *p, struct netif *inp)
{
    /* tcpip thread, core locked, p->payload = IPv4 header, fired before the
     * not-for-us drop. The feed (stack419) consumes alias-destined traffic;
     * everything else continues down lwIP's normal path. */
    (void)inp;
    if (s_feed && s_feed(p)) {
        return 1;
    }
    return 0;
}

void mp_vif_set_ip4_feed(mp_vif_ip4_feed_fn fn)
{
    s_feed = fn;
}

esp_err_t mp_vif_install(struct netif *netif)
{
    if (!netif) {
        return ESP_ERR_INVALID_ARG;
    }
    LOCK_TCPIP_CORE();
    s_netif = netif;
    s_orig_input = netif->input;
    netif->input = vif_input;
    UNLOCK_TCPIP_CORE();
    ESP_LOGI(TAG, "alias ARP responder installed");
    return ESP_OK;
}
