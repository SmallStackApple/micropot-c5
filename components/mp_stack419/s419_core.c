/*
 * Engine core: raw-PCB interception, packet output, TCB table, timers.
 *
 * lwIP delivers every inbound IPv4 packet to raw PCBs *before* its own
 * TCP/UDP/ICMP processing (ip4_input -> raw_input), and a raw callback
 * that returns 1 "eats" the packet — this is where the 4.19 personality
 * takes over from lwIP. Outbound packets are built complete (IP header
 * included) and emitted verbatim through an IP_HDRINCL raw PCB, so TTL,
 * DF, IP ID and checksums are exactly what Linux 4.19 would emit.
 */
#include <stdlib.h>
#include <string.h>

#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/raw.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "mp_log.h"
#include "mp_net.h"

#include "s419_pkt.h"
#include "s419_priv.h"

static const char *TAG = "s419";

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

#define UDP_PORT_DHCP_CLIENT 68 /* lwIP's DHCP client lives here: pass */

const mp_s419_params_t *s419_par;

static struct raw_pcb *s_pcb_tcp;
static struct raw_pcb *s_pcb_udp;
static struct raw_pcb *s_pcb_icmp;
static struct raw_pcb *s_pcb_tx;   /* IP_HDRINCL sender */

static s419_listener_t s_listeners[S419_MAX_LISTENERS];
static size_t          s_n_listeners;

static s419_tcb       *s_tcbs;
static uint16_t        s_synrecv_count;
static uint16_t        s_icmp_id;
static int64_t         s_last_flood_evt_ms;

int64_t s419_now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

uint32_t s419_our_ip(void)
{
    /* mp_net stores lwIP's address word (first octet in the low byte on
     * little-endian); the engine's numeric domain reads packet fields
     * big-endian, so swap once here. */
    return PP_HTONL(mp_net_get_ip()); /* 0 before DHCP */
}

uint16_t s419_icmp_ipid(void)
{
    return ++s_icmp_id; /* incrementing: nmap II=I */
}

/* ---------------------------------------------------------------- output */

void s419_output(const uint8_t *pkt, size_t len, uint32_t dst_nbo)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
    if (!p) {
        ESP_LOGD(TAG, "tx: pbuf alloc failed (%u)", (unsigned)len);
        return;
    }
    pbuf_take(p, pkt, (u16_t)len);
    ip_addr_t dst;
    ip_addr_t *dstp = &dst; /* avoid &local inside lwIP's boolean macros */
    ip_addr_set_ip4_u32(dstp, dst_nbo);
    err_t err = raw_sendto(s_pcb_tx, p, dstp); /* HDRINCL: sent verbatim */
    if (err != ERR_OK) {
        ESP_LOGD(TAG, "tx: raw_sendto -> %d", err);
    }
    pbuf_free(p);
}

/* ------------------------------------------------------------- overload */

void s419_report_overload(const s419_listener_t *lst)
{
    mp_xport_report_overload(lst->name, lst->port);
}

void s419_report_synflood(void)
{
    int64_t now = s419_now_ms();
    if (now - s_last_flood_evt_ms < 1000) {
        return; /* throttled: one event per second at most */
    }
    s_last_flood_evt_ms = now;

    mp_evt_t e;
    mp_evt_begin(&e, NULL, "net", "net.syn_flood");
    mp_evt_int(&e, "syn_recv", S419_SYNRECV_CAP);
    mp_evt_send(&e);
}

/* ------------------------------------------------------------ TCB table */

s419_tcb *s419_tcb_alloc(void)
{
    s419_tcb *tcb = calloc(1, sizeof(*tcb));
    if (!tcb) {
        return NULL;
    }
    /* Rings live in PSRAM when present; they are only touched under the
     * TCB spinlock by the tcpip thread and one conn task. */
    tcb->rxbuf = heap_caps_malloc(S419_RX_CAP,
                                  MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    tcb->txbuf = heap_caps_malloc(S419_TX_CAP,
                                  MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!tcb->rxbuf) {
        tcb->rxbuf = heap_caps_malloc(S419_RX_CAP, MALLOC_CAP_8BIT);
    }
    if (!tcb->txbuf) {
        tcb->txbuf = heap_caps_malloc(S419_TX_CAP, MALLOC_CAP_8BIT);
    }
    if (!tcb->rxbuf || !tcb->txbuf) {
        heap_caps_free(tcb->rxbuf);
        heap_caps_free(tcb->txbuf);
        free(tcb);
        return NULL;
    }
    tcb->lock = (portMUX_TYPE)portMUX_INITIALIZER_UNLOCKED;
    return tcb;
}

void s419_tcb_link(s419_tcb *tcb)
{
    tcb->next = s_tcbs;
    s_tcbs = tcb;
}

void s419_tcb_unlink_free(s419_tcb *tcb)
{
    s419_tcb **pp = &s_tcbs;
    while (*pp) {
        if (*pp == tcb) {
            *pp = tcb->next;
            break;
        }
        pp = &(*pp)->next;
    }
    if (tcb->rx_sem) {
        vSemaphoreDelete(tcb->rx_sem);
    }
    if (tcb->tx_sem) {
        vSemaphoreDelete(tcb->tx_sem);
    }
    heap_caps_free(tcb->rxbuf);
    heap_caps_free(tcb->txbuf);
    free(tcb);
}

s419_tcb *s419_tcb_find(uint32_t lip, uint32_t rip,
                        uint16_t lport, uint16_t rport)
{
    for (s419_tcb *t = s_tcbs; t; t = t->next) {
        if (t->lip == lip && t->rip == rip &&
            t->lport == lport && t->rport == rport) {
            return t;
        }
    }
    return NULL;
}

s419_tcb *s419_tcbs(void)
{
    return s_tcbs;
}

/* ------------------------------------------------------------- listeners */

const s419_listener_t *s419_listener_find(uint16_t port)
{
    for (size_t i = 0; i < s_n_listeners; i++) {
        if (s_listeners[i].port == port) {
            return &s_listeners[i];
        }
    }
    return NULL;
}

esp_err_t s419_listener_add(uint16_t port, const char *name,
                            mp_conn_handler_t handler, void *arg)
{
    if (s_n_listeners >= S419_MAX_LISTENERS) {
        return ESP_ERR_NO_MEM;
    }
    if (s419_listener_find(port)) {
        return ESP_ERR_INVALID_STATE;
    }
    s419_listener_t *l = &s_listeners[s_n_listeners++];
    l->port = port;
    l->name = name;
    l->handler = handler;
    l->arg = arg;
    ESP_LOGI(TAG, "%s listening on port %u (stack419)", name, port);
    return ESP_OK;
}

/* --------------------------------------------------------------- receive */

static bool for_us(uint32_t dst_nbo)
{
    uint32_t ip = s419_our_ip();
    return ip != 0 && dst_nbo == ip;
}

/* TCP receive classification, following 4.19:
 *  - established 4-tuple        -> session machine       (tcp_v4_do_rcv)
 *  - LISTEN port, ACK           -> RST                   (tcp_input.c:6002)
 *  - LISTEN port, RST           -> discard               (:6005)
 *  - LISTEN port, SYN+FIN       -> discard               (:6009)
 *  - LISTEN port, SYN           -> conn_request          (:6008)
 *  - LISTEN port, other flags   -> discard               (T2: R=N)
 *  - closed port, not RST       -> tcp_v4_send_reset     (T5/T6/T7)
 */
static u8_t on_tcp(void *arg, struct raw_pcb *pcb, struct pbuf *p,
                   const ip_addr_t *addr)
{
    (void)arg; (void)pcb; (void)addr;
    const uint8_t *ip = (const uint8_t *)p->payload;
    if (p->tot_len < S419_IP_HLEN + S419_TCP_HLEN) {
        return 0;
    }
    size_t ihl = (ip[0] & 0x0f) * 4;
    uint32_t ip_src = s419_rd32(ip + 12);
    uint32_t ip_dst = s419_rd32(ip + 16);
    if (!for_us(ip_dst)) {
        return 0;
    }
    size_t ip_len = s419_rd16(ip + 2);
    if (ip_len > p->tot_len || ihl + S419_TCP_HLEN > ip_len) {
        return 1; /* truncated garbage for us: drop silently */
    }
    const uint8_t *th = ip + ihl;
    size_t tcp_len = ip_len - ihl;
    uint16_t rport = s419_rd16(th + 0);
    uint16_t lport = s419_rd16(th + 2);
    uint8_t flags = th[13];

    if (lport >= S419_EPHEMERAL_MIN) {
        return 0; /* lwIP's own outbound flows (log collector) */
    }

    s419_tcb *tcb = s419_tcb_find(ip_dst, ip_src, lport, rport);
    if (tcb) {
        s419_tcp_input(tcb, th, tcp_len, ip_src, ip_dst);
        return 1;
    }

    const s419_listener_t *lst = s419_listener_find(lport);
    if (lst) {
        if (flags & S419_ACK) {
            s419_tcp_closed_reset(ip_dst, ip_src, lport, rport, th, tcp_len);
        } else if (flags & S419_RST) {
            /* discard */
        } else if (flags & S419_SYN) {
            if (!(flags & S419_FIN)) {
                s419_tcp_new_syn(lst, ip_dst, ip_src, lport, rport,
                                 th, tcp_len);
            } /* SYN+FIN: discard (T3: R=N) */
        } /* other flag combos: discard (T2: R=N) */
        return 1;
    }

    if (!(flags & S419_RST)) {
        s419_tcp_closed_reset(ip_dst, ip_src, lport, rport, th, tcp_len);
    }
    return 1;
}

static u8_t on_udp(void *arg, struct raw_pcb *pcb, struct pbuf *p,
                   const ip_addr_t *addr)
{
    (void)arg; (void)pcb; (void)addr;
    const uint8_t *ip = (const uint8_t *)p->payload;
    if (p->tot_len < S419_IP_HLEN + 8) {
        return 0;
    }
    size_t ihl = (ip[0] & 0x0f) * 4;
    uint32_t ip_dst = s419_rd32(ip + 16);
    if (!for_us(ip_dst)) {
        return 0;
    }
    const uint8_t *uh = ip + ihl;
    uint16_t dport = s419_rd16(uh + 2);
    if (dport >= S419_EPHEMERAL_MIN || dport == UDP_PORT_DHCP_CLIENT) {
        return 0; /* lwIP traffic (DNS/NTP/DHCP client) */
    }
    /* UDP to a closed port: ICMP port unreachable (nmap U1 test) */
    uint8_t pkt[128];
    size_t n = s419_build_icmp_unreach(pkt, ip, p->tot_len, s419_icmp_ipid(),
                                       ip_dst, s419_rd32(ip + 12), s419_par);
    if (n) {
        s419_output(pkt, n, s419_rd32(ip + 12));
    }
    return 1;
}

static u8_t on_icmp(void *arg, struct raw_pcb *pcb, struct pbuf *p,
                    const ip_addr_t *addr)
{
    (void)arg; (void)pcb; (void)addr;
    const uint8_t *ip = (const uint8_t *)p->payload;
    if (p->tot_len < S419_IP_HLEN + 8) {
        return 0;
    }
    size_t ihl = (ip[0] & 0x0f) * 4;
    uint32_t ip_dst = s419_rd32(ip + 16);
    if (!for_us(ip_dst)) {
        return 0;
    }
    const uint8_t *icmp = ip + ihl;
    if (icmp[0] != 8 || icmp[1] != 0) {
        return 0; /* only echo requests are ours (nmap IE test) */
    }
    uint8_t pkt[S419_MAX_PKT];
    size_t n = s419_build_icmp_echo_reply(pkt, ip, p->tot_len,
                                          s419_icmp_ipid(), s419_par);
    if (n) {
        s419_output(pkt, n, s419_rd32(ip + 12));
    }
    return 1;
}

/* ----------------------------------------------------------------- timer */

static void s419_tick(void *arg)
{
    (void)arg;
    s419_tcp_tick();
    sys_timeout(10, s419_tick, NULL);
}

/* ------------------------------------------------------------------ init */

static void core_up(void *ctx)
{
    (void)ctx;
    s_pcb_tcp = raw_new_ip_type(IPADDR_TYPE_V4, IP_PROTO_TCP);
    s_pcb_udp = raw_new_ip_type(IPADDR_TYPE_V4, IP_PROTO_UDP);
    s_pcb_icmp = raw_new_ip_type(IPADDR_TYPE_V4, IP_PROTO_ICMP);
    s_pcb_tx = raw_new_ip_type(IPADDR_TYPE_V4, IP_PROTO_TCP);
    if (!s_pcb_tcp || !s_pcb_udp || !s_pcb_icmp || !s_pcb_tx) {
        ESP_LOGE(TAG, "raw pcb allocation failed");
        return;
    }
    s_pcb_tx->flags |= RAW_FLAGS_HDRINCL;
    raw_recv(s_pcb_tcp, on_tcp, NULL);
    raw_recv(s_pcb_udp, on_udp, NULL);
    raw_recv(s_pcb_icmp, on_icmp, NULL);
    sys_timeout(10, s419_tick, NULL);
    ESP_LOGI(TAG, "stack419 engine up (ttl=%u mss=%u wnd=%u wscale=%u ts=%d)",
             s419_par->ttl, s419_par->mss, s419_par->rcv_wnd,
             s419_par->wscale, s419_par->timestamps);
}

static void core_down(void *ctx)
{
    (void)ctx;
    if (s_pcb_tcp)  { raw_remove(s_pcb_tcp);  s_pcb_tcp = NULL; }
    if (s_pcb_udp)  { raw_remove(s_pcb_udp);  s_pcb_udp = NULL; }
    if (s_pcb_icmp) { raw_remove(s_pcb_icmp); s_pcb_icmp = NULL; }
    if (s_pcb_tx)   { raw_remove(s_pcb_tx);   s_pcb_tx = NULL; }
}

void s419_core_init(const mp_s419_params_t *params)
{
    s419_par = params;
    tcpip_callback_with_block(core_up, NULL, 1);
}
