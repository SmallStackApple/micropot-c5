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
#include "esp_random.h"
#include "esp_timer.h"

#include "mp_log.h"
#include "mp_net.h"
#include "mp_vdev.h"
#include "mp_vif.h"

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
static uint16_t        s_tcb_count;       /* live TCBs, capped by S419_MAX_TCBS */
static uint16_t        s_synrecv_count;
static uint16_t        s_icmp_id;
static int64_t         s_last_flood_evt_ms;
static int64_t         s_last_tx_warn_ms; /* raw_sendto warning throttle */
static int64_t         s_last_rx_ms = -1; /* any inbound IPv4, diagnostics */
static volatile uint32_t s_tick_count;    /* tcpip-thread heartbeat */

int64_t mp_s419_rx_age_ms(void)
{
    return s_last_rx_ms < 0 ? -1 : s419_now_ms() - s_last_rx_ms;
}

uint32_t mp_s419_tick_count(void)
{
    return s_tick_count;
}

uint16_t mp_s419_tcb_count(void)
{
    return s_tcb_count;
}

/* raw-PCB callback contract: returning 1 (RAW_INPUT_EATEN) transfers pbuf
 * ownership to the callback — ip4_input() will NOT free it. We never keep
 * input pbufs, so free on the spot. (Forgetting this leaked every
 * intercepted packet and slowly starved the WiFi RX path of buffers.) */
static uint8_t eat(struct pbuf *p)
{
    pbuf_free(p);
    return 1;
}

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

/* UDP replies for engine-level listeners (management plane). The buffer is
 * shared scratch — the mp_ctl task is the only producer. */
void s419_udp_send(uint32_t lip, uint32_t rip, uint16_t lport, uint16_t rport,
                   const void *data, size_t len)
{
    static uint8_t pkt[1400];
    if (len > sizeof(pkt) - S419_IP_HLEN - 8) {
        len = sizeof(pkt) - S419_IP_HLEN - 8; /* truncated reply beats none */
    }
    size_t n = s419_build_udp(pkt, data, len, s419_icmp_ipid(),
                              lip, rip, lport, rport, s419_par);
    s419_output(pkt, n, rip);
}

/* ---------------------------------------------------------------- output */

void s419_output(const uint8_t *pkt, size_t len, uint32_t dst_nbo)
{
    /* PBUF_LINK reserves PBUF_LINK_HLEN (Ethernet header) before the
     * payload: ethernet_output() prepends it with pbuf_add_header(), which
     * fails (ERR_BUF) without the headroom. PBUF_RAW_TX only reserves
     * PBUF_LINK_ENCAPSULATION_HLEN, which is 0 in ESP-IDF. */
    struct pbuf *p = pbuf_alloc(PBUF_LINK, (u16_t)len, PBUF_RAM);
    if (!p) {
        /* Memory-pressure symptom; rate-limited like the raw_sendto failure
         * below so it cannot flood the tcpip thread's UART under load. */
        int64_t now = s419_now_ms();
        if (now - s_last_tx_warn_ms >= 2000) {
            s_last_tx_warn_ms = now;
            ESP_LOGW(TAG, "tx: pbuf alloc failed (%u) (throttled)",
                     (unsigned)len);
        }
        return;
    }
    pbuf_take(p, pkt, (u16_t)len);
    ip_addr_t dst;
    ip_addr_t *dstp = &dst; /* avoid &local inside lwIP's boolean macros */
    ip_addr_set_ip4_u32(dstp, dst_nbo);
    err_t err = raw_sendto(s_pcb_tx, p, dstp); /* HDRINCL: sent verbatim */
    if (err != ERR_OK) {
        /* Under a flood this fires on every packet (ERR_MEM when the lwIP
         * pools are drained); logging each one over UART makes the overload
         * worse, so keep it visible but rate-limited. */
        int64_t now = s419_now_ms();
        if (now - s_last_tx_warn_ms >= 2000) {
            s_last_tx_warn_ms = now;
            ESP_LOGW(TAG, "tx: raw_sendto -> %d (throttled)", err);
        }
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
    if (s_tcb_count >= S419_MAX_TCBS) {
        return NULL; /* overloaded: drop the SYN, like a full SYN queue */
    }
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
    s_tcb_count++;
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
    s419_tcb_free_rx(tcb);
    s419_tcb_free_tx(tcb);
    free(tcb);
    if (s_tcb_count) {
        s_tcb_count--;
    }
}

/* Early ring release (tcpip thread). The app side is detached by the time
 * either is called, so rx has no reader and tx holds no unsent/unacked
 * data; a TCB kept only for TIME_WAIT then costs bytes instead of 20 KiB. */
void s419_tcb_free_rx(s419_tcb *tcb)
{
    heap_caps_free(tcb->rxbuf);
    tcb->rxbuf = NULL;
    tcb->rx_len = 0;
}

void s419_tcb_free_tx(s419_tcb *tcb)
{
    heap_caps_free(tcb->txbuf);
    tcb->txbuf = NULL;
    tcb->tx_len = 0;
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

#define S419_MAX_UDP_LISTENERS 4

typedef struct {
    uint32_t vaddr; /* lwIP word; 0 = wildcard */
    uint16_t port;
    bool (*allow)(uint32_t src_ip);
    s419_udp_handler_t handler;
} s419_udp_listener_t;

static s419_udp_listener_t s_udp_listeners[S419_MAX_UDP_LISTENERS];
static size_t              s_n_udp_listeners;

static const s419_udp_listener_t *s419_udp_listener_find(uint32_t vaddr,
                                                         uint16_t port)
{
    const s419_udp_listener_t *wild = NULL;
    for (size_t i = 0; i < s_n_udp_listeners; i++) {
        if (s_udp_listeners[i].port != port) {
            continue;
        }
        if (s_udp_listeners[i].vaddr == vaddr) {
            return &s_udp_listeners[i];
        }
        if (s_udp_listeners[i].vaddr == 0) {
            wild = &s_udp_listeners[i];
        }
    }
    return wild;
}

esp_err_t s419_udp_listen(uint32_t vaddr, uint16_t port,
                          bool (*allow)(uint32_t src_ip),
                          s419_udp_handler_t fn)
{
    if (s_n_udp_listeners >= S419_MAX_UDP_LISTENERS) {
        return ESP_ERR_NO_MEM;
    }
    for (size_t i = 0; i < s_n_udp_listeners; i++) {
        if (s_udp_listeners[i].port == port &&
            s_udp_listeners[i].vaddr == vaddr) {
            return ESP_ERR_INVALID_STATE; /* exact duplicate only */
        }
    }
    s419_udp_listener_t *l = &s_udp_listeners[s_n_udp_listeners++];
    l->vaddr = vaddr;
    l->port = port;
    l->allow = allow;
    l->handler = fn;
    return ESP_OK;
}

/* Exact vaddr match wins over the wildcard (vaddr 0 = primary), so two
 * personas can share a port on different virtual devices. */
const s419_listener_t *s419_listener_find(uint32_t vaddr, uint16_t port)
{
    const s419_listener_t *wild = NULL;
    for (size_t i = 0; i < s_n_listeners; i++) {
        if (s_listeners[i].port != port) {
            continue;
        }
        if (s_listeners[i].vaddr == vaddr) {
            return &s_listeners[i];
        }
        if (s_listeners[i].vaddr == 0) {
            wild = &s_listeners[i];
        }
    }
    return wild;
}

esp_err_t s419_listener_add(uint32_t vaddr, uint16_t port, const char *name,
                            const char *persona,
                            bool (*allow)(uint32_t src_ip),
                            mp_conn_handler_t handler, void *arg)
{
    if (s_n_listeners >= S419_MAX_LISTENERS) {
        return ESP_ERR_NO_MEM;
    }
    /* exact duplicate only: a wildcard listener must not block an
     * alias-specific one on the same port (and vice versa) */
    for (size_t i = 0; i < s_n_listeners; i++) {
        if (s_listeners[i].port == port && s_listeners[i].vaddr == vaddr) {
            return ESP_ERR_INVALID_STATE;
        }
    }
    s419_listener_t *l = &s_listeners[s_n_listeners++];
    l->vaddr = vaddr;
    l->port = port;
    l->name = name;
    l->persona = persona;
    l->allow = allow;
    l->handler = handler;
    l->arg = arg;
    ESP_LOGI(TAG, "%s listening on vaddr 0x%08lx port %u (stack419)", name,
             (unsigned long)vaddr, port);
    return ESP_OK;
}

/* --------------------------------------------------------------- receive */

static bool for_us(uint32_t dst_nbo)
{
    uint32_t ip = s419_our_ip();
    if (ip != 0 && dst_nbo == ip) {
        return true;
    }
    /* alias vdevs: reached through the mp_vif ip4 hook for inbound, but
     * keep the check here so the raw-PCB path stays consistent */
    return mp_vdev_by_vaddr(PP_HTONL(dst_nbo)) != NULL;
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
    s_last_rx_ms = s419_now_ms();
    size_t ihl = (ip[0] & 0x0f) * 4;
    uint32_t ip_src = s419_rd32(ip + 12);
    uint32_t ip_dst = s419_rd32(ip + 16);
    if (!for_us(ip_dst)) {
        return 0;
    }
    size_t ip_len = s419_rd16(ip + 2);
    if (ip_len > p->tot_len || ihl + S419_TCP_HLEN > ip_len) {
        return eat(p); /* truncated garbage for us: drop silently */
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
        return eat(p);
    }

    const s419_listener_t *lst = s419_listener_find(PP_HTONL(ip_dst), lport);
    if (lst) {
        if (flags & S419_ACK) {
            s419_tcp_closed_reset(ip_dst, ip_src, lport, rport, th, tcp_len);
        } else if (flags & S419_RST) {
            /* discard */
        } else if (flags & S419_SYN) {
            if (!(flags & S419_FIN)) {
                if (lst->allow && !lst->allow(PP_HTONL(ip_src))) {
                    return eat(p); /* ACL: filtered, silently dropped */
                }
                /* No per-packet logging here: this runs in the tcpip thread
                 * and a blocking UART write per SYN starves the idle task
                 * (task watchdog) under a flood. Connection attempts show
                 * up as the services' *.connect events instead. */
                s419_tcp_new_syn(lst, ip_dst, ip_src, lport, rport,
                                 th, tcp_len);
            } /* SYN+FIN: discard (T3: R=N) */
        } /* other flag combos: discard (T2: R=N) */
        return eat(p);
    }

    if (!(flags & S419_RST)) {
        s419_tcp_closed_reset(ip_dst, ip_src, lport, rport, th, tcp_len);
    }
    return eat(p);
}

static u8_t on_udp(void *arg, struct raw_pcb *pcb, struct pbuf *p,
                   const ip_addr_t *addr)
{
    (void)arg; (void)pcb; (void)addr;
    const uint8_t *ip = (const uint8_t *)p->payload;
    if (p->tot_len < S419_IP_HLEN + 8) {
        return 0;
    }
    s_last_rx_ms = s419_now_ms();
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
    /* UDP listeners (management plane): ACL failure = filtered, silent. */
    const s419_udp_listener_t *ul = s419_udp_listener_find(PP_HTONL(ip_dst), dport);
    if (ul) {
        if (ul->allow && !ul->allow(PP_HTONL(s419_rd32(ip + 12)))) {
            return eat(p);
        }
        size_t udp_len = s419_rd16(uh + 4);
        if (udp_len >= 8 && ihl + udp_len <= p->tot_len) {
            ul->handler(ip_dst, s419_rd32(ip + 12), dport,
                        s419_rd16(uh + 0), uh + 8, udp_len - 8);
        }
        return eat(p);
    }
    /* UDP to a closed port: ICMP port unreachable (nmap U1 test). The
     * buffer must fit the fully-quoted offending packet (up to 576). */
    uint8_t pkt[600];
    size_t n = s419_build_icmp_unreach(pkt, ip, p->tot_len, s419_icmp_ipid(),
                                       ip_dst, s419_rd32(ip + 12), s419_par);
    if (n) {
        s419_output(pkt, n, s419_rd32(ip + 12));
    }
    return eat(p);
}

static u8_t on_icmp(void *arg, struct raw_pcb *pcb, struct pbuf *p,
                    const ip_addr_t *addr)
{
    (void)arg; (void)pcb; (void)addr;
    const uint8_t *ip = (const uint8_t *)p->payload;
    if (p->tot_len < S419_IP_HLEN + 8) {
        return 0;
    }
    s_last_rx_ms = s419_now_ms();
    size_t ihl = (ip[0] & 0x0f) * 4;
    uint32_t ip_dst = s419_rd32(ip + 16);
    if (!for_us(ip_dst)) {
        return 0;
    }
    const uint8_t *icmp = ip + ihl;
    if (icmp[0] != 8) {
        return 0; /* only echo requests are ours */
    }
    /* Linux 4.19 answers echo requests with ANY code and copies the code
     * into the reply (icmp_reply reuses the received icmp_bxm) — nmap's
     * IE(1) probe uses code 9 and expects R=Y, CD=S. No per-packet log:
     * tcpip-thread UART writes starve the idle task under an ICMP flood. */
    uint8_t pkt[S419_MAX_PKT];
    size_t n = s419_build_icmp_echo_reply(pkt, ip, p->tot_len,
                                          s419_icmp_ipid(), s419_par);
    if (n) {
        s419_output(pkt, n, s419_rd32(ip + 12));
    }
    return eat(p);
}

/* ----------------------------------------------------------------- timer */

static void s419_tick(void *arg)
{
    (void)arg;
    s_tick_count++; /* tcpip-thread heartbeat, read by the stats task */
    s419_tcp_tick();
    sys_timeout(10, s419_tick, NULL);
}

/* Alias-destined packets arrive here through mp_vif's LWIP_HOOK_IP4_INPUT
 * glue: lwIP would drop them as not-for-us before its raw PCBs ever run.
 * Same ownership contract as the raw callbacks — returning true means the
 * pbuf was consumed (freed) here. */
bool s419_feed_ip4(struct pbuf *p)
{
    const uint8_t *ip = (const uint8_t *)p->payload;
    if (p->tot_len < S419_IP_HLEN || (ip[0] >> 4) != 4) {
        return false;
    }
    uint32_t ip_dst = s419_rd32(ip + 16);
    if (!mp_vdev_by_vaddr(PP_HTONL(ip_dst))) {
        return false; /* not an alias: lwIP's normal path handles it */
    }
    s_last_rx_ms = s419_now_ms();
    uint8_t eaten = 0;
    switch (ip[9]) {
    case IP_PROTO_TCP:
        eaten = on_tcp(NULL, NULL, p, NULL);
        break;
    case IP_PROTO_UDP:
        eaten = on_udp(NULL, NULL, p, NULL);
        break;
    case IP_PROTO_ICMP:
        eaten = on_icmp(NULL, NULL, p, NULL);
        break;
    default:
        break; /* unemulated protocol on an alias: fall through to drop */
    }
    if (!eaten) {
        pbuf_free(p);
    }
    return true;
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
    /* alias-destined traffic arrives via the mp_vif ip4-input hook */
    mp_vif_set_ip4_feed(s419_feed_ip4);
    s_icmp_id = (uint16_t)esp_random(); /* natural, non-zero counter start */
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
