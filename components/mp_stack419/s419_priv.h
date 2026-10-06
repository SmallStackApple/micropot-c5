#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/semphr.h"

#include "mp_s419_params.h"
#include "mp_xport.h"

/* -------------------------------------------------------------------------
 * mp_stack419 internals.
 *
 * Threading model: everything that touches a TCB's TCP state runs in the
 * lwIP tcpip thread (raw-PCB receive callbacks, sys_timeout timer and
 * tcpip_callback messages). Application connection tasks only touch the
 * rx/tx rings, and only under the TCB spinlock; blocking is done with
 * semaphores. A TCB is freed exclusively in the tcpip thread, and only
 * after the app side has detached (release posted).
 * ---------------------------------------------------------------------- */

#define S419_RX_CAP        4096
#define S419_TX_CAP        16384
#define S419_MAX_LISTENERS 12
#define S419_SYNRECV_CAP   32
#define S419_MAX_PKT       1600

/* Hard ceiling on live TCBs across all states (SYN_RECV, established,
 * FIN_WAIT_2, TIME_WAIT). Without it, a connection-churn flood accumulates
 * one small TCB per closed connection for the whole 60 s TIME_WAIT and can
 * exhaust the internal heap; with it, excess SYNs are dropped exactly like
 * an overloaded Linux host. */
#define S419_MAX_TCBS      96

/** lwIP ephemeral port floor (TCP/UDP_LOCAL_PORT_RANGE_START = 0xC000).
 *  Inbound traffic to these ports belongs to lwIP's own outbound flows
 *  (log collector) and must pass through untouched. */
#define S419_EPHEMERAL_MIN 49152

typedef enum {
    S419_S_CLOSED = 0,
    S419_S_SYN_RECV,
    S419_S_ESTABLISHED,
    S419_S_FIN_WAIT_1,
    S419_S_FIN_WAIT_2,
    S419_S_CLOSE_WAIT,
    S419_S_LAST_ACK,
    S419_S_TIME_WAIT,
} s419_state_t;

typedef struct {
    uint32_t          vaddr;   /* lwIP word; 0 = primary (wildcard) */
    uint16_t          port;    /* host byte order */
    const char       *name;
    const char       *persona; /* persona id stamped on sessions, or NULL */
    /* NULL or an ACL over the peer address (lwIP word); false = silently
     * drop the SYN, the port reads as filtered (iptables DROP realism) */
    bool             (*allow)(uint32_t src_ip);
    mp_conn_handler_t handler;
    void             *arg;
} s419_listener_t;

/* UDP listeners (management plane). Handler runs in the tcpip thread —
 * copy what you need and defer; engine-domain (big-endian) addresses. */
typedef void (*s419_udp_handler_t)(uint32_t lip, uint32_t rip,
                                   uint16_t lport, uint16_t rport,
                                   const uint8_t *data, size_t len);

typedef struct s419_tcb {
    struct s419_tcb *next;

    /* 4-tuple, all in network byte order (straight into packet builders) */
    uint32_t lip, rip;
    uint16_t lport, rport;

    uint8_t  state;
    bool     ecn;           /* negotiated ECN (ECE in SYN-ACK) */
    bool     overload;      /* accepted over budget: RST right after handshake */
    bool     peer_fin;      /* in-order FIN received */
    bool     dead;          /* RST received / timed out: no more output */
    bool     app_attached;  /* a conn task owns the app side */
    bool     close_posted;  /* app asked to close (FIN queued) */
    bool     fin_sent;
    bool     fin_acked;
    bool     flushed_posted;/* a flush tcpip_callback is already queued */

    /* peer parameters learned from the SYN */
    uint16_t peer_mss;
    uint8_t  peer_wscale;
    bool     peer_ws_ok;
    bool     peer_sack_ok;  /* SYN offered SACK-permitted (mirror in SYN-ACK) */
    uint32_t peer_wnd;      /* bytes, already scaled */

    /* sequence space */
    uint32_t iss, snd_una, snd_nxt;
    uint32_t rcv_nxt;

    /* retransmission (RFC 6298, tcp_timer.c semantics) */
    uint32_t rto_ms, srtt_ms, rttvar_ms;
    bool     rtt_valid, meas_ok;
    int64_t  sent_ms;       /* when the oldest unacked segment went out */
    int64_t  rto_due_ms;
    bool     rto_armed;
    uint8_t  retries;
    uint8_t  dupacks;

    /* delayed ACK (TCP_DELACK_MIN: 2nd full segment ACKs at once) */
    bool     ack_pending;
    int64_t  ack_due_ms;
    uint8_t  segs_unacked;

    /* state deadlines (TIME_WAIT, FIN_WAIT_2, SYN_RECV) */
    int64_t  state_due_ms;

    /* app-facing buffers (allocated in PSRAM when available) */
    portMUX_TYPE lock;
    SemaphoreHandle_t rx_sem; /* given when rx data / FIN / death arrives */
    SemaphoreHandle_t tx_sem; /* given when ACK frees tx space */
    uint8_t  *rxbuf;
    uint16_t  rx_len;         /* bytes buffered (in-order only) */
    uint8_t  *txbuf;
    uint16_t  tx_len;         /* bytes from snd_una to the app write end */

    const s419_listener_t *listener;
    struct mp_conn      *conn; /* NULL until the handshake completes */
} s419_tcb;

/* ---- s419_core.c ---- */
extern const mp_s419_params_t *s419_par;

void      s419_core_init(const mp_s419_params_t *params);
uint32_t  s419_our_ip(void);                  /* nbo, 0 when unknown */
uint16_t  s419_icmp_ipid(void);               /* incrementing counter */
void      s419_output(const uint8_t *pkt, size_t len, uint32_t dst_nbo);
s419_tcb *s419_tcb_alloc(void);
void      s419_tcb_link(s419_tcb *tcb);
void      s419_tcb_unlink_free(s419_tcb *tcb);

/* Release the app-facing rings early (tcpip thread, app side detached):
 * rx once nobody will read again, tx once every byte is acked. A lingering
 * TIME_WAIT TCB then costs bytes, not the 20 KiB of rings. */
void      s419_tcb_free_rx(s419_tcb *tcb);
void      s419_tcb_free_tx(s419_tcb *tcb);
s419_tcb *s419_tcb_find(uint32_t lip, uint32_t rip,
                        uint16_t lport, uint16_t rport);
s419_tcb *s419_tcbs(void);                    /* list head, tcpip thread only */
const s419_listener_t *s419_listener_find(uint32_t vaddr, uint16_t port);
esp_err_t s419_listener_add(uint32_t vaddr, uint16_t port, const char *name,
                            const char *persona,
                            bool (*allow)(uint32_t src_ip),
                            mp_conn_handler_t handler, void *arg);
esp_err_t s419_udp_listen(uint32_t vaddr, uint16_t port,
                          bool (*allow)(uint32_t src_ip),
                          s419_udp_handler_t fn);
/* Reply path for UDP listeners; callable from any task (precedent: the
 * app-task TCP flush path does the same via s419_output). */
void      s419_udp_send(uint32_t lip, uint32_t rip,
                        uint16_t lport, uint16_t rport,
                        const void *data, size_t len);
int64_t   s419_now_ms(void);
void      s419_report_overload(const s419_listener_t *lst);
void      s419_report_synflood(void);

/* ---- s419_tcp.c ---- */
void s419_tcp_new_syn(const s419_listener_t *lst,
                      uint32_t lip, uint32_t rip,
                      uint16_t lport, uint16_t rport,
                      const uint8_t *tcp_hdr, size_t tcp_len);
void s419_tcp_input(s419_tcb *tcb, const uint8_t *tcp_hdr, size_t tcp_len,
                    uint32_t ip_src, uint32_t ip_dst);
void s419_tcp_closed_reset(uint32_t lip, uint32_t rip,
                           uint16_t lport, uint16_t rport,
                           const uint8_t *tcp_hdr, size_t tcp_len);
void s419_tcp_active_reset(s419_tcb *tcb);
void s419_tcp_tick(void);                     /* 10 ms, tcpip thread */
void s419_tcp_flush_msg(void *ctx);           /* tcpip_callback: send pending */
void s419_tcp_close_msg(void *ctx);           /* tcpip_callback: FIN/detach */

/* app side (called from conn tasks via s419_xport conn ops) */
int  s419_app_recv(s419_tcb *tcb, void *buf, size_t len, uint32_t timeout_ms);
int  s419_app_send(s419_tcb *tcb, const void *buf, size_t len);
void s419_app_shutdown(s419_tcb *tcb);
void s419_app_release(s419_tcb *tcb);

/* ---- s419_xport.c ---- */
bool s419_established(s419_tcb *tcb);         /* tcpip thread; false = TCB gone */

static inline uint16_t s419_rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline uint32_t s419_rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
