/*
 * Mini TCP for the 4.19 personality.
 *
 * This is not a toy: it carries real honeypot sessions (telnet shells, HTTP
 * responses, SSH handshakes) while behaving like Linux 4.19 where scanners
 * can see it. Behaviours are modelled on the 4.19 tree:
 *   - handshake / SYN-ACK retransmit : tcp_input.c tcp_conn_request(),
 *                                      tcp_output.c tcp_make_synack()
 *   - closed-port / bad-state reset  : tcp_ipv4.c tcp_v4_send_reset()
 *   - list-state flag handling       : tcp_input.c tcp_rcv_state_process()
 *   - delayed ACK, RTO (RFC 6298)    : tcp_input.c tcp_ack()/tcp_timer.c
 *
 * Everything in this file runs in the lwIP tcpip thread (raw callbacks,
 * sys_timeout, tcpip_callback) except the s419_app_* entry points, which
 * are called from the connection task.
 */
#include <string.h>

#include "lwip/tcpip.h"

#include "esp_log.h"

#include "s419_isn.h"
#include "s419_pkt.h"
#include "s419_priv.h"

static const char *TAG = "s419_tcp";

/* TCP option kinds */
#define OPT_END   0
#define OPT_NOP   1
#define OPT_MSS   2
#define OPT_WS    3
#define OPT_SACKP 4
#define OPT_TS    8

#define S419_OPT_MSS_DEFAULT 536

/* --------------------------------------------------------------- helpers */

static void wake(s419_tcb *t)
{
    if (t->rx_sem) {
        xSemaphoreGive(t->rx_sem);
    }
    if (t->tx_sem) {
        xSemaphoreGive(t->tx_sem);
    }
}

static void send_plain(s419_tcb *t, uint32_t seq, uint32_t ack, uint8_t flags,
                       const void *payload, size_t len)
{
    uint8_t pkt[S419_MAX_PKT];
    if (S419_IP_HLEN + S419_TCP_HLEN + len > sizeof(pkt)) {
        return;
    }
    size_t n = s419_build_tcp(pkt, s419_par, t->lip, t->rip, t->lport, t->rport,
                              seq, ack, flags, s419_par->rcv_wnd, payload, len);
    s419_output(pkt, n, t->rip);
}

static void send_synack(s419_tcb *t)
{
    uint8_t pkt[S419_MAX_PKT];
    size_t n = s419_build_synack(pkt, s419_par, t->lip, t->rip,
                                 t->lport, t->rport,
                                 t->iss, t->rcv_nxt, t->ecn, t->peer_ws_ok);
    s419_output(pkt, n, t->rip);
}

static void send_ack(s419_tcb *t)
{
    t->ack_pending = false;
    t->segs_unacked = 0;
    send_plain(t, t->snd_nxt, t->rcv_nxt, S419_ACK, NULL, 0);
}

static void ack_now(s419_tcb *t)
{
    send_ack(t);
}

static void ack_schedule(s419_tcb *t)
{
    if (!t->ack_pending) {
        t->ack_pending = true;
        t->ack_due_ms = s419_now_ms() + (int64_t)s419_par->delack_ms;
    }
}

/* ------------------------------------------------------- reset semantics */

/* tcp_v4_send_reset(): quit the connection (tcp_ipv4.c). A segment that
 * acknowledges gets RST with seq=ack and no ACK flag; otherwise RST|ACK
 * with seq=0 and ack=seq+len+SYN+FIN. Window 0, no options. */
static void send_reset(uint32_t lip, uint32_t rip, uint16_t lport,
                       uint16_t rport, const uint8_t *th, size_t tcp_len)
{
    uint32_t seq = s419_rd32(th + 4);
    uint32_t ack = s419_rd32(th + 8);
    uint8_t flags = th[13];
    size_t hdr = (th[12] >> 4) * 4;
    uint32_t seg_len = 0;
    if (tcp_len > hdr) {
        seg_len = (uint32_t)(tcp_len - hdr);
    }

    uint32_t rseq, rack;
    uint8_t rflags;
    if (flags & S419_ACK) {
        rseq = ack;
        rack = 0;
        rflags = S419_RST;
    } else {
        rseq = 0;
        rack = seq + seg_len + ((flags & S419_SYN) ? 1 : 0) +
               ((flags & S419_FIN) ? 1 : 0);
        rflags = S419_RST | S419_ACK;
    }

    uint8_t pkt[S419_MAX_PKT];
    size_t n = s419_build_tcp(pkt, s419_par, lip, rip, lport, rport,
                              rseq, rack, rflags, 0, NULL, 0);
    s419_output(pkt, n, rip);
}

void s419_tcp_closed_reset(uint32_t lip, uint32_t rip, uint16_t lport,
                           uint16_t rport, const uint8_t *th, size_t tcp_len)
{
    send_reset(lip, rip, lport, rport, th, tcp_len);
}

/* Active reset for an established connection (tcp_send_active_reset). */
static void reset_conn(s419_tcb *t)
{
    send_plain(t, t->snd_nxt, t->rcv_nxt, S419_RST | S419_ACK, NULL, 0);
    t->dead = true;
    wake(t);
}

/* ------------------------------------------------------------- RTT / RTO */

static void rtt_sample(s419_tcb *t, uint32_t m)
{
    if (m == 0 || m > 60000) {
        return;
    }
    if (!t->rtt_valid) {
        t->srtt_ms = m;
        t->rttvar_ms = m / 2;
        t->rtt_valid = true;
    } else {
        uint32_t delta = m > t->srtt_ms ? m - t->srtt_ms : t->srtt_ms - m;
        t->rttvar_ms = (3 * t->rttvar_ms + delta) / 4;
        t->srtt_ms = (7 * t->srtt_ms + m) / 8;
    }
    uint32_t rto = t->srtt_ms + 4 * t->rttvar_ms;
    if (rto < s419_par->rto_min_ms) {
        rto = s419_par->rto_min_ms;
    }
    if (rto > s419_par->rto_max_ms) {
        rto = s419_par->rto_max_ms;
    }
    t->rto_ms = rto;
}

static void rto_arm(s419_tcb *t)
{
    if (t->rto_armed || (t->snd_nxt == t->snd_una)) {
        return;
    }
    if (t->snd_una == t->snd_nxt) {
        t->meas_ok = true;
    }
    t->rto_due_ms = s419_now_ms() + t->rto_ms;
    t->rto_armed = true;
}

/* ---------------------------------------------------------------- output */

/* Send as much buffered application data as the peer window and the fixed
 * congestion window allow, then the FIN if the app asked to close. */
static void flush(s419_tcb *t)
{
    if (t->dead || t->state < S419_S_ESTABLISHED) {
        return;
    }

    uint32_t cwnd = (uint32_t)s419_par->tx_cwnd_segs * t->peer_mss;
    uint32_t limit = t->peer_wnd < cwnd ? t->peer_wnd : cwnd;

    for (;;) {
        uint32_t flight = t->snd_nxt - t->snd_una;
        uint32_t data_flight = flight - (t->fin_sent ? 1 : 0);
        if (data_flight >= limit || data_flight >= t->tx_len) {
            break;
        }
        uint32_t want = t->peer_mss;
        if (want > t->tx_len - data_flight) {
            want = t->tx_len - data_flight;
        }
        if (want > limit - data_flight) {
            want = limit - data_flight;
        }

        uint8_t seg[S419_MAX_PKT];
        portENTER_CRITICAL(&t->lock);
        if (want > S419_TX_CAP) {
            want = S419_TX_CAP;
        }
        memcpy(seg, t->txbuf + data_flight, want);
        portEXIT_CRITICAL(&t->lock);

        bool fresh = (t->snd_una == t->snd_nxt);
        send_plain(t, t->snd_una + data_flight, t->rcv_nxt,
                   S419_ACK | S419_PSH, seg, want);
        t->snd_nxt += want;
        t->dupacks = 0;
        if (fresh) {
            t->meas_ok = true;
            t->sent_ms = s419_now_ms();
        }
        rto_arm(t);
    }

    if (t->close_posted && !t->fin_sent &&
        (t->snd_nxt - t->snd_una) == t->tx_len && t->peer_wnd > 0) {
        send_plain(t, t->snd_nxt, t->rcv_nxt, S419_ACK | S419_FIN, NULL, 0);
        t->snd_nxt += 1;
        t->fin_sent = true;
        t->meas_ok = false;
        rto_arm(t);
        if (t->peer_fin) {
            t->state = S419_S_LAST_ACK;
        } else {
            t->state = S419_S_FIN_WAIT_1;
        }
    }
}

void s419_tcp_flush_msg(void *ctx)
{
    s419_tcb *t = (s419_tcb *)ctx;
    portENTER_CRITICAL(&t->lock);
    t->flushed_posted = false;
    portEXIT_CRITICAL(&t->lock);
    flush(t);
    /* If the app already detached and everything is closed, reap now. */
    if (!t->app_attached && t->dead) {
        s419_tcb_unlink_free(t);
    }
}

void s419_tcp_close_msg(void *ctx)
{
    s419_tcb *t = (s419_tcb *)ctx;

    portENTER_CRITICAL(&t->lock);
    t->app_attached = false;
    if (t->rx_sem) {
        xSemaphoreGive(t->rx_sem); /* unblock a parked reader */
    }
    portEXIT_CRITICAL(&t->lock);

    if (t->state >= S419_S_ESTABLISHED && !t->fin_sent && !t->dead) {
        t->close_posted = true;
        flush(t);
    }
    if (t->dead) {
        /* Retransmission gave up or RST: nothing left to keep. */
        s419_tcb_unlink_free(t);
    }
}

/* ------------------------------------------------------- retransmission */

static void retransmit(s419_tcb *t)
{
    uint32_t flight = t->snd_nxt - t->snd_una;
    uint32_t data_flight = flight - (t->fin_sent ? 1 : 0);

    if (t->state == S419_S_SYN_RECV) {
        send_synack(t);
    } else if (data_flight > 0) {
        uint32_t want = t->peer_mss;
        if (want > data_flight) {
            want = data_flight;
        }
        uint8_t seg[S419_MAX_PKT];
        portENTER_CRITICAL(&t->lock);
        memcpy(seg, t->txbuf, want);
        portEXIT_CRITICAL(&t->lock);
        send_plain(t, t->snd_una, t->rcv_nxt, S419_ACK | S419_PSH, seg, want);
    } else if (t->fin_sent) {
        send_plain(t, t->snd_una, t->rcv_nxt, S419_ACK | S419_FIN, NULL, 0);
    } else {
        return;
    }

    t->meas_ok = false;
    t->retries++;
    uint32_t max = (t->state == S419_S_SYN_RECV)
                       ? s419_par->synack_retries
                       : s419_par->data_retries;
    if (t->retries > max) {
        t->dead = true;
        wake(t);
        return;
    }
    t->rto_ms = t->rto_ms * 2;
    if (t->rto_ms > s419_par->rto_max_ms) {
        t->rto_ms = s419_par->rto_max_ms;
    }
    t->rto_due_ms = s419_now_ms() + t->rto_ms;
}

/* ------------------------------------------------------------ SYN intake */

static void parse_syn_options(s419_tcb *t, const uint8_t *th, size_t tcp_len)
{
    size_t hdr = (th[12] >> 4) * 4;
    if (hdr <= S419_TCP_HLEN || hdr > tcp_len) {
        return;
    }
    const uint8_t *o = th + S419_TCP_HLEN;
    size_t n = hdr - S419_TCP_HLEN;
    size_t i = 0;
    while (i < n) {
        uint8_t kind = o[i];
        if (kind == OPT_END) {
            break;
        }
        if (kind == OPT_NOP) {
            i++;
            continue;
        }
        if (i + 1 >= n) {
            break;
        }
        uint8_t olen = o[i + 1];
        if (olen < 2 || i + olen > n) {
            break;
        }
        if (kind == OPT_MSS && olen == 4) {
            t->peer_mss = s419_rd16(o + i + 2);
            if (t->peer_mss < 536) {
                t->peer_mss = 536;
            }
            if (t->peer_mss > s419_par->mss) {
                t->peer_mss = s419_par->mss; /* clamp to local MSS */
            }
        } else if (kind == OPT_WS && olen == 3) {
            uint8_t ws = o[i + 2];
            if (ws <= 14) {
                t->peer_wscale = ws;
                t->peer_ws_ok = true;
            }
        }
        i += olen;
    }
}

void s419_tcp_new_syn(const s419_listener_t *lst,
                      uint32_t lip, uint32_t rip,
                      uint16_t lport, uint16_t rport,
                      const uint8_t *th, size_t tcp_len)
{
    /* Accept-queue behaviour under load: cap half-open sockets and drop
     * new SYNs (a loaded Linux drops SYNs unless syncookies are on, which
     * is exactly the "filtered" look a flood should produce). */
    unsigned halfopen = 0;
    for (s419_tcb *it = s419_tcb_first(); it; it = it->next) {
        if (it->state == S419_S_SYN_RECV) {
            halfopen++;
        }
    }
    if (halfopen >= S419_SYNRECV_CAP) {
        s419_report_synflood();
        return;
    }

    if (!mp_xport_budget_take()) {
        s419_report_overload(lst);
        return;
    }

    s419_tcb *t = s419_tcb_alloc();
    if (!t) {
        mp_xport_budget_give();
        return;
    }

    t->lip = lip;
    t->rip = rip;
    t->lport = lport;
    t->rport = rport;
    t->state = S419_S_SYN_RECV;
    t->listener = lst;
    t->peer_mss = S419_OPT_MSS_DEFAULT;
    t->peer_wnd = 65535;
    t->rto_ms = s419_par->rto_initial_ms;
    t->iss = s419_isn(rip, lip, rport, lport);
    t->snd_una = t->iss;
    t->snd_nxt = t->iss;
    t->rcv_nxt = s419_rd32(th + 4) + 1;
    parse_syn_options(t, th, tcp_len);

    /* Linux answers an ECN-setup SYN (ECE+CWR) with ECE under
     * tcp_ecn=2, the default. */
    uint8_t flags = th[13];
    if (s419_par->ecn_mode == 2 && (flags & S419_ECE) && (flags & S419_CWR)) {
        t->ecn = true;
    }

    s419_tcb_link(t);
    t->budget_taken = true;

    send_synack(t);
    t->snd_nxt = t->iss + 1;
    t->meas_ok = false;
    t->sent_ms = s419_now_ms();
    rto_arm(t);
}

/* -------------------------------------------------------------- input */

/* Handle ACK/seq bookkeeping common to established states. */
static void process_ack(s419_tcb *t, uint32_t ack)
{
    if (ack <= t->snd_una || ack > t->snd_nxt) {
        return;
    }
    uint32_t acked = ack - t->snd_una;

    portENTER_CRITICAL(&t->lock);
    if (acked > t->tx_len) {
        acked = t->tx_len;
    }
    if (acked) {
        memmove(t->txbuf, t->txbuf + acked, t->tx_len - acked);
        t->tx_len -= acked;
    }
    portEXIT_CRITICAL(&t->lock);

    t->snd_una = ack;
    t->retries = 0;
    if (t->meas_ok && t->sent_ms) {
        rtt_sample(t, (uint32_t)(s419_now_ms() - t->sent_ms));
    }
    if (t->snd_una == t->snd_nxt) {
        t->rto_armed = false;
        t->meas_ok = false;
        if (t->fin_sent) {
            t->fin_acked = true;
        }
        /* Close-state machine, tcp_rcv_state_process() */
        if (t->state == S419_S_LAST_ACK) {
            t->state = S419_S_CLOSED;
        } else if (t->state == S419_S_FIN_WAIT_1) {
            t->state = S419_S_FIN_WAIT_2;
            t->state_due_ms = s419_now_ms() + s419_par->finwait2_ms;
        } else if (t->state == S419_S_FIN_WAIT_2 && t->peer_fin) {
            t->state = S419_S_TIME_WAIT;
            t->state_due_ms = s419_now_ms() + s419_par->timewait_ms;
        }
    } else {
        t->sent_ms = s419_now_ms();
        t->rto_due_ms = s419_now_ms() + t->rto_ms;
        t->rto_armed = true;
    }
    if (t->tx_sem) {
        xSemaphoreGive(t->tx_sem);
    }
}

static void handle_fin(s419_tcb *t)
{
    t->peer_fin = true;
    t->rcv_nxt += 1;
    ack_now(t);
    wake(t);
    switch (t->state) {
    case S419_S_ESTABLISHED:
        t->state = S419_S_CLOSE_WAIT;
        break;
    case S419_S_FIN_WAIT_1:
        if (t->fin_acked) {
            t->state = S419_S_TIME_WAIT;
            t->state_due_ms = s419_now_ms() + s419_par->timewait_ms;
        } else {
            t->state = S419_S_FIN_WAIT_2;
        }
        break;
    case S419_S_FIN_WAIT_2:
        t->state = S419_S_TIME_WAIT;
        t->state_due_ms = s419_now_ms() + s419_par->timewait_ms;
        break;
    default:
        break;
    }
}

void s419_tcp_input(s419_tcb *t, const uint8_t *th, size_t tcp_len,
                    uint32_t ip_src, uint32_t ip_dst)
{
    (void)ip_src; (void)ip_dst;
    uint32_t seq = s419_rd32(th + 4);
    uint32_t ack = s419_rd32(th + 8);
    uint16_t wnd = s419_rd16(th + 14);
    uint8_t flags = th[13];
    size_t hdr = (th[12] >> 4) * 4;
    size_t data_len = tcp_len > hdr ? tcp_len - hdr : 0;
    const uint8_t *data = th + hdr;

    /* RST: Linux aborts the connection (TIME_WAIT is only assassinated on
     * a valid RST; we accept it there too). */
    if (flags & S419_RST) {
        t->dead = true;
        wake(t);
        if (!t->app_attached) {
            s419_tcb_unlink_free(t);
        }
        return;
    }

    if (t->state == S419_S_SYN_RECV) {
        if (flags & S419_SYN) {
            /* retransmitted SYN: resend the same SYN-ACK (tcp_check_req) */
            send_synack(t);
            return;
        }
        if ((flags & S419_ACK) && ack == t->snd_nxt) {
            t->snd_una = ack;
            t->rcv_nxt = seq;
            rtt_sample(t, (uint32_t)(s419_now_ms() - t->sent_ms));
            t->rto_armed = false;
            t->state = S419_S_ESTABLISHED;
            t->peer_wnd = (uint32_t)wnd << t->peer_wscale;
            s419_established(t);
        } else if (flags & S419_ACK) {
            send_reset(t->lip, t->rip, t->lport, t->rport, th, tcp_len);
        }
        return;
    }

    if (t->state == S419_S_TIME_WAIT) {
        if (flags & S419_FIN) {
            ack_now(t);
        }
        return;
    }

    /* window update */
    if (!(flags & S419_SYN)) {
        t->peer_wnd = (uint32_t)wnd << t->peer_wscale;
    }

    if (flags & S419_ACK) {
        process_ack(t, ack);
    }

    if (data_len > 0) {
        if (seq == t->rcv_nxt) {
            if (!t->app_attached) {
                t->rcv_nxt += data_len;
                ack_now(t);
            } else {
                portENTER_CRITICAL(&t->lock);
                bool fits = (t->rx_len + data_len <= S419_RX_CAP);
                if (fits) {
                    memcpy(t->rxbuf + t->rx_len, data, data_len);
                    t->rx_len += (uint16_t)data_len;
                } else {
                    t->rcv_nxt -= 0; /* keep window honest: drop + dup */
                }
                portEXIT_CRITICAL(&t->lock);

                if (fits) {
                    t->rcv_nxt += data_len;
                    t->segs_unacked++;
                    if (t->segs_unacked >= 2 || data_len < t->peer_mss) {
                        ack_now(t);
                    } else {
                        ack_schedule(t);
                    }
                    wake(t);
                } else {
                    /* no room: force peer retransmit with an immediate ACK */
                    ack_now(t);
                }
            }
        } else {
            /* out of order: duplicate ACK (we do not keep an ofo queue;
             * the sender retransmits, which is what a lossy path looks
             * like and keeps seq bookkeeping exact) */
            ack_now(t);
        }
    }

    if (flags & S419_FIN) {
        uint32_t fin_seq = seq + (uint32_t)data_len;
        if (fin_seq == t->rcv_nxt) {
            handle_fin(t);
        } else {
            ack_now(t);
        }
    }

    flush(t);
    if (t->dead && !t->app_attached) {
        s419_tcb_unlink_free(t);
    }
}

/* --------------------------------------------------------------- timers */

void s419_tcp_tick(void)
{
    int64_t now = s419_now_ms();
    for (s419_tcb *t = s419_tcb_first(); t; ) {
        s419_tcb *next = t->next;
        if (!t->dead) {
            if (t->ack_pending && now >= t->ack_due_ms) {
                send_ack(t);
            }
            if (t->rto_armed && now >= t->rto_due_ms) {
                retransmit(t);
            }
            if ((t->state == S419_S_TIME_WAIT ||
                 t->state == S419_S_FIN_WAIT_2) &&
                t->state_due_ms && now >= t->state_due_ms) {
                s419_tcb_unlink_free(t);
                continue;
            }
        }
        if (t->dead && !t->app_attached) {
            s419_tcb_unlink_free(t);
            continue;
        }
        t = next;
    }
}

/* ------------------------------------------------------------ app side */

static bool is_writable(const s419_tcb *t)
{
    if (t->dead || t->fin_sent) {
        return false;
    }
    return t->state == S419_S_ESTABLISHED || t->state == S419_S_CLOSE_WAIT;
}

int s419_app_recv(s419_tcb *t, void *buf, size_t len, uint32_t timeout_ms)
{
    for (;;) {
        portENTER_CRITICAL(&t->lock);
        if (t->rx_len) {
            uint16_t n = t->rx_len < len ? t->rx_len : (uint16_t)len;
            memcpy(buf, t->rxbuf, n);
            memmove(t->rxbuf, t->rxbuf + n, t->rx_len - n);
            t->rx_len -= n;
            portEXIT_CRITICAL(&t->lock);
            return (int)n;
        }
        bool fin = t->peer_fin;
        bool dead = t->dead;
        portEXIT_CRITICAL(&t->lock);

        if (fin) {
            return 0;
        }
        if (dead) {
            return MP_CONN_ABORTED;
        }
        if (xSemaphoreTake(t->rx_sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
            return MP_CONN_TIMEOUT;
        }
    }
}

int s419_app_send(s419_tcb *t, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = len;

    while (left) {
        portENTER_CRITICAL(&t->lock);
        bool ok = is_writable(t);
        uint16_t space = ok ? (uint16_t)(S419_TX_CAP - t->tx_len) : 0;
        if (space) {
            size_t n = left < space ? left : space;
            memcpy(t->txbuf + t->tx_len, p, n);
            t->tx_len += (uint16_t)n;
            left -= n;
            p += n;
        }
        bool post = space && !t->flushed_posted;
        if (post) {
            t->flushed_posted = true;
        }
        portEXIT_CRITICAL(&t->lock);

        if (!ok) {
            return -1;
        }
        if (post) {
            tcpip_callback(s419_tcp_flush_msg, t);
        }
        if (left) {
            if (xSemaphoreTake(t->tx_sem, pdMS_TO_TICKS(30000)) != pdTRUE) {
                return -1;
            }
        }
    }
    return 0;
}

void s419_app_shutdown(s419_tcb *t)
{
    t->close_posted = true;
    tcpip_callback(s419_tcp_flush_msg, t);
}

void s419_app_release(s419_tcb *t)
{
    tcpip_callback(s419_tcp_close_msg, t);
}
