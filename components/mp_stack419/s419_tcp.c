/*
 * Mini TCP session machine, following Linux 4.19 net/ipv4/tcp_input.c and
 * tcp_output.c where it is observable from the outside:
 *
 *  - SYN-ACK retransmission and connection request handling
 *    (tcp_conn_request / tcp_check_req)
 *  - RST semantics of tcp_v4_send_reset (closed ports and bad segments)
 *  - delayed ACKs, RFC 6298 RTO with Karn's rule (tcp_timer.c)
 *  - FIN state machine and TIME_WAIT (tcp_fin_timeout / TCP_TIMEWAIT_LEN)
 *
 * Everything here runs in the lwIP tcpip thread except the s419_app_*
 * entry points, which are called by connection tasks and only touch the
 * rings under the TCB spinlock.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/tcpip.h"

#include "esp_log.h"

#include "s419_isn.h"
#include "s419_pkt.h"
#include "s419_priv.h"

static const char *TAG = "s419tcp";

#define S419_SYN_RECV_TIMEOUT_MS 20000

/* --------------------------------------------------------------- output */

static void send_synack(s419_tcb *tcb)
{
    uint8_t pkt[S419_IP_HLEN + 60];
    /* The fixed builder emits the 4.19 option layout including a window
     * scale word, which is what a peer that offered WS expects. */
    size_t n = s419_build_synack(pkt, s419_par, tcb->lip, tcb->rip,
                                 tcb->lport, tcb->rport, tcb->iss,
                                 tcb->rcv_nxt, tcb->ecn);
    s419_output(pkt, n, tcb->rip);
}

static void send_ack(s419_tcb *tcb)
{
    uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN];
    size_t n = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                              tcb->lport, tcb->rport, tcb->snd_nxt,
                              tcb->rcv_nxt, S419_ACK, s419_par->rcv_wnd,
                              NULL, 0);
    s419_output(pkt, n, tcb->rip);
    tcb->ack_pending = false;
    tcb->segs_unacked = 0;
}

/* tcp_send_active_reset(): RST|ACK, seq=snd_nxt, ack=rcv_nxt. */
static void send_active_reset(s419_tcb *tcb)
{
    uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN];
    size_t n = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                              tcb->lport, tcb->rport, tcb->snd_nxt,
                              tcb->rcv_nxt, S419_RST | S419_ACK, 0, NULL, 0);
    s419_output(pkt, n, tcb->rip);
}

/* tcp_v4_send_reset(): what a closed port (or a LISTEN socket fed an ACK)
 * answers. With ACK: seq := ack_seq, RST only. Otherwise seq := 0 and
 * ack := seq + len + syn + fin, RST|ACK. Window is 0, no options.
 * This produces exactly nmap T4-T7. */
void s419_tcp_closed_reset(uint32_t lip, uint32_t rip,
                           uint16_t lport, uint16_t rport,
                           const uint8_t *th, size_t tcp_len)
{
    uint8_t flags = th[13];
    if (flags & S419_RST) {
        return;
    }
    size_t doff = (size_t)(th[12] >> 4) * 4;
    if (doff < S419_TCP_HLEN || doff > tcp_len) {
        return;
    }
    size_t plen = tcp_len - doff;

    uint32_t seq, ack;
    uint8_t  out_flags;
    if (flags & S419_ACK) {
        seq = s419_rd32(th + 8);
        ack = 0;
        out_flags = S419_RST;
    } else {
        seq = 0;
        ack = s419_rd32(th + 4) + (uint32_t)plen;
        if (flags & S419_SYN) {
            ack++;
        }
        if (flags & S419_FIN) {
            ack++;
        }
        out_flags = S419_RST | S419_ACK;
    }

    uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN];
    size_t n = s419_build_tcp(pkt, s419_par, lip, rip, lport, rport,
                              seq, ack, out_flags, 0, NULL, 0);
    s419_output(pkt, n, rip);
}

/* ------------------------------------------------------------- RTO / RTT */

static void rto_rearm(s419_tcb *tcb, int64_t now)
{
    tcb->sent_ms = now;
    tcb->rto_due_ms = now + (int64_t)tcb->rto_ms;
    tcb->rto_armed = true;
}

static void rto_clear(s419_tcb *tcb)
{
    tcb->rto_armed = false;
}

/* RFC 6298 with Linux clamps (tcp_ack_update_rtt / tcp_set_rto). */
static void rtt_sample(s419_tcb *tcb, uint32_t sample_ms)
{
    if (sample_ms == 0) {
        sample_ms = 1;
    }
    if (!tcb->rtt_valid) {
        tcb->srtt_ms = sample_ms;
        tcb->rttvar_ms = sample_ms / 2;
        tcb->rtt_valid = true;
    } else {
        int32_t err = (int32_t)sample_ms - (int32_t)tcb->srtt_ms;
        if (err < 0) {
            err = -err;
        }
        tcb->rttvar_ms = (tcb->rttvar_ms * 3 + (uint32_t)err) / 4;
        tcb->srtt_ms = (tcb->srtt_ms * 7 + sample_ms) / 8;
    }
    uint32_t rto = tcb->srtt_ms + 4 * tcb->rttvar_ms;
    if (rto < s419_par->rto_min_ms) {
        rto = s419_par->rto_min_ms;
    }
    if (rto > s419_par->rto_max_ms) {
        rto = s419_par->rto_max_ms;
    }
    tcb->rto_ms = rto;
}

/* -------------------------------------------------------------- output TX */

static uint32_t tx_in_flight(const s419_tcb *tcb)
{
    return tcb->snd_nxt - tcb->snd_una;
}

static uint32_t tx_pending(const s419_tcb *tcb)
{
    return (uint32_t)tcb->tx_len - tx_in_flight(tcb);
}

/* Effective send window: peer's advertised window (scaled) limited by the
 * fixed congestion window. No slow start: honeypot replies are tiny. */
static uint32_t tx_usable(const s419_tcb *tcb)
{
    uint32_t cwnd = (uint32_t)s419_par->tx_cwnd_segs * tcb->peer_mss;
    uint32_t wnd = tcb->peer_wnd; /* zero means the peer shut its window */
    if (wnd > cwnd) {
        wnd = cwnd;
    }
    uint32_t flight = tx_in_flight(tcb);
    return wnd > flight ? wnd - flight : 0;
}

/* Send pending data, then the queued FIN, respecting the window. */
static void flush_tx(s419_tcb *tcb)
{
    if (tcb->dead || tcb->state == S419_S_SYN_RECV) {
        return;
    }
    int64_t now = s419_now_ms();

    while (tx_pending(tcb) > 0) {
        uint32_t usable = tx_usable(tcb);
        if (usable == 0) {
            break;
        }
        uint32_t off = tx_in_flight(tcb);
        uint32_t chunk = tx_pending(tcb);
        if (chunk > tcb->peer_mss) {
            chunk = tcb->peer_mss;
        }
        if (chunk > usable) {
            chunk = usable;
        }
        uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN + 1460];
        size_t n = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                                  tcb->lport, tcb->rport, tcb->snd_nxt,
                                  tcb->rcv_nxt, S419_ACK | S419_PSH,
                                  s419_par->rcv_wnd, tcb->txbuf + off, chunk);
        s419_output(pkt, n, tcb->rip);
        tcb->snd_nxt += chunk;
        if (!tcb->rto_armed) {
            rto_rearm(tcb, now);
        }
        tcb->meas_ok = true;
        if (tx_pending(tcb) == 0) {
            break;
        }
    }

    if (tcb->fin_queued && !tcb->fin_sent && tx_pending(tcb) == 0 &&
        tx_usable(tcb) > 0) {
        uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN];
        uint8_t flags = S419_FIN | S419_ACK;
        if (tx_in_flight(tcb) == 0) {
            /* no data riding along: FIN is the only thing unacked */
            tcb->meas_ok = false;
        }
        size_t n = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                                  tcb->lport, tcb->rport, tcb->snd_nxt,
                                  tcb->rcv_nxt, flags, s419_par->rcv_wnd,
                                  NULL, 0);
        s419_output(pkt, n, tcb->rip);
        tcb->snd_nxt++;
        tcb->fin_sent = true;
        if (!tcb->rto_armed) {
            rto_rearm(tcb, now);
        }
    }
}

/* Retransmit the oldest unacked byte (data or FIN), tcp_retransmit_skb(). */
static void retransmit(s419_tcb *tcb)
{
    if (tcb->state == S419_S_SYN_RECV) {
        send_synack(tcb);
        return;
    }
    if (tcb->dead) {
        return;
    }
    if (tx_in_flight(tcb) == 0) {
        rto_clear(tcb);
        return;
    }

    if (tx_in_flight(tcb) == 1 && tcb->fin_sent &&
        tcb->snd_nxt - tcb->snd_una == 1) {
        /* only the FIN is outstanding */
        uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN];
        size_t n = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                                  tcb->lport, tcb->rport, tcb->snd_una,
                                  tcb->rcv_nxt, S419_FIN | S419_ACK,
                                  s419_par->rcv_wnd, NULL, 0);
        s419_output(pkt, n, tcb->rip);
        return;
    }

    uint32_t len = tx_in_flight(tcb);
    if (tcb->fin_sent && len > 0) {
        len--; /* don't retransmit the FIN sequence byte as data */
    }
    if (len > tcb->peer_mss) {
        len = tcb->peer_mss;
    }
    uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN + 1460];
    size_t n = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                              tcb->lport, tcb->rport, tcb->snd_una,
                              tcb->rcv_nxt, S419_ACK | S419_PSH,
                              s419_par->rcv_wnd, tcb->txbuf, len);
    s419_output(pkt, n, tcb->rip);
    tcb->meas_ok = false; /* Karn: no RTT sample from retransmitted data */
}

static void rto_backoff(s419_tcb *tcb)
{
    uint32_t next = tcb->rto_ms ? tcb->rto_ms * 2 : s419_par->rto_initial_ms;
    if (next > s419_par->rto_max_ms) {
        next = s419_par->rto_max_ms;
    }
    tcb->rto_ms = next;
}

static void connection_dead(s419_tcb *tcb)
{
    tcb->dead = true;
    tcb->state = S419_S_CLOSED;
    rto_clear(tcb);
    if (tcb->rx_sem) {
        xSemaphoreGive(tcb->rx_sem);
    }
    if (tcb->tx_sem) {
        xSemaphoreGive(tcb->tx_sem);
    }
}

/* Free when both sides are done: app detached and no state to hold. */
static void try_free(s419_tcb *tcb)
{
    if (tcb->app_attached) {
        return;
    }
    if (tcb->state == S419_S_TIME_WAIT && !tcb->dead) {
        return; /* held until the 2*MSL timer */
    }
    if (tcb->state == S419_S_CLOSED || tcb->dead) {
        if (tcb->budget_held) {
            tcb->budget_held = false;
            mp_xport_budget_give();
        }
        s419_tcb_unlink_free(tcb);
    }
}

/* ------------------------------------------------------------- SYN parse */

typedef struct {
    uint16_t mss;
    uint8_t  wscale;
    bool     ws_ok;
    bool     sack_ok;
    bool     ecn;
} syn_opts_t;

/* tcp_parse_options() subset: MSS, window scale, SACK permitted; ECN from
 * the ECE/CWR flags (Linux tcp_ecn_accept / TCP_ECN_ok). */
static void parse_syn_opts(const uint8_t *th, size_t tcp_len, syn_opts_t *o)
{
    o->mss = 536; /* RFC 1122 default when the peer sends no MSS */
    o->wscale = 0;
    o->ws_ok = false;
    o->sack_ok = false;
    o->ecn = false;

    uint8_t flags = th[13];
    o->ecn = s419_par->ecn_mode != 0 &&
             ((flags & S419_ECE) && (flags & S419_CWR));

    size_t doff = (size_t)(th[12] >> 4) * 4;
    if (doff <= S419_TCP_HLEN || doff > tcp_len) {
        return;
    }
    const uint8_t *p = th + S419_TCP_HLEN;
    const uint8_t *end = th + doff;
    while (p < end) {
        uint8_t kind = p[0];
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            p++;
            continue;
        }
        if (p + 1 >= end) {
            break;
        }
        uint8_t len = p[1];
        if (len < 2 || p + len > end) {
            break;
        }
        if (kind == 2 && len == 4) {
            o->mss = s419_rd16(p + 2);
        } else if (kind == 3 && len == 3) {
            o->ws_ok = true;
            o->wscale = p[2] > 14 ? 14 : p[2];
        } else if (kind == 4 && len == 2) {
            o->sack_ok = true;
        }
        p += len;
    }
}

/* ------------------------------------------------------------ conn setup */

void s419_tcp_new_syn(const s419_listener_t *lst,
                      uint32_t lip, uint32_t rip,
                      uint16_t lport, uint16_t rport,
                      const uint8_t *th, size_t tcp_len)
{
    if (!s419_core_ready()) {
        return;
    }

    {
        static bool first = true;
        if (first) {
            first = false;
            ESP_LOGW(TAG, "first SYN -> listener %s:%u (ready=%d our_ip=%08lx)",
                     lst->name, lst->port, (int)s419_core_ready(),
                     (unsigned long)s419_our_ip());
        }
    }

    s419_tcb *tcb = s419_tcb_find(lip, rip, lport, rport);
    if (tcb == NULL && s419_synrecv_count() >= S419_SYNRECV_CAP) {
        /* backlog pressure: drop new SYNs and report the flood instead of
         * exhausting the heap with half-open TCBs */
        s419_report_synflood();
        return;
    }
    if (tcb == NULL) {
        tcb = s419_tcb_alloc();
        if (!tcb) {
            return;
        }
        syn_opts_t o;
        parse_syn_opts(th, tcp_len, &o);
        tcb->lip = lip;
        tcb->rip = rip;
        tcb->lport = lport;
        tcb->rport = rport;
        tcb->state = S419_S_SYN_RECV;
        tcb->peer_mss = o.mss < 216 ? 536 : o.mss;
        tcb->peer_ws_ok = o.ws_ok;
        tcb->peer_wscale = o.wscale;
        tcb->peer_wnd = (uint32_t)s419_rd16(th + 14) << (o.ws_ok ? o.wscale : 0);
        tcb->ecn = o.ecn;
        tcb->iss = s419_isn(rip, lip, rport, lport);
        tcb->snd_una = tcb->iss;
        tcb->snd_nxt = tcb->iss;
        tcb->rcv_nxt = s419_rd32(th + 4) + 1; /* SYN occupies one sequence */
        tcb->rto_ms = s419_par->rto_initial_ms;
        tcb->listener = lst;
        tcb->state_due_ms = s419_now_ms() + S419_SYN_RECV_TIMEOUT_MS;
        tcb->budget_held = mp_xport_budget_take();
        tcb->overload = !tcb->budget_held;
        s419_tcb_link(tcb);
        s419_synrecv_inc();
        ESP_LOGD(TAG, "SYN %08lx:%u -> SYN-ACK iss=%08lx", (unsigned long)rip,
                 rport, (unsigned long)tcb->iss);
    }
    send_synack(tcb);
    rto_rearm(tcb, s419_now_ms());
}

/* ---------------------------------------------------------- state machine */

void s419_tcp_input(s419_tcb *tcb, const uint8_t *th, size_t tcp_len,
                    uint32_t ip_src, uint32_t ip_dst)
{
    (void)ip_src; (void)ip_dst;
    if (tcp_len < S419_TCP_HLEN) {
        return;
    }
    size_t doff = (size_t)(th[12] >> 4) * 4;
    if (doff < S419_TCP_HLEN || doff > tcp_len) {
        return;
    }
    uint8_t  flags = th[13];
    uint32_t seq = s419_rd32(th + 4);
    uint32_t ack = s419_rd32(th + 8);
    uint16_t wnd = s419_rd16(th + 14);
    const uint8_t *payload = th + doff;
    size_t   plen = tcp_len - doff;
    int64_t  now = s419_now_ms();

    /* RST is terminal in every state (tcp_reset / tcp_rcv_established). */
    if (flags & S419_RST) {
        if (tcb->state == S419_S_SYN_RECV) {
            s419_synrecv_dec();
        }
        connection_dead(tcb);
        try_free(tcb);
        return;
    }

    if (flags & S419_SYN) {
        if (tcb->state == S419_S_SYN_RECV) {
            send_synack(tcb); /* tcp_check_req retransmits the SYN-ACK */
            return;
        }
        /* SYN inside an established window: tcp_validate_incoming resets */
        send_active_reset(tcb);
        connection_dead(tcb);
        try_free(tcb);
        return;
    }

    switch (tcb->state) {
    case S419_S_SYN_RECV:
        if (!(flags & S419_ACK)) {
            return; /* stray segment before the handshake completes */
        }
        if (ack != tcb->snd_nxt) {
            /* tcp_check_req: invalid ack -> send RST and drop the request */
            s419_tcp_closed_reset(tcb->lip, tcb->rip, tcb->lport, tcb->rport,
                                  th, tcp_len);
            s419_synrecv_dec();
            if (tcb->budget_held) {
                tcb->budget_held = false;
                mp_xport_budget_give();
            }
            s419_tcb_unlink_free(tcb);
            return;
        }
        /* handshake complete */
        tcb->snd_una = tcb->snd_nxt;
        tcb->rcv_nxt = seq; /* ACK carries no data */
        rto_clear(tcb);
        s419_synrecv_dec();
        tcb->state = S419_S_ESTABLISHED;
        if (tcb->overload) {
            send_active_reset(tcb);
            connection_dead(tcb);
            s419_report_overload(tcb->listener);
            try_free(tcb);
            return;
        }
        if (!s419_established(tcb)) {
            return; /* TCB was aborted and freed */
        }
        /* ACK may carry data (simultaneous open is out of scope) */
        if (plen == 0) {
            return;
        }
        /* fall through to shared data handling below */
        [[fallthrough]];

    case S419_S_ESTABLISHED:
    case S419_S_FIN_WAIT_1:
    case S419_S_FIN_WAIT_2:
    case S419_S_CLOSE_WAIT:
    case S419_S_LAST_ACK:
        break;

    case S419_S_TIME_WAIT:
        send_ack(tcb); /* tcp_timewait_state_process answers strays */
        return;

    default:
        return;
    }

    /* peer window (scaled by the scale it announced in its SYN) */
    tcb->peer_wnd = (uint32_t)wnd << (tcb->peer_ws_ok ? tcb->peer_wscale : 0);
    if (tcb->peer_wnd == 0 && tx_pending(tcb) > 0) {
        /* zero window: nothing to send until a window update arrives */
    }

    /* ---- ACK processing (tcp_ack) ---- */
    if (flags & S419_ACK) {
        if (ack > tcb->snd_nxt) {
            send_ack(tcb); /* challenge ACK, tcp_send_challenge_ack */
            return;
        }
        if (ack > tcb->snd_una) {
            uint32_t acked = ack - tcb->snd_una;
            if (tcb->rto_armed && tcb->meas_ok && tcb->sent_ms) {
                rtt_sample(tcb, (uint32_t)(now - tcb->sent_ms));
            }
            if (acked > tcb->tx_len) {
                acked = tcb->tx_len;
            }
            tcb->tx_len -= (uint16_t)acked;
            if (tcb->tx_len) {
                memmove(tcb->txbuf, tcb->txbuf + acked, tcb->tx_len);
            }
            tcb->snd_una = ack;
            tcb->retries = 0;
            tcb->dupacks = 0;
            if (tx_in_flight(tcb) == 0) {
                tcb->meas_ok = false;
                rto_clear(tcb);
            } else {
                rto_rearm(tcb, now);
            }
            if (tcb->fin_sent && tcb->snd_una == tcb->snd_nxt) {
                tcb->fin_acked = true;
            }
            if (tcb->tx_sem) {
                xSemaphoreGive(tcb->tx_sem);
            }

            if (tcb->state == S419_S_FIN_WAIT_1 && tcb->fin_acked) {
                tcb->state = S419_S_FIN_WAIT_2;
                tcb->state_due_ms = now + (int64_t)s419_par->finwait2_ms;
            } else if (tcb->state == S419_S_LAST_ACK && tcb->fin_acked) {
                tcb->state = S419_S_CLOSED;
                try_free(tcb);
                return;
            } else if (tcb->state == S419_S_TIME_WAIT && tcb->fin_acked) {
                /* refresh the 2*MSL timer on retransmitted FIN */
                tcb->state_due_ms = now + (int64_t)s419_par->timewait_ms;
            }
        } else if (plen == 0 && !(flags & S419_FIN) && tx_in_flight(tcb) > 0) {
            /* duplicate ACK: tcp_fastretransmit needs 3 (dupacks) */
            if (++tcb->dupacks == 3) {
                retransmit(tcb);
                rto_rearm(tcb, now);
            }
        }
    }

    /* ---- in-order data ---- */
    if (plen > 0) {
        if (seq == tcb->rcv_nxt) {
            if (tcb->app_attached && (uint32_t)tcb->rx_len + plen <= S419_RX_CAP) {
                memcpy(tcb->rxbuf + tcb->rx_len, payload, plen);
                tcb->rx_len = (uint16_t)(tcb->rx_len + plen);
                tcb->rcv_nxt += plen;
                if (tcb->rx_sem) {
                    xSemaphoreGive(tcb->rx_sem);
                }
                /* delayed ACK: ack at once on the 2nd segment or a full one */
                tcb->segs_unacked++;
                if (tcb->segs_unacked >= 2 || plen >= tcb->peer_mss) {
                    send_ack(tcb);
                } else if (!tcb->ack_pending) {
                    tcb->ack_pending = true;
                    tcb->ack_due_ms = now + (int64_t)s419_par->delack_ms;
                }
            } else {
                send_ack(tcb); /* no room: let the peer retransmit later */
            }
        } else {
            send_ack(tcb); /* out of order: duplicate ACK, tcp_send_dupack */
        }
    }

    /* ---- FIN ---- */
    if (flags & S419_FIN) {
        if (seq + (uint32_t)plen == tcb->rcv_nxt) {
            tcb->rcv_nxt++;
            tcb->peer_fin = true;
            send_ack(tcb);
            if (tcb->rx_sem) {
                xSemaphoreGive(tcb->rx_sem);
            }
            switch (tcb->state) {
            case S419_S_ESTABLISHED:
            case S419_S_SYN_RECV:
                tcb->state = S419_S_CLOSE_WAIT;
                break;
            case S419_S_FIN_WAIT_1:
                if (tcb->fin_acked) {
                    tcb->state = S419_S_TIME_WAIT;
                    tcb->state_due_ms = now + (int64_t)s419_par->timewait_ms;
                } else {
                    tcb->state = S419_S_LAST_ACK;
                }
                break;
            case S419_S_FIN_WAIT_2:
                tcb->state = S419_S_TIME_WAIT;
                tcb->state_due_ms = now + (int64_t)s419_par->timewait_ms;
                break;
            default:
                break;
            }
        } else {
            send_ack(tcb);
        }
    }

    flush_tx(tcb);
}

/* ------------------------------------------------------------- app close */

void s419_tcp_abort(s419_tcb *tcb)
{
    if (!tcb->dead) {
        send_active_reset(tcb);
        connection_dead(tcb);
    }
    if (tcb->budget_held) {
        tcb->budget_held = false;
        mp_xport_budget_give();
    }
    if (tcb->state == S419_S_SYN_RECV) {
        s419_synrecv_dec();
    }
    tcb->app_attached = false;
    s419_tcb_unlink_free(tcb);
}

void s419_tcp_close_msg(void *ctx)
{
    s419_tcb *tcb = (s419_tcb *)ctx;
    tcb->close_posted = true;
    if (tcb->dead) {
        return;
    }
    if (tcb->state == S419_S_TIME_WAIT) {
        return;
    }
    /* orderLY release: all data first, then FIN (tcp_close) */
    tcb->fin_queued = true;
    if (tcb->state == S419_S_CLOSE_WAIT) {
        /* peer already sent FIN: our FIN moves us to LAST_ACK */
    } else if (tcb->state == S419_S_ESTABLISHED) {
        tcb->state = S419_S_FIN_WAIT_1;
    }
    flush_tx(tcb);
    if (!tcb->fin_sent && tx_pending(tcb) == 0) {
        /* flush_tx emits the FIN when the window allows */
    }
}

void s419_tcp_flush_msg(void *ctx)
{
    s419_tcb *tcb = (s419_tcb *)ctx;
    tcb->flushed_posted = false;
    flush_tx(tcb);
}

void s419_tcp_detach_msg(void *ctx)
{
    s419_tcb *tcb = (s419_tcb *)ctx;
    tcb->app_attached = false;
    if (tcb->budget_held) {
        /* the budget counts live application sessions, exactly like the
         * lwIP backend (the TCB may linger in TIME_WAIT without one) */
        tcb->budget_held = false;
        mp_xport_budget_give();
    }
    if (!tcb->close_posted && !tcb->dead && tcb->state != S419_S_TIME_WAIT) {
        tcb->close_posted = true;
        tcb->fin_queued = true;
        if (tcb->state == S419_S_ESTABLISHED) {
            tcb->state = S419_S_FIN_WAIT_1;
        }
    }
    flush_tx(tcb);
    try_free(tcb);
}

/* ------------------------------------------------------------------ tick */

void s419_tcp_tick(void)
{
    int64_t now = s419_now_ms();

    s419_tcb *tcb = s419_tcb_head;
    while (tcb) {
        s419_tcb *next = tcb->next;

        if (tcb->dead) {
            tcb = next;
            continue;
        }

        /* retransmission timeout */
        if (tcb->rto_armed && now >= tcb->rto_due_ms) {
            uint8_t max_retries = (tcb->state == S419_S_SYN_RECV)
                                      ? s419_par->synack_retries
                                      : s419_par->data_retries;
            if (tcb->retries >= max_retries) {
                /* give up: Linux drops silently (ETIMEDOUT) */
                if (tcb->state == S419_S_SYN_RECV) {
                    s419_synrecv_dec();
                }
                connection_dead(tcb);
                tcb->state = S419_S_CLOSED;
                try_free(tcb);
                tcb = next;
                continue;
            }
            tcb->retries++;
            rto_backoff(tcb);
            retransmit(tcb);
            rto_rearm(tcb, now);
        }

        /* delayed ACK */
        if (tcb->ack_pending && now >= tcb->ack_due_ms) {
            send_ack(tcb);
        }

        /* state deadlines: SYN_RECV gives up, FIN_WAIT_2 lingers,
         * TIME_WAIT is the 2*MSL hold */
        if (tcb->state_due_ms && now >= tcb->state_due_ms) {
            if (tcb->state == S419_S_SYN_RECV) {
                s419_synrecv_dec();
                if (tcb->budget_held) {
                    tcb->budget_held = false;
                    mp_xport_budget_give();
                }
                connection_dead(tcb);
                try_free(tcb);
                tcb = next;
                continue;
            }
            if (tcb->state == S419_S_FIN_WAIT_2) {
                tcb->state = S419_S_CLOSED;
                try_free(tcb);
                tcb = next;
                continue;
            }
            if (tcb->state == S419_S_TIME_WAIT) {
                tcb->state = S419_S_CLOSED;
                try_free(tcb);
                tcb = next;
                continue;
            }
        }

        tcb = next;
    }
}

/* --------------------------------------------------- application interface */

int s419_app_recv(s419_tcb *tcb, void *buf, size_t len, uint32_t timeout_ms)
{
    for (;;) {
        portENTER_CRITICAL(&tcb->lock);
        if (tcb->rx_len > 0) {
            size_t n = tcb->rx_len < len ? tcb->rx_len : len;
            memcpy(buf, tcb->rxbuf, n);
            tcb->rx_len -= (uint16_t)n;
            if (tcb->rx_len) {
                memmove(tcb->rxbuf, tcb->rxbuf + n, tcb->rx_len);
            }
            portEXIT_CRITICAL(&tcb->lock);
            return (int)n;
        }
        bool dead = tcb->dead;
        bool fin = tcb->peer_fin;
        portEXIT_CRITICAL(&tcb->lock);
        if (dead) {
            return MP_CONN_ABORTED;
        }
        if (fin) {
            return 0; /* clean close */
        }
        if (tcb->rx_sem == NULL) {
            return MP_CONN_ABORTED;
        }
        if (xSemaphoreTake(tcb->rx_sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
            /* re-check before reporting the timeout */
            portENTER_CRITICAL(&tcb->lock);
            bool have = tcb->rx_len > 0 || tcb->dead || tcb->peer_fin;
            portEXIT_CRITICAL(&tcb->lock);
            if (!have) {
                return MP_CONN_TIMEOUT;
            }
        }
    }
}

int s419_app_send(s419_tcb *tcb, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    bool notified = false;

    while (off < len) {
        if (tcb->dead) {
            return -1;
        }
        portENTER_CRITICAL(&tcb->lock);
        if (tcb->dead) {
            portEXIT_CRITICAL(&tcb->lock);
            return -1;
        }
        uint32_t space = tcb->tx_len < S419_TX_CAP ? S419_TX_CAP - tcb->tx_len : 0;
        size_t n = len - off < space ? len - off : space;
        if (n) {
            memcpy(tcb->txbuf + tcb->tx_len, p + off, n);
            tcb->tx_len = (uint16_t)(tcb->tx_len + n);
            off += n;
            notified = false;
        }
        portEXIT_CRITICAL(&tcb->lock);

        if (off < len) {
            if (tcb->tx_sem) {
                xSemaphoreTake(tcb->tx_sem, pdMS_TO_TICKS(30000));
            } else {
                return -1;
            }
        }
        if (!notified) {
            tcpip_callback_with_block(s419_tcp_flush_msg, tcb, 0);
            notified = true;
        }
    }
    tcpip_callback_with_block(s419_tcp_flush_msg, tcb, 0);
    return 0;
}

void s419_app_shutdown(s419_tcb *tcb)
{
    if (tcb->dead || tcb->close_posted) {
        return;
    }
    tcpip_callback_with_block(s419_tcp_close_msg, tcb, 0);
}

void s419_app_release(s419_tcb *tcb)
{
    /* Hand the TCB back to the tcpip thread: it orders the close and frees
     * the TCB (and its rings) once the connection is fully closed. The app
     * must not touch the TCB after this point. */
    tcpip_callback_with_block(s419_tcp_detach_msg, tcb, 0);
}
