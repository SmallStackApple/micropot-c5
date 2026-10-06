/*
 * Linux-4.19 mini TCP state machine — receive half.
 *
 * SYN handling and the established-path ACK/data/FIN processing, mirroring
 * net/ipv4/tcp_input.c (tcp_rcv_state_process / tcp_ack / tcp_data_queue).
 * The transmit primitives and teardown live in s419_tcp.c; the timer in
 * s419_tcp_timer.c. See s419_tcp.c for the behaviour citations.
 */
#include <string.h>

#include "s419_isn.h"
#include "s419_pkt.h"
#include "s419_priv.h"
#include "s419_tcp_internal.h"

/* sequence comparison, wrap-safe */
static inline bool seq_leq(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static inline bool seq_gt(uint32_t a, uint32_t b)  { return (int32_t)(a - b) > 0; }

/* ---------------------------------------------------------- handshake */

static void parse_syn_options(s419_tcb *tcb, const uint8_t *opts, size_t len)
{
    /* tcp_parse_options (tcp_input.c): only what a 4.19 server acts on. */
    tcb->peer_mss = 536; /* RFC 1122 default when no MSS option */
    for (size_t i = 0; i < len;) {
        uint8_t kind = opts[i];
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            i++;
            continue;
        }
        if (i + 1 >= len) {
            break;
        }
        uint8_t olen = opts[i + 1];
        if (olen < 2 || i + olen > len) {
            break;
        }
        switch (kind) {
        case 2: /* MSS */
            if (olen == 4) {
                uint16_t m = s419_rd16(opts + i + 2);
                if (m >= 88 && m <= 1460) { /* TCP_MIN_SND_MSS .. wire max */
                    tcb->peer_mss = m;
                }
            }
            break;
        case 3: /* window scale */
            if (olen == 3) {
                tcb->peer_ws_ok = true;
                tcb->peer_wscale = opts[i + 2] > 14 ? 14 : opts[i + 2];
            }
            break;
        case 4: /* SACK permitted: mirrored in the SYN-ACK */
            tcb->peer_sack_ok = true;
            break;
        default:
            break; /* TS/etc: parsed, not acted on (TS=U target) */
        }
        i += olen;
    }
}

void s419_tcp_new_syn(const s419_listener_t *lst,
                      uint32_t lip, uint32_t rip,
                      uint16_t lport, uint16_t rport,
                      const uint8_t *th, size_t tcp_len)
{
    if (s419_synrecv_count >= S419_SYNRECV_CAP) {
        s419_report_synflood();
        return; /* backlog full: drop, like Linux without syncookies */
    }

    s419_tcb *tcb = s419_tcb_alloc();
    if (!tcb) {
        s419_report_synflood(); /* TCB table / memory full: drop the SYN */
        return;
    }
    tcb->lip = lip;
    tcb->rip = rip;
    tcb->lport = lport;
    tcb->rport = rport;
    tcb->listener = lst;
    tcb->state = S419_S_SYN_RECV;

    parse_syn_options(tcb, th + S419_TCP_HLEN, tcp_len - S419_TCP_HLEN);
    tcb->peer_wnd = s419_rd16(th + 14);

    /* ECN: serve when requested (net.ipv4.tcp_ecn = 2, the default) */
    tcb->ecn = (s419_par->ecn_mode == 2) &&
               (th[13] & S419_ECE) && (th[13] & S419_CWR);

    /* ISN: secure_tcp_sequence_number(peer_ip, our_ip, peer_port, our_port) */
    tcb->iss = s419_isn(rip, lip, rport, lport);
    tcb->snd_una = tcb->iss;
    tcb->snd_nxt = tcb->iss + 1;
    tcb->rcv_nxt = s419_rd32(th + 4) + 1;

    tcb->rto_ms = s419_par->rto_initial_ms;
    tcb->sent_ms = s419_now_ms();
    tcb->rto_due_ms = tcb->sent_ms + tcb->rto_ms;
    tcb->rto_armed = true;
    tcb->meas_ok = true;
    tcb->state_due_ms = tcb->sent_ms + 60000; /* request_sock expiry */

    s419_synrecv_count++;
    s419_tcb_link(tcb);
    s419_tcp_send_synack(tcb);
}

/* ------------------------------------------------------------- receive */

/* tcp_ack (tcp_input.c): advance snd_una, sample the RTT (Karn: only for
 *  segments never retransmitted), restart or stop the RTO timer. */
static void process_ack(s419_tcb *tcb, uint32_t ack)
{
    if (seq_leq(ack, tcb->snd_una)) {
        if (ack == tcb->snd_una && seq_gt(tcb->snd_nxt, tcb->snd_una)) {
            tcb->dupacks++;
        }
        return;
    }
    if (seq_gt(ack, tcb->snd_nxt)) {
        return; /* ack for unsent data: Linux sends a dup ACK; ignore here */
    }

    uint32_t acked = ack - tcb->snd_una;
    tcb->snd_una = ack;
    if (tcb->fin_sent && ack == tcb->snd_nxt) {
        tcb->fin_acked = true;
    }

    uint32_t data_acked = acked;
    if (tcb->fin_sent && tcb->fin_acked) {
        data_acked = acked ? acked - 1 : 0; /* FIN occupies one sequence */
    }
    if (data_acked && tcb->txbuf) { /* txbuf is NULL only with tx_len == 0 */
        portENTER_CRITICAL(&tcb->lock);
        if (data_acked > tcb->tx_len) {
            data_acked = tcb->tx_len;
        }
        tcb->tx_len -= (uint16_t)data_acked;
        memmove(tcb->txbuf, tcb->txbuf + data_acked, tcb->tx_len);
        portEXIT_CRITICAL(&tcb->lock);
        if (tcb->tx_sem) {
            xSemaphoreGive(tcb->tx_sem);
        }
    }

    if (tcb->meas_ok) {
        /* RFC 6298 RTT estimation */
        int64_t sample = s419_now_ms() - tcb->sent_ms;
        if (sample < 1) {
            sample = 1;
        }
        if (!tcb->rtt_valid) {
            tcb->rtt_valid = true;
            tcb->srtt_ms = (uint32_t)sample;
            tcb->rttvar_ms = (uint32_t)(sample / 2);
        } else {
            int32_t d = (int32_t)tcb->srtt_ms - (int32_t)sample;
            if (d < 0) {
                d = -d;
            }
            tcb->rttvar_ms = (3 * tcb->rttvar_ms + (uint32_t)d) / 4;
            tcb->srtt_ms = (7 * tcb->srtt_ms + (uint32_t)sample) / 8;
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

    tcb->retries = 0;
    tcb->dupacks = 0;
    if (tcb->snd_una == tcb->snd_nxt) {
        tcb->rto_armed = false;
    } else {
        tcb->rto_due_ms = s419_now_ms() + tcb->rto_ms;
    }
    s419_tcp_flush(tcb); /* window opened up */
}

static void enter_timewait(s419_tcb *tcb)
{
    tcb->state = S419_S_TIME_WAIT;
    tcb->state_due_ms = s419_now_ms() + s419_par->timewait_ms;
    /* A TIME_WAIT TCB only needs its 4-tuple and timers: drop the rings so
     * a flood of closed connections cannot pin off PSRAM. */
    s419_tcb_free_rx(tcb);
    s419_tcb_free_tx(tcb);
}

void s419_tcp_input(s419_tcb *tcb, const uint8_t *th, size_t tcp_len,
                    uint32_t ip_src, uint32_t ip_dst)
{
    (void)ip_src;
    (void)ip_dst;
    uint32_t seg_seq = s419_rd32(th + 4);
    uint32_t seg_ack = s419_rd32(th + 8);
    uint8_t  flags = th[13];
    size_t   doff = S419_TCPHDR_LEN(th);
    uint32_t payload_len = (uint32_t)(tcp_len - doff);

    /* receiver window update (tcp_ack also does this; always safe) */
    tcb->peer_wnd = (uint32_t)s419_rd16(th + 14)
                    << (tcb->peer_ws_ok ? tcb->peer_wscale : 0);

    switch (tcb->state) {
    case S419_S_SYN_RECV:
        if (flags & S419_RST) {
            s419_synrecv_count--;
            s419_tcb_unlink_free(tcb);
            return;
        }
        if (flags & S419_SYN) {
            s419_tcp_send_synack(tcb); /* retransmitted SYN: same ISN */
            return;
        }
        if (!(flags & S419_ACK)) {
            return;
        }
        if (seg_ack != tcb->snd_nxt || seg_seq != tcb->rcv_nxt) {
            /* bad handshake ACK: reset, drop the request */
            s419_tcp_send_raw(tcb, seg_ack, 0, S419_RST, 0, NULL, 0);
            s419_synrecv_count--;
            s419_tcb_unlink_free(tcb);
            return;
        }
        /* handshake complete (tcp_check_req -> tcp_rcv_state_process) */
        s419_synrecv_count--;
        tcb->snd_una = seg_ack;
        tcb->state = S419_S_ESTABLISHED;
        tcb->rto_armed = false;
        if (tcb->meas_ok) {
            int64_t sample = s419_now_ms() - tcb->sent_ms;
            if (sample < 1) {
                sample = 1;
            }
            tcb->rtt_valid = true;
            tcb->srtt_ms = (uint32_t)sample;
            tcb->rttvar_ms = (uint32_t)(sample / 2);
            uint32_t rto = tcb->srtt_ms + 4 * tcb->rttvar_ms;
            if (rto < s419_par->rto_min_ms) {
                rto = s419_par->rto_min_ms;
            }
            tcb->rto_ms = rto;
        }
        if (!s419_established(tcb)) {
            return; /* overload / task failure: TCB is gone */
        }
        if (payload_len == 0 && !(flags & S419_FIN)) {
            return;
        }
        /* piggybacked data/FIN: fall through */
        break;

    case S419_S_TIME_WAIT:
        /* stray segment for a closed connection: ACK it (RFC 1122) */
        if (!(flags & S419_RST)) {
            s419_tcp_send_ack(tcb);
            tcb->state_due_ms = s419_now_ms() + s419_par->timewait_ms;
        } else {
            s419_tcb_unlink_free(tcb);
        }
        return;

    default:
        break;
    }

    /* ------- ESTABLISHED / FIN_WAIT_1 / FIN_WAIT_2 / CLOSE_WAIT / LAST_ACK */

    if (flags & S419_RST) {
        s419_tcp_kill(tcb);
        return;
    }

    if (flags & S419_ACK) {
        process_ack(tcb, seg_ack);
        if (tcb->dead) {
            return;
        }
        if (tcb->state == S419_S_FIN_WAIT_1 && tcb->fin_acked) {
            tcb->state = S419_S_FIN_WAIT_2;
            tcb->state_due_ms = s419_now_ms() + s419_par->finwait2_ms;
        } else if (tcb->state == S419_S_LAST_ACK && tcb->fin_acked) {
            s419_tcb_unlink_free(tcb);
            return;
        }
    }

    if (payload_len) {
        if (seg_seq == tcb->rcv_nxt && !tcb->peer_fin) {
            /* in-order: buffer what fits, ACK what we took. With the app
             * detached the rx ring is freed, so discard but keep the
             * sequence space moving (the peer still gets its ACK). */
            uint32_t take = payload_len;
            if (tcb->rxbuf) {
                portENTER_CRITICAL(&tcb->lock);
                uint32_t space = S419_RX_CAP - tcb->rx_len;
                take = payload_len < space ? payload_len : space;
                if (take) {
                    memcpy(tcb->rxbuf + tcb->rx_len, th + doff, take);
                    tcb->rx_len += (uint16_t)take;
                }
                portEXIT_CRITICAL(&tcb->lock);
            }
            tcb->rcv_nxt += take;
            if (tcb->rx_sem && tcb->rxbuf) {
                xSemaphoreGive(tcb->rx_sem);
            }
            /* delayed ACK: every 2nd full segment at once, else 40 ms
             * (TCP_DELACK_MIN); short reads (take<payload) ACK at once */
            tcb->segs_unacked++;
            if (tcb->segs_unacked >= 2 || take < payload_len) {
                s419_tcp_send_ack(tcb);
            } else {
                tcb->ack_pending = true;
                tcb->ack_due_ms = s419_now_ms() + s419_par->delack_ms;
            }
        } else {
            s419_tcp_send_ack(tcb); /* out of order: duplicate ACK */
        }
    }

    if ((flags & S419_FIN) && !tcb->peer_fin &&
        tcb->rcv_nxt == seg_seq + payload_len) {
        tcb->rcv_nxt++;
        tcb->peer_fin = true;
        s419_tcp_send_ack(tcb);
        if (tcb->rx_sem) {
            xSemaphoreGive(tcb->rx_sem);
        }
        switch (tcb->state) {
        case S419_S_ESTABLISHED:
            tcb->state = S419_S_CLOSE_WAIT;
            break;
        case S419_S_FIN_WAIT_1:
            if (tcb->fin_acked) {
                enter_timewait(tcb);
            } else {
                tcb->state = S419_S_FIN_WAIT_2; /* CLOSING folded in */
                tcb->state_due_ms = s419_now_ms() + s419_par->finwait2_ms;
            }
            break;
        case S419_S_FIN_WAIT_2:
            enter_timewait(tcb);
            break;
        default:
            break;
        }
    }
}
