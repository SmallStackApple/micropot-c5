/*
 * Mini TCP state machine with Linux 4.19 wire semantics.
 *
 * Behaviours mirrored from v4.19 (cited per function):
 *  - net/ipv4/tcp_input.c   tcp_rcv_state_process / tcp_ack / tcp_data_queue
 *  - net/ipv4/tcp_output.c  tcp_make_synack / tcp_send_ack / tcp_send_fin
 *  - net/ipv4/tcp_ipv4.c    tcp_v4_send_reset
 *  - net/ipv4/tcp_timer.c   tcp_retransmit_timer (RTO backoff, RFC 6298)
 *  - net/core/secure_seq.c  secure_tcp_sequence_number (ISN)
 *
 * Scope: server-side only (LISTEN -> ...), in-order delivery with a
 * bounded rx ring, fixed congestion window (LAN honeypot traffic), no
 * SACK blocks / PAWS / timestamps (the target fingerprint has TS=U).
 * Out-of-order segments are dropped after a duplicate ACK, exactly the
 * observable behaviour of a real host whose receive buffer was full.
 */
#include <stdlib.h>
#include <string.h>

#include "lwip/def.h"
#include "lwip/tcpip.h"

#include "esp_log.h"

#include "s419_isn.h"
#include "s419_pkt.h"
#include "s419_priv.h"

static const char *TAG = "s419_tcp";

#define S419_TCPHDR_LEN(h) (((h)[12] >> 4) * 4)

/* sequence comparison, wrap-safe */
static inline bool seq_leq(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static inline bool seq_gt(uint32_t a, uint32_t b)  { return (int32_t)(a - b) > 0; }

static uint16_t s_synrecv_count;

/* ------------------------------------------------------------- senders */

static void send_raw_tcp(s419_tcb *tcb, uint32_t seq, uint32_t ack,
                         uint8_t flags, uint16_t wnd,
                         const void *payload, size_t payload_len)
{
    uint8_t pkt[64 + 1500];
    size_t n = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                              tcb->lport, tcb->rport, seq, ack, flags, wnd,
                              payload, payload_len);
    s419_output(pkt, n, tcb->rip);
}

/* tcp_send_ack (tcp_output.c): current seq/ack, our receive window. */
static void send_ack(s419_tcb *tcb)
{
    send_raw_tcp(tcb, tcb->snd_nxt, tcb->rcv_nxt, S419_ACK,
                 s419_par->rcv_wnd, NULL, 0);
    tcb->ack_pending = false;
    tcb->segs_unacked = 0;
}

static void send_synack(s419_tcb *tcb)
{
    uint8_t pkt[64];
    size_t n = s419_build_synack(pkt, s419_par, tcb->lip, tcb->rip,
                                 tcb->lport, tcb->rport,
                                 tcb->iss, tcb->rcv_nxt, tcb->ecn);
    s419_output(pkt, n, tcb->rip);
}

/* tcp_v4_send_reset for an established connection we tear down
 *  (overload drop): RST|ACK with the current sequence numbers. */
void s419_tcp_active_reset(s419_tcb *tcb)
{
    send_raw_tcp(tcb, tcb->snd_nxt, tcb->rcv_nxt, S419_RST | S419_ACK,
                 0, NULL, 0);
}

/* tcp_v4_send_reset (tcp_ipv4.c) for segments with no matching socket:
 *  - incoming ACK  -> RST with seq = their ack number, no ACK flag
 *  - otherwise     -> RST|ACK with seq = 0, ack = their seq + length
 * window 0, no options. Matches nmap T4/T5/T6/T7. */
void s419_tcp_closed_reset(uint32_t lip, uint32_t rip,
                           uint16_t lport, uint16_t rport,
                           const uint8_t *th, size_t tcp_len)
{
    uint32_t seq = s419_rd32(th + 4);
    uint32_t ack = s419_rd32(th + 8);
    uint8_t flags = th[13];
    size_t doff = S419_TCPHDR_LEN(th);
    uint32_t seg_len = (uint32_t)(tcp_len - doff) +
                       ((flags & S419_SYN) ? 1 : 0) + ((flags & S419_FIN) ? 1 : 0);

    uint8_t pkt[64];
    size_t n;
    if (flags & S419_ACK) {
        n = s419_build_tcp(pkt, s419_par, lip, rip, lport, rport,
                           ack, 0, S419_RST, 0, NULL, 0);
    } else {
        n = s419_build_tcp(pkt, s419_par, lip, rip, lport, rport,
                           0, seq + seg_len, S419_RST | S419_ACK, 0, NULL, 0);
    }
    s419_output(pkt, n, rip);
}

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
        default:
            break; /* SACK/TS/etc: parsed, not acted on (TS=U target) */
        }
        i += olen;
    }
}

void s419_tcp_new_syn(const s419_listener_t *lst,
                      uint32_t lip, uint32_t rip,
                      uint16_t lport, uint16_t rport,
                      const uint8_t *th, size_t tcp_len)
{
    if (s_synrecv_count >= S419_SYNRECV_CAP) {
        s419_report_synflood();
        return; /* backlog full: drop, like Linux without syncookies */
    }

    s419_tcb *tcb = s419_tcb_alloc();
    if (!tcb) {
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

    s_synrecv_count++;
    s419_tcb_link(tcb);
    send_synack(tcb);
}

/* ------------------------------------------------------------ app side */

int s419_app_recv(s419_tcb *tcb, void *buf, size_t len, uint32_t timeout_ms)
{
    for (;;) {
        portENTER_CRITICAL(&tcb->lock);
        if (tcb->rx_len) {
            size_t n = tcb->rx_len < len ? tcb->rx_len : len;
            memcpy(buf, tcb->rxbuf, n);
            tcb->rx_len -= (uint16_t)n;
            memmove(tcb->rxbuf, tcb->rxbuf + n, tcb->rx_len);
            portEXIT_CRITICAL(&tcb->lock);
            return (int)n;
        }
        bool fin = tcb->peer_fin;
        bool dead = tcb->dead;
        portEXIT_CRITICAL(&tcb->lock);

        if (dead) {
            return MP_CONN_ABORTED;
        }
        if (fin) {
            return 0;
        }
        if (!tcb->rx_sem ||
            xSemaphoreTake(tcb->rx_sem, pdMS_TO_TICKS(timeout_ms)) != pdTRUE) {
            return MP_CONN_TIMEOUT;
        }
    }
}

int s419_app_send(s419_tcb *tcb, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = len;
    while (left) {
        portENTER_CRITICAL(&tcb->lock);
        bool dead = tcb->dead || tcb->close_posted;
        size_t space = S419_TX_CAP - tcb->tx_len;
        size_t n = space < left ? space : left;
        if (!dead && n) {
            memcpy(tcb->txbuf + tcb->tx_len, p, n);
            tcb->tx_len += (uint16_t)n;
        }
        bool post = !tcb->flushed_posted;
        if (!dead && n && post) {
            tcb->flushed_posted = true;
        }
        portEXIT_CRITICAL(&tcb->lock);

        if (dead) {
            return -1;
        }
        if (n) {
            if (post && tcpip_callback(s419_tcp_flush_msg, tcb) != ERR_OK) {
                portENTER_CRITICAL(&tcb->lock);
                tcb->flushed_posted = false;
                portEXIT_CRITICAL(&tcb->lock);
            }
            p += n;
            left -= n;
            continue;
        }
        /* tx ring full: wait for ACKs to drain it */
        if (!tcb->tx_sem ||
            xSemaphoreTake(tcb->tx_sem, pdMS_TO_TICKS(30000)) != pdTRUE) {
            return -1;
        }
    }
    return 0;
}

void s419_app_shutdown(s419_tcb *tcb)
{
    portENTER_CRITICAL(&tcb->lock);
    bool post = !tcb->close_posted;
    tcb->close_posted = true;
    portEXIT_CRITICAL(&tcb->lock);
    if (post) {
        tcpip_callback(s419_tcp_close_msg, tcb);
    }
}

void s419_app_release(s419_tcb *tcb)
{
    if (tcpip_callback(s419_tcp_close_msg, tcb) != ERR_OK) {
        ESP_LOGD(TAG, "close msg post failed");
    }
}

/* ------------------------------------------------------------ transmit
 * tcp_output.c: send while the peer window (and our fixed cwnd) allow,
 * then FIN once the app has closed and the data is out. */

static void flush(s419_tcb *tcb)
{
    if (tcb->dead || tcb->state == S419_S_SYN_RECV ||
        tcb->state == S419_S_TIME_WAIT || tcb->state == S419_S_CLOSED) {
        return;
    }

    int64_t now = s419_now_ms();
    uint32_t cwnd = (uint32_t)s419_par->tx_cwnd_segs * tcb->peer_mss;
    uint32_t limit = tcb->peer_wnd < cwnd ? tcb->peer_wnd : cwnd;

    for (;;) {
        uint32_t in_flight = tcb->snd_nxt - tcb->snd_una;
        uint32_t data_flight = in_flight - (tcb->fin_sent ? 1 : 0);
        if (in_flight >= limit) {
            break;
        }

        portENTER_CRITICAL(&tcb->lock);
        uint32_t pending = tcb->tx_len - data_flight;
        portEXIT_CRITICAL(&tcb->lock);
        if (!pending) {
            break;
        }

        uint32_t n = limit - in_flight;
        if (n > tcb->peer_mss) {
            n = tcb->peer_mss;
        }
        if (n > pending) {
            n = pending;
        }

        /* header first, payload staged in place, then fix the checksum */
        uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN + 1460];
        size_t tcp_len = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                                        tcb->lport, tcb->rport,
                                        tcb->snd_nxt, tcb->rcv_nxt,
                                        S419_ACK | S419_PSH, s419_par->rcv_wnd,
                                        NULL, n);
        portENTER_CRITICAL(&tcb->lock);
        memcpy(pkt + tcp_len - n, tcb->txbuf + data_flight, n);
        portEXIT_CRITICAL(&tcb->lock);
        s419_tcp_set_cksum(pkt, tcp_len);
        s419_output(pkt, tcp_len, tcb->rip);

        tcb->snd_nxt += n;
        tcb->meas_ok = true;
        tcb->sent_ms = now;
        if (!tcb->rto_armed) {
            tcb->rto_armed = true;
            tcb->rto_due_ms = now + tcb->rto_ms;
        }
        /* ACK piggybacked on data: the delayed-ACK timer is served */
        tcb->ack_pending = false;
        tcb->segs_unacked = 0;
    }

    /* FIN goes out once the app closed and every buffered byte is on the
     * wire (tcp_send_fin, tcp_output.c). */
    uint32_t data_flight = tcb->snd_nxt - tcb->snd_una - (tcb->fin_sent ? 1 : 0);
    uint16_t tx_len;
    portENTER_CRITICAL(&tcb->lock);
    tx_len = tcb->tx_len;
    portEXIT_CRITICAL(&tcb->lock);
    if (tcb->close_posted && !tcb->fin_sent && data_flight == tx_len &&
        (tcb->state == S419_S_ESTABLISHED || tcb->state == S419_S_CLOSE_WAIT)) {
        send_raw_tcp(tcb, tcb->snd_nxt, tcb->rcv_nxt, S419_FIN | S419_ACK,
                     s419_par->rcv_wnd, NULL, 0);
        tcb->fin_sent = true;
        tcb->snd_nxt++;
        tcb->state = (tcb->state == S419_S_CLOSE_WAIT) ? S419_S_LAST_ACK
                                                       : S419_S_FIN_WAIT_1;
        tcb->sent_ms = now;
        tcb->meas_ok = true;
        tcb->rto_armed = true;
        tcb->rto_due_ms = now + tcb->rto_ms;
    }
}

void s419_tcp_flush_msg(void *ctx)
{
    s419_tcb *tcb = (s419_tcb *)ctx;
    portENTER_CRITICAL(&tcb->lock);
    tcb->flushed_posted = false;
    portEXIT_CRITICAL(&tcb->lock);
    flush(tcb);
}

/* App detached: queue FIN, keep TCP closure running; free when dead. */
void s419_tcp_close_msg(void *ctx)
{
    s419_tcb *tcb = (s419_tcb *)ctx;
    portENTER_CRITICAL(&tcb->lock);
    tcb->close_posted = true;
    tcb->app_attached = false;
    portEXIT_CRITICAL(&tcb->lock);

    if (tcb->dead || tcb->state == S419_S_SYN_RECV) {
        s419_tcb_unlink_free(tcb);
        return;
    }
    flush(tcb);
}

/* tcb_kill returns true when the TCB was freed (caller must not touch it). */
static bool tcb_kill(s419_tcb *tcb)
{
    tcb->dead = true;
    if (tcb->rx_sem) {
        xSemaphoreGive(tcb->rx_sem);
    }
    if (tcb->tx_sem) {
        xSemaphoreGive(tcb->tx_sem);
    }
    if (!tcb->app_attached) {
        s419_tcb_unlink_free(tcb);
        return true;
    }
    return false;
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
    if (data_acked) {
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
    flush(tcb); /* window opened up */
}

static void enter_timewait(s419_tcb *tcb)
{
    tcb->state = S419_S_TIME_WAIT;
    tcb->state_due_ms = s419_now_ms() + s419_par->timewait_ms;
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
            s_synrecv_count--;
            s419_tcb_unlink_free(tcb);
            return;
        }
        if (flags & S419_SYN) {
            send_synack(tcb); /* retransmitted SYN: same ISN, same SYN-ACK */
            return;
        }
        if (!(flags & S419_ACK)) {
            return;
        }
        if (seg_ack != tcb->snd_nxt || seg_seq != tcb->rcv_nxt) {
            /* bad handshake ACK: reset, drop the request */
            send_raw_tcp(tcb, seg_ack, 0, S419_RST, 0, NULL, 0);
            s_synrecv_count--;
            s419_tcb_unlink_free(tcb);
            return;
        }
        /* handshake complete (tcp_check_req -> tcp_rcv_state_process) */
        s_synrecv_count--;
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
            send_ack(tcb);
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
        tcb_kill(tcb);
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
            /* in-order: buffer what fits, ACK what we took */
            portENTER_CRITICAL(&tcb->lock);
            uint32_t space = S419_RX_CAP - tcb->rx_len;
            uint32_t take = payload_len < space ? payload_len : space;
            if (take) {
                memcpy(tcb->rxbuf + tcb->rx_len, th + doff, take);
                tcb->rx_len += (uint16_t)take;
            }
            portEXIT_CRITICAL(&tcb->lock);
            tcb->rcv_nxt += take;
            if (tcb->rx_sem) {
                xSemaphoreGive(tcb->rx_sem);
            }
            /* delayed ACK: every 2nd full segment at once, else 40 ms
             * (TCP_DELACK_MIN); short reads (take<payload) ACK at once */
            tcb->segs_unacked++;
            if (tcb->segs_unacked >= 2 || take < payload_len) {
                send_ack(tcb);
            } else {
                tcb->ack_pending = true;
                tcb->ack_due_ms = s419_now_ms() + s419_par->delack_ms;
            }
        } else {
            send_ack(tcb); /* out of order: duplicate ACK, peer retransmits */
        }
    }

    if ((flags & S419_FIN) && !tcb->peer_fin &&
        tcb->rcv_nxt == seg_seq + payload_len) {
        tcb->rcv_nxt++;
        tcb->peer_fin = true;
        send_ack(tcb);
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

/* -------------------------------------------------------------- timers */

static void retransmit(s419_tcb *tcb)
{
    int64_t now = s419_now_ms();

    if (tcb->state == S419_S_SYN_RECV) {
        send_synack(tcb);
    } else {
        uint32_t una_data = tcb->snd_nxt - tcb->snd_una -
                            (tcb->fin_sent ? 1 : 0);
        if (una_data) {
            /* tcp_retransmit_skb: resend from snd_una, one MSS */
            uint32_t n = una_data > tcb->peer_mss ? tcb->peer_mss : una_data;
            uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN + 1460];
            size_t tcp_len = s419_build_tcp(pkt, s419_par, tcb->lip, tcb->rip,
                                            tcb->lport, tcb->rport,
                                            tcb->snd_una, tcb->rcv_nxt,
                                            S419_ACK | S419_PSH,
                                            s419_par->rcv_wnd, NULL, n);
            portENTER_CRITICAL(&tcb->lock);
            memcpy(pkt + tcp_len - n, tcb->txbuf, n);
            portEXIT_CRITICAL(&tcb->lock);
            s419_tcp_set_cksum(pkt, tcp_len);
            s419_output(pkt, tcp_len, tcb->rip);
            tcb->meas_ok = false; /* Karn: no RTT sample off retransmits */
        } else if (tcb->fin_sent && !tcb->fin_acked) {
            send_raw_tcp(tcb, tcb->snd_nxt - 1, tcb->rcv_nxt,
                         S419_FIN | S419_ACK, s419_par->rcv_wnd, NULL, 0);
            tcb->meas_ok = false;
        }
    }

    tcb->rto_ms = tcb->rto_ms * 2 > s419_par->rto_max_ms
                      ? s419_par->rto_max_ms : tcb->rto_ms * 2;
    tcb->rto_due_ms = now + tcb->rto_ms;
}

void s419_tcp_tick(void)
{
    int64_t now = s419_now_ms();
    s419_tcb *tcb = s419_tcbs();
    while (tcb) {
        s419_tcb *next = tcb->next;
        bool gone = false;

        if (tcb->rto_armed && now >= tcb->rto_due_ms && !tcb->dead) {
            tcb->retries++;
            uint8_t max = tcb->state == S419_S_SYN_RECV
                              ? s419_par->synack_retries
                              : s419_par->data_retries;
            if (tcb->retries > max) {
                /* tcp_write_timeout: give up silently (ETIMEDOUT) */
                gone = tcb_kill(tcb);
            } else {
                retransmit(tcb);
            }
        }

        if (!gone) {
            if (tcb->ack_pending && now >= tcb->ack_due_ms && !tcb->dead) {
                send_ack(tcb);
            }

            /* safety net: retry a flush whose tcpip_callback post failed */
            if ((tcb->state == S419_S_ESTABLISHED ||
                 tcb->state == S419_S_CLOSE_WAIT) && !tcb->dead) {
                flush(tcb);
            }

            if (tcb->state_due_ms && now >= tcb->state_due_ms) {
                switch (tcb->state) {
                case S419_S_SYN_RECV:
                    s_synrecv_count--;
                    s419_tcb_unlink_free(tcb);
                    break;
                case S419_S_TIME_WAIT:
                case S419_S_FIN_WAIT_2:
                    s419_tcb_unlink_free(tcb);
                    break;
                default:
                    break;
                }
            }
        }

        tcb = next;
    }
}

