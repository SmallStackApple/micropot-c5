/*
 * Mini TCP state machine with Linux 4.19 wire semantics — transmit core.
 *
 * This file owns the packet senders, the application-facing rx/tx rings,
 * the window/FIN pump and TCB teardown. The receive state machine is in
 * s419_tcp_in.c and the RTO/tick timer in s419_tcp_timer.c; the shared
 * primitives are declared in s419_tcp_internal.h.
 *
 * Behaviours mirrored from v4.19 (cited per function):
 *  - net/ipv4/tcp_output.c  tcp_make_synack / tcp_send_ack / tcp_send_fin
 *  - net/ipv4/tcp_ipv4.c    tcp_v4_send_reset
 *  - net/ipv4/tcp_timer.c   tcp_retransmit_timer (RTO backoff, RFC 6298)
 *
 * Scope: server-side only (LISTEN -> ...), in-order delivery with a
 * bounded rx ring, fixed congestion window (LAN honeypot traffic), no
 * SACK blocks / PAWS / timestamps (the target fingerprint has TS=U).
 */
#include <stdlib.h>
#include <string.h>

#include "lwip/def.h"
#include "lwip/tcpip.h"

#include "esp_log.h"

#include "s419_pkt.h"
#include "s419_priv.h"
#include "s419_tcp_internal.h"

static const char *TAG = "s419_tcp";

/* Half-open (SYN_RECV) TCBs; incremented in s419_tcp_in.c, decremented
 * there and in s419_tcp_timer.c. */
uint16_t s419_synrecv_count;

/* ------------------------------------------------------------- senders */

void s419_tcp_send_raw(s419_tcb *tcb, uint32_t seq, uint32_t ack,
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
void s419_tcp_send_ack(s419_tcb *tcb)
{
    s419_tcp_send_raw(tcb, tcb->snd_nxt, tcb->rcv_nxt, S419_ACK,
                      s419_par->rcv_wnd, NULL, 0);
    tcb->ack_pending = false;
    tcb->segs_unacked = 0;
}

void s419_tcp_send_synack(s419_tcb *tcb)
{
    uint8_t pkt[64];
    size_t n = s419_build_synack(pkt, s419_par, tcb->lip, tcb->rip,
                                 tcb->lport, tcb->rport,
                                 tcb->iss, tcb->rcv_nxt, tcb->ecn,
                                 tcb->peer_sack_ok, tcb->peer_ws_ok);
    s419_output(pkt, n, tcb->rip);
}

/* tcp_v4_send_reset for an established connection we tear down
 *  (overload drop): RST|ACK with the current sequence numbers. */
void s419_tcp_active_reset(s419_tcb *tcb)
{
    s419_tcp_send_raw(tcb, tcb->snd_nxt, tcb->rcv_nxt, S419_RST | S419_ACK,
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

void s419_tcp_flush(s419_tcb *tcb)
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
        /* build_tcp's return includes the IP header; set_cksum wants the
         * bare TCP segment length (its build-time sum covered an unstaged
         * payload area, so it must be redone now). */
        s419_tcp_set_cksum(pkt, tcp_len - S419_IP_HLEN);
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
        s419_tcp_send_raw(tcb, tcb->snd_nxt, tcb->rcv_nxt, S419_FIN | S419_ACK,
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

    /* All data (and the FIN, if any) is acked and the app is gone: the tx
     * ring is dead weight through FIN_WAIT_2 / TIME_WAIT. */
    if (!tcb->app_attached && tcb->txbuf && tcb->tx_len == 0 &&
        tcb->snd_una == tcb->snd_nxt) {
        s419_tcb_free_tx(tcb);
    }
}

void s419_tcp_flush_msg(void *ctx)
{
    s419_tcb *tcb = (s419_tcb *)ctx;
    portENTER_CRITICAL(&tcb->lock);
    tcb->flushed_posted = false;
    portEXIT_CRITICAL(&tcb->lock);
    s419_tcp_flush(tcb);
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
    /* the app will never read again: drop its receive buffer now */
    s419_tcb_free_rx(tcb);
    s419_tcp_flush(tcb);
}

/* Returns true when the TCB was freed (caller must not touch it). */
bool s419_tcp_kill(s419_tcb *tcb)
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
