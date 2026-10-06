/*
 * Linux-4.19 mini TCP state machine — timers.
 *
 * RTO retransmission (tcp_retransmit_timer, RFC 6298 backoff), delayed-ACK
 * expiry and the per-state deadlines, driven by a 10 ms tick in the tcpip
 * thread. Transmit primitives live in s419_tcp.c.
 */
#include <string.h>

#include "s419_pkt.h"
#include "s419_priv.h"
#include "s419_tcp_internal.h"

static void retransmit(s419_tcb *tcb)
{
    int64_t now = s419_now_ms();

    if (tcb->state == S419_S_SYN_RECV) {
        s419_tcp_send_synack(tcb);
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
            /* same contract as s419_tcp_flush(): strip the IP header length */
            s419_tcp_set_cksum(pkt, tcp_len - S419_IP_HLEN);
            s419_output(pkt, tcp_len, tcb->rip);
            tcb->meas_ok = false; /* Karn: no RTT sample off retransmits */
        } else if (tcb->fin_sent && !tcb->fin_acked) {
            s419_tcp_send_raw(tcb, tcb->snd_nxt - 1, tcb->rcv_nxt,
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
                gone = s419_tcp_kill(tcb);
            } else {
                retransmit(tcb);
            }
        }

        if (!gone) {
            if (tcb->ack_pending && now >= tcb->ack_due_ms && !tcb->dead) {
                s419_tcp_send_ack(tcb);
            }

            /* safety net: retry a flush whose tcpip_callback post failed */
            if ((tcb->state == S419_S_ESTABLISHED ||
                 tcb->state == S419_S_CLOSE_WAIT) && !tcb->dead) {
                s419_tcp_flush(tcb);
            }

            if (tcb->state_due_ms && now >= tcb->state_due_ms) {
                switch (tcb->state) {
                case S419_S_SYN_RECV:
                    s419_synrecv_count--;
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
