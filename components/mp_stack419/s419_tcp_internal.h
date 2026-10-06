#pragma once

/*
 * Shared internals of the Linux-4.19 mini TCP state machine, split across:
 *   s419_tcp.c        transmit primitives, app-side rings, FIN/close
 *   s419_tcp_in.c     SYN handling, ACK/data/FIN receive path
 *   s419_tcp_timer.c  RTO retransmit + 10 ms tick
 *
 * The transmit primitives and the SYN-backlog counter are the only state
 * shared between the three, so they are declared here and defined in
 * s419_tcp.c. Not part of the public component API.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "s419_priv.h"

#define S419_TCPHDR_LEN(h) (((h)[12] >> 4) * 4)

/** Number of half-open (SYN_RECV) TCBs, bounded by S419_SYNRECV_CAP. */
extern uint16_t s419_synrecv_count;

/* ---- transmit primitives (s419_tcp.c) ---- */
void s419_tcp_send_raw(s419_tcb *tcb, uint32_t seq, uint32_t ack,
                       uint8_t flags, uint16_t wnd,
                       const void *payload, size_t payload_len);
void s419_tcp_send_ack(s419_tcb *tcb);
void s419_tcp_send_synack(s419_tcb *tcb);

/* ---- window/FIN pump and teardown (s419_tcp.c) ---- */
void s419_tcp_flush(s419_tcb *tcb);
bool s419_tcp_kill(s419_tcb *tcb); /* true when the TCB was freed */
