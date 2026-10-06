#pragma once

#include "esp_err.h"
#include "mp_s419_params.h"
#include "mp_wprof.h"
#include "mp_xport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * mp_stack419 — Linux 4.19 TCP/IP behaviour engine
 *
 * Intercepts inbound TCP/UDP/ICMP ahead of lwIP's own stack (raw PCBs run
 * before tcp/udp input) and answers with packets crafted to be
 * indistinguishable from a Linux 4.19 host: ISN generation, SYN-ACK option
 * layout, probe responses (nmap T1-T7/ECN/U1/IE), ICMP behaviour, plus a
 * mini TCP session machine that carries real honeypot sessions.
 *
 * Services attach through the mp_xport backend below; the engine itself is
 * brand-agnostic and driven by mp_s419_params_t.
 * ---------------------------------------------------------------------- */

/** Bring up the engine: raw PCBs, timers, secrets. Call once after the
 *  netif is up, before any service starts. Idempotent. */
esp_err_t mp_stack419_init(const mp_s419_params_t *params);

/** Milliseconds since any inbound IPv4 packet reached the raw intercept
 *  (link-liveness diagnostic). -1 when nothing has ever arrived. */
int64_t mp_s419_rx_age_ms(void);

/** tcpip-thread heartbeat counter (10ms tick); frozen means tcpip wedged. */
uint32_t mp_s419_tick_count(void);

/** Live TCBs across all states (SYN_RECV/established/closing), capped by
 *  S419_MAX_TCBS. A monotonically pinned value under churn means lingering
 *  TIME_WAIT/FIN_WAIT_2 state is accumulating. */
uint16_t mp_s419_tcb_count(void);

/** The xport backend that routes listeners/connections through the engine. */
extern const mp_xport_backend_t mp_xport_s419;

/** Wire profile bundling the generic nmap "Fingerprint Linux 4.19" params
 *  with this engine — registered into mp_wprof by the app. */
extern const mp_wprof_t mp_wprof_linux419;

#ifdef __cplusplus
}
#endif
