#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Linux 4.19 TCP/IP behaviour parameters
 *
 * The stack engine (mp_stack419) is brand-agnostic: everything that makes
 * the wire personality "Linux 4.19" lives in this parameter block, handed
 * out by the brand as a behaviour blob keyed "stack419". Presets below are
 * derived from nmap-os-db "Fingerprint Linux 4.19" records.
 * ---------------------------------------------------------------------- */

typedef struct {
    /* --- IP layer --- */
    uint8_t  ttl;             /* 64: Linux default (include/linux/ip.h sysctl) */
    bool     tcp_df;          /* DF on TCP segments (nmap DF=Y in T1/T4-T7) */
    bool     tcp_ipid_zero;   /* 4.19 emits IP ID 0 on DF TCP (nmap TI=Z/CI=Z) */
    bool     icmp_df;         /* DF on ICMP replies (nmap IE DFI=N, U1 DF=N) */

    /* --- TCP SYN-ACK (nmap SEQ/OPS/WIN/ECN probes) --- */
    uint16_t mss;             /* 1460 (0x5B4) */
    uint16_t rcv_wnd;         /* advertised window, unscaled (0xFAF0) */
    uint8_t  wscale;          /* window scale we advertise (6) */
    bool     sack_perm;       /* advertise SACK-permitted */
    bool     timestamps;      /* offer TCP timestamps (generic record: off) */
    uint8_t  ecn_mode;        /* like net.ipv4.tcp_ecn: 2 = serve when asked */

    /* --- TCP session --- */
    uint8_t  tx_cwnd_segs;    /* fixed congestion window, segments */
    uint32_t rto_initial_ms;  /* 1000 (RFC 6298 / tcp_timeout_init) */
    uint32_t rto_min_ms;      /* 200 (TCP_RTO_MIN) */
    uint32_t rto_max_ms;      /* 120000 (TCP_RTO_MAX) */
    uint8_t  synack_retries;  /* 5 (net.ipv4.tcp_synack_retries) */
    uint8_t  data_retries;    /* give-up retransmits for established data */
    uint32_t delack_ms;       /* 40 (TCP_DELACK_MIN @ HZ=1000) */
    uint32_t timewait_ms;     /* 60000 (TCP_TIMEWAIT_LEN) */
    uint32_t finwait2_ms;     /* 60000 (TCP_LINGER2 default) */
} mp_s419_params_t;

/**
 * Generic "Fingerprint Linux 4.19" record from nmap-os-db (no distro):
 *   SEQ(TI=Z,CI=Z,II=I,TS=U) OPS=M5B4NNSNW6 WIN=FAF0
 *   ECN(O=M5B4NNSNW6,W=FAF0,CC=Y) U1(DF=N) IE(DFI=N)
 * Timestamps disabled => options on the wire are
 *   MSS | NOP NOP SACK_PERM | NOP WSCALE   (4.19 tcp_options_write layout).
 */
extern const mp_s419_params_t mp_s419_params_linux419;

#ifdef __cplusplus
}
#endif
