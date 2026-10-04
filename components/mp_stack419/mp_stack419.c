/*
 * mp_stack419 public entry point and the Linux 4.19 parameter presets.
 */
#include "mp_stack419.h"

#include "s419_isn.h"
#include "s419_priv.h"

/*
 * Generic "Fingerprint Linux 4.19" (nmap-os-db, no distro comment):
 *   SEQ(SP=F5-FF%GCD=1-6%ISR=10A-114%TI=Z%CI=Z%II=I%TS=U)
 *   OPS(O1=M5B4NNSNW6 ... O6=M5B4NNS)
 *   WIN(W1..W6=FAF0)
 *   ECN(R=Y%DF=Y%T=3B-45%TG=40%W=FAF0%O=M5B4NNSNW6%CC=Y%Q=)
 *   T1(R=Y%DF=Y%T=3B-45%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
 *   T2(R=N) T3(R=N) T4(R=Y%DF=Y%T=3B-45%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
 *   T5/T7(F=AR) T6(F=R)
 *   U1(DF=N%T=3B-45%TG=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
 *   IE(DFI=N%T=3B-45%TG=40%CD=S)
 *
 * TTL 64 and TG=40 (0x40) match s419_par->ttl; timestamps are off (TS=U),
 * which is also why the SYN-ACK option string is M5B4NNSNW6 and not the
 * timestamped Debian variant.
 */
const mp_s419_params_t mp_s419_params_linux419 = {
    .ttl = 64,
    .tcp_df = true,
    .tcp_ipid_zero = true,   /* TI=Z, CI=Z */
    .icmp_df = false,        /* IE DFI=N, U1 DF=N */

    .mss = 1460,             /* 0x5B4 */
    .rcv_wnd = 64240,        /* 0xFAF0 */
    .wscale = 6,             /* W6 */
    .sack_perm = true,       /* S */
    .timestamps = false,     /* TS=U */
    .ecn_mode = 2,           /* net.ipv4.tcp_ecn default: serve when asked */

    .tx_cwnd_segs = 8,
    .rto_initial_ms = 1000,
    .rto_min_ms = 200,       /* TCP_RTO_MIN */
    .rto_max_ms = 120000,    /* TCP_RTO_MAX */
    .synack_retries = 5,     /* tcp_synack_retries */
    .data_retries = 8,
    .delack_ms = 40,         /* TCP_DELACK_MIN at HZ=1000 */
    .timewait_ms = 60000,    /* TCP_TIMEWAIT_LEN */
    .finwait2_ms = 60000,    /* tcp_fin_timeout */
};

static bool s_inited;

esp_err_t mp_stack419_init(const mp_s419_params_t *params)
{
    if (!params) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_inited) {
        return ESP_OK;
    }
    s419_isn_init();
    s419_core_init(params);
    s_inited = true;
    return ESP_OK;
}
