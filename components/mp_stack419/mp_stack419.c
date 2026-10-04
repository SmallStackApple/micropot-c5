/*
 * mp_stack419 public entry point and the Linux 4.19 parameter preset.
 *
 * The preset is the generic "Fingerprint Linux 4.19" record from
 * nmap-os-db (the only 4.19 record that names no distribution):
 *
 *   SEQ(SP=..,GCD=..,ISR=..,TI=Z,CI=Z,II=I,TS=U)
 *   OPS(O1=M5B4NNSNW6 ... O6=M5B4NNS)
 *   WIN(W1..W6=FAF0)
 *   ECN(R=Y,DF=Y,T=3B-45,TG=40,W=FAF0,O=M5B4NNSNW6,CC=Y)
 *   T1 SYN-ACK AS ; T4-T7 closed-port resets ; U1 DF=N ; IE DFI=N
 */
#include "mp_stack419.h"

#include "esp_log.h"

#include "s419_isn.h"
#include "s419_priv.h"

static const char *TAG = "stack419";

esp_err_t mp_stack419_init(const mp_s419_params_t *params)
{
    if (!params) {
        return ESP_ERR_INVALID_ARG;
    }
    s419_isn_init();
    s419_core_init(params);
    ESP_LOGI(TAG, "Linux 4.19 personality armed");
    return ESP_OK;
}

const mp_s419_params_t mp_s419_params_linux419 = {
    /* IP layer */
    .ttl = 64,
    .tcp_df = true,
    .tcp_ipid_zero = true,
    .icmp_df = false,

    /* SYN-ACK: OPS M5B4NNSNW6, WIN FAF0, ECN CC=Y */
    .mss = 1460,
    .rcv_wnd = 64240, /* 0xFAF0 */
    .wscale = 6,
    .sack_perm = true,
    .timestamps = false, /* TS=U: timestamp option disabled */
    .ecn_mode = 2,

    /* session */
    .tx_cwnd_segs = 8,
    .rto_initial_ms = 1000,
    .rto_min_ms = 200,
    .rto_max_ms = 120000,
    .synack_retries = 5,
    .data_retries = 8,
    .delack_ms = 40,
    .timewait_ms = 60000,
    .finwait2_ms = 60000,
};
