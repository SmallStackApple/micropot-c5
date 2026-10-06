/*
 * mp_stack419 public entry: engine init + the built-in parameter presets.
 */
#include "esp_log.h"

#include "mp_stack419.h"
#include "s419_isn.h"
#include "s419_priv.h"

static const char *TAG = "s419";
static bool s_inited;

/* nmap-os-db "Fingerprint Linux 4.19" (generic record, no distro):
 *   SEQ(TI=Z,CI=Z,II=I,TS=U) OPS=M5B4NNSNW6 WIN=FAF0 ECN(W=FAF0,CC=Y)
 *   U1(DF=N) IE(DFI=N,CD=S) */
const mp_s419_params_t mp_s419_params_linux419 = {
    .ttl = 64,
    .tcp_df = true,
    .tcp_ipid_zero = true,
    .icmp_df = false,
    .mss = 1460,
    .rcv_wnd = 64240,          /* 0xFAF0 */
    .wscale = 6,
    .sack_perm = true,
    .timestamps = false,       /* TS=U in the target record */
    .ecn_mode = 2,             /* serve ECN when requested */
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

esp_err_t mp_stack419_init(const mp_s419_params_t *params)
{
    if (s_inited) {
        return ESP_OK;
    }
    if (!params) {
        return ESP_ERR_INVALID_ARG;
    }
    s419_isn_init();
    s419_core_init(params);
    s_inited = true;
    ESP_LOGI(TAG, "Linux 4.19 TCP/IP engine initialised");
    return ESP_OK;
}

static esp_err_t wprof_init_thunk(const void *params)
{
    return mp_stack419_init((const mp_s419_params_t *)params);
}

esp_err_t mp_s419_udp_listen(uint32_t vaddr, uint16_t port,
                             bool (*allow)(uint32_t src_ip_lwip),
                             mp_s419_udp_handler_t fn)
{
    return s419_udp_listen(vaddr, port, allow, fn);
}

void mp_s419_udp_send(uint32_t lip, uint32_t rip, uint16_t lport,
                      uint16_t rport, const void *data, size_t len)
{
    s419_udp_send(lip, rip, lport, rport, data, len);
}

const mp_wprof_t mp_wprof_linux419 = {
    .id = "linux419",
    .init = wprof_init_thunk,
    .params = &mp_s419_params_linux419,
    .xport = &mp_xport_s419,
};
