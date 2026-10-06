/*
 * MicroPot-C5 — phase 1 entry point.
 *
 * Single device IP hosting two brand-driven honeypot services (Telnet + HTTP)
 * with structured JSON event logging to a PC collector.
 */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <string.h>

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "lwip/etharp.h"
#include "lwip/tcpip.h"
#include "lwip/ip_addr.h"
#include "ping/ping_sock.h"
#include "nvs_flash.h"
#include "esp_netif_net_stack.h" /* esp_netif_get_netif_impl */

#include "mp_core.h"
#include "mp_brand_hikvision.h"
#include "mp_brand_linux419.h"
#include "mp_brand_printer.h"
#include "mp_brand_router.h"
#include "mp_cfg_esp.h"
#include "mp_cli.h"
#include "mp_ctl.h"
#include "mp_ftpd.h"
#include "mp_http_ui.h"
#include "mp_apache.h"
#include "mp_log.h"
#include "mp_ssh_server.h"
#include "mp_net.h"
#include "mp_ssh_banner.h"
#include "mp_stack419.h"
#include "mp_telnet.h"

static const char *TAG = "micropot";

/* Fatal startup error: log, give the collector a moment, then restart.
 * app_main must never return with services half-started. */
static void fatal_restart(const char *what)
{
    ESP_LOGE(TAG, "fatal: %s — restarting in 3 s", what);
    vTaskDelay(pdMS_TO_TICKS(3000));
    esp_restart();
}

/* Register every compiled-in brand and wire profile. */
static void register_all(void)
{
    mp_brand_register(&mp_brand_hikvision);
    mp_brand_register(&mp_brand_router);
    mp_brand_register(&mp_brand_printer);
    mp_brand_register(&mp_brand_linux419);
    mp_wprof_register(&mp_wprof_linux419);
}

/* Emitted when the global session budget is exhausted; runs in accept-loop
 * context, so it only enqueues and returns. */
static void on_session_overload(const char *service, uint16_t port)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "system", "svc.overload");
    mp_evt_str(&e, "service", service);
    mp_evt_int(&e, "port", port);
    mp_evt_send(&e);
}

static void log_started_services(void)
{
    for (size_t i = 0; i < mp_registry_count(); i++) {
        mp_service_t *svc = mp_registry_at(i);
        if (svc->started) {
            mp_log_service(svc->ops->name, svc->bind.port, true);
        }
    }
}

/* Bring up every wire profile referenced by the vdev table (dedup by
 * profile id; engine init is idempotent) and select the default backend
 * from the primary persona. */
static void wire_init(void)
{
    const char *inited[8];
    size_t n_inited = 0;

    for (size_t i = 0; i < mp_vdev_count(); i++) {
        const mp_persona_t *p = mp_vdev_at(i)->persona;
        if (!p || !p->wire) {
            continue;
        }
        bool seen = false;
        for (size_t j = 0; j < n_inited; j++) {
            if (strcmp(inited[j], p->wire) == 0) {
                seen = true;
            }
        }
        if (seen) {
            continue;
        }
        const mp_wprof_t *wp = mp_wprof_find(p->wire);
        if (!wp) {
            ESP_LOGE(TAG, "persona '%s' references unknown wire profile '%s'",
                     p->id, p->wire);
            continue;
        }
        ESP_ERROR_CHECK(wp->init(wp->params));
        inited[n_inited++] = p->wire;
        if (i == 0) {
            mp_xport_use(wp->xport); /* primary persona's engine = default */
        }
    }
}

#if CONFIG_MICROPOT_LINK_PROBES
/* ---- debug-only wire probes (NEVER ship enabled: periodic GARP/ping/ARP
 * is traffic a real Linux host never sends) --------------------------- */

/* Decisive liveness probe: ping the gateway once per stats round. */
static volatile int s_gw_rtt_ms = -2; /* -2 never ran, -1 timeout, >=0 rtt */

static void gw_ping_end(esp_ping_handle_t hdl, void *args)
{
    (void)args;
    uint32_t rtt = 0, replied = 0;
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &rtt, sizeof(rtt));
    esp_ping_get_profile(hdl, ESP_PING_PROF_REPLY, &replied, sizeof(replied));
    s_gw_rtt_ms = replied ? (int)rtt : -1;
}

static void gw_ping_once(void)
{
    uint32_t gw = mp_net_get_gw();
    if (!gw) {
        return;
    }
    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    cfg.count = 1;
    cfg.timeout_ms = 1000;
    ip_addr_t target = { 0 };
    target.type = IPADDR_TYPE_V4;
    target.u_addr.ip4.addr = gw;
    cfg.target_addr = target;
    esp_ping_callbacks_t cbs = { .on_ping_end = gw_ping_end };
    esp_ping_handle_t hdl;
    if (esp_ping_new_session(&cfg, &cbs, &hdl) != ESP_OK) {
        return;
    }
    esp_ping_start(hdl);
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_ping_stop(hdl);
    esp_ping_delete_session(hdl);
}

/* ARP probe of the gateway — unlike ICMP, the gateway MUST answer ARP.
 * Each round checks the entry refreshed by the previous round's request,
 * so a stable entry proves our TX+RX both work at L2 even when the
 * scanner sees nothing. */
static volatile int s_gw_arp = -2; /* -2 never ran, -1 no entry, 1 resolved */

static void gw_arp_probe(void)
{
    uint32_t gw = mp_net_get_gw();
    struct netif *netif = esp_netif_get_netif_impl(mp_net_netif());
    if (!gw || !netif) {
        return;
    }
    LOCK_TCPIP_CORE();
    ip4_addr_t gw4 = { .addr = gw };
    struct eth_addr *eth = NULL;
    const ip4_addr_t *ip = NULL;
    s_gw_arp = (etharp_find_addr(netif, &gw4, &eth, &ip) >= 0) ? 1 : -1;
    etharp_request(netif, &gw4);  /* answer (if any) lands before next round */
    etharp_gratuitous(netif);     /* keep the AP's STA entry hot */
    UNLOCK_TCPIP_CORE();
}
#endif /* CONFIG_MICROPOT_LINK_PROBES */

/* Periodic health line, passive only: heap (internal min-ever catches slow
 * leaks during wolfSSH KEX), PSRAM (s419 rings), live session count, WiFi
 * RSSI, last-inbound-packet age and the tcpip-thread heartbeat. */
static void stats_task(void *arg)
{
    (void)arg;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(CONFIG_MICROPOT_LINK_PROBES ? 15000 : 30000));
#if CONFIG_MICROPOT_LINK_PROBES
        gw_arp_probe();
        gw_ping_once();
#endif
        int rssi = 0;
        wifi_ap_record_t ap = { 0 };
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            rssi = ap.rssi;
        }
        int64_t rx_age = mp_s419_rx_age_ms();
        static uint32_t s_prev_tick;
        uint32_t tick = mp_s419_tick_count();
        uint32_t tick_delta = tick - s_prev_tick; /* ~3000/round when alive */
        s_prev_tick = tick;
#if CONFIG_MICROPOT_LINK_PROBES
        ESP_LOGI(TAG, "stats: heap %u (min %u) psram %u sessions %u tcbs %u rssi %d rx_age %llds gwping %dms gwarp %d tick +%lu",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                 (unsigned)mp_xport_active(), (unsigned)mp_s419_tcb_count(), rssi,
                 (long long)(rx_age < 0 ? -1 : rx_age / 1000), s_gw_rtt_ms,
                 s_gw_arp, (unsigned long)tick_delta);
#else
        ESP_LOGI(TAG, "stats: heap %u (min %u) psram %u sessions %u tcbs %u rssi %d rx_age %llds tick +%lu",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL),
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                 (unsigned)mp_xport_active(), (unsigned)mp_s419_tcb_count(), rssi,
                 (long long)(rx_age < 0 ? -1 : rx_age / 1000),
                 (unsigned long)tick_delta);
#endif
    }
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }
    /* Runtime config layer: opens the "mpc" NVS namespace; must precede any
     * component that registers keys or reads overrides (mp_log is first). */
    ESP_ERROR_CHECK(mp_cfg_init());
    mp_ctl_init(); /* registers mgmt/ctl config keys */

    /* Persona/brand/vdev data is pure data, so resolve it before bringing
     * up the radio: the primary brand's OUI and persona hostname are applied
     * to the interface. */
    register_all();
    mp_vdev_load();

    const mp_vdev_t *vdev0 = mp_vdev_at(0);
    const mp_persona_t *persona = vdev0->persona;
    const mp_brand_t   *brand = mp_brand_find(persona->brand_id);
    if (!brand) {
        ESP_LOGE(TAG, "persona '%s' references unknown brand '%s'", persona->id,
                 persona->brand_id);
        fatal_restart("unknown brand");
    }
    mp_log_set_persona(persona->id);
    ESP_LOGI(TAG, "persona '%s' -> brand '%s' (%s %s)", persona->id, brand->meta->id,
             brand->meta->vendor, brand->meta->model);

    /* The network stack (esp_netif/lwIP) must be up before anything creates a
     * socket, which is why mp_net_init() precedes mp_log_init(). */
    ESP_ERROR_CHECK(mp_net_init(brand->meta->mac_oui, persona->hostname));
    /* Alias ARP responder on the wrapped netif input path. */
    ESP_ERROR_CHECK(mp_vif_install(esp_netif_get_netif_impl(mp_net_netif())));

    ESP_ERROR_CHECK(mp_log_init());
    mp_xport_set_overload_hook(on_session_overload);

    /* Wire personalities (Linux-4.19-behaving TCP/IP engines) are bound by
     * wire profile id per vdev — fully decoupled from brands. */
    wire_init();

    mp_registry_register(mp_telnet_get_ops(), mp_bind_any(CONFIG_MICROPOT_TELNET_PORT));
    mp_registry_register(mp_http_ui_get_ops(), mp_bind_any(CONFIG_MICROPOT_HTTP_PORT));
    mp_registry_register(mp_apache_get_ops(), mp_bind_any(CONFIG_MICROPOT_HTTP_PORT));
    mp_registry_register(mp_ssh_banner_get_ops(), mp_bind_any(CONFIG_MICROPOT_SSH_PORT));
    mp_registry_register(mp_ssh_server_get_ops(), mp_bind_any(CONFIG_MICROPOT_SSH_PORT));
    mp_registry_register(mp_ftpd_get_ops(), mp_bind_any(CONFIG_MICROPOT_FTP_PORT));

    char ip[16] = "0.0.0.0";
    char gw[16] = "0.0.0.0";
    if (mp_net_wait_connected(30000) == ESP_OK) {
        char mac[18] = "";
        mp_net_get_ip_str(ip, sizeof(ip));
        mp_net_get_gw_str(gw, sizeof(gw));
        mp_net_get_mac_str(mac, sizeof(mac));
        mp_log_net_up(ip, gw, mac);
        ESP_LOGI(TAG, "honeypot online at %s (gw %s, mac %s)", ip, gw, mac);
    } else {
        ESP_LOGW(TAG, "no IP obtained within timeout, starting services anyway");
    }

    err = mp_registry_start_all();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to start services: %s", esp_err_to_name(err));
        mp_registry_stop_all();
        fatal_restart("service start failed");
    }
    log_started_services();

    /* Management plane on its own dedicated address (no-op when mgmt.ip
     * is unset) plus the serial CLI fallback. */
    mp_ctl_start();
    mp_cli_start();

    /* vdev inventory + narrative coherence: distinct brand vendors on one
     * shared MAC read as "one box with aliases" — warn, don't forbid. */
    const char *va, *vb;
    if (!mp_vdev_vendor_coherent(&va, &vb)) {
        ESP_LOGW(TAG, "mixed vendors on one MAC (%s vs %s): aliases read as "
                 "one multi-identity host", va, vb);
        mp_evt_t e;
        mp_evt_begin(&e, NULL, "system", "config_warn");
        mp_evt_str(&e, "msg", "mixed brand vendors share one MAC");
        mp_evt_str(&e, "vendor_a", va);
        mp_evt_str(&e, "vendor_b", vb);
        mp_evt_send(&e);
    }
    for (size_t i = 1; i < mp_vdev_count(); i++) {
        const mp_vdev_t *v = mp_vdev_at(i);
        char ip[16];
        mp_ip4_str(v->vaddr, ip, sizeof(ip));
        mp_evt_t e;
        mp_evt_begin(&e, NULL, "system", "vdev");
        mp_evt_str(&e, "ip", ip);
        mp_evt_str(&e, "persona", v->persona->id);
        mp_evt_str(&e, "wire", v->persona->wire ? v->persona->wire : "lwip");
        mp_evt_send(&e);
    }

    char list[96] = "";
    for (size_t i = 0; i < mp_registry_count(); i++) {
        mp_service_t *svc = mp_registry_at(i);
        if (svc->started) {
            snprintf(list + strlen(list), sizeof(list) - strlen(list),
                     "%s%s:%d", list[0] ? ", " : "", svc->ops->name,
                     svc->bind.port);
        }
    }
    ESP_LOGI(TAG, "honeypot ready: %s", list);
    xTaskCreate(stats_task, "stats", 2048, NULL, 3, NULL);
}
