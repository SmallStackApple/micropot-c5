/*
 * MicroPot-C5 — phase 1 entry point.
 *
 * Single device IP hosting two brand-driven honeypot services (Telnet + HTTP)
 * with structured JSON event logging to a PC collector.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "mp_core.h"
#include "mp_brand_hikvision.h"
#include "mp_brand_linux419.h"
#include "mp_brand_printer.h"
#include "mp_brand_router.h"
#include "mp_http.h"
#include "mp_httpd.h"
#include "mp_log.h"
#include "mp_net.h"
#include "mp_s419_params.h"
#include "mp_ssh.h"
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

static const mp_brand_t *select_brand(const mp_persona_t *persona)
{
    /* Brand registry: one line per compiled-in brand module. */
    mp_brand_register(&mp_brand_hikvision);
    mp_brand_register(&mp_brand_router);
    mp_brand_register(&mp_brand_printer);
    mp_brand_register(&mp_brand_linux419);
    return mp_brand_find(persona->brand_id);
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

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    /* Persona/brand are pure data, so resolve them before bringing up the
     * radio: the brand OUI and persona hostname are applied to the interface. */
    const mp_persona_t *persona = mp_persona_active();
    const mp_brand_t   *brand = select_brand(persona);
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

    /* Persona-selected transport. When the brand carries a "stack419"
     * behaviour, services are carried by the Linux 4.19 TCP/IP engine
     * instead of lwIP; lwIP keeps handling ARP and the log transport. */
    if (persona->transport && strcmp(persona->transport, "s419") == 0) {
        const mp_s419_params_t *par = mp_brand_behavior(brand, "stack419");
        if (par && mp_stack419_init(par) == ESP_OK) {
            mp_xport_use(&mp_xport_s419);
            ESP_LOGI(TAG, "transport: Linux 4.19 engine (mp_stack419)");
        } else {
            ESP_LOGE(TAG, "stack419 requested but unavailable, using lwIP");
        }
    }

    ESP_ERROR_CHECK(mp_log_init());
    mp_xport_set_overload_hook(on_session_overload);

    mp_registry_register(mp_telnet_get_ops(), mp_bind_any(CONFIG_MICROPOT_TELNET_PORT));
    mp_registry_register(mp_http_get_ops(), mp_bind_any(CONFIG_MICROPOT_HTTP_PORT));
    /* Apache-style server on mp_xport: the Linux 4.19 persona uses this
     * one, vendor brands keep the esp_http_server path above. */
    mp_registry_register(mp_httpd_get_ops(), mp_bind_any(CONFIG_MICROPOT_HTTP_PORT));
    mp_registry_register(mp_ssh_get_ops(), mp_bind_any(CONFIG_MICROPOT_SSH_PORT));

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

    err = mp_registry_start_all(persona, brand);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "failed to start all services: %s", esp_err_to_name(err));
        mp_registry_stop_all();
        fatal_restart("service start failed");
    }
    log_started_services();

    ESP_LOGI(TAG, "MicroPot-C5 phase-1 ready: telnet :%d, http :%d, ssh :%d",
             CONFIG_MICROPOT_TELNET_PORT, CONFIG_MICROPOT_HTTP_PORT,
             CONFIG_MICROPOT_SSH_PORT);
}
