#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "lwip/inet.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "mp_net.h"
#include "mp_util.h"

static const char *TAG = "mp_net";

#define WIFI_CONNECTED_BIT BIT0

/* Reconnect backoff: 1s, 2s, 4s ... capped, reset once an IP is obtained.
 * A wrong password otherwise makes the event handler spin at full rate. */
#define WIFI_RECONNECT_BASE_MS 1000
#define WIFI_RECONNECT_MAX_MS  30000

static EventGroupHandle_t s_wifi_eg;
static esp_netif_t       *s_sta_netif;
static esp_timer_handle_t s_reconnect_timer;
static uint8_t            s_mac[6];
static uint32_t           s_ip;
static uint32_t           s_gw;
static unsigned           s_retry;
static bool               s_reconnect_pending;

static void reconnect_cb(void *arg)
{
    (void)arg;
    s_reconnect_pending = false;
    ESP_LOGI(TAG, "reconnecting (attempt %u)...", s_retry);
    esp_wifi_connect();
}

static void schedule_reconnect(void)
{
    s_retry++;
    uint32_t delay_ms = WIFI_RECONNECT_BASE_MS << (s_retry - 1);
    if (delay_ms > WIFI_RECONNECT_MAX_MS || s_retry > 20) {
        delay_ms = WIFI_RECONNECT_MAX_MS;
    }
    if (!s_reconnect_pending) {
        s_reconnect_pending = true;
        esp_timer_start_once(s_reconnect_timer, (uint64_t)delay_ms * 1000);
    }
    ESP_LOGW(TAG, "disconnected, reconnecting in %u ms", (unsigned)delay_ms);
}

static void on_wifi(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)data;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        xEventGroupClearBits(s_wifi_eg, WIFI_CONNECTED_BIT);
        schedule_reconnect();
    }
}

static void on_ip(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        s_ip = e->ip_info.ip.addr;
        s_gw = e->ip_info.gw.addr;
        s_retry = 0;
        if (s_reconnect_pending) {
            esp_timer_stop(s_reconnect_timer);
            s_reconnect_pending = false;
        }
        char buf[16];
        mp_net_get_ip_str(buf, sizeof(buf));
        ESP_LOGI(TAG, "got IP %s", buf);
        xEventGroupSetBits(s_wifi_eg, WIFI_CONNECTED_BIT);
    }
}

#ifdef CONFIG_MICROPOT_USE_STATIC_IP
static esp_err_t apply_static_ip(void)
{
    esp_netif_dhcpc_stop(s_sta_netif);
    esp_netif_ip_info_t info = { 0 };
    if (inet_pton(AF_INET, CONFIG_MICROPOT_STATIC_IP, &info.ip) != 1 ||
        inet_pton(AF_INET, CONFIG_MICROPOT_STATIC_NETMASK, &info.netmask) != 1 ||
        inet_pton(AF_INET, CONFIG_MICROPOT_STATIC_GW, &info.gw) != 1) {
        ESP_LOGE(TAG, "invalid static IP configuration");
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = esp_netif_set_ip_info(s_sta_netif, &info);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_set_ip_info failed: %s", esp_err_to_name(err));
    }
    return err;
}
#endif

esp_err_t mp_net_init(const uint8_t mac_oui[3], const char *hostname)
{
    s_wifi_eg = xEventGroupCreate();
    if (!s_wifi_eg) {
        return ESP_ERR_NO_MEM;
    }

    const esp_timer_create_args_t targs = {
        .callback = reconnect_cb,
        .name = "mp_wifi_rc",
    };
    ESP_ERROR_CHECK(esp_timer_create(&targs, &s_reconnect_timer));

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &on_wifi, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &on_ip, NULL, NULL));

    wifi_config_t wcfg = { 0 };
    strlcpy((char *)wcfg.sta.ssid, CONFIG_MICROPOT_WIFI_SSID, sizeof(wcfg.sta.ssid));
    strlcpy((char *)wcfg.sta.password, CONFIG_MICROPOT_WIFI_PASSWORD,
            sizeof(wcfg.sta.password));
    wcfg.sta.threshold.authmode = WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    /* Vendor MAC spoofing: brand OUI + the unique tail of the factory MAC.
     * esp_wifi_set_mac() must be called while the interface is still disabled. */
    if (mac_oui && (mac_oui[0] | mac_oui[1] | mac_oui[2])) {
        uint8_t base[6] = { 0 };
        if (esp_efuse_mac_get_default(base) == ESP_OK) {
            s_mac[0] = mac_oui[0];
            s_mac[1] = mac_oui[1];
            s_mac[2] = mac_oui[2];
            s_mac[3] = base[3];
            s_mac[4] = base[4];
            s_mac[5] = base[5];
            esp_err_t err = esp_wifi_set_mac(WIFI_IF_STA, s_mac);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "MAC spoof failed (%s), keeping factory MAC",
                         esp_err_to_name(err));
            } else {
                char ms[18];
                mp_net_get_mac_str(ms, sizeof(ms));
                ESP_LOGI(TAG, "station MAC spoofed to %s (OUI %02x:%02x:%02x)",
                         ms, mac_oui[0], mac_oui[1], mac_oui[2]);
            }
        }
    } else {
        ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, s_mac));
    }

    if (hostname && hostname[0]) {
        esp_err_t err = esp_netif_set_hostname(s_sta_netif, hostname);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "DHCP hostname set to '%s'", hostname);
        } else {
            ESP_LOGW(TAG, "failed to set hostname: %s", esp_err_to_name(err));
        }
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wcfg));

#ifdef CONFIG_MICROPOT_USE_STATIC_IP
    apply_static_ip();
#endif

    ESP_ERROR_CHECK(esp_wifi_start());

    /* A honeypot emulates mains-powered appliances: cameras/routers do not
     * nap their radios. Modem sleep also adds 100-300 ms of jitter in both
     * directions (AP-side buffering + wake cycles), which makes interactive
     * sessions stutter and can trip an attacker's timeouts. */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_LOGI(TAG, "station started, joining '%s'", CONFIG_MICROPOT_WIFI_SSID);
    return ESP_OK;
}

esp_err_t mp_net_wait_connected(uint32_t timeout_ms)
{
    EventBits_t bits = xEventGroupWaitBits(s_wifi_eg, WIFI_CONNECTED_BIT,
                                           pdFALSE, pdTRUE,
                                           pdMS_TO_TICKS(timeout_ms));
    return (bits & WIFI_CONNECTED_BIT) ? ESP_OK : ESP_ERR_TIMEOUT;
}

uint32_t mp_net_get_ip(void)
{
    return s_ip;
}

esp_netif_t *mp_net_netif(void)
{
    return s_sta_netif;
}

void mp_net_get_mac(uint8_t out[6])
{
    if (out) {
        memcpy(out, s_mac, 6);
    }
}

void mp_net_get_ip_str(char *buf, size_t len)
{
    mp_ip4_str(s_ip, buf, len);
}

void mp_net_get_gw_str(char *buf, size_t len)
{
    mp_ip4_str(s_gw, buf, len);
}

void mp_net_get_mac_str(char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
}
