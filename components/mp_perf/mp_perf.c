/*
 * Performance monitoring: periodic system.perf event + alert edges.
 *
 * The collector sees the same health picture the serial stats line shows;
 * under attack (hydra, floods) the events keep flowing even when nobody
 * watches the UART.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/temperature_sensor.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "lwip/stats.h"

#include "mp_cfg.h"
#include "mp_log.h"
#include "mp_perf.h"
#include "mp_stack419.h"
#include "mp_wolfmem.h"
#include "mp_xport.h"

static const char *TAG = "mp_perf";

static const mp_cfg_key_t s_cfg_keys[] = {
    { "perf.int_s", MP_CFG_T_U32, { .u.u32 = 60 }, 0, 3600, NULL, false, NULL, false },
    { "perf.heap_kb", MP_CFG_T_U32, { .u.u32 = 32 }, 8, 512, NULL, false, NULL, false },
};

static temperature_sensor_handle_t s_tsens;
static bool s_heap_alerted;
static uint32_t s_last_dropped;

static void emit_alert(const char *kind, long long value)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "system", "alert");
    mp_evt_str(&e, "kind", kind);
    mp_evt_int(&e, "value", value);
    mp_evt_send(&e);
    ESP_LOGW(TAG, "alert: %s = %lld", kind, value);
}

static void perf_round(void)
{
    uint32_t heap_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    uint32_t heap_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    uint32_t psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    uint32_t sessions = mp_xport_active();
    uint32_t dropped, queued;
    mp_log_stats(&dropped, &queued);

    int rssi = 0;
    wifi_ap_record_t ap = { 0 };
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        rssi = ap.rssi;
    }
    float temp_c = -127.0f;
    if (s_tsens) {
        temperature_sensor_get_celsius(s_tsens, &temp_c);
    }

    static uint32_t s_prev_tick;
    uint32_t tick = mp_s419_tick_count();
    uint32_t tick_delta = tick - s_prev_tick;
    s_prev_tick = tick;

    uint32_t wolf_cur = 0, wolf_peak = 0;
    mp_wolfmem_stats(&wolf_cur, &wolf_peak, NULL);
    uint16_t c_est = 0, c_syn = 0, c_tw = 0;
    mp_s419_state_counts(&c_est, &c_syn, &c_tw, NULL);

    /* serial line (formerly main's stats_task) */
    int64_t rx_age = mp_s419_rx_age_ms();
    ESP_LOGI(TAG, "stats: heap %lu (min %lu) psram %lu wolf %lu/%lu sessions %lu tcbs %u(e%hu/s%hu/tw%hu) "
             "rssi %d rx_age %llds tick +%lu logdrop %lu",
             (unsigned long)heap_free, (unsigned long)heap_min,
             (unsigned long)psram, (unsigned long)wolf_cur,
             (unsigned long)wolf_peak, (unsigned long)sessions,
             (unsigned)mp_s419_tcb_count(), c_est, c_syn, c_tw, rssi,
             (long long)(rx_age < 0 ? -1 : rx_age / 1000),
             (unsigned long)tick_delta, (unsigned long)dropped);

    /* collector event */
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "system", "perf");
    mp_evt_int(&e, "uptime_s", (long long)(esp_timer_get_time() / 1000000));
    mp_evt_int(&e, "heap_free", heap_free);
    mp_evt_int(&e, "heap_min", heap_min);
    mp_evt_int(&e, "psram_free", psram);
    mp_evt_int(&e, "sessions", sessions);
    mp_evt_int(&e, "tcbs", mp_s419_tcb_count());
    mp_evt_int(&e, "tcb_estab", c_est);
    mp_evt_int(&e, "tcb_syn_recv", c_syn);
    mp_evt_int(&e, "tcb_time_wait", c_tw);
    mp_evt_int(&e, "rssi", rssi);
    mp_evt_int(&e, "temp_c_x10", (long long)(temp_c * 10));
    mp_evt_int(&e, "log_dropped", dropped);
    mp_evt_int(&e, "log_queued", queued);
    mp_evt_int(&e, "wolf_cur", wolf_cur);
    mp_evt_int(&e, "wolf_peak", wolf_peak);
#if LWIP_STATS && MEMP_STATS
    /* lwIP only carries the log socket / DHCP / gw probe; big numbers
     * here would mean something is leaking PCBs or pbufs. */
    mp_evt_int(&e, "lwip_tcp_pcb", lwip_stats.memp[MEMP_TCP_PCB].used);
    mp_evt_int(&e, "lwip_pbuf", lwip_stats.memp[MEMP_PBUF_POOL].used);
#endif
    mp_evt_send(&e);

    /* alert edges */
    uint32_t warn_kb = mp_cfg_u32("perf.heap_kb", 32);
    if (!s_heap_alerted && heap_min < warn_kb * 1024) {
        s_heap_alerted = true;
        emit_alert("heap_min", heap_min);
    }
    if (dropped != s_last_dropped) {
        emit_alert("log_dropped", dropped);
        s_last_dropped = dropped;
    }
}

static void perf_task(void *arg)
{
    (void)arg;
    for (;;) {
        uint32_t interval = mp_cfg_u32("perf.int_s", 60);
        if (interval == 0) {
            interval = 5; /* re-check the knob soon while disabled */
            vTaskDelay(pdMS_TO_TICKS(interval * 1000));
            continue;
        }
        vTaskDelay(pdMS_TO_TICKS(interval * 1000));
        perf_round();
    }
}

esp_err_t mp_perf_init(void)
{
    mp_cfg_register(s_cfg_keys, sizeof(s_cfg_keys) / sizeof(s_cfg_keys[0]));

    /* die temperature: nice-to-have, never fatal */
    temperature_sensor_config_t ts_cfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
    if (temperature_sensor_install(&ts_cfg, &s_tsens) == ESP_OK) {
        if (temperature_sensor_enable(s_tsens) != ESP_OK) {
            s_tsens = NULL;
        }
    }

    if (xTaskCreate(perf_task, "mp_perf", 3072, NULL, 3, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
