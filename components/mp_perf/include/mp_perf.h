#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Performance monitoring
 *
 * Periodic system.perf event (interval from cfg key perf.interval_s,
 * 0 = off) + edge-triggered system.alert events (heap watermark, log
 * drops). Also prints the serial stats line formerly produced by main's
 * stats_task. CPU% needs CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS, which is
 * off — enable in sdkconfig if per-task stats are ever wanted.
 * ---------------------------------------------------------------------- */

esp_err_t mp_perf_init(void);

#ifdef __cplusplus
}
#endif
