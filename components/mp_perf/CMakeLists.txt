idf_component_register(
    SRCS "mp_perf.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_cfg mp_log mp_stack419 esp_timer heap esp_wifi esp_driver_tsens
)
