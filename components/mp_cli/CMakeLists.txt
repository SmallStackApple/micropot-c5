idf_component_register(
    SRCS "mp_cli.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_cfg mp_log mp_stack419 console esp_timer heap esp_app_format
)
