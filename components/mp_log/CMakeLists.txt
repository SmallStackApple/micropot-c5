idf_component_register(
    SRCS "mp_log.c" "mp_evt.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_cfg lwip nvs_flash esp_timer
    PRIV_REQUIRES heap
)
