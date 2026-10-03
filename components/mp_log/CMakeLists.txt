idf_component_register(
    SRCS "mp_log.c" "mp_evt.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core lwip nvs_flash esp_timer
)
