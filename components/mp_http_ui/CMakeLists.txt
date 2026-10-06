idf_component_register(
    SRCS "mp_http_ui.c" "mp_form.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_log esp_http_server lwip esp_timer
)
