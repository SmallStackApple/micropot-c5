idf_component_register(
    SRCS "mp_ssh_banner.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_linekit mp_log
    PRIV_REQUIRES esp_timer
)
