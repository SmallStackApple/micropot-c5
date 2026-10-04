idf_component_register(
    SRCS "mp_telnet.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_linekit mp_log mp_shell
    PRIV_REQUIRES esp_timer
)
