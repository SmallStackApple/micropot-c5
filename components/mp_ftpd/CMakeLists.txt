idf_component_register(
    SRCS "mp_ftpd.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_linekit mp_linuxfs mp_log mp_net
    PRIV_REQUIRES esp_timer
)
