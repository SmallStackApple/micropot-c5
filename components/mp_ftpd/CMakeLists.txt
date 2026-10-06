idf_component_register(
    SRCS "mp_ftpd.c" "mp_ftpd_data.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_linekit mp_linuxfs mp_log
)
