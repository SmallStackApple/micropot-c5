idf_component_register(
    SRCS
        "mp_linuxsh.c"
        "mp_linuxsh_cmd_fs.c"
        "mp_linuxsh_cmd_net.c"
        "mp_linuxsh_cmd_misc.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_linekit mp_linuxfs mp_log mp_net
    PRIV_REQUIRES esp_timer
)
