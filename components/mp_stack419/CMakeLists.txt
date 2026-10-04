idf_component_register(
    SRCS
        "mp_stack419.c"
        "s419_core.c"
        "s419_isn.c"
        "s419_pkt.c"
        "s419_siphash.c"
        "s419_tcp.c"
        "s419_xport.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_net mp_log lwip
    PRIV_REQUIRES esp_timer
)
