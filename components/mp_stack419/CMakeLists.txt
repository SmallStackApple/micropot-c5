idf_component_register(
    SRCS
        "mp_stack419.c"
        "s419_core.c"
        "s419_tcp.c"
        "s419_xport.c"
        "s419_pkt.c"
        "s419_siphash.c"
        "s419_isn.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_log mp_net
    PRIV_REQUIRES lwip esp_timer esp_hw_support heap
)
