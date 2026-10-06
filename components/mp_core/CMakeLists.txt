idf_component_register(
    SRCS
        "mp_brand.c"
        "mp_persona.c"
        "mp_registry.c"
        "mp_udp_listener.c"
        "mp_util.c"
        "mp_vdev.c"
        "mp_vif.c"
        "mp_wprof.c"
        "mp_xport.c"
        "mp_xport_lwip.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_netif lwip esp_wifi mp_cfg
    PRIV_REQUIRES esp_timer heap
)
