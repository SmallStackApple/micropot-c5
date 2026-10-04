idf_component_register(
    SRCS "micropot_main.c"
    INCLUDE_DIRS "."
    REQUIRES
        mp_core
        mp_log
        mp_net
        mp_stack419
        mp_telnet
        mp_http
        mp_ssh
        mp_brand_hikvision
        mp_brand_router
        mp_brand_printer
        mp_brand_linux419
        nvs_flash
)
