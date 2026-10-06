idf_component_register(
    SRCS "micropot_main.c"
    INCLUDE_DIRS "."
    REQUIRES
        mp_core
        mp_cfg
        mp_log
        mp_net
        mp_telnet
        mp_http_ui
        mp_apache
        mp_ssh_banner
        mp_ssh_server
        mp_ftpd
        mp_brand_hikvision
        mp_brand_router
        mp_brand_printer
        mp_brand_linux419
        mp_stack419
        mp_ctl
        nvs_flash
)
