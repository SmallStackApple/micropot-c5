idf_component_register(
    SRCS "mp_brand_router.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_net mp_telnet mp_http_ui mp_ssh_banner
    EMBED_TXTFILES
        "www/tplink_login.html"
        "www/tplink_fail.html"
        "www/tplink_admin.html"
)
