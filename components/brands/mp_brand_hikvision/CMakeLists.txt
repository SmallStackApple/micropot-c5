idf_component_register(
    SRCS "mp_brand_hikvision.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_net mp_telnet mp_http_ui mp_ssh_banner
    EMBED_TXTFILES
        "www/hikvision_login.html"
        "www/hikvision_fail.html"
        "www/hikvision_admin.html"
)
