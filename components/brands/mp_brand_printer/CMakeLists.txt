idf_component_register(
    SRCS "mp_brand_printer.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_telnet mp_http mp_ssh
    EMBED_TXTFILES
        "www/printer_login.html"
        "www/printer_fail.html"
        "www/printer_admin.html"
)
