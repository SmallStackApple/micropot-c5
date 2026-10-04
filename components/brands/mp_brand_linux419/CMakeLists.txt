idf_component_register(
    SRCS "mp_brand_linux419.c"
    INCLUDE_DIRS "include"
    REQUIRES
        mp_stack419 mp_core mp_net mp_telnet mp_http mp_httpd mp_ssh
        mp_sshd mp_linuxfs mp_shell
    EMBED_TXTFILES
        "www/linux_login.html"
        "www/linux_fail.html"
        "www/linux_admin.html"
)
