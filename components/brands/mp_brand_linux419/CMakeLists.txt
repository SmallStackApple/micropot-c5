idf_component_register(
    SRCS "mp_brand_linux419.c" "linux419_fs.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_net mp_telnet mp_http_ui mp_apache mp_ssh_banner mp_ssh_server mp_ftpd mp_linuxfs mp_linuxsh
    EMBED_FILES "keys/ssh_host_rsa_key.der" "keys/ssh_host_ecdsa_key.der"
    EMBED_TXTFILES
        "www/linux_login.html"
        "www/linux_fail.html"
        "www/linux_admin.html"
)
