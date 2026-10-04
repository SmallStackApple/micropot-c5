idf_component_register(
    SRCS "mp_sshd.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_log mp_shell wolfssl__wolfssh wolfssl__wolfssl
    PRIV_REQUIRES esp_timer
    EMBED_FILES "keys/ssh_host_ecdsa_key.der"
)
