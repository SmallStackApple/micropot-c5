idf_component_register(
    SRCS "mp_linuxfs.c" "mp_crypt.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core wolfssl__wolfssl
)

# wolfSSL user_settings.h config (same knob as mp_ssh_server/mp_ctl).
target_compile_definitions(${COMPONENT_LIB} PRIVATE WOLFSSL_USER_SETTINGS)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=cpp)
