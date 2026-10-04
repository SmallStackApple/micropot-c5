idf_component_register(
    SRCS "mp_sshd.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_log wolfssl__wolfssh
    PRIV_REQUIRES esp_timer
)

# Same config knobs the vendored components use: wolfSSL user_settings.h
# plus the SSH KDF visibility define.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WOLFSSL_USER_SETTINGS WOLFSSH_USER_SETTINGS WOLFSSL_WOLFSSH)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=cpp)
