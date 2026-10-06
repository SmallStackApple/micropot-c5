idf_component_register(
    SRCS "mp_ctl.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_cfg mp_log mp_stack419 mp_linekit wolfssl__wolfssl esp_timer heap lwip esp_app_format esp_system
    PRIV_REQUIRES esp_wifi
)

# wolfSSL user_settings.h config (same knob the sshd component uses).
target_compile_definitions(${COMPONENT_LIB} PRIVATE WOLFSSL_USER_SETTINGS)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=cpp)
