idf_component_register(
    SRCS "mp_ssh_server.c" "mp_wolfmem.c"
    INCLUDE_DIRS "include"
    REQUIRES mp_core mp_cfg mp_log wolfssl__wolfssh
    PRIV_REQUIRES esp_timer heap
)

# Same config knobs the vendored components use: wolfSSL user_settings.h
# plus the SSH KDF visibility define. XMALLOC_USER tells wolfSSL/wolfSSH to
# use the XMALLOC/XREALLOC/XFREE functions in mp_wolfmem.c (PSRAM-aware)
# instead of the default pvPortMalloc path. It must be defined for every
# translation unit that includes the wolfSSL headers, including the library.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WOLFSSL_USER_SETTINGS WOLFSSH_USER_SETTINGS WOLFSSL_WOLFSSH XMALLOC_USER)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-error=cpp)

# The vendored wolfSSL/wolfSSH libraries must see XMALLOC_USER too.
foreach(tgt __idf_wolfssl__wolfssl __idf_wolfssl__wolfssh)
    if(TARGET ${tgt})
        target_compile_definitions(${tgt} PRIVATE XMALLOC_USER)
    endif()
endforeach()
