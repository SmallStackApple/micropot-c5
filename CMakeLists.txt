# MicroPot-C5 — ESP32-C5 resource-constrained multi-virtual-device honeypot
# Phase 1: single IP hosting brand-driven honeypot services + JSON logging.
cmake_minimum_required(VERSION 3.16)

# Brand behaviour modules live under components/brands/ so they stay grouped.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components/brands")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(micropot_c5)

# managed_components/ is fetched during project() (the component manager
# retries until Kconfig is available), and compilation starts after this
# configure step, so this is the safe window to patch the vendored
# wolfSSL/wolfSSH sources. Doing it here keeps a fresh clone, CI and
# Windows builds on the same path; no sh/sed is required.
execute_process(
    COMMAND "${CMAKE_COMMAND}" -P
            "${CMAKE_CURRENT_LIST_DIR}/tools/patch_wolfssl.cmake"
    RESULT_VARIABLE mp_patch_rc
    OUTPUT_VARIABLE mp_patch_out
    ERROR_VARIABLE  mp_patch_err
)
if(NOT mp_patch_rc EQUAL 0)
    message(FATAL_ERROR
        "wolfSSL/wolfSSH patch failed (exit ${mp_patch_rc}):\n"
        "${mp_patch_out}${mp_patch_err}")
endif()
message(STATUS "${mp_patch_out}")

# wolfSSL's ESP user_settings.h predates the ESP32-C5 target and emits
# "#warning Unexpected CONFIG_IDF_TARGET_NN value"; the #else branch then
# (correctly) disables hardware acceleration for the C5. Keep -Werror=cpp
# from turning that benign warning into a build failure.
# WOLFSSL_WOLFSSH exposes wc_SSH_KDF(), which wolfSSH's KEX needs.
if(TARGET __idf_wolfssl__wolfssl)
    target_compile_options(__idf_wolfssl__wolfssl PRIVATE -Wno-error=cpp)
    target_compile_definitions(__idf_wolfssl__wolfssl PRIVATE WOLFSSL_WOLFSSH)
endif()

# Alias vdev demux: our LWIP_HOOK_IP4_INPUT lives in mp_core's
# mp_lwip_hooks.h, injected into the lwip build via the IDF extension point.
if(TARGET __idf_lwip)
    # target_compile_definitions handles per-generator quoting; passing a
    # raw -D...=\"...\" through target_compile_options is fragile on the
    # Windows Ninja/cmd path.
    target_compile_definitions(__idf_lwip PRIVATE
        "-DESP_IDF_LWIP_HOOK_FILENAME=\"mp_lwip_hooks.h\"")
    target_include_directories(__idf_lwip PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/components/mp_core/include")
endif()
if(TARGET __idf_wolfssl__wolfssh)
    target_compile_options(__idf_wolfssl__wolfssh PRIVATE -Wno-error=cpp)
    target_compile_definitions(__idf_wolfssl__wolfssh PRIVATE WOLFSSL_WOLFSSH)
endif()
