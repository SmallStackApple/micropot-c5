# MicroPot-C5 — ESP32-C5 resource-constrained multi-virtual-device honeypot
# Phase 1: single IP + Telnet/HTTP honeypot + structured JSON logging.
cmake_minimum_required(VERSION 3.16)

# Brand behaviour modules live under components/brands/ so they stay grouped.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components/brands")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(micropot_c5)

# wolfSSL's ESP user_settings.h predates the ESP32-C5 target and emits
# "#warning Unexpected CONFIG_IDF_TARGET_NN value"; the #else branch then
# (correctly) disables hardware acceleration for the C5. Keep -Werror=cpp
# from turning that benign warning into a build failure.
# WOLFSSL_WOLFSSH exposes wc_SSH_KDF(), which wolfSSH's KEX needs.
if(TARGET __idf_wolfssl__wolfssl)
    target_compile_options(__idf_wolfssl__wolfssl PRIVATE -Wno-error=cpp)
    target_compile_definitions(__idf_wolfssl__wolfssl PRIVATE WOLFSSL_WOLFSSH)
endif()
if(TARGET __idf_wolfssl__wolfssh)
    target_compile_options(__idf_wolfssl__wolfssh PRIVATE -Wno-error=cpp)
    target_compile_definitions(__idf_wolfssl__wolfssh PRIVATE WOLFSSL_WOLFSSH)
endif()
