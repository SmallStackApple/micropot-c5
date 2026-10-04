# MicroPot-C5 — ESP32-C5 resource-constrained multi-virtual-device honeypot
# Phase 1: single IP + Telnet/HTTP honeypot + structured JSON logging.
cmake_minimum_required(VERSION 3.16)

# Brand behaviour modules live under components/brands/ so they stay grouped.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components/brands")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(micropot_c5)

# wolfSSL 5.7.6 does not recognise the ESP32-C5 target and emits an
# informational #warning; with -Werror that would be fatal. Pragmas inside
# the component are not enough because the flag is applied per object, so
# keep cpp diagnostics non-fatal build-wide.
idf_build_set_property(COMPILE_OPTIONS "-Wno-error=cpp" APPEND)

# wolfSSH calls wolfSSL's wc_SSH_KDF, whose prototype is guarded by
# WOLFSSL_WOLFSSH; the managed components do not define it for us.
idf_build_set_property(COMPILE_OPTIONS "-DWOLFSSL_WOLFSSH" APPEND)

# (wolfSSL's ESP32-C5 entropy hook is injected into its user_settings.h by
# tools/patches/wolfssl-esp32c5.py; the function lives in mp_sshd.)
