# MicroPot-C5 — ESP32-C5 resource-constrained multi-virtual-device honeypot
# Phase 1: single IP + Telnet/HTTP honeypot + structured JSON logging.
cmake_minimum_required(VERSION 3.16)

# Brand behaviour modules live under components/brands/ so they stay grouped.
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components/brands")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(micropot_c5)
