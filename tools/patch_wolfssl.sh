#!/bin/sh
# Compatibility wrapper. The actual implementation is patch_wolfssl.cmake,
# which is also run automatically by the top-level CMakeLists.txt during
# the CMake configure step (so `idf.py build` needs no manual step).
#
# Kept so existing habits/scripts still work on Linux/macOS/Git Bash:
#     tools/patch_wolfssl.sh
set -e
exec cmake -P "$(dirname "$0")/patch_wolfssl.cmake"
