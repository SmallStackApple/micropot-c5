# Patch the vendored wolfSSL/wolfSSH sources fetched by the ESP-IDF
# component manager.
#
# This replaces the old POSIX sh + sed script so the same logic runs on
# Linux and Windows (no sh, sed or Git Bash required). It is idempotent:
# files are only rewritten when an upstream anchor is still in the
# unpatched form, so running it on every CMake configure does not touch
# mtimes and does not force a wolfSSL rebuild.
#
# It runs automatically from the top-level CMakeLists.txt after project()
# (which is when managed_components/ has been fetched) and before any
# wolfSSL source is compiled. Manual run:
#
#     cmake -P tools/patch_wolfssl.cmake
#
# The patches:
#   1. MY_USE_RSA=1 in wolfSSL's ESP user_settings.h (the registry build
#      flips it to 0 on targets other than ESP8266/C2, which makes wolfSSH
#      reject RSA host keys with WS_UNIMPLEMENTED_E -1017).
#   2. Enable WOLFSSH_YES_RSA_SHA2_512; wolfSSH 1.4.20 hard-disables it.
#   3. Fix the upstream trailing-comma typo in internal.c's canned
#      rsa-sha2-512 key-algorithm string (only compiled once #2 is on).
#
# Every patch has a post-condition check: if an upstream version moves the
# text, configure fails loudly instead of silently shipping broken SSH.

cmake_minimum_required(VERSION 3.16)

get_filename_component(_mp_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(_mp_ws  "${_mp_root}/managed_components/wolfssl__wolfssl")
set(_mp_wsh "${_mp_root}/managed_components/wolfssl__wolfssh")
set(_mp_us  "${_mp_ws}/include/user_settings.h")
set(_mp_int "${_mp_wsh}/src/internal.c")

foreach(_f "${_mp_us}" "${_mp_int}")
    if(NOT EXISTS "${_f}")
        message(FATAL_ERROR
            "patch_wolfssl: ${_f} missing; run 'idf.py reconfigure' first")
    endif()
endforeach()

# Replace old with new once. If old is absent, accept the state only when
# new is already present (i.e. a previous run patched it); otherwise the
# upstream text moved and the build must stop.
function(_mp_replace path old new)
    file(READ "${path}" _text)
    string(FIND "${_text}" "${old}" _pos)
    if(_pos EQUAL -1)
        string(FIND "${_text}" "${new}" _done)
        if(_done EQUAL -1)
            message(FATAL_ERROR "patch_wolfssl: anchor not found in ${path}")
        endif()
        return()
    endif()
    string(REPLACE "${old}" "${new}" _text "${_text}")
    file(WRITE "${path}" "${_text}")
    message(STATUS "patched: ${path}")
endfunction()

# 1) RSA host keys on every target. Some wolfSSH releases also ship their
#    own user_settings.h; patch it if present, but wolfSSL's is required.
foreach(_f "${_mp_us}" "${_mp_wsh}/include/user_settings.h")
    if(EXISTS "${_f}")
        _mp_replace("${_f}" "#define MY_USE_RSA 0" "#define MY_USE_RSA 1")
    endif()
endforeach()

# 2) rsa-sha2-512 name mapping (wolfSSH 1.4.20).
file(READ "${_mp_us}" _text)
string(FIND "${_text}" "#define WOLFSSH_YES_RSA_SHA2_512" _has)
if(_has EQUAL -1)
    string(PREPEND _text "#define WOLFSSH_YES_RSA_SHA2_512\n")
    file(WRITE "${_mp_us}" "${_text}")
    message(STATUS "patched: ${_mp_us} (WOLFSSH_YES_RSA_SHA2_512)")
endif()

# 3) Upstream typo: the comma sits outside the rsa-sha2-512 literal.
#    Bracket arguments keep the quotes without backslash escaping.
set(_mp_bad  [=[    "rsa-sha2-512",]=])
set(_mp_good [=[    "rsa-sha2-512,"]=])
_mp_replace("${_mp_int}" "${_mp_bad}" "${_mp_good}")

# 4) Post-conditions.
foreach(_f "${_mp_us}" "${_mp_wsh}/include/user_settings.h")
    if(EXISTS "${_f}")
        file(READ "${_f}" _text)
        string(FIND "${_text}" "#define MY_USE_RSA 0" _left)
        if(NOT _left EQUAL -1)
            message(FATAL_ERROR "patch_wolfssl: MY_USE_RSA is still 0 in ${_f}")
        endif()
    endif()
endforeach()

file(READ "${_mp_us}" _text)
string(FIND "${_text}" "#define WOLFSSH_YES_RSA_SHA2_512" _has)
if(_has EQUAL -1)
    message(FATAL_ERROR "patch_wolfssl: WOLFSSH_YES_RSA_SHA2_512 missing")
endif()

file(READ "${_mp_int}" _text)
string(FIND "${_text}" [=["rsa-sha2-512,"]=] _has)
if(_has EQUAL -1)
    message(FATAL_ERROR "patch_wolfssl: rsa-sha2-512 literal not fixed")
endif()

message(STATUS "wolfSSL/wolfSSH patches OK")
