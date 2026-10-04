#!/usr/bin/env python3
"""Apply the minimal ESP32-C5 support patch to the fetched wolfSSL component.

wolfSSL 5.8.2 has no ESP32-C5 port: its Espressif watchdog helper falls back
to rtc_wdt_* (not available on C5), and the memory-map debug module assumes
linker symbols/SDK macros that C5 does not define. Both files are diagnostics
or watchdogs; the application only needs the crypto core.

This script is idempotent and is run automatically by tools/setup_deps.sh
after the component manager has fetched the dependencies. managed_components/
is not tracked by git, so the patch must be re-applied after a clean fetch.

Usage: tools/patches/wolfssl-esp32c5.py [managed_components/wolfssl__wolfssl]
"""
import os
import re
import sys


def patch_watchdog(root):
    path = os.path.join(root, "wolfcrypt/src/port/Espressif/esp32_util.c")
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()

    # Add C5 to the esp_task_wdt_deinit() target list (disable + enable).
    needle = ("defined(CONFIG_IDF_TARGET_ESP32H2) || \\\n"
              "              defined(CONFIG_IDF_TARGET_ESP32P4)")
    repl = ("defined(CONFIG_IDF_TARGET_ESP32H2) || \\\n"
            "              defined(CONFIG_IDF_TARGET_ESP32P4) || \\\n"
            "              defined(CONFIG_IDF_TARGET_ESP32C5)")
    count = src.count(needle)
    if count:
        src = src.replace(needle, repl)
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
    print("esp32_util.c: watchdog branches patched:", count)


def patch_memlib(root):
    # The enum member `thread_local` collides with the C23 keyword, which
    # breaks the whole enum and cascades into "undeclared enumerator"
    # errors. Rename it; its only uses are inside XTENSA-only blocks that
    # do not build for ESP32-C5 anyway.
    path = os.path.join(root, "wolfcrypt/src/port/Espressif/esp_sdk_mem_lib.c")
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    n = src.count("thread_local,     /* enum member */")
    refs = src.count("sdk_log_meminfo(thread_local,")
    src = src.replace("sdk_log_meminfo(thread_local,", "sdk_log_meminfo(thread_local_seg,")
    # the enum member itself, identified by its neighbours
    src = src.replace("    thread_local,\n    data,", "    thread_local_seg,\n    data,")
    with open(path, "w", encoding="utf-8") as f:
        f.write(src)
    print("esp_sdk_mem_lib.c: keyword refs patched:", refs, "enum:", n)


def patch_user_settings(root):
    # wolfSSL has no ESP32-C5 entropy port: point its RNG seed hook at the
    # hardware RNG wrapper implemented in mp_sshd (declaration must be
    # visible where random.c expands the macro).
    path = os.path.join(root, "include/user_settings.h")
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    if "mp_wolfssl_rand_seed" in src:
        print("user_settings.h: entropy hook already present")
        return
    src += ("\n/* MicroPot-C5: ESP32-C5 entropy source (mp_sshd) */\n"
            "#ifndef CUSTOM_RAND_GENERATE_SEED\n"
            "int mp_wolfssl_rand_seed(unsigned char* output, unsigned int sz);\n"
            "#define CUSTOM_RAND_GENERATE_SEED mp_wolfssl_rand_seed\n"
            "#endif\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(src)
    print("user_settings.h: entropy hook appended")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else \
        "managed_components/wolfssl__wolfssl"
    if not os.path.isdir(root):
        print("wolfSSL component not found at", root, file=sys.stderr)
        return 1
    patch_watchdog(root)
    patch_memlib(root)
    patch_user_settings(root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
