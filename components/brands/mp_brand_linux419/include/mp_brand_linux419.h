#pragma once

#include "mp_brand.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Generic Linux 4.19 server brand behaviour module.
 *
 *  Emulates a plain x86_64 Linux 4.19 host exposing OpenSSH, Apache and a
 *  root shell. Kernel/service strings are taken from the v4.19 kernel tree and
 *  typical generic-distro defaults so that nmap -sV recognises the services. */
extern const mp_brand_t mp_brand_linux419;

#ifdef __cplusplus
}
#endif
