#pragma once

#include <stddef.h>

#include "mp_brand.h"
#include "mp_linuxfs.h"
#include "mp_linuxsh.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Generic Linux 4.19 server brand behaviour module.
 *
 *  Emulates a plain x86_64 Linux 4.19 host exposing OpenSSH, Apache, vsftpd
 *  and a root shell over a distro-neutral fake filesystem. Kernel/service
 *  strings come from the v4.19 kernel tree and the referenced daemon
 *  sources (openssh-portable V_7_9_P1, httpd 2.4.38, vsftpd 3.0.3). */
extern const mp_brand_t mp_brand_linux419;

/** The persona's fake filesystem (linux419_fs.c). */
extern const mpfs_node_t mp_linux419_fs[];
extern const size_t      mp_linux419_fs_n;

/** Shell interpreter configuration bound to the filesystem (linux419_fs.c). */
extern const mp_linuxsh_config_t mp_linux419_shell_cfg;

/** Regenerate /etc/shadow from the effective credentials (cfg overrides
 *  else defaults), keeping the original salts. Called by brand init and by
 *  the cred.* on_change hook. */
void mp_linux419_shadow_rebuild(void);

#ifdef __cplusplus
}
#endif
