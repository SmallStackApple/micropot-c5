#pragma once

#include <stddef.h>
#include <stdint.h>

#include "mp_brand.h"
#include "mp_linuxfs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Behaviour table for mp_ftpd, the vsftpd-style FTP server.
 * ---------------------------------------------------------------------- */

typedef struct {
    const char *version;      /* banner version, e.g. "3.0.3" */
    const mp_cred_t *creds;
    uint8_t      n_creds;
    const mpfs_node_t *fs;    /* served file tree (read-only persona) */
    size_t       fs_n;
    uint8_t      max_clients; /* 421 past this many control sessions
                               * (CVE-2021-30047 connection-limit DoS) */
} mp_ftpd_behavior_t;

#ifdef __cplusplus
}
#endif
