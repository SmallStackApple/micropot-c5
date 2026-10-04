#pragma once

#include <stdint.h>

#include "mp_brand.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * FTP behaviour blob.
 *
 * Reproduces vsftpd 3.0.3 (greeting "220 (vsFTPd 3.0.3)", command set and
 * reply codes from ftpcodes.h). This version predates the fixes for
 * CVE-2021-30047 (DoS) and CVE-2021-3618 (ALPACA), so the version string
 * itself is the fingerprint scanners key on; parsing also stays as
 * permissive as the original (unknown/oversized input gets a plain 500,
 * which is what the cross-protocol attack reflects).
 * ---------------------------------------------------------------------- */

typedef struct {
    const char      *banner;      /* NULL => "220 (vsFTPd 3.0.3)" */
    const mp_cred_t *creds;
    uint8_t          n_creds;
    const char      *root;        /* listing root, e.g. "/home/admin" */
    uint16_t         data_port;   /* passive-mode data listener port */
    const char      *hostname;
} mp_ftpd_behavior_t;

#ifdef __cplusplus
}
#endif
