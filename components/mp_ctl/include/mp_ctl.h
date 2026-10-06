#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Management plane
 *
 * Runs on its own dedicated vdev address (mgmt.ip) — never on a honeypot
 * persona. UDP + TCP control channel with HMAC-SHA256 request signing and
 * an optional source-IP ACL; to non-admin sources the control port reads
 * as filtered, everything else on the mgmt address reads closed.
 * ---------------------------------------------------------------------- */

/** Register config keys; call once after mp_cfg_init. */
esp_err_t mp_ctl_init(void);

/** Start listeners when mgmt.ip is configured; otherwise a no-op.
 *  Call after the wire engines are up. */
esp_err_t mp_ctl_start(void);

#ifdef __cplusplus
}
#endif
