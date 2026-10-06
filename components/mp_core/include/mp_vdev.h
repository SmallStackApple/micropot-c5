#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "mp_persona.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Virtual devices
 *
 * A virtual device binds a persona (L7 identity) to one IPv4 address. All
 * vdevs share the single station MAC (802.11 infrastructure can only ever
 * source one MAC — IP aliasing is the real-world equivalent). vdev[0] is
 * the primary address (DHCP/static) carrying the Kconfig persona; aliases
 * come from the runtime config keys vdev1.ip/vdev1.persona ... and require
 * a persona with a wire profile, because only the packet-crafting engines
 * (stack419) can serve addresses lwIP does not own.
 * ---------------------------------------------------------------------- */

#define MP_VDEV_MAX 8

typedef struct {
    uint32_t              vaddr;   /* lwIP convention (first octet low); 0 = primary */
    const mp_persona_t   *persona;
} mp_vdev_t;

/** Build the vdev table: primary persona + alias entries from mp_cfg.
 *  Call after mp_cfg_init and brand/persona registration. */
esp_err_t mp_vdev_load(void);

size_t          mp_vdev_count(void);
const mp_vdev_t *mp_vdev_at(size_t i);

/** Alias lookup by address (lwIP convention). The primary (vaddr 0) is not
 *  returned here — it is matched by lwIP itself. */
const mp_vdev_t *mp_vdev_by_vaddr(uint32_t vaddr);

/** Narrative coherence: distinct brand vendors on one MAC look like what
 *  they are (one box). Returns the first conflicting pair via out-params.
 *  True when every vdev's brand shares one vendor (or unknown). */
bool mp_vdev_vendor_coherent(const char **vendor_a, const char **vendor_b);

#ifdef __cplusplus
}
#endif
