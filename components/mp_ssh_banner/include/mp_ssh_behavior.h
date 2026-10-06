#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SSH behaviour table — brand-owned data for the banner-level SSH
 * honeypot (mp_ssh). Banner-level means: send a plausible server version,
 * harvest the client's version string, linger, drop. No key exchange —
 * the goal is catching scanners and client fingerprints, not logins (yet).
 */
typedef struct {
    const char *banner;    /* server version, e.g. "SSH-2.0-dropbear_2014.63" */
    uint16_t    linger_ms; /* pause after the banner exchange before closing;
                              0 => default 5000 ms */
} mp_ssh_behavior_t;

#ifdef __cplusplus
}
#endif
