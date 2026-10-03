#pragma once

#include <stdint.h>

#include "mp_brand.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HTTP management-page behaviour table — the brand-owned data that drives
 * the brand-agnostic web honeypot (mp_http).
 */

typedef struct {
    const char *path;
    const char *content_type;
    const char *body;
} mp_http_route_t;

typedef struct {
    const char            *server_hdr; /* spoofed Server header */
    const char            *realm;
    const char            *login_html; /* NUL-terminated (EMBED_TXTFILES) */
    const char            *fail_html;
    const char            *admin_html;
    const mp_cred_t       *creds;
    uint8_t                n_creds;
    const mp_http_route_t *routes;
    uint8_t                n_routes;
} mp_http_behavior_t;

#ifdef __cplusplus
}
#endif
