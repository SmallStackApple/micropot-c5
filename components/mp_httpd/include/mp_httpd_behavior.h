#pragma once

#include <stdint.h>

#include "mp_brand.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * HTTP server behaviour blob.
 *
 * Interpreted by mp_httpd, an Apache-2.4-style server built on mp_xport
 * (so on the linux_419 persona the TCP fingerprint stays Linux while the
 * application layer stays Apache). Brands supply identity, credentials and
 * pages; the service supplies the protocol.
 * ---------------------------------------------------------------------- */

/** Static URL -> body mapping (pages not covered by the login flow). */
typedef struct {
    const char *path;         /* exact path, e.g. "/index.html" */
    const char *content_type; /* e.g. "text/html" */
    const char *body;
} mp_httpd_route_t;

typedef struct {
    const char *server_hdr;   /* "Apache/2.4.38" (generic, no distro) */
    const char *realm;        /* Basic-auth realm */
    const char *hostname;     /* used in error-page address lines */
    const char *login_html;
    const char *fail_html;
    const char *admin_html;
    const mp_cred_t *creds;
    uint8_t     n_creds;
    const mp_httpd_route_t *routes;
    uint8_t     n_routes;
    uint32_t    keepalive_ms; /* idle timeout between requests */
    uint8_t     max_requests; /* per connection, Apache MaxKeepAliveRequests */
} mp_httpd_behavior_t;

#ifdef __cplusplus
}
#endif
