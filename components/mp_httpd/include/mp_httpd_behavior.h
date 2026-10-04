#pragma once

#include <stdint.h>

#include "mp_brand.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Behaviour table for mp_httpd, the Apache-style HTTP server.
 * ---------------------------------------------------------------------- */

typedef struct {
    const char *path;         /* exact URI path, e.g. "/" or "/index.html" */
    const char *content_type; /* e.g. "text/html; charset=UTF-8" */
    const char *body;         /* response body (NUL-terminated text) */
    uint32_t    body_len;     /* 0 => strlen(body) */
} mp_httpd_route_t;

typedef struct {
    const char *server_hdr;   /* Server header, e.g. "Apache/2.4.38" */
    const char *server_name;  /* ServerSignature host, e.g. "linux" */
    const char *realm;        /* Basic realm protecting all routes; NULL = open */
    const mp_cred_t *creds;
    uint8_t      n_creds;
    const mp_httpd_route_t *routes;
    uint8_t      n_routes;
} mp_httpd_behavior_t;

#ifdef __cplusplus
}
#endif
