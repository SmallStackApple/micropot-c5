#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Brand behaviour modules
 *
 * A brand module describes *how* a specific vendor's device behaves
 * (banners, prompts, credentials, canned replies, web pages). A persona is
 * an *instance* that selects a brand, a service set and (phase 2) a
 * virtual IP.
 *
 * This header is protocol-agnostic and frozen: behaviour structs are
 * defined by each protocol service component (e.g. mp_telnet_behavior.h)
 * and brands hand them out through an open, name-keyed table. Adding a new
 * protocol therefore never touches mp_core.
 * ---------------------------------------------------------------------- */

typedef struct {
    const char *user;
    const char *pass;
} mp_cred_t;

/** Linear-match helper shared by protocol services (constant-time not required:
 *  a honeypot *wants* attackers to enumerate). */
bool mp_creds_match(const mp_cred_t *creds, uint8_t n,
                    const char *user, const char *pass);

typedef struct {
    const char *id;       /* unique brand id, referenced by mp_persona_t */
    const char *vendor;
    const char *model;
    const char *firmware;
    const char *hostname;
    uint8_t     mac_oui[3];
} mp_brand_meta_t;

/** One behaviour blob, interpreted by the protocol service named @c proto. */
typedef struct {
    const char *proto;    /* service name, e.g. "telnet", "http", "ssh" */
    const void *behavior; /* protocol-specific struct, owned by the brand */
} mp_brand_behavior_entry_t;

typedef struct mp_brand {
    const mp_brand_meta_t           *meta;
    const mp_brand_behavior_entry_t *behaviors; /* terminated by {NULL, NULL} */
    esp_err_t (*init)(const struct mp_brand *self);
} mp_brand_t;

/** Look up the brand's behaviour for protocol @p proto; NULL when the brand
 *  does not emulate that protocol. */
const void *mp_brand_behavior(const mp_brand_t *brand, const char *proto);

/** Register a brand module (idempotent per id). */
esp_err_t         mp_brand_register(const mp_brand_t *brand);

/** Look up a brand by id; returns NULL when unknown. */
const mp_brand_t *mp_brand_find(const char *id);

size_t            mp_brand_count(void);
const mp_brand_t *mp_brand_at(size_t index);

#ifdef __cplusplus
}
#endif
