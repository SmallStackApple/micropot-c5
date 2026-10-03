#pragma once

#include "esp_err.h"

#include "mp_bind.h"
#include "mp_brand.h"
#include "mp_persona.h"
#include "mp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MP_PROTO_TCP,
    MP_PROTO_UDP,
    MP_PROTO_HTTP,
} mp_proto_t;

typedef struct mp_service mp_service_t;

typedef struct {
    const char *name;
    mp_proto_t  proto;
    uint16_t    default_port;
    esp_err_t (*start)(mp_service_t *svc);
    void      (*stop)(mp_service_t *svc);
} mp_service_ops_t;

struct mp_service {
    const mp_service_ops_t *ops;
    const mp_persona_t     *persona;
    const mp_brand_t       *brand;
    mp_bind_t               bind;
    bool                    started;
    void                   *ctx; /* service-private state (e.g. httpd handle) */
};

#ifdef __cplusplus
}
#endif
