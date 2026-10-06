#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "mp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Transport abstraction
 *
 * Services never touch sockets directly. A connection is an opaque
 * mp_conn_t with recv/send/shutdown ops; listeners are registered through
 * the active backend (lwIP sockets today, the Linux-4.19 stack emulation
 * for the linux_419 persona). Backends share one global session budget so
 * a flood cannot starve the heap regardless of which stack carries the
 * connection.
 * ---------------------------------------------------------------------- */

typedef struct mp_conn mp_conn_t;

typedef struct {
    /** Read up to @p len bytes, waiting at most @p timeout_ms.
     *  @return >0 bytes read, 0 peer closed cleanly,
     *          MP_CONN_TIMEOUT, MP_CONN_ABORTED. */
    int  (*recv)(mp_conn_t *c, void *buf, size_t len, uint32_t timeout_ms);
    /** Send the whole buffer. @return 0 on success, -1 on error. */
    int  (*send)(mp_conn_t *c, const void *buf, size_t len);
    /** Half-close the write side (FIN). Optional; may be NULL. */
    void (*shutdown)(mp_conn_t *c);
    /** Backend releases the connection (called after the handler returns). */
    void (*release)(mp_conn_t *c);
} mp_conn_ops_t;

struct mp_conn {
    const mp_conn_ops_t *ops;
    void                *ctx; /* backend state (fd, tcb, ...) */
};

#define MP_CONN_TIMEOUT  (-1)
#define MP_CONN_ABORTED  (-2)

static inline int mp_conn_recv(mp_conn_t *c, void *buf, size_t len, uint32_t timeout_ms)
{
    return c->ops->recv(c, buf, len, timeout_ms);
}

static inline int mp_conn_send(mp_conn_t *c, const void *buf, size_t len)
{
    return c->ops->send(c, buf, len);
}

static inline void mp_conn_shutdown(mp_conn_t *c)
{
    if (c->ops->shutdown) {
        c->ops->shutdown(c);
    }
}

/** Connection handler, invoked in a dedicated task per accepted connection.
 *  The backend closes and releases @p conn once the handler returns. */
typedef void (*mp_conn_handler_t)(mp_conn_t *conn, const mp_session_t *sess, void *arg);

typedef struct {
    uint32_t          vaddr;   /* network byte order; 0 = any */
    uint16_t          port;    /* host byte order */
    const char       *name;    /* used for task naming / logs */
    const char       *persona; /* persona id stamped on the session, or NULL */
    mp_conn_handler_t handler;
    void             *arg;
    const struct mp_xport_backend *xport; /* NULL = active default backend */
} mp_listener_cfg_t;

typedef struct mp_xport_backend {
    const char *name;
    esp_err_t (*listen)(const mp_listener_cfg_t *cfg);
} mp_xport_backend_t;

/** Select the active backend (default: lwIP sockets). Call once at boot,
 *  before any service starts. */
void        mp_xport_use(const mp_xport_backend_t *backend);
const char *mp_xport_backend_name(void);

/** Start listening through the active backend. */
esp_err_t mp_xport_listen(const mp_listener_cfg_t *cfg);

/* ---- global session budget, shared by every backend -------------------- */

bool     mp_xport_budget_take(void);
void     mp_xport_budget_give(void);
uint32_t mp_xport_active(void);

/** Called (in accept context, keep it short) whenever a connection is
 *  rejected because the global session budget is exhausted. */
typedef void (*mp_overload_hook_t)(const char *service, uint16_t port);
void mp_xport_set_overload_hook(mp_overload_hook_t hook);
void mp_xport_report_overload(const char *service, uint16_t port);

/** Built-in backend: lwIP BSD sockets (the historical phase-1 path). */
extern const mp_xport_backend_t mp_xport_lwip;

#ifdef __cplusplus
}
#endif
