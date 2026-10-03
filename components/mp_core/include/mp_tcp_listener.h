#pragma once

#include <stdint.h>

#include "esp_err.h"
#include "mp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback invoked in a dedicated task for every accepted TCP connection.
 * The callback owns @p sock and must not close it; the listener closes it
 * once the callback returns.
 */
typedef void (*mp_conn_handler_t)(int sock, const mp_session_t *sess, void *arg);

typedef struct {
    uint32_t          vaddr; /* network byte order; 0 = any */
    uint16_t          port;  /* host byte order */
    const char       *name;  /* used for task naming / logs */
    mp_conn_handler_t handler;
    void             *arg;
} mp_tcp_listener_cfg_t;

/**
 * Create a listening TCP socket and spawn an accept loop. Each connection
 * is dispatched to @c cfg->handler in its own detached task, bounded by
 * the global session budget (CONFIG_MICROPOT_MAX_SESSIONS).
 */
esp_err_t mp_tcp_listener_start(const mp_tcp_listener_cfg_t *cfg);

/** Called (in accept-loop context, keep it short) whenever a connection is
 *  rejected because the global session budget is exhausted. */
typedef void (*mp_overload_hook_t)(const char *service, uint16_t port);

void mp_tcp_listener_set_overload_hook(mp_overload_hook_t hook);

/** Current number of live connection tasks across all listeners. */
uint32_t mp_tcp_listener_active(void);

#ifdef __cplusplus
}
#endif
