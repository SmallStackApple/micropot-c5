#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"
#include "mp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Generic event bus
 *
 * Every honeypot event is one JSON object built field-by-field through
 * mp_evt_t and delivered over a bounded queue to the logger task, which
 * stamps ts/seq, wraps it in the envelope and ships it to the collector.
 *
 * The bus is protocol-agnostic: new protocol services emit their own
 * event names without touching this component. The mp_log_xxx() helpers
 * below are thin wrappers kept for the phase-1 services.
 * ---------------------------------------------------------------------- */

#define MP_EVT_DATA_MAX 384

typedef struct {
    /* envelope fields (filled by mp_evt_begin / logger task) */
    int64_t  ts_ms;
    uint32_t sid;
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    char     proto[12];
    char     evt[28];
    /* builder state for the "data" object (without braces) */
    char     data[MP_EVT_DATA_MAX];
    size_t   data_len;
    bool     truncated; /* a field was cut short to fit MP_EVT_DATA_MAX */
} mp_evt_t;

/** Start an event. @p s may be NULL (system events: zero addresses/sid). */
void mp_evt_begin(mp_evt_t *e, const mp_session_t *s,
                  const char *proto, const char *evt);

/** Append fields to the data object. Keys must be JSON-safe literals. */
void mp_evt_str (mp_evt_t *e, const char *key, const char *val);
void mp_evt_int (mp_evt_t *e, const char *key, long long val);
void mp_evt_bool(mp_evt_t *e, const char *key, bool val);

/** Enqueue for delivery. Non-blocking; counted as dropped when the queue
 *  is full (reported later as a log.dropped event). */
void mp_evt_send(mp_evt_t *e);

/** Initialise the logger: NVS boot counter, transport socket, worker task. */
esp_err_t mp_log_init(void);

/** Set the persona id embedded in every subsequent event. */
void mp_log_set_persona(const char *persona_id);

/* ----------------------------------------------------- phase-1 wrappers */

void mp_log_net_up(const char *ip, const char *gw, const char *mac);
void mp_log_service(const char *service, uint16_t port, bool up);

void mp_log_telnet_connect(const mp_session_t *s);
void mp_log_telnet_login(const mp_session_t *s, const char *user, const char *pass,
                         bool ok, int attempt);
void mp_log_telnet_command(const mp_session_t *s, const char *cmd);
void mp_log_telnet_disconnect(const mp_session_t *s, int64_t dur_ms, const char *reason);

void mp_log_http_request(const mp_session_t *s, const char *method, const char *uri,
                         int code);
void mp_log_http_login(const mp_session_t *s, const char *user, const char *pass, bool ok);
void mp_log_http_notfound(const mp_session_t *s, const char *uri);

#ifdef __cplusplus
}
#endif
