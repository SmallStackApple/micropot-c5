#pragma once

#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"
#include "mp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * UDP datagram listener with pseudo-sessions.
 *
 * UDP has no connections, but honeypot analysis wants per-peer session
 * correlation (same sid across a conversation). The listener keeps a small
 * peer table: the first datagram from a (src_ip, src_port) pair mints a
 * session id, later datagrams reuse it, and entries idle for
 * MP_UDP_SESSION_IDLE_MS are recycled lazily on receive.
 *
 * Not wired into main yet — first consumers are phase-2 UDP services
 * (DNS/SNMP/SSDP). Replies are sent by the handler via sendto() on
 * @c sess->sock (the shared listener socket).
 * ---------------------------------------------------------------------- */

#define MP_UDP_MAX_PEERS      16
#define MP_UDP_SESSION_IDLE_MS 120000
#define MP_UDP_BUF_MAX        1500

typedef void (*mp_dgram_handler_t)(const mp_session_t *sess,
                                   const uint8_t *data, size_t len, void *arg);

typedef struct {
    uint32_t            vaddr; /* network byte order; 0 = any */
    uint16_t            port;  /* host byte order */
    const char         *name;  /* used for task naming / logs */
    mp_dgram_handler_t  handler;
    void               *arg;
} mp_udp_listener_cfg_t;

esp_err_t mp_udp_listener_start(const mp_udp_listener_cfg_t *cfg);

#ifdef __cplusplus
}
#endif
