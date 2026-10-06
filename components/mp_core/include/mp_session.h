#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Per-connection context shared by protocol services and the logger.
 * Addresses are kept as raw IPv4 words in network byte order to avoid
 * pulling lwIP headers into every consumer.
 */
typedef struct {
    int      sock;       /* socket fd, -1 if not applicable */
    uint32_t src_ip;     /* peer address, network byte order */
    uint16_t src_port;   /* peer port, host byte order */
    uint32_t dst_ip;     /* local / virtual address, network byte order */
    uint16_t dst_port;   /* local port, host byte order */
    uint32_t id;         /* monotonic session id */
    int64_t  start_us;   /* esp_timer_get_time() at accept */
    /**
     * Persona id this session belongs to, or NULL. Phase 1 sets one persona
     * for the whole device (so this matches mp_log's global persona); phase
     * 2 lets each virtual IP own a persona, and events carry theirs.
     * Points at a static string with session lifetime.
     */
    const char *persona;
} mp_session_t;

#ifdef __cplusplus
}
#endif
