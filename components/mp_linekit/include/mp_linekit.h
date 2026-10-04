#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "mp_xport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Line-oriented protocol toolkit
 *
 * Shared building blocks for text protocols that read newline-terminated
 * input and reply from a canned command table (Telnet today, FTP/SMTP/
 * Redis-style services later). Services provide the brand table; linekit
 * provides the connection mechanics on top of mp_xport.
 * ---------------------------------------------------------------------- */

/** One canned command reply: exact match first, prefix match second. */
typedef struct {
    const char *cmd;      /* exact command, or a prefix used for matching */
    const char *response; /* canned multi-line reply */
} mp_cmd_t;

typedef enum {
    MP_LINE_ECHO_OFF = 0, /* secret entry (password): nothing is echoed */
    MP_LINE_ECHO_ON,      /* normal input: chars echoed as typed */
} mp_line_echo_t;

/** Send the whole buffer; @return 0 on success, -1 on error/close. */
int mp_send_all(mp_conn_t *conn, const void *buf, size_t len);

/** Send a NUL-terminated string (NULL is a no-op). */
int mp_send_str(mp_conn_t *conn, const char *str);

/**
 * Read one newline-terminated line.
 *
 * - strips Telnet IAC negotiation sequences when @p strip_iac
 * - '\r' and NUL bytes are ignored; backspace/DEL erase one char
 * - with MP_LINE_ECHO_ON the peer sees its own input (busybox style)
 *
 * @return line length (>= 0), -1 on close/error, -2 on timeout.
 */
int mp_line_read(mp_conn_t *conn, char *buf, size_t cap, int timeout_ms,
                 bool strip_iac, mp_line_echo_t echo);

/**
 * Find a canned reply: exact match first, then prefix match
 * ("cat " matches "cat /etc/passwd"). NULL when nothing matches.
 */
const mp_cmd_t *mp_cmd_lookup(const mp_cmd_t *cmds, uint8_t n, const char *cmdline);

#ifdef __cplusplus
}
#endif
