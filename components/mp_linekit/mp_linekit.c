#include <string.h>

#include "mp_linekit.h"

#define TELNET_IAC 255
#define TELNET_SB  250
#define TELNET_SE  240

int mp_send_all(mp_conn_t *conn, const void *buf, size_t len)
{
    return mp_conn_send(conn, buf, len);
}

int mp_send_str(mp_conn_t *conn, const char *str)
{
    if (!str) {
        return 0;
    }
    return mp_send_all(conn, str, strlen(str));
}

static void echo_char(mp_conn_t *conn, char c)
{
    mp_conn_send(conn, &c, 1);
}

/* Read a single byte with the line timeout applied to every call.
 * @return 1 ok, 0 peer closed, -1 aborted, -2 timeout. */
static int read_char(mp_conn_t *conn, unsigned char *c, int timeout_ms)
{
    int r = mp_conn_recv(conn, c, 1, (uint32_t)timeout_ms);
    if (r == 1) {
        return 1;
    }
    if (r == 0) {
        return 0;
    }
    return (r == MP_CONN_TIMEOUT) ? -2 : -1;
}

/* Swallow one ANSI escape sequence without consuming normal input:
 * CSI (ESC [ params final-byte), SS3 (ESC O x), or two-byte ESC x.
 * Follow-up bytes get a short timeout so a lone ESC keypress does
 * not stall the line for the full line timeout. */
static void swallow_escape(mp_conn_t *conn)
{
    unsigned char b;
    if (read_char(conn, &b, 100) != 1) {
        return;
    }
    if (b == '[') {
        /* CSI: parameter (0x30-0x3f) / intermediate (0x20-0x2f) bytes,
         * terminated by a final byte in 0x40-0x7e. */
        while (read_char(conn, &b, 100) == 1) {
            if (b >= 0x40 && b <= 0x7e) {
                break;
            }
        }
    } else if (b == 'O') {
        read_char(conn, &b, 100); /* SS3: exactly one more byte */
    }
    /* plain ESC x: the trailing byte is already eaten */
}

int mp_line_read(mp_conn_t *conn, char *buf, size_t cap, int timeout_ms,
                 bool strip_iac, mp_line_echo_t echo)
{
    size_t len = 0;
    for (;;) {
        unsigned char c;
        int r = read_char(conn, &c, timeout_ms);
        if (r <= 0) {
            return r == -2 ? -2 : -1;
        }
        if (strip_iac && c == TELNET_IAC) {
            unsigned char cmd = 0;
            if (read_char(conn, &cmd, timeout_ms) <= 0) {
                return -1;
            }
            if (cmd == TELNET_SB) {
                unsigned char prev = 0, b;
                while (read_char(conn, &b, timeout_ms) == 1) {
                    if (prev == TELNET_IAC && b == TELNET_SE) {
                        break;
                    }
                    prev = b;
                }
            } else if (cmd >= 251 && cmd <= 254) {
                unsigned char opt;
                read_char(conn, &opt, timeout_ms);
            }
            continue;
        }
        if (c == 0) {
            continue; /* telnet CR NUL */
        }
        if (c == 0x1b) {
            /* ANSI escape (arrow keys, Home/End, ...): swallow the whole
             * sequence — no echo, no buffering. A lone ESC[A turning
             * into a "command" once crashed the shell dispatch. */
            swallow_escape(conn);
            continue;
        }
        if (c == '\r') {
            /* Enter. An ssh pty sends CR alone (on a real tty the line
             * discipline maps it with icrnl); telnet sends CR LF — the
             * LF is then absorbed by the bare-LF rule on the next call. */
            if (echo == MP_LINE_ECHO_ON) {
                mp_send_all(conn, "\r\n", 2);
            }
            buf[len] = '\0';
            return (int)len;
        }
        if (c == '\n') {
            /* Bare LF ends a line only once something was typed (piped
             * input); at line start it is the LF of a telnet CR LF. */
            if (!len) {
                continue;
            }
            if (echo == MP_LINE_ECHO_ON) {
                mp_send_all(conn, "\r\n", 2);
            }
            buf[len] = '\0';
            return (int)len;
        }
        if (c == 0x7f || c == 0x08) {
            if (len) {
                len--;
                if (echo == MP_LINE_ECHO_ON) {
                    mp_send_all(conn, "\b \b", 3);
                }
            }
            continue;
        }
        if (len + 1 < cap) {
            buf[len++] = (char)c;
            if (echo == MP_LINE_ECHO_ON) {
                echo_char(conn, (char)c);
            }
        }
    }
}

const mp_cmd_t *mp_cmd_lookup(const mp_cmd_t *cmds, uint8_t n, const char *cmdline)
{
    if (!cmds || !cmdline) {
        return NULL;
    }
    /* exact match first */
    for (uint8_t i = 0; i < n; i++) {
        if (cmds[i].cmd && strcmp(cmds[i].cmd, cmdline) == 0) {
            return &cmds[i];
        }
    }
    /* then prefix match (e.g. "cat /etc/passwd" matches "cat ") */
    for (uint8_t i = 0; i < n; i++) {
        if (cmds[i].cmd &&
            strncmp(cmdline, cmds[i].cmd, strlen(cmds[i].cmd)) == 0) {
            return &cmds[i];
        }
    }
    return NULL;
}
