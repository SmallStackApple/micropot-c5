#include <errno.h>
#include <string.h>

#include "lwip/sockets.h"

#include "mp_linekit.h"

#define TELNET_IAC 255
#define TELNET_SB  250
#define TELNET_SE  240

/* POSIX raises SIGPIPE when writing to a closed peer; lwIP just returns an
 * error. Ask for the error so the honeypot task survives rude clients. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

int mp_send_all(int sock, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        int r = send(sock, p + sent, len - sent, MSG_NOSIGNAL);
        if (r <= 0) {
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

int mp_send_str(int sock, const char *str)
{
    if (!str) {
        return 0;
    }
    return mp_send_all(sock, str, strlen(str));
}

static void echo_char(int sock, char c)
{
    send(sock, &c, 1, 0);
}

int mp_line_read(int sock, char *buf, size_t cap, int timeout_ms,
                 bool strip_iac, mp_line_echo_t echo)
{
    struct timeval tv = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    size_t len = 0;
    for (;;) {
        unsigned char c;
        int r = recv(sock, &c, 1, 0);
        if (r == 0) {
            return -1;
        }
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -2;
            }
            return -1;
        }
        if (strip_iac && c == TELNET_IAC) {
            unsigned char cmd = 0;
            if (recv(sock, &cmd, 1, 0) <= 0) {
                return -1;
            }
            if (cmd == TELNET_SB) {
                unsigned char prev = 0, b;
                while (recv(sock, &b, 1, 0) == 1) {
                    if (prev == TELNET_IAC && b == TELNET_SE) {
                        break;
                    }
                    prev = b;
                }
            } else if (cmd >= 251 && cmd <= 254) {
                unsigned char opt;
                recv(sock, &opt, 1, 0);
            }
            continue;
        }
        if (c == '\r' || c == 0) {
            continue;
        }
        if (c == '\n') {
            if (echo == MP_LINE_ECHO_ON) {
                mp_send_all(sock, "\r\n", 2);
            }
            buf[len] = '\0';
            return (int)len;
        }
        if (c == 0x7f || c == 0x08) {
            if (len) {
                len--;
                if (echo == MP_LINE_ECHO_ON) {
                    mp_send_all(sock, "\b \b", 3);
                }
            }
            continue;
        }
        if (len + 1 < cap) {
            buf[len++] = (char)c;
            if (echo == MP_LINE_ECHO_ON) {
                echo_char(sock, (char)c);
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
