/*
 * Event builder — pure formatting code, no ESP dependencies, so it can be
 * unit-tested on the host (see test/host).
 */
#include <stdio.h>
#include <string.h>

#include "mp_log.h"

static void copy_str(char *dst, const char *src, size_t n)
{
    if (!n) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    for (; i + 1 < n && src[i]; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* Escape @p in as a JSON string *content* (no surrounding quotes) into
 * @p out. Returns the number of bytes written (excluding the NUL). */
static size_t json_escape(const char *in, char *out, size_t out_len)
{
    if (!out_len) {
        return 0;
    }
    if (!in) {
        out[0] = '\0';
        return 0;
    }
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 7 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
        case '"':  out[j++] = '\\'; out[j++] = '"';  break;
        case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
        case '\n': out[j++] = '\\'; out[j++] = 'n';  break;
        case '\r': out[j++] = '\\'; out[j++] = 'r';  break;
        case '\t': out[j++] = '\\'; out[j++] = 't';  break;
        default:
            if (c < 0x20) {
                j += (size_t)snprintf(out + j, out_len - j, "\\u%04x", c);
            } else {
                out[j++] = (char)c;
            }
        }
    }
    out[j] = '\0';
    return j;
}

void mp_evt_begin(mp_evt_t *e, const mp_session_t *s,
                  const char *proto, const char *evt)
{
    memset(e, 0, sizeof(*e));
    if (s) {
        e->sid      = s->id;
        e->src_ip   = s->src_ip;
        e->src_port = s->src_port;
        e->dst_ip   = s->dst_ip;
        e->dst_port = s->dst_port;
    }
    copy_str(e->proto, proto, sizeof(e->proto));
    copy_str(e->evt, evt, sizeof(e->evt));
}

static void append_raw(mp_evt_t *e, const char *frag, size_t len)
{
    if (e->data_len + len >= sizeof(e->data)) {
        len = sizeof(e->data) - e->data_len - 1;
        e->truncated = true;
    }
    memcpy(e->data + e->data_len, frag, len);
    e->data_len += len;
    e->data[e->data_len] = '\0';
}

static void append_key(mp_evt_t *e, const char *key)
{
    if (e->data_len) {
        append_raw(e, ",", 1);
    }
    append_raw(e, "\"", 1);
    append_raw(e, key, strlen(key));
    append_raw(e, "\":", 2);
}

void mp_evt_str(mp_evt_t *e, const char *key, const char *val)
{
    append_key(e, key);
    append_raw(e, "\"", 1);
    if (!e->truncated) {
        /* escape directly into the remaining space */
        size_t left = sizeof(e->data) - e->data_len - 2; /* closing quote + NUL */
        size_t w = json_escape(val, e->data + e->data_len, left);
        if (val && val[w] && w + 7 >= left) {
            e->truncated = true; /* input did not fully fit */
        }
        e->data_len += w;
        e->data[e->data_len] = '\0';
    }
    append_raw(e, "\"", 1);
}

void mp_evt_int(mp_evt_t *e, const char *key, long long val)
{
    char num[24];
    int n = snprintf(num, sizeof(num), "%lld", val);
    append_key(e, key);
    append_raw(e, num, (size_t)n);
}

void mp_evt_bool(mp_evt_t *e, const char *key, bool val)
{
    append_key(e, key);
    append_raw(e, val ? "true" : "false", val ? 4 : 5);
}
