/*
 * Apache-2.4-style HTTP server on mp_xport.
 *
 * Replaces esp_http_server for the linux_419 persona: the TCP fingerprint
 * is owned by mp_stack419, and this file owns the application layer —
 * server header, date, keep-alive, error pages and Basic auth, following
 * httpd-2.4.38 (server/protocol.c and the server/error templates).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "mp_core.h"
#include "mp_log.h"
#include "mp_net.h"
#include "mp_util.h"

#include "mp_httpd.h"
#include "mp_httpd_behavior.h"

static const char *TAG = "mp_httpd";

#define HTTPD_TASK_STACK 8192
#define HTTPD_TASK_PRIO  5
#define HDR_LINE_MAX     512
#define BODY_MAX         1024
#define AUTH_MAX         256

/* ------------------------------------------------------------ reader */

typedef struct {
    mp_conn_t *c;
    char       buf[1024];
    size_t     len, pos;
    int        timeout_ms;
} hr_t;

/* @return byte (0..255), 0 on close, or a negative MP_CONN_* value. */
static int hr_getc(hr_t *r)
{
    if (r->pos >= r->len) {
        int n = mp_conn_recv(r->c, r->buf, sizeof(r->buf),
                             (uint32_t)r->timeout_ms);
        if (n <= 0) {
            return n == 0 ? 0 : n;
        }
        r->len = (size_t)n;
        r->pos = 0;
    }
    return (unsigned char)r->buf[r->pos++];
}

/* Read one CRLF/LF-terminated line (without the newline). @return length,
 * negative on error/close. */
static int hr_line(hr_t *r, char *out, size_t cap)
{
    size_t n = 0;
    bool   over = false;
    for (;;) {
        int c = hr_getc(r);
        if (c <= 0) {
            return c == 0 ? (n ? (int)n : -1) : c;
        }
        if (c == '\n') {
            break;
        }
        if (c == '\r') {
            continue;
        }
        if (n + 1 < cap) {
            out[n++] = (char)c;
        } else {
            over = true;
        }
    }
    out[n] = '\0';
    (void)over;
    return (int)n;
}

static size_t hr_read_body(hr_t *r, char *out, size_t cap, size_t want)
{
    size_t got = 0;
    while (r->pos < r->len && got < want && got + 1 < cap) {
        out[got++] = r->buf[r->pos++];
    }
    while (got < want && got + 1 < cap) {
        int n = mp_conn_recv(r->c, out + got, want - got, (uint32_t)r->timeout_ms);
        if (n <= 0) {
            break;
        }
        got += (size_t)n;
    }
    out[got] = '\0';
    return got;
}

/* ------------------------------------------------------------- helpers */

static const char *status_reason(int code)
{
    switch (code) {
    case 200: return "OK";
    case 302: return "Found";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 414: return "Request-URI Too Long";
    case 501: return "Not Implemented";
    default:  return "OK";
    }
}

static void http_date(char *out, size_t len)
{
    time_t now = time(NULL);
    if (now < 1600000000) {
        /* pre-SNTP: anchor to 2026-01-01 UTC + uptime so the header is at
         * least monotonic and plausible instead of 1970 */
        now = (time_t)1767225600 + (time_t)(esp_timer_get_time() / 1000000);
    }
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(out, len, "%a, %d %b %Y %H:%M:%S GMT", &tmv);
}

static int b64val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decode "Basic dXNlcjpwYXNz" -> "user:pass". @return true on success. */
static bool decode_basic(const char *hdr, char *out, size_t cap)
{
    while (*hdr == ' ' || *hdr == '\t') hdr++;
    if (strncmp(hdr, "Basic", 5) != 0) {
        return false;
    }
    hdr += 5;
    while (*hdr == ' ') hdr++;

    size_t o = 0;
    int acc = 0, nbits = 0;
    for (; *hdr && *hdr != '\r' && *hdr != '\n'; hdr++) {
        if (*hdr == '=') break;
        int v = b64val((unsigned char)*hdr);
        if (v < 0) continue;
        acc = (acc << 6) | v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (o + 1 < cap) {
                out[o++] = (char)((acc >> nbits) & 0xff);
            }
        }
    }
    out[o] = '\0';
    return o > 0;
}

static void form_get(const char *body, const char *key, char *out, size_t cap)
{
    out[0] = '\0';
    size_t klen = strlen(key);
    const char *p = body;
    while (p && *p) {
        const char *eq = strchr(p, '=');
        if (!eq) break;
        const char *amp = strchr(eq, '&');
        size_t nlen = (size_t)(eq - p);
        if (nlen == klen && strncmp(p, key, klen) == 0) {
            const char *v = eq + 1;
            size_t vlen = amp ? (size_t)(amp - v) : strlen(v);
            if (vlen >= cap) vlen = cap - 1;
            size_t o = 0;
            for (size_t i = 0; i < vlen && o + 1 < cap; i++) {
                char c = v[i];
                if (c == '+') {
                    out[o++] = ' ';
                } else if (c == '%' && i + 2 < vlen) {
                    char h[3] = { v[i + 1], v[i + 2], 0 };
                    out[o++] = (char)strtol(h, NULL, 16);
                    i += 2;
                } else {
                    out[o++] = c;
                }
            }
            out[o] = '\0';
            return;
        }
        p = amp ? amp + 1 : NULL;
    }
}

/* ----------------------------------------------------------- responses */

static int send_response(mp_conn_t *c, const mp_httpd_behavior_t *beh,
                         const char *extra_hdr, int code,
                         const char *ctype, const char *body, size_t body_len,
                         bool keep_alive, bool head_only)
{
    char date[64];
    http_date(date, sizeof(date));

    char hdr[1024];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\n"
                     "Date: %s\r\n"
                     "Server: %s\r\n"
                     "%s"
                     "%s%s%s"
                     "Content-Length: %u\r\n"
                     "Connection: %s\r\n"
                     "%s"
                     "\r\n",
                     code, status_reason(code), date,
                     beh->server_hdr ? beh->server_hdr : "Apache/2.4.38",
                     extra_hdr ? extra_hdr : "",
                     ctype ? "Content-Type: " : "",
                     ctype ? ctype : "",
                     ctype ? "\r\n" : "",
                     (unsigned)body_len,
                     keep_alive ? "keep-alive" : "close",
                     keep_alive ? "Keep-Alive: timeout=5, max=100\r\n" : "");
    if (n < 0 || (size_t)n >= sizeof(hdr)) {
        return -1;
    }
    if (mp_conn_send(c, hdr, (size_t)n) != 0) {
        return -1;
    }
    if (!head_only && body_len && mp_conn_send(c, body, body_len) != 0) {
        return -1;
    }
    return 0;
}

static int send_error(mp_conn_t *c, const mp_httpd_behavior_t *beh,
                      const char *extra_hdr, int code, const char *detail,
                      bool keep_alive)
{
    char body[640];
    int blen = snprintf(body, sizeof(body),
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
        "<html><head>\r\n<title>%d %s</title>\r\n</head><body>\r\n"
        "<h1>%s</h1>\r\n"
        "<p>%s</p>\r\n"
        "<hr>\r\n"
        "<address>%s Server at %s Port 80</address>\r\n"
        "</body></html>\r\n",
        code, status_reason(code), status_reason(code),
        detail ? detail : "",
        beh->server_hdr ? beh->server_hdr : "Apache/2.4.38",
        beh->hostname ? beh->hostname : "localhost");
    return send_response(c, beh, extra_hdr, code,
                         "text/html; charset=iso-8859-1", body,
                         blen > 0 ? (size_t)blen : 0, keep_alive, false);
}

static const mp_httpd_route_t *route_find(const mp_httpd_behavior_t *beh,
                                          const char *path)
{
    for (uint8_t i = 0; i < beh->n_routes; i++) {
        if (beh->routes[i].path && strcmp(beh->routes[i].path, path) == 0) {
            return &beh->routes[i];
        }
    }
    return NULL;
}

/* --------------------------------------------------------------- session */

typedef struct {
    char method[8];
    char uri[256];
    char version[12];
    long content_length;
    bool conn_close;
    bool have_auth;
    char auth[AUTH_MAX];
} http_req_t;

static void strip_query(char *uri)
{
    char *q = strchr(uri, '?');
    if (q) {
        *q = '\0';
    }
    /* percent-decode the path in place */
    char *r = uri, *w = uri;
    while (*r) {
        if (*r == '%' && r[1] && r[2]) {
            char h[3] = { r[1], r[2], 0 };
            *w++ = (char)strtol(h, NULL, 16);
            r += 3;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static bool header_is(const char *line, const char *name, const char **val)
{
    size_t n = strlen(name);
    if (strncasecmp(line, name, n) != 0 || line[n] != ':') {
        return false;
    }
    const char *v = line + n + 1;
    while (*v == ' ' || *v == '\t') v++;
    *val = v;
    return true;
}

static int read_request(hr_t *r, http_req_t *req)
{
    char line[HDR_LINE_MAX];
    memset(req, 0, sizeof(*req));
    req->content_length = -1;

    int n = hr_line(r, line, sizeof(line));
    if (n <= 0) {
        return n; /* close/timeout before a request */
    }
    if (sscanf(line, "%7s %255s %11s", req->method, req->uri, req->version) != 3) {
        return -2; /* malformed */
    }

    for (;;) {
        n = hr_line(r, line, sizeof(line));
        if (n <= 0) {
            return n;
        }
        if (n == 0) {
            break; /* end of headers */
        }
        const char *v;
        if (header_is(line, "Content-Length", &v)) {
            req->content_length = strtol(v, NULL, 10);
        } else if (header_is(line, "Connection", &v)) {
            req->conn_close = strncasecmp(v, "close", 5) == 0;
        } else if (header_is(line, "Authorization", &v)) {
            req->have_auth = true;
            snprintf(req->auth, sizeof(req->auth), "%s", v);
        }
    }
    return 1;
}

static void httpd_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    mp_service_t *svc = (mp_service_t *)arg;
    const mp_httpd_behavior_t *beh =
        svc->brand ? mp_brand_behavior(svc->brand, "httpd") : NULL;
    if (!beh) {
        return;
    }

    mp_evt_t e;
    mp_evt_begin(&e, sess, "http", "http.connect");
    mp_evt_send(&e);

    hr_t r = { .c = conn, .timeout_ms = 10000 };
    uint8_t served = 0;
    uint8_t maxreq = beh->max_requests ? beh->max_requests : 100;

    for (;;) {
        http_req_t req;
        r.timeout_ms = served ? (int)(beh->keepalive_ms ? beh->keepalive_ms : 5000)
                              : 10000;
        int pr = read_request(&r, &req);
        if (pr == 0) {
            break; /* closed */
        }
        if (pr == -2) {
            mp_log_http_request(sess, "?", "-", 400);
            send_error(conn, beh, NULL, 400, "Your browser sent a request that "
                       "this server could not understand.", false);
            break;
        }
        if (pr < 0) {
            break; /* timeout / abort */
        }

        bool keep = !req.conn_close && strcmp(req.version, "HTTP/1.0") != 0;
        if (++served >= maxreq) {
            keep = false;
        }

        char path[256];
        snprintf(path, sizeof(path), "%s", req.uri);
        strip_query(path);

        /* OPTIONS: Apache answers with an Allow list */
        if (strcmp(req.method, "OPTIONS") == 0) {
            mp_log_http_request(sess, req.method, req.uri, 200);
            send_response(conn, beh, "Allow: GET,POST,OPTIONS,HEAD\r\n",
                         200, NULL, NULL, 0, keep, false);
            if (!keep) break;
            continue;
        }

        bool head = strcmp(req.method, "HEAD") == 0;
        bool get = strcmp(req.method, "GET") == 0 || head;
        bool post = strcmp(req.method, "POST") == 0;

        if (!get && !post) {
            mp_log_http_request(sess, req.method, req.uri, 501);
            send_error(conn, beh, NULL, 501, "The requested method is not "
                       "implemented by this server.", keep);
            if (!keep) break;
            continue;
        }

        /* Authorization header on any path: capture Basic credentials */
        char user[64] = { 0 }, pass[64] = { 0 };
        bool have_creds = false;
        if (req.have_auth) {
            char dec[AUTH_MAX];
            if (decode_basic(req.auth, dec, sizeof(dec))) {
                char *colon = strchr(dec, ':');
                if (colon) {
                    *colon = '\0';
                    snprintf(user, sizeof(user), "%.63s", dec);
                    snprintf(pass, sizeof(pass), "%.63s", colon + 1);
                    have_creds = true;
                }
            }
        }

        /* "/" -> login page, honeypot-style */
        if (get && strcmp(path, "/") == 0) {
            mp_log_http_request(sess, req.method, req.uri, 302);
            send_response(conn, beh, "Location: /login\r\n", 302, NULL,
                         NULL, 0, keep, head);
            if (!keep) break;
            continue;
        }

        if (get && strcmp(path, "/login") == 0) {
            mp_log_http_request(sess, req.method, req.uri, 200);
            send_response(conn, beh, NULL, 200,
                         "text/html; charset=iso-8859-1",
                         beh->login_html,
                         beh->login_html ? strlen(beh->login_html) : 0,
                         keep, head);
            if (!keep) break;
            continue;
        }

        if (post && strcmp(path, "/login") == 0) {
            mp_log_http_request(sess, req.method, req.uri, 200);
            size_t want = req.content_length > 0 ? (size_t)req.content_length : 0;
            if (want > BODY_MAX) {
                want = BODY_MAX;
            }
            char body[BODY_MAX + 1];
            hr_read_body(&r, body, sizeof(body), want);

            if (!have_creds) {
                if (!user[0]) form_get(body, "username", user, sizeof(user));
                if (!user[0]) form_get(body, "user", user, sizeof(user));
                if (!pass[0]) form_get(body, "password", pass, sizeof(pass));
                if (!pass[0]) form_get(body, "pass", pass, sizeof(pass));
            }
            bool ok = mp_creds_match(beh->creds, beh->n_creds, user, pass);
            mp_log_http_login(sess, user, pass, ok);
            const char *page = ok ? beh->admin_html : beh->fail_html;
            send_response(conn, beh, NULL, ok ? 200 : 401,
                         "text/html; charset=iso-8859-1",
                         page, page ? strlen(page) : 0, keep, head);
            if (!keep) break;
            continue;
        }

        if (strcmp(path, "/admin") == 0) {
            bool ok = have_creds &&
                      mp_creds_match(beh->creds, beh->n_creds, user, pass);
            if (have_creds) {
                mp_log_http_login(sess, user, pass, ok);
            }
            mp_log_http_request(sess, req.method, req.uri, ok ? 200 : 401);
            if (!ok) {
                char extra[160];
                snprintf(extra, sizeof(extra),
                         "WWW-Authenticate: Basic realm=\"%s\"\r\n",
                         beh->realm ? beh->realm : "Restricted");
                send_error(conn, beh, extra, 401,
                           "This server could not verify that you are "
                           "authorized to access this document.", keep);
            } else {
                send_response(conn, beh, NULL, 200,
                             "text/html; charset=iso-8859-1",
                             beh->admin_html,
                             beh->admin_html ? strlen(beh->admin_html) : 0,
                             keep, head);
            }
            if (!keep) break;
            continue;
        }

        /* static routes */
        const mp_httpd_route_t *rt = get ? route_find(beh, path) : NULL;
        if (rt) {
            mp_log_http_request(sess, req.method, req.uri, 200);
            send_response(conn, beh, NULL, 200,
                         rt->content_type ? rt->content_type : "text/html",
                         rt->body, rt->body ? strlen(rt->body) : 0, keep, head);
            if (!keep) break;
            continue;
        }

        mp_log_http_request(sess, req.method, req.uri, 404);
        mp_log_http_notfound(sess, req.uri);
        send_error(conn, beh, NULL, 404, "The requested URL was not found on "
                   "this server.", keep);
        if (!keep) break;
    }

    int64_t dur = (esp_timer_get_time() - sess->start_us) / 1000;
    mp_evt_begin(&e, sess, "http", "http.disconnect");
    mp_evt_int(&e, "dur_ms", (long long)dur);
    mp_evt_send(&e);
}

/* -------------------------------------------------------------- lifecycle */

static mp_listener_cfg_t s_listener;

static esp_err_t httpd_start(mp_service_t *svc)
{
    if (!svc->brand || !mp_brand_behavior(svc->brand, "httpd")) {
        ESP_LOGE(TAG, "brand '%s' has no httpd behaviour",
                 svc->brand ? svc->brand->meta->id : "(null)");
        return ESP_ERR_NOT_SUPPORTED;
    }
    memset(&s_listener, 0, sizeof(s_listener));
    s_listener.vaddr = svc->bind.vaddr;
    s_listener.port = svc->bind.port;
    s_listener.name = "httpd";
    s_listener.handler = httpd_conn;
    s_listener.arg = svc;
    return mp_xport_listen(&s_listener);
}

static const mp_service_ops_t s_ops = {
    .name = "httpd",
    .proto = MP_PROTO_HTTP,
    .default_port = 80,
    .start = httpd_start,
    .stop = NULL,
};

const mp_service_ops_t *mp_httpd_get_ops(void)
{
    return &s_ops;
}
