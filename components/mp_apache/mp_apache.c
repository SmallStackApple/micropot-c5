/*
 * Apache-style HTTP honeypot running on mp_xport.
 *
 * Response bytes are modelled on Apache httpd 2.4.38
 * (modules/http/http_protocol.c):
 *  - header order and names per ap_basic_http_header / ap_send_error_response
 *  - default error documents: DOCTYPE_HTML_2_0 + canned reason text +
 *    <address>"Server: banner" Server at <name> Port <port></address>
 *  - keep-alive semantics (KeepAlive On, timeout 5, max 100)
 *  - 400 on missing Host for HTTP/1.1, 405 for POST/TRACE to static
 *    content, 501 for unknown methods
 *
 * The clock is a fixed build base plus uptime: the box simply looks like
 * its RTC drifted, which is unremarkable for a random Linux host.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "mp_core.h"
#include "mp_apache.h"
#include "mp_httpd_behavior.h"
#include "mp_linekit.h"
#include "mp_log.h"

static const char *TAG = "mp_httpd";

#define REQ_MAX        4096
#define URI_MAX        512
#define HDR_BUF        1024
#define KEEPALIVE_MAX  100
#define KEEPALIVE_TIMEOUT_MS 5000
#define REQ_TIMEOUT_MS 30000

/* 2026-01-01 00:00:00 UTC; Last-Modified of the "installed" files. */
#define CLOCK_BASE_EPOCH 1767225600L

static mp_listener_cfg_t s_listener;

static time_t httpd_now(void)
{
    return (time_t)(CLOCK_BASE_EPOCH + esp_timer_get_time() / 1000000);
}

static void fmt_gmt(time_t t, char *out, size_t len)
{
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, len, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

/* ------------------------------------------------------------- base64 */

static int b64_decode(const char *in, char *out, size_t out_len)
{
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0;
    int acc = 0, bits = 0;
    for (const char *p = in; *p && *p != '='; p++) {
        const char *q = strchr(T, *p);
        if (!q) {
            continue;
        }
        acc = (acc << 6) | (int)(q - T);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n + 1 >= out_len) {
                return -1;
            }
            out[n++] = (char)((acc >> bits) & 0xff);
        }
    }
    out[n] = '\0';
    return (int)n;
}

/* --------------------------------------------------------- error pages */

static const char *reason_phrase(int code)
{
    switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 501: return "Not Implemented";
    default:  return "Internal Server Error";
    }
}

/* Canned error text per get_canned_error_string() (http_protocol.c). */
static int error_body(char *out, size_t out_len, int code,
                      const char *method, const char *uri,
                      const mp_httpd_behavior_t *b, uint16_t port)
{
    const char *title = reason_phrase(code);
    char canned[640];

    switch (code) {
    case 400:
        snprintf(canned, sizeof(canned),
                 "<p>Your browser sent a request that this server could not "
                 "understand.<br />\n</p>\n");
        break;
    case 401:
        snprintf(canned, sizeof(canned),
                 "<p>This server could not verify that you\n"
                 "are authorized to access the document\n"
                 "requested.  Either you supplied the wrong\n"
                 "credentials (e.g., bad password), or your\n"
                 "browser doesn't understand how to supply\n"
                 "the credentials required.</p>\n");
        break;
    case 404:
        snprintf(canned, sizeof(canned),
                 "<p>The requested URL %s was not found on this server.</p>\n",
                 uri);
        break;
    case 405:
        snprintf(canned, sizeof(canned),
                 "<p>The requested method %s is not allowed for the URL %s.</p>\n",
                 method, uri);
        break;
    case 501:
        snprintf(canned, sizeof(canned),
                 "<p>%s to %s not supported.<br />\n</p>\n", method, uri);
        break;
    default:
        canned[0] = '\0';
        break;
    }

    return snprintf(out, out_len,
                    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    "<html><head>\n<title>%d %s</title>\n"
                    "</head><body>\n<h1>%s</h1>\n"
                    "%s"
                    "<hr>\n"
                    "<address>%s Server at %s Port %u</address>\n"
                    "</body></html>\n",
                    code, title, title, canned,
                    b->server_hdr, b->server_name, port);
}

/* ------------------------------------------------------------- request */

typedef struct {
    char method[12];
    char uri[URI_MAX];
    int  http_minor; /* 0 or 1 */
    bool has_host;
    bool conn_close;
    bool conn_keepalive;
    char auth[192];  /* decoded "user:pass" when Basic auth present */
    bool has_auth;
} http_req_t;

static int send_all(mp_conn_t *conn, const char *buf, size_t len)
{
    return mp_conn_send(conn, buf, len);
}

/** Send a full response (headers + optional body). */
static int respond(mp_conn_t *conn, const mp_httpd_behavior_t *b, uint16_t port,
                   int code, const char *extra_hdrs,
                   const char *content_type, const char *body, size_t body_len,
                   bool head_only, bool keepalive, int ka_max)
{
    char hdr[HDR_BUF];
    char date[40];
    fmt_gmt(httpd_now(), date, sizeof(date));

    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %d %s\r\n"
                     "Date: %s\r\n"
                     "Server: %s\r\n"
                     "%s"
                     "Content-Length: %u\r\n",
                     code, reason_phrase(code), date, b->server_hdr,
                     extra_hdrs ? extra_hdrs : "",
                     (unsigned)body_len);
    if (keepalive) {
        n += snprintf(hdr + n, sizeof(hdr) - n,
                      "Keep-Alive: timeout=%d, max=%d\r\n"
                      "Connection: Keep-Alive\r\n",
                      KEEPALIVE_TIMEOUT_MS / 1000, ka_max);
    } else {
        n += snprintf(hdr + n, sizeof(hdr) - n, "Connection: close\r\n");
    }
    n += snprintf(hdr + n, sizeof(hdr) - n, "Content-Type: %s\r\n\r\n",
                  content_type);

    if (send_all(conn, hdr, (size_t)n) < 0) {
        return -1;
    }
    if (!head_only && body_len) {
        return send_all(conn, body, body_len);
    }
    return 0;
}

/** Read one request header block (up to CRLFCRLF). @return length, 0 peer
 *  closed, MP_CONN_TIMEOUT, MP_CONN_ABORTED. */
static int read_request(mp_conn_t *conn, char *buf, size_t cap, uint32_t timeout_ms)
{
    size_t len = 0;
    while (len + 1 < cap) {
        char c;
        int r = mp_conn_recv(conn, &c, 1, timeout_ms);
        if (r <= 0) {
            return len ? (int)len : r; /* partial request: serve what we got */
        }
        buf[len++] = c;
        if (len >= 4 && memcmp(buf + len - 4, "\r\n\r\n", 4) == 0) {
            break;
        }
    }
    buf[len] = '\0';
    return (int)len;
}

static bool parse_request(char *buf, http_req_t *req)
{
    memset(req, 0, sizeof(*req));

    /* request line: METHOD SP URI SP HTTP/1.x */
    char *line_end = strstr(buf, "\r\n");
    if (!line_end) {
        return false;
    }
    *line_end = '\0';
    char ver[12] = { 0 };
    if (sscanf(buf, "%11s %511s %11s", req->method, req->uri, ver) != 3) {
        return false;
    }
    if (sscanf(ver, "HTTP/1.%1d", &req->http_minor) != 1) {
        return false;
    }

    for (char *p = line_end + 2; *p;) {
        char *eol = strstr(p, "\r\n");
        if (!eol || eol == p) {
            break;
        }
        *eol = '\0';
        if (strncasecmp(p, "Host:", 5) == 0) {
            req->has_host = true;
        } else if (strncasecmp(p, "Connection:", 11) == 0) {
            if (strcasestr(p + 11, "close")) {
                req->conn_close = true;
            }
            if (strcasestr(p + 11, "keep-alive")) {
                req->conn_keepalive = true;
            }
        } else if (strncasecmp(p, "Authorization: Basic ", 21) == 0) {
            if (b64_decode(p + 21, req->auth, sizeof(req->auth)) > 0) {
                req->has_auth = true;
            }
        }
        p = eol + 2;
    }
    return true;
}

/* ------------------------------------------------------------- session */

static void httpd_conn(mp_conn_t *conn, const mp_session_t *sess, void *arg)
{
    mp_service_t *svc = (mp_service_t *)arg;
    const mp_httpd_behavior_t *b =
        svc->brand ? mp_brand_behavior(svc->brand, "httpd") : NULL;
    if (!b || !b->server_hdr) {
        return;
    }
    const uint16_t port = svc->bind.port;
    char *rbuf = malloc(REQ_MAX);
    if (!rbuf) {
        return;
    }

    int ka_left = KEEPALIVE_MAX;
    for (;;) {
        uint32_t timeout = (ka_left == KEEPALIVE_MAX) ? REQ_TIMEOUT_MS
                                                      : KEEPALIVE_TIMEOUT_MS;
        int n = read_request(conn, rbuf, REQ_MAX, timeout);
        if (n <= 0) {
            break; /* closed / timeout / aborted */
        }

        http_req_t req;
        bool keepalive = false;
        if (!parse_request(rbuf, &req)) {
            mp_log_http_request(sess, "-", "-", 400);
            char body[768];
            int bl = error_body(body, sizeof(body), 400, "-", "-", b, port);
            respond(conn, b, port, 400, NULL, "text/html; charset=iso-8859-1",
                    body, (size_t)bl, false, false, 0);
            break;
        }

        /* keep-alive decision (http_protocol.c ap_should_keep_alive) */
        if (req.http_minor >= 1) {
            keepalive = !req.conn_close;
        } else {
            keepalive = req.conn_keepalive;
        }
        if (--ka_left <= 0) {
            keepalive = false;
        }

        /* strip query for routing */
        char path[URI_MAX];
        snprintf(path, sizeof(path), "%s", req.uri);
        char *q = strchr(path, '?');
        if (q) {
            *q = '\0';
        }

        int code = 200;
        const mp_httpd_route_t *route = NULL;
        char extra[256] = { 0 };
        char body[768];
        const char *body_p = NULL;
        size_t body_len = 0;
        const char *ctype = "text/html; charset=iso-8859-1";
        bool head_only = false;

        if (req.http_minor >= 1 && !req.has_host) {
            /* RFC 2616 §14.23: HTTP/1.1 requires Host */
            code = 400;
            body_len = (size_t)error_body(body, sizeof(body), code,
                                          req.method, req.uri, b, port);
            body_p = body;
            keepalive = false;
        } else if (strcmp(req.method, "OPTIONS") == 0) {
            snprintf(extra, sizeof(extra), "Allow: GET,HEAD,OPTIONS,TRACE\r\n");
            code = 200;
            ctype = "text/html; charset=UTF-8"; /* empty body anyway */
        } else if (strcmp(req.method, "GET") == 0 ||
                   (head_only = (strcmp(req.method, "HEAD") == 0))) {
            for (uint8_t i = 0; i < b->n_routes; i++) {
                if (strcmp(b->routes[i].path, path) == 0) {
                    route = &b->routes[i];
                    break;
                }
            }
            if (!route) {
                code = 404;
                body_len = (size_t)error_body(body, sizeof(body), code,
                                              req.method, req.uri, b, port);
                body_p = body;
                mp_log_http_notfound(sess, req.uri);
            } else if (b->realm) {
                /* Basic-auth protected content (mod_auth_basic) */
                bool ok = false;
                char user[96] = { 0 }, pass[96] = { 0 };
                if (req.has_auth) {
                    char *colon = strchr(req.auth, ':');
                    if (colon) {
                        *colon = '\0';
                        strlcpy(user, req.auth, sizeof(user));
                        strlcpy(pass, colon + 1, sizeof(pass));
                        ok = mp_creds_match(b->creds, b->n_creds, user, pass);
                    }
                    mp_log_http_login(sess, user, pass, ok);
                }
                if (!ok) {
                    code = 401;
                    snprintf(extra, sizeof(extra),
                             "WWW-Authenticate: Basic realm=\"%s\"\r\n",
                             b->realm);
                    body_len = (size_t)error_body(body, sizeof(body), code,
                                                  req.method, req.uri, b, port);
                    body_p = body;
                }
            }
        } else if (strcmp(req.method, "POST") == 0 ||
                   strcmp(req.method, "PUT") == 0 ||
                   strcmp(req.method, "DELETE") == 0 ||
                   strcmp(req.method, "TRACE") == 0 ||
                   strcmp(req.method, "CONNECT") == 0) {
            /* static handler: TRACE is TraceEnable Off, the rest 405 */
            code = 405;
            snprintf(extra, sizeof(extra), "Allow: GET,HEAD,OPTIONS,TRACE\r\n");
            body_len = (size_t)error_body(body, sizeof(body), code,
                                          req.method, req.uri, b, port);
            body_p = body;
        } else {
            code = 501;
            body_len = (size_t)error_body(body, sizeof(body), code,
                                          req.method, req.uri, b, port);
            body_p = body;
        }

        if (code == 200 && route) {
            /* static file: Last-Modified / ETag / Accept-Ranges like
             * Apache's default handler (modules/http/http_core.c) */
            char lm[40];
            fmt_gmt((time_t)CLOCK_BASE_EPOCH, lm, sizeof(lm));
            body_len = route->body_len ? route->body_len : strlen(route->body);
            snprintf(extra, sizeof(extra),
                     "Last-Modified: %s\r\n"
                     "ETag: \"%lx-%x\"\r\n"
                     "Accept-Ranges: bytes\r\n",
                     lm, (unsigned long)(CLOCK_BASE_EPOCH & 0xffffff),
                     (unsigned)body_len);
            ctype = route->content_type;
            body_p = route->body;
        }

        mp_log_http_request(sess, req.method, req.uri, code);
        if (respond(conn, b, port, code, extra[0] ? extra : NULL, ctype,
                    body_p, body_len, head_only, keepalive,
                    ka_left > 0 ? ka_left : 1) < 0) {
            break;
        }
        if (!keepalive) {
            break;
        }
    }

    free(rbuf);
}

/* ----------------------------------------------------------- lifecycle */

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
    s_listener.persona = svc->persona ? svc->persona->id : NULL;
    s_listener.handler = httpd_conn;
    s_listener.arg = svc;
    return mp_xport_listen(&s_listener);
}

static const mp_service_ops_t s_ops = {
    .name = "httpd",
    .proto = MP_PROTO_TCP,
    .default_port = 80,
    .start = httpd_start,
    .stop = NULL,
};

const mp_service_ops_t *mp_apache_get_ops(void)
{
    return &s_ops;
}
