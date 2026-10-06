#include <string.h>

#include "freertos/FreeRTOS.h"
#include "lwip/ip6_addr.h"
#include "lwip/sockets.h"

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mp_core.h"
#include "mp_form.h"
#include "mp_http_ui.h"
#include "mp_http_behavior.h"
#include "mp_log.h"

static const char *TAG = "mp_http";

/*
 * Phase 1 runs a single HTTP instance bound to the single device IP. The
 * active behaviour is kept in a module global because esp_http_server's
 * public API does not expose a per-instance user context to handlers.
 * Phase 2 (multi virtual IP) will need one server instance per persona;
 * that is tracked as a known limitation in the design notes.
 */
static const mp_http_behavior_t *s_behavior;
static uint16_t                  s_port;

/* --------------------------------------------------------------- helpers */

/* Extract an IPv4 address (network byte order) and host-order port from either
 * an AF_INET or an IPv4-mapped AF_INET6 socket address. */
static uint32_t addr_port_from_sockaddr(const struct sockaddr_storage *ss, uint16_t *port)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)ss;
        *port = ntohs(a->sin_port);
        return a->sin_addr.s_addr;
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)ss;
        *port = ntohs(a6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&a6->sin6_addr)) {
            return a6->sin6_addr.un.u32_addr[3];
        }
    }
    *port = 0;
    return 0;
}

static void session_from_req(httpd_req_t *req, mp_session_t *s)
{
    memset(s, 0, sizeof(*s));
    s->sock = httpd_req_to_sockfd(req);
    s->id = mp_session_next_id();
    s->start_us = esp_timer_get_time();

    /* esp_http_server uses dual-stack (IPv6) sockets, so peer/local addresses
     * may arrive as IPv4-mapped IPv6. Handle both families. */
    struct sockaddr_storage peer, local;
    socklen_t len = sizeof(peer);
    if (getpeername(s->sock, (struct sockaddr *)&peer, &len) == 0) {
        s->src_ip = addr_port_from_sockaddr(&peer, &s->src_port);
    }
    len = sizeof(local);
    if (getsockname(s->sock, (struct sockaddr *)&local, &len) == 0) {
        s->dst_ip = addr_port_from_sockaddr(&local, &s->dst_port);
    }
}

static void common_headers(httpd_req_t *req)
{
    if (s_behavior && s_behavior->server_hdr) {
        httpd_resp_set_hdr(req, "Server", s_behavior->server_hdr);
    }
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Connection", "close");
}

static esp_err_t send_html(httpd_req_t *req, const char *html)
{
    common_headers(req);
    return httpd_resp_send(req, html ? html : "", html ? strlen(html) : 0);
}

/* -------------------------------------------------------------- handlers */

static esp_err_t root_get(httpd_req_t *req)
{
    mp_session_t s;
    session_from_req(req, &s);
    mp_log_http_request(&s, "GET", req->uri, 302);
    common_headers(req);
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/login");
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t login_get(httpd_req_t *req)
{
    mp_session_t s;
    session_from_req(req, &s);
    mp_log_http_request(&s, "GET", req->uri, 200);
    return send_html(req, s_behavior->login_html);
}

static esp_err_t login_post(httpd_req_t *req)
{
    mp_session_t s;
    session_from_req(req, &s);
    mp_log_http_request(&s, "POST", req->uri, 200);

    char body[512];
    int  total = req->content_len;
    if (total < 0 || total >= (int)sizeof(body)) {
        total = sizeof(body) - 1;
    }
    int received = 0;
    while (received < total) {
        int r = httpd_req_recv(req, body + received, total - received);
        if (r <= 0) {
            break;
        }
        received += r;
    }
    body[received] = '\0';

    char user[64] = { 0 };
    char pass[64] = { 0 };
    mp_form_get(body, "username", user, sizeof(user));
    mp_form_get(body, "password", pass, sizeof(pass));

    bool ok = mp_creds_match(s_behavior->creds, s_behavior->n_creds, user, pass);
    mp_log_http_login(&s, user, pass, ok);

    return send_html(req, ok ? s_behavior->admin_html : s_behavior->fail_html);
}

static esp_err_t admin_get(httpd_req_t *req)
{
    mp_session_t s;
    session_from_req(req, &s);
    mp_log_http_request(&s, "GET", req->uri, 200);
    return send_html(req, s_behavior->admin_html);
}

static const char *method_str(int method)
{
    switch (method) {
    case HTTP_GET:     return "GET";
    case HTTP_POST:    return "POST";
    case HTTP_PUT:     return "PUT";
    case HTTP_DELETE:  return "DELETE";
    case HTTP_HEAD:    return "HEAD";
    case HTTP_OPTIONS: return "OPTIONS";
    case HTTP_PATCH:   return "PATCH";
    default:           return "?";
    }
}

static esp_err_t not_found(httpd_req_t *req, httpd_err_code_t err)
{
    (void)err;
    mp_session_t s;
    session_from_req(req, &s);
    mp_log_http_request(&s, method_str(req->method), req->uri, 404);
    mp_log_http_notfound(&s, req->uri);

    common_headers(req);
    httpd_resp_set_status(req, "404 Not Found");
    /* Brand-driven 404: the address line echoes the active server's own
     * header instead of leaking a fixed vendor string. */
    char page[320];
    int n = snprintf(page, sizeof(page),
                     "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                     "<body><h1>404 Not Found</h1><hr><address>"
                     "%s Server at device Port %u</address></body></html>",
                     (s_behavior && s_behavior->server_hdr) ? s_behavior->server_hdr
                                                            : "embedded",
                     (unsigned)s_port);
    return httpd_resp_send(req, page, (size_t)n);
}

/* -------------------------------------------------------------- lifecycle */

static esp_err_t http_start(mp_service_t *svc)
{
    const mp_http_behavior_t *behavior =
        svc->brand ? mp_brand_behavior(svc->brand, "http") : NULL;
    if (!behavior) {
        ESP_LOGE(TAG, "brand '%s' has no http behaviour",
                 svc->brand ? svc->brand->meta->id : "(null)");
        return ESP_ERR_NOT_SUPPORTED;
    }
    s_behavior = behavior;
    s_port = svc->bind.port;

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = svc->bind.port;
    config.max_uri_handlers = 8;
    config.max_open_sockets = 5;
    config.lru_purge_enable = true;
    config.stack_size = 8192;

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        return err;
    }

    const httpd_uri_t routes[] = {
        { .uri = "/",       .method = HTTP_GET,  .handler = root_get,   .user_ctx = NULL },
        { .uri = "/login",  .method = HTTP_GET,  .handler = login_get,  .user_ctx = NULL },
        { .uri = "/login",  .method = HTTP_POST, .handler = login_post, .user_ctx = NULL },
        { .uri = "/admin",  .method = HTTP_GET,  .handler = admin_get,  .user_ctx = NULL },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        err = httpd_register_uri_handler(server, &routes[i]);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "register %s %s failed: %s", routes[i].uri,
                     routes[i].method == HTTP_GET ? "GET" : "POST",
                     esp_err_to_name(err));
        }
    }
    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, not_found);

    svc->ctx = server;
    return ESP_OK;
}

static void http_stop(mp_service_t *svc)
{
    if (svc->ctx) {
        httpd_stop((httpd_handle_t)svc->ctx);
        svc->ctx = NULL;
    }
}

static const mp_service_ops_t s_ops = {
    .name = "http",
    .proto = MP_PROTO_HTTP,
    .default_port = 80,
    .start = http_start,
    .stop = http_stop,
};

const mp_service_ops_t *mp_http_ui_get_ops(void)
{
    return &s_ops;
}
