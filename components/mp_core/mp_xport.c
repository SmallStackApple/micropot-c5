/*
 * Transport core: active backend pointer plus the global session budget
 * shared by every backend.
 */
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

#include "mp_xport.h"

#include "sdkconfig.h"

static const mp_xport_backend_t *s_backend = &mp_xport_lwip;

static portMUX_TYPE       s_budget_lock = portMUX_INITIALIZER_UNLOCKED;
static uint32_t           s_active;
static mp_overload_hook_t s_overload_hook;

void mp_xport_use(const mp_xport_backend_t *backend)
{
    if (backend) {
        s_backend = backend;
    }
}

const char *mp_xport_backend_name(void)
{
    return s_backend->name;
}

esp_err_t mp_xport_listen(const mp_listener_cfg_t *cfg)
{
    if (!cfg || !cfg->handler) {
        return ESP_ERR_INVALID_ARG;
    }
    return s_backend->listen(cfg);
}

bool mp_xport_budget_take(void)
{
    bool ok;
    portENTER_CRITICAL(&s_budget_lock);
    ok = s_active < CONFIG_MICROPOT_MAX_SESSIONS;
    if (ok) {
        s_active++;
    }
    portEXIT_CRITICAL(&s_budget_lock);
    return ok;
}

void mp_xport_budget_give(void)
{
    portENTER_CRITICAL(&s_budget_lock);
    if (s_active) {
        s_active--;
    }
    portEXIT_CRITICAL(&s_budget_lock);
}

uint32_t mp_xport_active(void)
{
    return s_active;
}

void mp_xport_set_overload_hook(mp_overload_hook_t hook)
{
    s_overload_hook = hook;
}

void mp_xport_report_overload(const char *service, uint16_t port)
{
    if (s_overload_hook) {
        s_overload_hook(service, port);
    }
}
