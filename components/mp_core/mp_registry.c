#include <string.h>

#include "esp_log.h"
#include "mp_registry.h"

static const char *TAG = "mp_registry";

#define MP_MAX_REGISTERED 8

static mp_service_t s_services[MP_MAX_REGISTERED];
static size_t       s_count;

esp_err_t mp_registry_register(const mp_service_ops_t *ops, mp_bind_t bind)
{
    if (!ops || !ops->name || !ops->start) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_count >= MP_MAX_REGISTERED) {
        return ESP_ERR_NO_MEM;
    }
    mp_service_t *svc = &s_services[s_count];
    memset(svc, 0, sizeof(*svc));
    svc->ops = ops;
    svc->bind = bind;
    s_count++;
    ESP_LOGI(TAG, "registered service '%s' port %u", ops->name, bind.port);
    return ESP_OK;
}

esp_err_t mp_registry_start_all(const mp_persona_t *persona, const mp_brand_t *brand)
{
    if (!persona || !brand) {
        return ESP_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < s_count; i++) {
        mp_service_t *svc = &s_services[i];
        if (svc->started) {
            continue;
        }
        if (!mp_persona_has_service(persona, svc->ops->name)) {
            ESP_LOGI(TAG, "service '%s' not in persona '%s', skipping",
                     svc->ops->name, persona->id);
            continue;
        }
        svc->persona = persona;
        svc->brand = brand;
        esp_err_t err = svc->ops->start(svc);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "service '%s' failed to start: %s", svc->ops->name,
                     esp_err_to_name(err));
            return err;
        }
        svc->started = true;
        ESP_LOGI(TAG, "service '%s' started on port %u", svc->ops->name, svc->bind.port);
    }
    return ESP_OK;
}

void mp_registry_stop_all(void)
{
    for (size_t i = 0; i < s_count; i++) {
        mp_service_t *svc = &s_services[i];
        if (svc->started && svc->ops->stop) {
            svc->ops->stop(svc);
            svc->started = false;
        }
    }
}

size_t mp_registry_count(void)
{
    return s_count;
}

mp_service_t *mp_registry_at(size_t index)
{
    return index < s_count ? &s_services[index] : NULL;
}
