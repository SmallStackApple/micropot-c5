/*
 * Service registry: a catalog of available service ops plus one runtime
 * instance per (vdev, persona service). Instance backends come from the
 * persona's wire profile; lwIP-backed services only work on the primary
 * address (vaddr 0), packet-engine backends serve aliases too.
 */
#include <string.h>

#include "esp_log.h"

#include "mp_registry.h"
#include "mp_vdev.h"
#include "mp_wprof.h"

static const char *TAG = "mp_registry";

#define MP_MAX_REGISTERED 8
#define MP_MAX_INSTANCES  24

typedef struct {
    const mp_service_ops_t *ops;
    uint16_t                port;
} catalog_t;

static catalog_t     s_catalog[MP_MAX_REGISTERED];
static size_t        s_n_catalog;
static mp_service_t  s_instances[MP_MAX_INSTANCES];
static size_t        s_n_instances;
static const mp_brand_t *s_inited_brands[MP_MAX_INSTANCES];
static size_t        s_n_inited_brands;

esp_err_t mp_registry_register(const mp_service_ops_t *ops, mp_bind_t bind)
{
    if (!ops || !ops->name || !ops->start) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_n_catalog >= MP_MAX_REGISTERED) {
        return ESP_ERR_NO_MEM;
    }
    s_catalog[s_n_catalog].ops = ops;
    s_catalog[s_n_catalog].port = bind.port;
    s_n_catalog++;
    ESP_LOGI(TAG, "registered service '%s' port %u", ops->name, bind.port);
    return ESP_OK;
}

static const catalog_t *catalog_find(const char *name)
{
    for (size_t i = 0; i < s_n_catalog; i++) {
        if (strcmp(s_catalog[i].ops->name, name) == 0) {
            return &s_catalog[i];
        }
    }
    return NULL;
}

static esp_err_t brand_init_once(const mp_brand_t *brand)
{
    for (size_t i = 0; i < s_n_inited_brands; i++) {
        if (s_inited_brands[i] == brand) {
            return ESP_OK;
        }
    }
    if (brand->init) {
        esp_err_t err = brand->init(brand);
        if (err != ESP_OK) {
            return err;
        }
    }
    if (s_n_inited_brands < MP_MAX_INSTANCES) {
        s_inited_brands[s_n_inited_brands++] = brand;
    }
    return ESP_OK;
}

/* One instance: service ops × vdev. A failure skips the instance instead
 * of aborting the boot — a broken persona must not take the others down. */
static void start_instance(const mp_vdev_t *vdev, const mp_persona_t *persona,
                           const char *service_name)
{
    const catalog_t *cat = catalog_find(service_name);
    if (!cat) {
        ESP_LOGW(TAG, "persona '%s' wants unregistered service '%s'",
                 persona->id, service_name);
        return;
    }
    if (s_n_instances >= MP_MAX_INSTANCES) {
        ESP_LOGE(TAG, "instance pool exhausted");
        return;
    }
    const mp_brand_t *brand = mp_brand_find(persona->brand_id);
    if (!brand) {
        ESP_LOGE(TAG, "persona '%s' references unknown brand '%s'",
                 persona->id, persona->brand_id);
        return;
    }
    if (brand_init_once(brand) != ESP_OK) {
        ESP_LOGE(TAG, "brand '%s' init failed", brand->meta->id);
        return;
    }

    mp_service_t *svc = &s_instances[s_n_instances];
    memset(svc, 0, sizeof(*svc));
    svc->ops = cat->ops;
    svc->persona = persona;
    svc->brand = brand;
    svc->bind.vaddr = vdev->vaddr;
    svc->bind.port = cat->port;

    esp_err_t err = svc->ops->start(svc);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "service '%s' on vdev 0x%08lx failed: %s",
                 svc->ops->name, (unsigned long)vdev->vaddr,
                 esp_err_to_name(err));
        return;
    }
    svc->started = true;
    s_n_instances++;
    ESP_LOGI(TAG, "service '%s' up: persona '%s' port %u vaddr 0x%08lx",
             svc->ops->name, persona->id, svc->bind.port,
             (unsigned long)vdev->vaddr);
}

esp_err_t mp_registry_start_all(void)
{
    for (size_t v = 0; v < mp_vdev_count(); v++) {
        const mp_vdev_t *vdev = mp_vdev_at(v);
        const mp_persona_t *persona = vdev->persona;
        if (!persona) {
            continue;
        }
        for (uint8_t i = 0; i < persona->n_services; i++) {
            start_instance(vdev, persona, persona->services[i]);
        }
    }
    return ESP_OK;
}

void mp_registry_stop_all(void)
{
    for (size_t i = 0; i < s_n_instances; i++) {
        mp_service_t *svc = &s_instances[i];
        if (svc->started && svc->ops->stop) {
            svc->ops->stop(svc);
            svc->started = false;
        }
    }
}

const mp_xport_backend_t *mp_service_xport(const mp_service_t *svc)
{
    if (!svc || !svc->persona || !svc->persona->wire) {
        return NULL; /* active default backend */
    }
    const mp_wprof_t *wp = mp_wprof_find(svc->persona->wire);
    return wp ? wp->xport : NULL;
}

size_t mp_registry_count(void)
{
    return s_n_instances;
}

mp_service_t *mp_registry_at(size_t index)
{
    return index < s_n_instances ? &s_instances[index] : NULL;
}
