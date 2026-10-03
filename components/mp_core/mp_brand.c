#include <string.h>

#include "esp_log.h"
#include "mp_brand.h"

static const char *TAG = "mp_brand";

#define MP_MAX_BRANDS 8

static const mp_brand_t *s_brands[MP_MAX_BRANDS];
static size_t            s_count;

static bool brand_valid(const mp_brand_t *b)
{
    return b && b->meta && b->meta->id;
}

bool mp_creds_match(const mp_cred_t *creds, uint8_t n,
                    const char *user, const char *pass)
{
    if (!creds || !user || !pass) {
        return false;
    }
    for (uint8_t i = 0; i < n; i++) {
        if (creds[i].user && creds[i].pass &&
            strcmp(creds[i].user, user) == 0 &&
            strcmp(creds[i].pass, pass) == 0) {
            return true;
        }
    }
    return false;
}

esp_err_t mp_brand_register(const mp_brand_t *brand)
{
    if (!brand_valid(brand)) {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < s_count; i++) {
        if (strcmp(s_brands[i]->meta->id, brand->meta->id) == 0) {
            return ESP_OK; /* already registered */
        }
    }
    if (s_count >= MP_MAX_BRANDS) {
        return ESP_ERR_NO_MEM;
    }
    s_brands[s_count++] = brand;
    ESP_LOGI(TAG, "registered brand '%s' (%s %s)", brand->meta->id,
             brand->meta->vendor ? brand->meta->vendor : "?",
             brand->meta->model ? brand->meta->model : "?");
    return ESP_OK;
}

const void *mp_brand_behavior(const mp_brand_t *brand, const char *proto)
{
    if (!brand || !brand->behaviors || !proto) {
        return NULL;
    }
    for (const mp_brand_behavior_entry_t *e = brand->behaviors; e->proto; e++) {
        if (strcmp(e->proto, proto) == 0) {
            return e->behavior;
        }
    }
    return NULL;
}

const mp_brand_t *mp_brand_find(const char *id)
{
    if (!id) {
        return NULL;
    }
    for (size_t i = 0; i < s_count; i++) {
        if (strcmp(s_brands[i]->meta->id, id) == 0) {
            return s_brands[i];
        }
    }
    return NULL;
}

size_t mp_brand_count(void)
{
    return s_count;
}

const mp_brand_t *mp_brand_at(size_t index)
{
    return index < s_count ? s_brands[index] : NULL;
}
