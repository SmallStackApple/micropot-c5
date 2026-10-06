/*
 * NVS storage backend for mp_cfg (namespace "mpc") + component init.
 *
 * The audit hook is installed by mp_log (it owns the event pipeline);
 * keeping it out of here avoids a circular component dependency.
 */
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "nvs.h"

#include "mp_cfg.h"

static const char *TAG = "mp_cfg";

static nvs_handle_t s_nvs;

static int nvs_load(const char *key, mp_cfg_type_t type, mp_cfg_value_t *out)
{
    esp_err_t err;
    switch (type) {
    case MP_CFG_T_STR:
    case MP_CFG_T_IP: {
        size_t len = sizeof(out->u.str);
        err = nvs_get_str(s_nvs, key, out->u.str, &len);
        break;
    }
    case MP_CFG_T_U32:
        err = nvs_get_u32(s_nvs, key, &out->u.u32);
        break;
    case MP_CFG_T_BOOL: {
        uint8_t b = 0;
        err = nvs_get_u8(s_nvs, key, &b);
        out->u.b = b != 0;
        break;
    }
    default:
        return -1;
    }
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return 0;
    }
    return err == ESP_OK ? 1 : -1;
}

static int nvs_save(const char *key, mp_cfg_type_t type, const mp_cfg_value_t *v)
{
    esp_err_t err;
    switch (type) {
    case MP_CFG_T_STR:
    case MP_CFG_T_IP:
        err = nvs_set_str(s_nvs, key, v->u.str);
        break;
    case MP_CFG_T_U32:
        err = nvs_set_u32(s_nvs, key, v->u.u32);
        break;
    case MP_CFG_T_BOOL:
        err = nvs_set_u8(s_nvs, key, v->u.b ? 1 : 0);
        break;
    default:
        return -1;
    }
    if (err != ESP_OK) {
        return -1;
    }
    return nvs_commit(s_nvs) == ESP_OK ? 0 : -1;
}

static int nvs_erase_one(const char *key)
{
    esp_err_t err = nvs_erase_key(s_nvs, key);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return 0;
    }
    if (err != ESP_OK) {
        return -1;
    }
    return nvs_commit(s_nvs) == ESP_OK ? 0 : -1;
}

static int nvs_erase_all_keys(void)
{
    if (nvs_erase_all(s_nvs) != ESP_OK) {
        return -1;
    }
    return nvs_commit(s_nvs) == ESP_OK ? 0 : -1;
}

static const mp_cfg_storage_t s_nvs_store = {
    .load = nvs_load,
    .save = nvs_save,
    .erase = nvs_erase_one,
    .erase_all = nvs_erase_all_keys,
};

esp_err_t mp_cfg_init(void)
{
    esp_err_t err = nvs_open("mpc", NVS_READWRITE, &s_nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }
    mp_cfg_use_storage(&s_nvs_store);
    return ESP_OK;
}
