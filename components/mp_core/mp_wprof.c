#include <string.h>

#include "mp_wprof.h"

#define MP_WPROF_MAX 8

static const mp_wprof_t *s_profs[MP_WPROF_MAX];
static size_t            s_n;

esp_err_t mp_wprof_register(const mp_wprof_t *prof)
{
    if (!prof || !prof->id || !prof->init || !prof->xport) {
        return ESP_ERR_INVALID_ARG;
    }
    if (mp_wprof_find(prof->id)) {
        return ESP_OK;
    }
    if (s_n >= MP_WPROF_MAX) {
        return ESP_ERR_NO_MEM;
    }
    s_profs[s_n++] = prof;
    return ESP_OK;
}

const mp_wprof_t *mp_wprof_find(const char *id)
{
    if (!id) {
        return NULL;
    }
    for (size_t i = 0; i < s_n; i++) {
        if (strcmp(s_profs[i]->id, id) == 0) {
            return s_profs[i];
        }
    }
    return NULL;
}
