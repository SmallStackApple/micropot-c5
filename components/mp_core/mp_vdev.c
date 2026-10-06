/*
 * Virtual device table: primary persona + aliases from runtime config.
 *
 * One physical MAC serves every vdev (802.11 infrastructure constraint —
 * IP aliasing in real-world terms), so ARP for alias addresses is answered
 * by mp_vif and alias-destined IP traffic is demuxed before lwIP's
 * not-for-us drop via mp_vif_ip4_input_hook().
 */
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "lwip/ip4_addr.h"

#include "mp_brand.h"
#include "mp_cfg.h"
#include "mp_vdev.h"

static const char *TAG = "mp_vdev";

static mp_vdev_t s_vdevs[MP_VDEV_MAX];
static size_t    s_n;

/* Alias slots; Kconfig strings are only the DEFAULTS (NVS overrides win). */
#define MP_VDEV_SLOTS(X) \
    X(1, CONFIG_MICROPOT_VDEV1_IP, CONFIG_MICROPOT_VDEV1_PERSONA) \
    X(2, CONFIG_MICROPOT_VDEV2_IP, CONFIG_MICROPOT_VDEV2_PERSONA) \
    X(3, CONFIG_MICROPOT_VDEV3_IP, CONFIG_MICROPOT_VDEV3_PERSONA) \
    X(4, CONFIG_MICROPOT_VDEV4_IP, CONFIG_MICROPOT_VDEV4_PERSONA) \
    X(5, CONFIG_MICROPOT_VDEV5_IP, CONFIG_MICROPOT_VDEV5_PERSONA) \
    X(6, CONFIG_MICROPOT_VDEV6_IP, CONFIG_MICROPOT_VDEV6_PERSONA) \
    X(7, CONFIG_MICROPOT_VDEV7_IP, CONFIG_MICROPOT_VDEV7_PERSONA)

static const mp_cfg_key_t s_cfg_keys[] = {
#define MP_VDEV_KEY(n, ip_dflt, persona_dflt) \
    { "vdev" #n ".ip", MP_CFG_T_IP, { .u.str = ip_dflt }, 0, 0, NULL, false, NULL, true }, \
    { "vdev" #n ".persona", MP_CFG_T_STR, { .u.str = persona_dflt }, 0, 0, NULL, false, NULL, true },
    MP_VDEV_SLOTS(MP_VDEV_KEY)
#undef MP_VDEV_KEY
};

esp_err_t mp_vdev_load(void)
{
    mp_cfg_register(s_cfg_keys, sizeof(s_cfg_keys) / sizeof(s_cfg_keys[0]));

    s_vdevs[0].vaddr = 0; /* primary: DHCP/static address, lwIP answers ARP */
    s_vdevs[0].persona = mp_persona_active();
    s_n = 1;

    for (int i = 1; i < MP_VDEV_MAX; i++) {
        char key[16], ip[24], pid[24];
        snprintf(key, sizeof(key), "vdev%d.ip", i);
        mp_cfg_str(key, ip, sizeof(ip));
        if (!ip[0] || strcmp(ip, "0.0.0.0") == 0) {
            continue;
        }
        snprintf(key, sizeof(key), "vdev%d.persona", i);
        mp_cfg_str(key, pid, sizeof(pid));
        const mp_persona_t *p = mp_persona_find(pid);
        if (!p) {
            ESP_LOGW(TAG, "vdev%d: unknown persona '%s', slot skipped", i, pid);
            continue;
        }
        if (!p->wire) {
            /* only packet-crafting engines can serve an address lwIP does
             * not own; an lwIP-backend persona cannot live on an alias */
            ESP_LOGW(TAG, "vdev%d: persona '%s' has no wire profile, slot skipped",
                     i, pid);
            continue;
        }
        ip4_addr_t a;
        if (ip4addr_aton(ip, &a) != 1) {
            ESP_LOGW(TAG, "vdev%d: bad ip '%s', slot skipped", i, ip);
            continue;
        }
        bool dup = false;
        for (size_t j = 0; j < s_n; j++) {
            if (s_vdevs[j].vaddr == a.addr) {
                dup = true;
            }
        }
        if (dup) {
            ESP_LOGW(TAG, "vdev%d: duplicate ip '%s', slot skipped", i, ip);
            continue;
        }
        s_vdevs[s_n].vaddr = a.addr;
        s_vdevs[s_n].persona = p;
        ESP_LOGI(TAG, "vdev%d: %s -> persona '%s'", i, ip, p->id);
        s_n++;
    }
    return ESP_OK;
}

size_t mp_vdev_count(void)
{
    return s_n;
}

const mp_vdev_t *mp_vdev_at(size_t i)
{
    return i < s_n ? &s_vdevs[i] : NULL;
}

const mp_vdev_t *mp_vdev_by_vaddr(uint32_t vaddr)
{
    for (size_t i = 1; i < s_n; i++) { /* aliases only; primary is lwIP's */
        if (s_vdevs[i].vaddr == vaddr) {
            return &s_vdevs[i];
        }
    }
    return NULL;
}

esp_err_t mp_vdev_add(uint32_t vaddr, const mp_persona_t *persona)
{
    if (mp_vdev_by_vaddr(vaddr)) {
        return ESP_OK;
    }
    if (s_n >= MP_VDEV_MAX) {
        return ESP_ERR_NO_MEM;
    }
    s_vdevs[s_n].vaddr = vaddr;
    s_vdevs[s_n].persona = persona;
    s_n++;
    return ESP_OK;
}

bool mp_vdev_vendor_coherent(const char **vendor_a, const char **vendor_b)
{
    const char *first = NULL;
    for (size_t i = 0; i < s_n; i++) {
        if (!s_vdevs[i].persona) {
            continue; /* management plane: no narrative */
        }
        const mp_brand_t *b = mp_brand_find(s_vdevs[i].persona->brand_id);
        const char *v = (b && b->meta) ? b->meta->vendor : NULL;
        if (!v) {
            continue;
        }
        if (!first) {
            first = v;
        } else if (strcmp(first, v) != 0) {
            if (vendor_a) {
                *vendor_a = first;
            }
            if (vendor_b) {
                *vendor_b = v;
            }
            return false;
        }
    }
    return true;
}
