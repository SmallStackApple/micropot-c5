#include <string.h>

#include "esp_log.h"
#include "mp_persona.h"

/*
 * Phase 1 persona table. Each entry selects a brand module and the protocol
 * services it exposes. Phase 2 will extend this with one entry per virtual IP
 * and replace the Kconfig choice with a runtime lookup.
 */
static const mp_persona_t s_personas[] = {
    {
        .id = "ipcam-01",
        .brand_id = "hikvision_ipcam",
        .bind = { .vaddr = 0, .port = 0 },
        .services = { "telnet", "http", "ssh" },
        .n_services = 3,
        .hostname = "IPCAM-01",
    },
    {
        .id = "router-01",
        .brand_id = "tplink_router",
        .bind = { .vaddr = 0, .port = 0 },
        .services = { "telnet", "http", "ssh" },
        .n_services = 3,
        .hostname = "TP-LINK_WR841N",
    },
    {
        .id = "printer-01",
        .brand_id = "hp_printer",
        .bind = { .vaddr = 0, .port = 0 },
        .services = { "telnet", "http", "ssh" },
        .n_services = 3,
        .hostname = "HP-LaserJet-M428",
    },
    {
        .id = "linux-419",
        .brand_id = "linux_419",
        .bind = { .vaddr = 0, .port = 0 },
        .services = { "telnet", "httpd", "sshd", "ftpd" },
        .n_services = 4,
        .hostname = "linux",
        .wire = "linux419",
    },
};

#if CONFIG_MICROPOT_PERSONA_ROUTER
#define MP_ACTIVE_PERSONA_INDEX 1
#elif CONFIG_MICROPOT_PERSONA_PRINTER
#define MP_ACTIVE_PERSONA_INDEX 2
#elif CONFIG_MICROPOT_PERSONA_LINUX419
#define MP_ACTIVE_PERSONA_INDEX 3
#else
#define MP_ACTIVE_PERSONA_INDEX 0
#endif

/* Runtime override set by phase-2 config loading; NULL = Kconfig choice. */
static const mp_persona_t *s_active_override;

void mp_persona_set_active(const mp_persona_t *persona)
{
    s_active_override = persona;
}

const mp_persona_t *mp_persona_active(void)
{
    return s_active_override ? s_active_override
                             : &s_personas[MP_ACTIVE_PERSONA_INDEX];
}

const mp_persona_t *mp_persona_by_vaddr(uint32_t vaddr)
{
    if (vaddr == 0) {
        return NULL; /* 0 == "any": not a per-IP persona (phase 1 default) */
    }
    for (size_t i = 0; i < sizeof(s_personas) / sizeof(s_personas[0]); i++) {
        if (s_personas[i].bind.vaddr == vaddr) {
            return &s_personas[i];
        }
    }
    return NULL;
}

const mp_persona_t *mp_persona_by_index(size_t index)
{
    if (index >= sizeof(s_personas) / sizeof(s_personas[0])) {
        return NULL;
    }
    return &s_personas[index];
}

size_t mp_persona_count(void)
{
    return sizeof(s_personas) / sizeof(s_personas[0]);
}

const mp_persona_t *mp_persona_find(const char *id)
{
    if (!id) {
        return NULL;
    }
    for (size_t i = 0; i < mp_persona_count(); i++) {
        if (strcmp(s_personas[i].id, id) == 0) {
            return &s_personas[i];
        }
    }
    return NULL;
}

bool mp_persona_has_service(const mp_persona_t *p, const char *name)
{
    if (!p || p->n_services == 0) {
        return true; /* empty list => expose everything registered */
    }
    for (uint8_t i = 0; i < p->n_services; i++) {
        if (p->services[i] && strcmp(p->services[i], name) == 0) {
            return true;
        }
    }
    return false;
}
