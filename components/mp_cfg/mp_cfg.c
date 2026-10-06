/*
 * Runtime configuration store — ESP-free core.
 *
 * Registry + RAM shadow + storage vtable; the NVS backend and the audit
 * event emission live in mp_cfg_esp.c / mp_log.c respectively.
 */
#include <stdio.h>
#include <string.h>

#include "mp_cfg.h"

typedef struct {
    mp_cfg_key_t  def;
    mp_cfg_value_t val;        /* shadow of the effective value */
    bool           loaded;     /* shadow reflects storage state */
    bool           overridden; /* storage holds a value */
} slot_t;

static slot_t               s_slots[MP_CFG_MAX_KEYS];
static size_t               s_n;
static const mp_cfg_storage_t *s_store;
static mp_cfg_audit_hook    s_audit;

/* ------------------------------------------------------------ validation */

static bool parse_ip4(const char *s)
{
    /* strict dotted quad: four 0..255, digits only */
    for (int part = 0; part < 4; part++) {
        if (!*s || *s < '0' || *s > '9') {
            return false;
        }
        int v = 0, digits = 0;
        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (*s - '0');
            if (v > 255) {
                return false;
            }
            s++;
            digits++;
        }
        if (part < 3) {
            if (*s != '.') {
                return false;
            }
            s++;
        } else if (*s != '\0') {
            return false;
        }
        (void)digits;
    }
    return true;
}

static bool value_ok(const mp_cfg_key_t *def, const mp_cfg_value_t *v)
{
    switch (def->type) {
    case MP_CFG_T_STR:
        return strlen(v->u.str) <= MP_CFG_STR_MAX;
    case MP_CFG_T_IP:
        return parse_ip4(v->u.str);
    case MP_CFG_T_U32:
        return v->u.u32 >= def->u32_min && v->u.u32 <= def->u32_max;
    case MP_CFG_T_BOOL:
        return true;
    }
    return false;
}

static bool validate(const mp_cfg_key_t *def, const mp_cfg_value_t *v)
{
    if (!value_ok(def, v)) {
        return false;
    }
    return !def->validate || def->validate(v);
}

/* ------------------------------------------------------------ slot table */

static slot_t *find(const char *key)
{
    for (size_t i = 0; i < s_n; i++) {
        if (strcmp(s_slots[i].def.key, key) == 0) {
            return &s_slots[i];
        }
    }
    return NULL;
}

int mp_cfg_register(const mp_cfg_key_t *keys, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        const mp_cfg_key_t *k = &keys[i];
        if (!k->key || !*k->key || strlen(k->key) > MP_CFG_KEY_MAX ||
            find(k->key) || s_n >= MP_CFG_MAX_KEYS ||
            !validate(k, &k->dflt)) {
            return -1;
        }
        slot_t *s = &s_slots[s_n++];
        s->def = *k;
        s->val = k->dflt;
        s->loaded = false;
        s->overridden = false;
    }
    return 0;
}

void mp_cfg_use_storage(const mp_cfg_storage_t *st)
{
    s_store = st;
}

void mp_cfg_set_audit_hook(mp_cfg_audit_hook fn)
{
    s_audit = fn;
}

static void load_lazy(slot_t *s)
{
    if (s->loaded || !s_store || !s_store->load) {
        /* no backend installed yet: stay unloadable so a later
         * mp_cfg_use_storage() still gets a chance to load */
        return;
    }
    s->loaded = true;
    mp_cfg_value_t v;
    int r = s_store->load(s->def.key, s->def.type, &v);
    if (r == 1 && validate(&s->def, &v)) {
        s->val = v;
        s->overridden = true;
    }
    /* A corrupt/invalid stored value is ignored: default wins, and the
     * next set() simply overwrites it. */
}

/* ------------------------------------------------------------------- API */

bool mp_cfg_get(const char *key, mp_cfg_value_t *out)
{
    slot_t *s = find(key);
    if (!s) {
        return false;
    }
    load_lazy(s);
    *out = s->val;
    return true;
}

void mp_cfg_value_str(mp_cfg_type_t t, const mp_cfg_value_t *v,
                      char *out, size_t cap)
{
    switch (t) {
    case MP_CFG_T_STR:
    case MP_CFG_T_IP:
        snprintf(out, cap, "%s", v->u.str);
        break;
    case MP_CFG_T_U32:
        snprintf(out, cap, "%lu", (unsigned long)v->u.u32);
        break;
    case MP_CFG_T_BOOL:
        snprintf(out, cap, "%s", v->u.b ? "true" : "false");
        break;
    }
}

static void audit(const slot_t *s, const mp_cfg_value_t *newv,
                  bool new_is_default, const char *src)
{
    if (!s_audit) {
        return;
    }
    char old_s[MP_CFG_STR_MAX + 8], new_s[MP_CFG_STR_MAX + 8];
    if (s->def.secret) {
        snprintf(old_s, sizeof(old_s), "***");
        snprintf(new_s, sizeof(new_s), "***");
    } else {
        mp_cfg_value_str(s->def.type, &s->val, old_s, sizeof(old_s));
        if (new_is_default) {
            mp_cfg_value_str(s->def.type, &s->def.dflt, new_s, sizeof(new_s));
        } else {
            mp_cfg_value_str(s->def.type, newv, new_s, sizeof(new_s));
        }
    }
    s_audit(s->def.key, old_s, new_s, src ? src : "local");
}

int mp_cfg_set(const char *key, const mp_cfg_value_t *v, const char *src)
{
    slot_t *s = find(key);
    if (!s) {
        return -1;
    }
    if (!validate(&s->def, v)) {
        return -2;
    }
    if (!s_store || !s_store->save) {
        return -3;
    }
    if (s_store->save(key, s->def.type, v) < 0) {
        return -4;
    }
    load_lazy(s);
    audit(s, v, false, src);
    s->val = *v;
    s->overridden = true;
    return 0;
}

int mp_cfg_unset(const char *key, const char *src)
{
    slot_t *s = find(key);
    if (!s) {
        return -1;
    }
    if (!s_store || !s_store->erase) {
        return -3;
    }
    load_lazy(s);
    bool was = s->overridden;
    if (s_store->erase(key) < 0) {
        return -4;
    }
    if (was) {
        audit(s, NULL, true, src);
    }
    s->val = s->def.dflt;
    s->overridden = false;
    return 0;
}

int mp_cfg_unset_all(const char *src)
{
    if (!s_store || !s_store->erase_all) {
        return -3;
    }
    if (s_store->erase_all() < 0) {
        return -4;
    }
    for (size_t i = 0; i < s_n; i++) {
        if (s_slots[i].overridden) {
            audit(&s_slots[i], NULL, true, src);
        }
        s_slots[i].val = s_slots[i].def.dflt;
        s_slots[i].overridden = false;
        s_slots[i].loaded = true;
    }
    return 0;
}

static bool get_typed(const char *key, mp_cfg_type_t t, mp_cfg_value_t *out)
{
    slot_t *s = find(key);
    if (!s || s->def.type != t) {
        return false;
    }
    load_lazy(s);
    *out = s->val;
    return true;
}

const char *mp_cfg_str(const char *key, char *buf, size_t cap)
{
    mp_cfg_value_t v;
    if (!get_typed(key, MP_CFG_T_STR, &v) && !get_typed(key, MP_CFG_T_IP, &v)) {
        if (cap) {
            buf[0] = '\0';
        }
        return buf;
    }
    snprintf(buf, cap, "%s", v.u.str);
    return buf;
}

uint32_t mp_cfg_u32(const char *key, uint32_t fallback)
{
    mp_cfg_value_t v;
    return get_typed(key, MP_CFG_T_U32, &v) ? v.u.u32 : fallback;
}

bool mp_cfg_bool(const char *key, bool fallback)
{
    mp_cfg_value_t v;
    return get_typed(key, MP_CFG_T_BOOL, &v) ? v.u.b : fallback;
}

size_t mp_cfg_count(void)
{
    return s_n;
}

const mp_cfg_key_t *mp_cfg_at(size_t i)
{
    return i < s_n ? &s_slots[i].def : NULL;
}

bool mp_cfg_is_overridden(const char *key)
{
    slot_t *s = find(key);
    if (!s) {
        return false;
    }
    load_lazy(s);
    return s->overridden;
}
