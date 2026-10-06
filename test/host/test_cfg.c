/*
 * Host tests for mp_cfg: registry semantics, validation, storage
 * round-trips and audit-hook behaviour, all over a RAM storage stub.
 */
#include <stdio.h>
#include <string.h>

#include "mp_cfg.h"
#include "test_util.h"

/* ------------------------------------------------------------ RAM storage */

#define RAM_MAX 16

static struct {
    char key[MP_CFG_KEY_MAX + 1];
    mp_cfg_type_t type;
    mp_cfg_value_t val;
} s_ram[RAM_MAX];
static int s_ram_n;
static int s_save_calls, s_erase_calls, s_erase_all_calls;

static int ram_find(const char *key)
{
    for (int i = 0; i < s_ram_n; i++) {
        if (strcmp(s_ram[i].key, key) == 0) {
            return i;
        }
    }
    return -1;
}

static int ram_load(const char *key, mp_cfg_type_t type, mp_cfg_value_t *out)
{
    int i = ram_find(key);
    if (i < 0) {
        return 0;
    }
    if (s_ram[i].type != type) {
        return -1; /* type confusion in storage: corrupt */
    }
    *out = s_ram[i].val;
    return 1;
}

static int ram_save(const char *key, mp_cfg_type_t type, const mp_cfg_value_t *v)
{
    s_save_calls++;
    int i = ram_find(key);
    if (i < 0) {
        if (s_ram_n >= RAM_MAX) {
            return -1;
        }
        i = s_ram_n++;
        snprintf(s_ram[i].key, sizeof(s_ram[i].key), "%s", key);
    }
    s_ram[i].type = type;
    s_ram[i].val = *v;
    return 0;
}

static int ram_erase(const char *key)
{
    s_erase_calls++;
    int i = ram_find(key);
    if (i < 0) {
        return 0;
    }
    s_ram[i] = s_ram[--s_ram_n];
    return 0;
}

static int ram_erase_all(void)
{
    s_erase_all_calls++;
    s_ram_n = 0;
    return 0;
}

static const mp_cfg_storage_t s_ram_store = {
    .load = ram_load, .save = ram_save,
    .erase = ram_erase, .erase_all = ram_erase_all,
};

/* ------------------------------------------------------------- audit log */

static char s_audit_key[MP_CFG_KEY_MAX + 1];
static char s_audit_old[MP_CFG_STR_MAX + 8];
static char s_audit_new[MP_CFG_STR_MAX + 8];
static char s_audit_src[32];
static int  s_audit_calls;

static void audit_spy(const char *key, const char *oldv, const char *newv,
                      const char *src)
{
    s_audit_calls++;
    snprintf(s_audit_key, sizeof(s_audit_key), "%s", key);
    snprintf(s_audit_old, sizeof(s_audit_old), "%s", oldv);
    snprintf(s_audit_new, sizeof(s_audit_new), "%s", newv);
    snprintf(s_audit_src, sizeof(s_audit_src), "%s", src ? src : "");
}

/* ------------------------------------------------------------ key fixture */

static const mp_cfg_key_t s_keys[] = {
    { "log.host", MP_CFG_T_IP,  { .u.str = "192.168.1.10" }, 0, 0, NULL, false },
    { "log.port", MP_CFG_T_U32, { .u.u32 = 9999 }, 1, 65535, NULL, false },
    { "log.tcp",  MP_CFG_T_BOOL,{ .u.b = false }, 0, 0, NULL, false },
    { "ctl.psk",  MP_CFG_T_STR, { .u.str = "change-me" }, 0, 0, NULL, true },
};

static void reset_fixture(void)
{
    /* fresh RAM storage; registry itself is process-static so tests share
     * the single registration done in main(). Counters are zeroed AFTER
     * the reset sweep, which itself calls erase_all. */
    s_ram_n = 0;
    mp_cfg_unset_all("test");
    s_save_calls = s_erase_calls = s_erase_all_calls = 0;
    s_audit_calls = 0;
}

/* ------------------------------------------------------------------ tests */

static void test_defaults_when_storage_empty(void)
{
    char buf[MP_CFG_STR_MAX + 1];
    CHECK_STR(mp_cfg_str("log.host", buf, sizeof(buf)), "192.168.1.10");
    CHECK(mp_cfg_u32("log.port", 0) == 9999);
    CHECK(mp_cfg_bool("log.tcp", true) == false);
    CHECK(mp_cfg_is_overridden("log.host") == false);
}

static void test_set_get_roundtrip(void)
{
    mp_cfg_value_t v;
    snprintf(v.u.str, sizeof(v.u.str), "10.0.0.7");
    CHECK(mp_cfg_set("log.host", &v, "udp:10.0.0.1") == 0);
    CHECK(s_save_calls == 1);
    CHECK(mp_cfg_is_overridden("log.host"));

    char buf[MP_CFG_STR_MAX + 1];
    CHECK_STR(mp_cfg_str("log.host", buf, sizeof(buf)), "10.0.0.7");

    /* persistence: value lives in the stub, a fresh slot state would
     * still load it — simulate by checking the storage directly */
    CHECK(ram_find("log.host") >= 0);

    /* audit fired with src and stringified old/new */
    CHECK(s_audit_calls == 1);
    CHECK_STR(s_audit_key, "log.host");
    CHECK_STR(s_audit_old, "192.168.1.10");
    CHECK_STR(s_audit_new, "10.0.0.7");
    CHECK_STR(s_audit_src, "udp:10.0.0.1");
}

static void test_unset_reverts_to_default(void)
{
    mp_cfg_value_t v;
    snprintf(v.u.str, sizeof(v.u.str), "10.1.2.3");
    CHECK(mp_cfg_set("log.host", &v, "test") == 0);
    int audits_after_set = s_audit_calls;
    CHECK(mp_cfg_unset("log.host", "serial") == 0);
    CHECK(s_erase_calls >= 1);
    CHECK(mp_cfg_is_overridden("log.host") == false);
    char buf[MP_CFG_STR_MAX + 1];
    CHECK_STR(mp_cfg_str("log.host", buf, sizeof(buf)), "192.168.1.10");
    /* unset of an overridden key audits old -> default */
    CHECK(s_audit_calls == audits_after_set + 1);
    CHECK_STR(s_audit_new, "192.168.1.10");
}

static void test_validation(void)
{
    mp_cfg_value_t v;

    /* bad IPs rejected, storage untouched */
    snprintf(v.u.str, sizeof(v.u.str), "999.1.1.1");
    CHECK(mp_cfg_set("log.host", &v, "test") == -2);
    snprintf(v.u.str, sizeof(v.u.str), "10.0.0.1.");
    CHECK(mp_cfg_set("log.host", &v, "test") == -2);
    snprintf(v.u.str, sizeof(v.u.str), "10.0.0");
    CHECK(mp_cfg_set("log.host", &v, "test") == -2);
    snprintf(v.u.str, sizeof(v.u.str), "10a.0.0.1");
    CHECK(mp_cfg_set("log.host", &v, "test") == -2);

    /* port range */
    v.u.u32 = 0;
    CHECK(mp_cfg_set("log.port", &v, "test") == -2);
    v.u.u32 = 65536;
    CHECK(mp_cfg_set("log.port", &v, "test") == -2);
    v.u.u32 = 443;
    CHECK(mp_cfg_set("log.port", &v, "test") == 0);
    CHECK(mp_cfg_u32("log.port", 0) == 443);

    /* unknown key */
    CHECK(mp_cfg_set("no.such.key", &v, "test") == -1);
    CHECK(mp_cfg_u32("no.such.key", 42) == 42);

    /* the value union caps strings at MP_CFG_STR_MAX by construction:
     * a full-size 63-char string is legal */
    memset(v.u.str, 'a', MP_CFG_STR_MAX);
    v.u.str[MP_CFG_STR_MAX] = '\0';
    CHECK(mp_cfg_set("ctl.psk", &v, "test") == 0);
}

static void test_secret_redaction(void)
{
    mp_cfg_value_t v;
    snprintf(v.u.str, sizeof(v.u.str), "hunter2");
    CHECK(mp_cfg_set("ctl.psk", &v, "serial") == 0);
    CHECK(s_audit_calls == 1);
    CHECK_STR(s_audit_new, "***");
    CHECK_STR(s_audit_old, "***");
    /* but the value itself is stored and readable */
    char buf[MP_CFG_STR_MAX + 1];
    CHECK_STR(mp_cfg_str("ctl.psk", buf, sizeof(buf)), "hunter2");
}

static void test_unset_all(void)
{
    mp_cfg_value_t v;
    snprintf(v.u.str, sizeof(v.u.str), "10.9.9.9");
    CHECK(mp_cfg_set("log.host", &v, "test") == 0);
    v.u.u32 = 1234;
    CHECK(mp_cfg_set("log.port", &v, "test") == 0);
    CHECK(mp_cfg_unset_all("serial") == 0);
    CHECK(s_erase_all_calls == 1);
    CHECK(s_ram_n == 0);
    char buf[MP_CFG_STR_MAX + 1];
    CHECK_STR(mp_cfg_str("log.host", buf, sizeof(buf)), "192.168.1.10");
    CHECK(mp_cfg_u32("log.port", 0) == 9999);
}

static void test_registry_guards(void)
{
    /* duplicate key rejected */
    static const mp_cfg_key_t dup[] = {
        { "log.host", MP_CFG_T_STR, { .u.str = "x" }, 0, 0, NULL, false },
    };
    CHECK(mp_cfg_register(dup, 1) == -1);

    /* overlong key rejected (NVS limit) */
    static const mp_cfg_key_t longk[] = {
        { "0123456789abcdef", MP_CFG_T_STR, { .u.str = "x" }, 0, 0, NULL, false },
    };
    CHECK(mp_cfg_register(longk, 1) == -1);

    /* invalid default rejected */
    static const mp_cfg_key_t baddflt[] = {
        { "bad.port", MP_CFG_T_U32, { .u.u32 = 70000 }, 1, 65535, NULL, false },
    };
    CHECK(mp_cfg_register(baddflt, 1) == -1);

    /* type-mismatched convenience getters fall back */
    CHECK(mp_cfg_u32("log.host", 77) == 77);
    CHECK(mp_cfg_bool("log.host", true) == true);
}

int main(void)
{
    mp_cfg_use_storage(&s_ram_store);
    mp_cfg_set_audit_hook(audit_spy);
    CHECK(mp_cfg_register(s_keys, sizeof(s_keys) / sizeof(s_keys[0])) == 0);
    CHECK(mp_cfg_count() == 4);
    CHECK(mp_cfg_at(0) != NULL && strcmp(mp_cfg_at(0)->key, "log.host") == 0);
    CHECK(mp_cfg_at(4) == NULL);

    reset_fixture(); test_defaults_when_storage_empty();
    reset_fixture(); test_set_get_roundtrip();
    reset_fixture(); test_unset_reverts_to_default();
    reset_fixture(); test_validation();
    reset_fixture(); test_secret_redaction();
    reset_fixture(); test_unset_all();
    reset_fixture(); test_registry_guards();
    TEST_SUMMARY("test_cfg");
}
