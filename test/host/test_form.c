/* Host tests for the form parser (components/mp_http/mp_form.c). */
#include "test_util.h"

#include "mp_form.h"

static void test_basic(void)
{
    char out[64];
    CHECK(mp_form_get("username=admin&password=12345", "username", out, sizeof(out)));
    CHECK_STR(out, "admin");
    CHECK(mp_form_get("username=admin&password=12345", "password", out, sizeof(out)));
    CHECK_STR(out, "12345");
    CHECK(!mp_form_get("username=admin&password=12345", "missing", out, sizeof(out)));
}

static void test_key_boundary(void)
{
    char out[64];
    /* "username=" inside "xusername=" must not match */
    CHECK(mp_form_get("xusername=evil&username=admin", "username", out, sizeof(out)));
    CHECK_STR(out, "admin");
    /* key as a strict prefix of another key */
    CHECK(!mp_form_get("username2=foo", "username", out, sizeof(out)));
    /* empty value is still found */
    CHECK(mp_form_get("username=&password=x", "username", out, sizeof(out)));
    CHECK_STR(out, "");
}

static void test_url_decoding(void)
{
    char out[64];
    CHECK(mp_form_get("password=p%40ss+w%25rd%21", "password", out, sizeof(out)));
    CHECK_STR(out, "p@ss w%rd!");
    /* malformed escapes pass through untouched */
    CHECK(mp_form_get("password=a%zz%4", "password", out, sizeof(out)));
    CHECK_STR(out, "a%zz%4");
}

static void test_value_truncation(void)
{
    char out[8];
    CHECK(mp_form_get("username=administrator", "username", out, sizeof(out)));
    CHECK_STR(out, "adminis");
}

int main(void)
{
    test_basic();
    test_key_boundary();
    test_url_decoding();
    test_value_truncation();
    TEST_SUMMARY("test_form");
}
