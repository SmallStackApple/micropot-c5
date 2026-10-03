/* Host tests for the generic event builder (components/mp_log/mp_evt.c). */
#include "test_util.h"

#include "mp_log.h"

static void test_basic_fields(void)
{
    mp_session_t s = {
        .id = 42, .src_ip = 0x0102A8C0, .src_port = 5000,
        .dst_ip = 0x6401A8C0, .dst_port = 23,
    };
    mp_evt_t e;
    mp_evt_begin(&e, &s, "telnet", "telnet.login_attempt");
    mp_evt_str(&e, "user", "admin");
    mp_evt_str(&e, "pass", "12345");
    mp_evt_str(&e, "result", "fail");
    mp_evt_int(&e, "attempt", 2);
    mp_evt_bool(&e, "up", true);

    CHECK_STR(e.data,
              "\"user\":\"admin\",\"pass\":\"12345\",\"result\":\"fail\","
              "\"attempt\":2,\"up\":true");
    CHECK(e.sid == 42);
    CHECK(e.src_port == 5000 && e.dst_port == 23);
    CHECK(strcmp(e.proto, "telnet") == 0);
    CHECK(strcmp(e.evt, "telnet.login_attempt") == 0);
    CHECK(!e.truncated);
}

static void test_json_escaping(void)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "x", "x");
    mp_evt_str(&e, "v", "a\"b\\c\nd\re\tf\x01g");
    CHECK_STR(e.data, "\"v\":\"a\\\"b\\\\c\\nd\\re\\tf\\u0001g\"");

    mp_evt_begin(&e, NULL, "x", "x");
    mp_evt_str(&e, "v", NULL);
    CHECK_STR(e.data, "\"v\":\"\"");
}

static void test_no_session(void)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "system", "net.up");
    mp_evt_str(&e, "ip", "192.168.1.100");
    CHECK(e.sid == 0 && e.src_ip == 0 && e.dst_port == 0);
    CHECK_STR(e.data, "\"ip\":\"192.168.1.100\"");
}

static void test_truncation(void)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL, "x", "x");
    char big[MP_EVT_DATA_MAX * 2];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    mp_evt_str(&e, "v", big);
    mp_evt_int(&e, "n", 1);
    CHECK(e.truncated);
    CHECK(e.data_len < sizeof(e.data));
    CHECK(e.data[e.data_len] == '\0');
}

static void test_long_names_clamped(void)
{
    mp_evt_t e;
    mp_evt_begin(&e, NULL,
                 "a-very-long-protocol-name", "an-even-longer-event-name-here");
    CHECK(strlen(e.proto) < sizeof(e.proto));
    CHECK(strlen(e.evt) < sizeof(e.evt));
}

int main(void)
{
    test_basic_fields();
    test_json_escaping();
    test_no_session();
    test_truncation();
    test_long_names_clamped();
    TEST_SUMMARY("test_evt");
}
