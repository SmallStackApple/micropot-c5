#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"

#include "mp_util.h"

static portMUX_TYPE s_id_lock = portMUX_INITIALIZER_UNLOCKED;
static uint32_t     s_next_id;

void mp_ip4_str(uint32_t addr, char *out, size_t n)
{
    snprintf(out, n, "%u.%u.%u.%u",
             (unsigned)(addr & 0xff), (unsigned)((addr >> 8) & 0xff),
             (unsigned)((addr >> 16) & 0xff), (unsigned)((addr >> 24) & 0xff));
}

uint32_t mp_session_next_id(void)
{
    uint32_t id;
    portENTER_CRITICAL(&s_id_lock);
    id = ++s_next_id;
    portEXIT_CRITICAL(&s_id_lock);
    return id;
}

static int hexnib(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool mp_parse_mac(const char *s, uint8_t out[6])
{
    if (!s || !out) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        int hi = hexnib(s[i * 3]);
        int lo = hexnib(s[i * 3 + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
        if (i < 5 && s[i * 3 + 2] != ':') {
            return false;
        }
    }
    if (s[17] != '\0') {
        return false;
    }
    return (out[0] & 1) == 0; /* group/multicast bit: not a station MAC */
}
