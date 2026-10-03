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
