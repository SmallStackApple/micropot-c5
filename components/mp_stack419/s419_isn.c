/*
 * ISN generation, mirroring Linux 4.19 net/core/secure_seq.c:
 *
 *   static u32 seq_scale(u32 seq) { return seq + (ktime_get_real_ns() >> 6); }
 *
 *   secure_tcp_sequence_number(saddr, daddr, sport, dport):
 *       hash = siphash({saddr,daddr,sport,dport}, 12, &net_secret);
 *       return seq_scale(hash);   // low 32 bits of the 64-bit hash
 */
#include <string.h>

#include "esp_random.h"
#include "esp_timer.h"

#include "s419_isn.h"
#include "s419_siphash.h"

static uint8_t s_net_secret[16];
static bool    s_seeded;

void s419_isn_init(void)
{
    esp_fill_random(s_net_secret, sizeof(s_net_secret));
    s_seeded = true;
}

uint32_t s419_isn(uint32_t saddr_nbo, uint32_t daddr_nbo,
                  uint16_t sport_nbo, uint16_t dport_nbo)
{
    if (!s_seeded) {
        s419_isn_init();
    }

    /* struct layout of secure_seq.c's "combined": members concatenated,
     * 12 bytes, fields kept in network byte order as on the wire. */
    struct {
        uint32_t saddr;
        uint32_t daddr;
        uint16_t sport;
        uint16_t dport;
    } __attribute__((packed)) combined = {
        .saddr = saddr_nbo,
        .daddr = daddr_nbo,
        .sport = sport_nbo,
        .dport = dport_nbo,
    };

    uint64_t hash = s419_siphash_2_4(&combined, sizeof(combined), s_net_secret);

    /* seq_scale(): add a 64 ns clock. esp_timer is µs since boot; the
     * nmap ISR/SP tests only see deltas, so boot-relative is fine. */
    uint64_t ns = (uint64_t)esp_timer_get_time() * 1000ULL;
    return (uint32_t)hash + (uint32_t)(ns >> 6);
}
