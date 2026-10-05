/*
 * ISN generation, shaped to the "Fingerprint Linux 4.19" nmap-os-db record.
 *
 * Linux 4.19 (net/core/secure_seq.c) uses one keyed siphash per 4-tuple
 * plus a 64 ns clock. That full-entropy distribution lands nmap's SP
 * statistic at ~ISR-6, while the DB record sits at SP ≈ ISR-16, so the
 * verbatim formula can never match the record it is scored against.
 * Instead each ISN advances a global counter by a fixed 0x70000000 step
 * plus keyed-hash noise and a fast time clock, concentrating the deltas
 * nmap measures (verified against the exact osscan2 SP/ISR math by
 * simulation). See s419_isn() for details.
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

    /* Shaping ISN increments into the record's SP/ISR bands. nmap sees
     * only deltas: SP = 8*log2(stddev/mean of the per-probe increment
     * rate). For deltas to concentrate, consecutive ISNs must advance by
     * a near-constant step — adding noise to a centered random ISN does
     * NOT work (mod 2^32 folds a centered distribution into a bathtub
     * with *larger* spread; verified by simulation of the exact osscan2
     * math). So:
     *
     *   ISN(n) = n * 0x70000000 + noise(tuple) + (t_ns << 2)
     *
     * with n a per-connection counter. Deltas = 0x70000000 + noise diff
     * + clock: mean ≈ 2.5e9 (ISR 0x10C-10F at the ~0.16-0.25 s probe
     * spacing seen on typical LANs) with stddev ≈ 4.7e8 (SP ≈ 0xF9-FE).
     * The noise is keyed-hash derived, so cross-host sequences stay
     * unpredictable without net_secret; GCD of the deltas stays 1. */
    static uint32_t s_step;
    uint64_t h1 = s419_siphash_2_4(&combined, sizeof(combined), s_net_secret);
    uint64_t h2 = s419_siphash_2_4(&h1, sizeof(h1), s_net_secret);
    int64_t noise = (int64_t)(((h1 >> 34) + (h2 >> 34)) * 3 / 4) - 0x30000000;

    uint64_t ns = (uint64_t)esp_timer_get_time() * 1000ULL;
    return (uint32_t)(s_step++ * 0x70000000u) + (uint32_t)noise +
           (uint32_t)(ns << 2);
}
