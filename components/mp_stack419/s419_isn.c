/*
 * ISN generation, shaped to the "Fingerprint Linux 4.19" nmap-os-db record.
 *
 * Linux 4.19 (net/core/secure_seq.c) uses one keyed siphash per 4-tuple
 * plus a 64 ns clock. That full-entropy distribution lands nmap's SP
 * statistic at ~ISR-6, while the DB record sits at SP ≈ ISR-16 — so we
 * keep the keyed-hash + time-clock structure but draw the random part as
 * a sum of four hash slices (triangular, half the relative spread) and
 * run the clock 4x fast, centring both SP and ISR inside the record's
 * bands. See s419_isn() for the full derivation.
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

    /* The faithful 4.19 formula (one siphash + ktime>>6) yields full-
     * entropy ISN increments, and nmap's SP statistic is a direct measure
     * of that entropy: SP = 8*log2(stddev/mean) + ISR ≈ ISR - 6 for a
     * uniform increment distribution. The target DB record instead sits
     * at SP ≈ ISR - 16 (SP F5-FF with ISR 10A-114), i.e. its increments
     * have roughly half the relative spread — a shape the verbatim
     * formula can never produce, however it is sampled.
     *
     * Match the record's shape instead: sum four 30-bit hash slices, a
     * triangular distribution with the same 2^31 mean increment but the
     * required lower spread (stddev/mean ≈ 0.29), and run the RFC 793
     * clock 4x faster so the mean increment (and thus ISR) centres in
     * the record's band rather than at its bottom edge. All slices chain
     * through the keyed siphash, so the sequence stays unpredictable to
     * anyone without net_secret. */
    uint64_t h1 = s419_siphash_2_4(&combined, sizeof(combined), s_net_secret);
    uint64_t h2 = s419_siphash_2_4(&h1, sizeof(h1), s_net_secret);
    uint64_t h3 = s419_siphash_2_4(&h2, sizeof(h2), s_net_secret);
    uint64_t h4 = s419_siphash_2_4(&h3, sizeof(h3), s_net_secret);
    uint32_t rnd = (uint32_t)((h1 >> 34) + (h2 >> 34) + (h3 >> 34) + (h4 >> 34));

    /* 64 ns clock x4; nmap only ever sees deltas, boot-relative is fine. */
    uint64_t ns = (uint64_t)esp_timer_get_time() * 1000ULL;
    return rnd + (uint32_t)(ns << 2);
}
