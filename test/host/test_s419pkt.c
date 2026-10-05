/*
 * Host test for the s419 packet builders, in particular the staged-payload
 * checksum contract used by s419_tcp.c flush()/retransmit():
 *
 *   len = s419_build_tcp(pkt, par, ..., NULL, n);   // returns IP hdr + seg
 *   memcpy(pkt + len - n, payload, n);              // stage in place
 *   s419_tcp_set_cksum(pkt, len - S419_IP_HLEN);    // BARE segment length
 *
 * (Passing len unmodified makes the checksum cover 20 bytes past the
 * segment; every data segment then fails the peer's verification and the
 * connection hangs with the banner never accepted — observed on hardware.)
 */
#include <stdint.h>

#include "s419_pkt.h"
#include "test_util.h"

static const mp_s419_params_t PAR = {
    .ttl = 64, .tcp_df = true, .tcp_ipid_zero = true, .icmp_df = false,
    .mss = 1460, .rcv_wnd = 64240, .wscale = 6,
    .sack_perm = true, .timestamps = false, .ecn_mode = 2,
    .tx_cwnd_segs = 8,
    .rto_initial_ms = 1000, .rto_min_ms = 200, .rto_max_ms = 120000,
    .synack_retries = 5, .data_retries = 15,
    .delack_ms = 40, .timewait_ms = 60000, .finwait2_ms = 60000,
};

/* unfolded sum of big-endian 16-bit words (odd tail padded with zero) */
static uint32_t raw_sum(const uint8_t *p, size_t len)
{
    uint32_t s = 0;
    while (len >= 2) {
        s += ((uint32_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len) {
        s += (uint32_t)p[0] << 8;
    }
    return s;
}

static uint16_t fold(uint32_t s)
{
    while (s >> 16) {
        s = (s & 0xffff) + (s >> 16);
    }
    return (uint16_t)s;
}

/* A correct TCP checksum makes pseudo-header + segment fold to 0xffff. */
static uint16_t tcp_residual(const uint8_t *pkt, size_t seg_len)
{
    uint32_t s = raw_sum(pkt + 12, 8);        /* src + dst */
    s += pkt[9];                              /* zero + proto word */
    s += (uint16_t)seg_len;                   /* TCP length word */
    s += raw_sum(pkt + S419_IP_HLEN, seg_len);
    return fold(s);
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

int main(void)
{
    static const char *BANNER = "SSH-2.0-OpenSSH_7.9p1\r\n";
    uint8_t pkt[S419_IP_HLEN + S419_TCP_HLEN + 64];

    /* ---- staged-payload data segment (the flush() pattern) ---- */
    size_t n = strlen(BANNER);
    size_t len = s419_build_tcp(pkt, &PAR, 0x0a000001, 0x0a000002,
                                0x1600, 0x5000, 100, 200,
                                S419_ACK | S419_PSH, PAR.rcv_wnd, NULL, n);
    CHECK(len == S419_IP_HLEN + S419_TCP_HLEN + n);
    CHECK(rd16(pkt + 2) == len);              /* IP total length */
    memcpy(pkt + len - n, BANNER, n);
    s419_tcp_set_cksum(pkt, len - S419_IP_HLEN);
    CHECK(tcp_residual(pkt, len - S419_IP_HLEN) == 0xffff);
    CHECK(memcmp(pkt + S419_IP_HLEN + S419_TCP_HLEN, BANNER, n) == 0);

    /* the buggy call (full length) must NOT validate: guards the test */
    s419_tcp_set_cksum(pkt, len);
    CHECK(tcp_residual(pkt, len - S419_IP_HLEN) != 0xffff);

    /* ---- SYN-ACK: checksummed inside the builder ---- */
    len = s419_build_synack(pkt, &PAR, 0x0a000001, 0x0a000002,
                            0x1600, 0x5000, 100, 200,
                            false, true, true);
    CHECK(len == S419_IP_HLEN + S419_TCP_HLEN + 12); /* M5B4 NNS NW6 */
    CHECK(rd16(pkt + 2) == len);
    CHECK(tcp_residual(pkt, len - S419_IP_HLEN) == 0xffff);
    /* O6 probe (no WScale offered): options collapse to M5B4NNS (8) */
    len = s419_build_synack(pkt, &PAR, 0x0a000001, 0x0a000002,
                            0x1600, 0x5000, 100, 200,
                            false, true, false);
    CHECK(len == S419_IP_HLEN + S419_TCP_HLEN + 8);
    CHECK(tcp_residual(pkt, len - S419_IP_HLEN) == 0xffff);

    /* ---- ICMP echo reply: checksum + id/seq preserved ---- */
    uint8_t req[S419_IP_HLEN + 8 + 4];
    memset(req, 0, sizeof(req));
    req[0] = 0x45;
    req[9] = 1; /* ICMP */
    s419_put_ip(req, sizeof(req), 7, false, 64, 1, 0x0a000002, 0x0a000001);
    uint8_t *iq = req + S419_IP_HLEN;
    iq[0] = 8;  /* echo request */
    iq[4] = 0x12; iq[5] = 0x34;      /* id */
    iq[6] = 0xab; iq[7] = 0xcd;      /* seq */
    iq[8] = 1; iq[9] = 2; iq[10] = 3; iq[11] = 4;
    iq[2] = 0; iq[3] = 0;
    uint16_t qc = s419_cksum(iq, 12);
    iq[2] = (uint8_t)(qc >> 8); iq[3] = (uint8_t)qc;

    uint8_t rep[sizeof(req)];
    len = s419_build_icmp_echo_reply(rep, req, sizeof(req), 99, &PAR);
    CHECK(len == sizeof(req));
    CHECK(rep[S419_IP_HLEN] == 0);                 /* echo reply */
    CHECK(s419_cksum(rep + S419_IP_HLEN, 12) == 0); /* incl. checksum */
    CHECK(rep[S419_IP_HLEN + 4] == 0x12 && rep[S419_IP_HLEN + 6] == 0xab);
    CHECK(rd16(rep + 4) == 99);                    /* caller's IP-ID */

    TEST_SUMMARY("test_s419pkt");
}
