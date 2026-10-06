/*
 * Packet crafting. Byte layouts follow Linux 4.19:
 *  - IP header:            net/ipv4/ip_output.c (ip_build_and_send_pkt)
 *  - SYN-ACK option order: net/ipv4/tcp_output.c tcp_options_write()
 *  - ICMP echo reply:      net/ipv4/icmp.c icmp_reply()
 *  - ICMP unreachable:     net/ipv4/icmp.c icmp_send() (quotes IP hdr + 8)
 */
#include <string.h>

#include "s419_pkt.h"

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

uint16_t s419_cksum(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

void s419_put_ip(uint8_t *out, uint16_t total_len, uint16_t id, bool df,
                 uint8_t ttl, uint8_t proto,
                 uint32_t src_nbo, uint32_t dst_nbo)
{
    out[0] = 0x45; /* v4, ihl 5 */
    out[1] = 0;    /* TOS */
    put16(out + 2, total_len);
    put16(out + 4, id);
    put16(out + 6, df ? 0x4000 : 0x0000);
    out[8] = ttl;
    out[9] = proto;
    put16(out + 10, 0);
    put32(out + 12, src_nbo);
    put32(out + 16, dst_nbo);
    put16(out + 10, s419_cksum(out, S419_IP_HLEN));
}

static uint16_t tcp_cksum(const uint8_t *ip, const uint8_t *tcp, size_t tcp_len)
{
    /* pseudo header: src, dst, zero+proto, tcp length */
    uint32_t sum = 0;
    const uint8_t *p;
    size_t len;

    for (p = ip + 12, len = 8; len > 1; p += 2, len -= 2) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
    }
    sum += IP_PROTO_TCP;
    sum += (uint16_t)tcp_len;

    for (p = tcp, len = tcp_len; len > 1; p += 2, len -= 2) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
    }
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* TCP header at out+20; @p opts may be NULL. Returns TCP segment length. */
static size_t put_tcp(uint8_t *out, uint32_t src_nbo, uint32_t dst_nbo,
                      uint16_t sport_nbo, uint16_t dport_nbo,
                      uint32_t seq, uint32_t ack, uint8_t flags, uint16_t wnd,
                      const uint8_t *opts, size_t opts_len,
                      const void *payload, size_t payload_len)
{
    uint8_t *tcp = out + S419_IP_HLEN;
    size_t hdr_len = S419_TCP_HLEN + opts_len;

    put16(tcp + 0, sport_nbo); /* engine domain is big-endian numeric */
    put16(tcp + 2, dport_nbo);
    put32(tcp + 4, seq);
    put32(tcp + 8, ack);
    tcp[12] = (uint8_t)((hdr_len / 4) << 4);
    tcp[13] = flags;
    put16(tcp + 14, wnd);
    put16(tcp + 16, 0); /* checksum, filled below */
    put16(tcp + 18, 0); /* urgent pointer */
    if (opts_len) {
        memcpy(tcp + S419_TCP_HLEN, opts, opts_len);
    }
    if (payload && payload_len) {
        memcpy(tcp + hdr_len, payload, payload_len);
    }

    /* The checksum covers the IP pseudo header, so it can only be computed
     * by the caller after s419_put_ip() filled the addresses. */
    return hdr_len + payload_len;
}

/** (Re)compute the TCP checksum of a built packet (call after the payload
 *  area was filled out-of-band, e.g. straight from a tx ring). */
void s419_tcp_set_cksum(uint8_t *pkt, size_t tcp_len)
{
    uint8_t *tcp = pkt + S419_IP_HLEN;
    tcp[16] = 0;
    tcp[17] = 0;
    put16(tcp + 16, tcp_cksum(pkt, tcp, tcp_len));
}

size_t s419_build_synack(uint8_t *out, const mp_s419_params_t *par,
                         uint32_t src_nbo, uint32_t dst_nbo,
                         uint16_t sport_nbo, uint16_t dport_nbo,
                         uint32_t seq, uint32_t ack, bool ece,
                         bool sack_offered, bool ws_offered)
{
    /* tcp_options_write() (net/ipv4/tcp_output.c), timestamps disabled:
     * options are mirrored only when the SYN offered them — nmap's O3
     * probe offers no SACK (answer M5B4NW6) and O6 offers no WScale
     * (answer M5B4NNS); with both offered: M5B4NNSNW6.
     *   word1: 02 04 mss          (MSS, always)
     *   word2: 01 01 04 02        (NOP NOP SACK_PERM, iff offered)
     *   word3: 01 03 03 ws        (NOP WSCALE, iff offered)
     * (A TS block would sit between SACK and WSCALE; the persona targets
     * TS=U, so timestamps are never emitted.) */
    uint8_t opts[12];
    size_t n = 0;
    opts[n++] = 0x02; opts[n++] = 0x04;
    opts[n++] = (uint8_t)(par->mss >> 8);
    opts[n++] = (uint8_t)par->mss;
    if (par->sack_perm && sack_offered) {
        opts[n++] = 0x01; opts[n++] = 0x01;
        opts[n++] = 0x04; opts[n++] = 0x02;
    }
    if (ws_offered) {
        opts[n++] = 0x01; opts[n++] = 0x03; opts[n++] = 0x03;
        opts[n++] = par->wscale;
    }

    uint8_t flags = S419_SYN | S419_ACK | (ece ? S419_ECE : 0);
    size_t tcp_len = put_tcp(out, src_nbo, dst_nbo, sport_nbo, dport_nbo,
                             seq, ack, flags, par->rcv_wnd, opts, n, NULL, 0);
    s419_put_ip(out, (uint16_t)(S419_IP_HLEN + tcp_len),
                par->tcp_ipid_zero ? 0 : 1, par->tcp_df, par->ttl, IP_PROTO_TCP,
                src_nbo, dst_nbo);
    s419_tcp_set_cksum(out, tcp_len);
    return S419_IP_HLEN + tcp_len;
}

size_t s419_build_tcp(uint8_t *out, const mp_s419_params_t *par,
                      uint32_t src_nbo, uint32_t dst_nbo,
                      uint16_t sport_nbo, uint16_t dport_nbo,
                      uint32_t seq, uint32_t ack, uint8_t flags,
                      uint16_t wnd, const void *payload, size_t payload_len)
{
    size_t tcp_len = put_tcp(out, src_nbo, dst_nbo, sport_nbo, dport_nbo,
                             seq, ack, flags, wnd, NULL, 0, payload, payload_len);
    s419_put_ip(out, (uint16_t)(S419_IP_HLEN + tcp_len),
                par->tcp_ipid_zero ? 0 : 1, par->tcp_df, par->ttl, IP_PROTO_TCP,
                src_nbo, dst_nbo);
    s419_tcp_set_cksum(out, tcp_len);
    return S419_IP_HLEN + tcp_len;
}

size_t s419_build_icmp_echo_reply(uint8_t *out, const uint8_t *req,
                                  size_t req_len, uint16_t ipid,
                                  const mp_s419_params_t *par)
{
    if (req_len < S419_IP_HLEN + 8) {
        return 0;
    }
    size_t icmp_len = req_len - S419_IP_HLEN;
    uint8_t *icmp = out + S419_IP_HLEN;

    memcpy(icmp, req + S419_IP_HLEN, icmp_len);
    icmp[0] = 0; /* echo reply */
    put16(icmp + 2, 0);
    put16(icmp + 2, s419_cksum(icmp, icmp_len));

    /* engine domain is big-endian numeric (s419_put_ip uses put32) */
    uint32_t src_nbo = ((uint32_t)req[16] << 24) | ((uint32_t)req[17] << 16) |
                       ((uint32_t)req[18] << 8) | (uint32_t)req[19];
    uint32_t dst_nbo = ((uint32_t)req[12] << 24) | ((uint32_t)req[13] << 16) |
                       ((uint32_t)req[14] << 8) | (uint32_t)req[15];
    s419_put_ip(out, (uint16_t)(S419_IP_HLEN + icmp_len), ipid, par->icmp_df,
                par->ttl, IP_PROTO_ICMP, src_nbo, dst_nbo);
    return S419_IP_HLEN + icmp_len;
}

size_t s419_build_icmp_unreach(uint8_t *out, const uint8_t *bad,
                               size_t bad_len, uint16_t ipid,
                               uint32_t src_nbo, uint32_t dst_nbo,
                               const mp_s419_params_t *par)
{
    /* icmp_send() (net/ipv4/icmp.c): quote as much of the offending
     * datagram as fits within the minimum MTU — in practice the whole
     * packet (nmap's 328-byte UDP probe -> IPL=0x164). */
    size_t quote = bad_len;
    if (quote > 576 - S419_IP_HLEN - 8) {
        quote = 576 - S419_IP_HLEN - 8;
    }
    uint8_t *icmp = out + S419_IP_HLEN;
    icmp[0] = 3; /* destination unreachable */
    icmp[1] = 3; /* port unreachable */
    put16(icmp + 2, 0);
    put16(icmp + 4, 0);
    put16(icmp + 6, 0);
    memcpy(icmp + 8, bad, quote);
    put16(icmp + 2, s419_cksum(icmp, 8 + quote));

    s419_put_ip(out, (uint16_t)(S419_IP_HLEN + 8 + quote), ipid, par->icmp_df,
                par->ttl, IP_PROTO_ICMP, src_nbo, dst_nbo);
    return S419_IP_HLEN + 8 + quote;
}

static uint16_t udp_cksum(const uint8_t *ip, const uint8_t *uh, size_t udp_len)
{
    /* pseudo header: src, dst, zero+proto, udp length */
    uint32_t sum = 0;
    const uint8_t *p;
    size_t len;

    for (p = ip + 12, len = 8; len > 1; p += 2, len -= 2) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
    }
    sum += IP_PROTO_UDP;
    sum += (uint16_t)udp_len;

    for (p = uh, len = udp_len; len > 1; p += 2, len -= 2) {
        sum += (uint16_t)((p[0] << 8) | p[1]);
    }
    if (len) {
        sum += (uint16_t)(p[0] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t r = (uint16_t)~sum;
    return r ? r : 0xffff; /* RFC 768: a computed zero checksum is all-ones */
}

size_t s419_build_udp(uint8_t *out, const uint8_t *data, size_t data_len,
                      uint16_t ipid, uint32_t src_nbo, uint32_t dst_nbo,
                      uint16_t sport, uint16_t dport,
                      const mp_s419_params_t *par)
{
    uint8_t *uh = out + S419_IP_HLEN;
    size_t udp_len = 8 + data_len;
    put16(uh + 0, sport);
    put16(uh + 2, dport);
    put16(uh + 4, (uint16_t)udp_len);
    put16(uh + 6, 0);
    memcpy(uh + 8, data, data_len);

    /* DF off, counter IPID: plain Linux UDP output (ip_finish_output). */
    s419_put_ip(out, (uint16_t)(S419_IP_HLEN + udp_len), ipid, false,
                par->ttl, IP_PROTO_UDP, src_nbo, dst_nbo);
    put16(uh + 6, udp_cksum(out, uh, udp_len));
    return S419_IP_HLEN + udp_len;
}
