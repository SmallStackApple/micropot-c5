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

    put16(tcp + 0, sport_nbo); /* ports are host order like the addresses */
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
    if (payload_len) {
        memcpy(tcp + hdr_len, payload, payload_len);
    }

    /* The checksum covers the IP pseudo header, so it can only be computed
     * by the caller after s419_put_ip() filled the addresses. */
    return hdr_len + payload_len;
}

size_t s419_build_synack(uint8_t *out, const mp_s419_params_t *par,
                         uint32_t src_nbo, uint32_t dst_nbo,
                         uint16_t sport_nbo, uint16_t dport_nbo,
                         uint32_t seq, uint32_t ack, bool ece)
{
    /* tcp_options_write(), timestamps disabled, SACK + WSCALE on:
     *   word1: 02 04 mss          (MSS)
     *   word2: 01 01 04 02        (NOP NOP SACK_PERM)
     *   word3: 01 03 03 ws        (NOP WSCALE)
     * on the wire: M5B4 N N S N W6  ==  nmap OPS "M5B4NNSNW6". */
    uint8_t opts[12];
    size_t n = 0;
    opts[n++] = 0x02; opts[n++] = 0x04;
    opts[n++] = (uint8_t)(par->mss >> 8);
    opts[n++] = (uint8_t)par->mss;
    if (par->sack_perm) {
        opts[n++] = 0x01; opts[n++] = 0x01;
        opts[n++] = 0x04; opts[n++] = 0x02;
    } else {
        opts[n++] = 0x01; opts[n++] = 0x01;
        opts[n++] = 0x01; opts[n++] = 0x01;
    }
    opts[n++] = 0x01; opts[n++] = 0x03; opts[n++] = 0x03;
    opts[n++] = par->wscale;

    uint8_t flags = S419_SYN | S419_ACK | (ece ? S419_ECE : 0);
    size_t tcp_len = put_tcp(out, src_nbo, dst_nbo, sport_nbo, dport_nbo,
                             seq, ack, flags, par->rcv_wnd, opts, n, NULL, 0);
    s419_put_ip(out, (uint16_t)(S419_IP_HLEN + tcp_len),
                par->tcp_ipid_zero ? 0 : 1, par->tcp_df, par->ttl, IP_PROTO_TCP,
                src_nbo, dst_nbo);
    put16(out + S419_IP_HLEN + 16, tcp_cksum(out, out + S419_IP_HLEN, tcp_len));
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
    put16(out + S419_IP_HLEN + 16, tcp_cksum(out, out + S419_IP_HLEN, tcp_len));
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

    uint32_t src, dst;
    src = ((uint32_t)req[16] << 24) | ((uint32_t)req[17] << 16) |
          ((uint32_t)req[18] << 8) | req[19]; /* reply src = original dst */
    dst = ((uint32_t)req[12] << 24) | ((uint32_t)req[13] << 16) |
          ((uint32_t)req[14] << 8) | req[15];
    s419_put_ip(out, (uint16_t)(S419_IP_HLEN + icmp_len), ipid, par->icmp_df,
                par->ttl, IP_PROTO_ICMP, src, dst);
    return S419_IP_HLEN + icmp_len;
}

size_t s419_build_icmp_unreach(uint8_t *out, const uint8_t *bad,
                               size_t bad_len, uint16_t ipid,
                               uint32_t src_nbo, uint32_t dst_nbo,
                               const mp_s419_params_t *par)
{
    /* icmp_send(): quote the original IP header and 8 bytes of its data. */
    size_t quote = bad_len;
    if (quote > S419_IP_HLEN + 8) {
        quote = S419_IP_HLEN + 8;
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
