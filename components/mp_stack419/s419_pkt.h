#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mp_s419_params.h"

/* -------------------------------------------------------------------------
 * Packet crafting helpers — pure functions, no lwIP dependency, so the
 * byte layouts stay auditable against the 4.19 sources they mirror.
 *
 * All builders write a complete IPv4 packet (header + payload) into @p out
 * and return its total length.
 * ---------------------------------------------------------------------- */

#define S419_IP_HLEN   20
#define S419_TCP_HLEN  20

/* TCP flags */
#define S419_FIN 0x01
#define S419_SYN 0x02
#define S419_RST 0x04
#define S419_PSH 0x08
#define S419_ACK 0x10
#define S419_URG 0x20
#define S419_ECE 0x40
#define S419_CWR 0x80

/** RFC 1071 internet checksum. */
uint16_t s419_cksum(const void *data, size_t len);

/** (Re)compute the TCP checksum field of a built IPv4 packet. */
void     s419_tcp_set_cksum(uint8_t *pkt, size_t tcp_len);

/** Fill the 20-byte IPv4 header (checksum included). */
void s419_put_ip(uint8_t *out, uint16_t total_len, uint16_t id, bool df,
                 uint8_t ttl, uint8_t proto,
                 uint32_t src_nbo, uint32_t dst_nbo);

/**
 * SYN-ACK with the 4.19 tcp_options_write() layout (net/ipv4/tcp_output.c):
 * SACK-permitted and WScale blocks are emitted only when the SYN offered
 * them (timestamps are never emitted — the persona targets TS=U):
 *   both offered : MSS | NOP NOP SACK_PERM | NOP WSCALE   ("MxxxxNNSNWx")
 *   WS only      : MSS | NOP WSCALE                       ("MxxxxNWx")
 *   SACK only    : MSS | NOP NOP SACK_PERM                ("MxxxxNNS")
 * When @p ece, the ECE flag is set (Linux answers an ECN-requesting SYN
 * with ECE in the SYN-ACK — nmap ECN test CC=Y).
 *
 * @return full packet length.
 */
size_t s419_build_synack(uint8_t *out, const mp_s419_params_t *par,
                         uint32_t src_nbo, uint32_t dst_nbo,
                         uint16_t sport_nbo, uint16_t dport_nbo,
                         uint32_t seq, uint32_t ack, bool ece,
                         bool sack_offered, bool ws_offered);

/**
 * Generic TCP segment without options (data, ACK, RST, FIN).
 * @return full packet length.
 */
size_t s419_build_tcp(uint8_t *out, const mp_s419_params_t *par,
                      uint32_t src_nbo, uint32_t dst_nbo,
                      uint16_t sport_nbo, uint16_t dport_nbo,
                      uint32_t seq, uint32_t ack, uint8_t flags,
                      uint16_t wnd, const void *payload, size_t payload_len);

/**
 * ICMP echo reply for the request in @p req (full IPv4 packet).
 * Payload is preserved, identifier/sequence untouched, IP ID comes from
 * @p ipid (Linux answers from an incrementing counter — nmap II=I).
 * @return full packet length.
 */
size_t s419_build_icmp_echo_reply(uint8_t *out, const uint8_t *req,
                                  size_t req_len, uint16_t ipid,
                                  const mp_s419_params_t *par);

/**
 * ICMP destination-port-unreachable for the offending datagram in @p bad
 * (RFC 792: quote the original IP header + 8 bytes). Linux sends this for
 * UDP to a closed port (nmap U1 test: DF=N, RIPL/RID/RIPCK/RUD = G).
 * @return full packet length.
 */
size_t s419_build_icmp_unreach(uint8_t *out, const uint8_t *bad,
                               size_t bad_len, uint16_t ipid,
                               uint32_t src_nbo, uint32_t dst_nbo,
                               const mp_s419_params_t *par);
