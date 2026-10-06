#pragma once

#include <stdbool.h>

#include "esp_err.h"

struct netif;
struct pbuf;

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Virtual interface glue: makes alias vdev addresses reachable on the wire.
 *
 *  - ARP: lwIP's etharp only answers who-has for the primary address, so we
 *    wrap netif->input and answer alias requests ourselves (replies are
 *    built in tcpip-thread context via tcpip_callback).
 *  - IP: esp-lwip drops alias-destined packets as "not for us" before raw
 *    PCBs run, so LWIP_HOOK_IP4_INPUT (injected via ESP_IDF_LWIP_HOOK_FILENAME
 *    -> mp_lwip_hooks.h) diverts them into the registered engine feed.
 * ---------------------------------------------------------------------- */

/** Engine feed for alias-destined IPv4 packets (tcpip thread, core locked;
 *  p->payload is the IPv4 header). Returns true when the packet was
 *  consumed — ownership transfers, exactly like an eaten raw-PCB packet. */
typedef bool (*mp_vif_ip4_feed_fn)(struct pbuf *p);
void mp_vif_set_ip4_feed(mp_vif_ip4_feed_fn fn);

/** Wrap the netif input path with the alias ARP responder. Call once after
 *  the netif exists (mp_net_init). */
esp_err_t mp_vif_install(struct netif *netif);

/* Invoked by lwIP through LWIP_HOOK_IP4_INPUT; not for direct use. */
int mp_vif_ip4_input_hook(struct pbuf *p, struct netif *inp);

#ifdef __cplusplus
}
#endif
