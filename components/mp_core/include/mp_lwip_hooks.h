/* Injected into the lwIP build via ESP_IDF_LWIP_HOOK_FILENAME (see the root
 * CMakeLists.txt): routes alias-destined IPv4 packets to the vdev engine
 * before lwIP's not-for-us drop. Self-contained on purpose — this header is
 * compiled into lwIP itself. */
#ifndef MP_LWIP_HOOKS_H
#define MP_LWIP_HOOKS_H

struct pbuf;
struct netif;

int mp_vif_ip4_input_hook(struct pbuf *p, struct netif *inp);

#define LWIP_HOOK_IP4_INPUT mp_vif_ip4_input_hook

#endif /* MP_LWIP_HOOKS_H */
