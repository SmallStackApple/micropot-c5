#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Bring up the WiFi station interface.
 *
 * @param mac_oui   3-byte vendor OUI to spoof, or NULL to keep the factory MAC.
 *                  The last 3 bytes are taken from the eFuse factory MAC so
 *                  every board stays unique on the network.
 * @param hostname  DHCP hostname advertised to the AP, or NULL.
 *
 * SSID/credentials/static-IP come from Kconfig.
 */
esp_err_t mp_net_init(const uint8_t mac_oui[3], const char *hostname);

/** Block until an IP address is obtained, or @p timeout_ms elapses. */
esp_err_t mp_net_wait_connected(uint32_t timeout_ms);

/** Device IPv4 in network byte order (0 before connect). */
uint32_t mp_net_get_ip(void);

/** STA netif handle (lwIP), for ARP keepalives and link diagnostics. */
esp_netif_t *mp_net_netif(void);

/** Active station MAC (post-spoofing). Brands use this to keep canned
 *  command output (e.g. ifconfig HWaddr) consistent with the wire. */
void mp_net_get_mac(uint8_t out[6]);

/** Human readable device IPv4, e.g. "192.168.1.42". */
void mp_net_get_ip_str(char *buf, size_t len);

/** Human readable gateway IPv4. */
void mp_net_get_gw_str(char *buf, size_t len);

/** Human readable active station MAC, e.g. "00:01:E6:1A:2B:3C". */
void mp_net_get_mac_str(char *buf, size_t len);

#ifdef __cplusplus
}
#endif
