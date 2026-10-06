# MicroPot-C5 architecture

MicroPot-C5 is a resource-constrained, multi-virtual-device honeypot for the
ESP32-C5 (module N16R8: 16 MB flash + 8 MB PSRAM). It emulates a set of
plausible devices on an isolated lab network, each exposing brand-coherent
network services and emitting structured JSON events to a PC collector.

This document describes the internal layering. For build/run instructions
see the top-level [`README.md`](../README.md); for extending with new brands
or protocols see [`EXTENDING.md`](EXTENDING.md).

## Layering

```
                    +-------------------------------------+
   persona          |              mp_core                |
   (instance)  ---> |  service registry                   |
                    |  brand registry (open, keyed by     |
                    |    protocol name)                   |
                    |  mp_xport: transport backends        |
                    |  global session budget               |
                    +-------------------------------------+
                          ^                  ^
        brand-agnostic    |                  |  brand modules (data + hooks)
   +----------------------+                  +--------------------------+
   |        |        |         |                                     |
mp_telnet mp_http_ui mp_ssh_banner mp_apache mp_ssh_server mp_ftpd
                                                    mp_brand_hikvision
                                                    mp_brand_router
                                                    mp_brand_printer
                                                    mp_brand_linux419
                                                    (+ fs + host keys)
   mp_stack419: Linux 4.19 wire behaviour (raw-PCB TCP/IP)
       ^
       |
   mp_log: generic event bus --UDP/TCP--> tools/log_collector.py
```

Two invariants keep the system extensible:

- **Services are brand-agnostic interpreters.** Vendor bytes live only in
  brand tables. `mp_brand.h` names no protocol; brands publish behaviours in
  an open `{"proto", behavior}` table and services look theirs up with
  `mp_brand_behavior(brand, "telnet")`.
- **The event bus is protocol-agnostic.** Services emit events via
  `mp_evt_begin/str/int/bool/send`; `mp_log` knows no event names.

## Components

| Path | Responsibility |
|------|----------------|
| `components/mp_core` | service registry, `mp_xport` transport abstraction + lwIP backend, global session budget, persona & brand registries, UDP listener |
| `components/mp_stack419` | Linux 4.19 TCP/IP behaviour engine: raw-PCB intercept, ISN/options/resets/ICMP per v4.19 sources, mini TCP session machine, `s419` xport backend |
| `components/mp_log` | generic event bus: builder (`mp_evt`), FreeRTOS queue, UDP/TCP transport, NVS boot counter |
| `components/mp_net` | WiFi STA (+ reconnect backoff), optional static IP, MAC/hostname spoofing |
| `components/mp_linekit` | line reader (echo/backspace/IAC), send helpers, canned-command lookup |
| `components/mp_linuxfs` | fake filesystem primitives (static tree, lookup, path normalisation) |
| `components/mp_linuxsh` | bash-flavoured shell: real cwd, fs commands, live ifconfig/ip/route, wget/curl URL harvest |
| `components/mp_telnet` | Telnet honeypot interpreter (canned or shell-hook driven) |
| `components/mp_http_ui` | HTTP management-page honeypot for the vendor brands (`esp_http_server`/lwIP) |
| `components/mp_apache` | Apache/2.4.38-style HTTP server on `mp_xport` |
| `components/mp_ssh_banner` | banner-level SSH honeypot (client-banner harvester) |
| `components/mp_ssh_server` | real SSH-2.0 transport (wolfSSH), OpenSSH 7.9p1 identity, password capture + shell |
| `components/mp_ftpd` | vsftpd 3.0.3-style FTP honeypot, read-only fs, PASV pool |
| `components/brands/mp_brand_*` | vendor behaviour tables (HIKVISION camera / TP-LINK router / HP printer / Linux 4.19 server) + fake trees + SSH host keys |
| `main` | Kconfig + boot sequence |
| `tools` | PC-side collector, mock attacker, golden regression check, key generation |
| `test/host` | host unit tests for the pure sources (no hardware needed) |

## Transport abstraction (`mp_xport`)

Services never touch sockets. A connection is an opaque `mp_conn_t` with
`recv`/`send`/`shutdown`/`release` ops; listeners are registered through the
active backend. Two backends exist:

- **`lwip`** (default): BSD sockets on lwIP. Used by the vendor brands and
  the logger's own collector traffic.
- **`s419`**: the Linux-4.19 wire engine. Used by the `linux-419` persona so
  that nmap `-O` sees a genuine 4.19 fingerprint.

Every backend draws from one global session budget
(`CONFIG_MICROPOT_MAX_SESSIONS`), so a flood cannot exhaust heap regardless
of which stack carries the connection. Excess connections are accepted and
closed immediately and reported as `svc.overload`.

## Event model

One JSON object per line, framed with `\n`. The logger task stamps `ts`/`seq`
and wraps the `mp_evt_t` payload:

```json
{"v":1,"ts":123456,"boot":7,"seq":1042,"sid":33,"evt":"telnet.login_attempt",
 "proto":"telnet","persona":"ipcam-01",
 "sip":"192.168.1.66","sport":51023,"dip":"192.168.1.100","dport":23,
 "data":{"user":"admin","pass":"12345","result":"fail","attempt":1}}
```

`sid` correlates the connect/login/command/disconnect events of one attacker
session. `persona` comes from the session (stamped by the transport from the
listener config); system events fall back to the global value set by
`mp_log_set_persona()`. Phase 1 has one persona so the value is uniform; phase
2 gives each virtual IP its own (see [`ROADMAP.md`](ROADMAP.md)). Event names
and notable `data` fields are listed in the top-level README.

## Boot sequence (`main/micropot_main.c`)

1. `nvs_flash_init()`.
2. Resolve persona (Kconfig) and brand (registry); apply brand OUI/hostname.
3. `mp_net_init()` — bring up WiFi before any socket exists.
4. `mp_log_init()` — boot counter, queue, logger task.
5. If the persona's transport is `s419`, initialise `mp_stack419` from the
   brand's `stack419` behaviour blob and select the backend.
6. Register services, wait for an IP, start them, emit `net.up`/`svc`.
7. Spawn the passive `stats_task` (heap/PSRAM/sessions/RSSI health line).
