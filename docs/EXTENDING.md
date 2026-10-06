# Extending MicroPot-C5

The design goal is that a new brand or a new protocol is a pure add-on: no
edits to shared core code. This document is the checklist.

## Add a brand

1. Create `components/brands/mp_brand_xxx/` with the same shape as an
   existing one (`mp_brand_hikvision`, `mp_brand_router`, `mp_brand_printer`,
   `mp_brand_linux419`).
2. Implement `mp_brand_xxx.c`:
   - an `mp_brand_meta_t` with `id`, vendor/model/firmware strings, the DHCP
     `hostname` and a vendor `mac_oui` (first octet must be even);
   - one `mp_brand_behavior_entry_t` per protocol you emulate, in the open
     `{"proto", behavior}` table terminated by `{NULL, NULL}`;
   - an optional `init` hook (e.g. to install the fake fs or host keys).
3. Add the protocol behaviour structs your services define (e.g.
   `mp_telnet_behavior.h`); brand data lives here, not in the service.
4. List the component in `main/CMakeLists.txt` `REQUIRES` and register it in
   `select_brand()` in `main/micropot_main.c`.
5. Add a persona entry in `components/mp_core/mp_persona.c` (id, brand id,
   service list, hostname, optional `transport`).

## Add a protocol

1. Copy `components/mp_ssh_banner/` as the template.
2. Define a behaviour struct in the component's own header; the brand fills
   it in. Never name a vendor in `mp_core` or the service.
3. Interpret the brand data, drive the session over an `mp_conn_t`
   (`mp_conn_recv`/`mp_conn_send`), and emit events with
   `mp_evt_begin/str/int/bool/send`.
4. Register in `main/micropot_main.c` with one
   `mp_registry_register(mp_xxx_get_ops(), mp_bind_any(PORT))` line, and add
   the name to the persona's service list.
5. Text protocols should build on `mp_linekit`; UDP protocols on
   `mp_udp_listener` (pseudo-sessions included).

No `mp_core`/`mp_brand.h` edits are required.

## Add a persona / virtual IP (phase 2)

Services already carry `mp_bind_t {vaddr, port}` and personas carry a
`bind`. Give a persona a non-zero `vaddr`, register its services for that
address, and start them through the per-IP registry path. See
[`ROADMAP.md`](ROADMAP.md) for the multi-IP work items.

## Conventions

- Formatting: `.clang-format` (Linux braces, 4-space indent, 80 columns).
- Component names describe role, not vendor software: `mp_http_ui` (vendor
  management pages), `mp_apache` (Apache-style daemon), `mp_ssh_banner`
  (banner harvester), `mp_ssh_server` (real SSH transport).
- Event `proto`/service names are part of the wire schema: keep them stable
  when renaming components, and update `docs/` plus the README when the
  schema changes.
