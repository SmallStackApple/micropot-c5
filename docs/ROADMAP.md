# Roadmap

## Phase 1 — single virtual device (done)

Single device IP hosting concurrent, brand-driven honeypot services
(Telnet + HTTP + banner SSH + vsftpd/Apache/OpenSSH for the Linux persona)
with structured JSON event logging to a PC collector. The architecture is
protocol- and brand-agnostic: adding a protocol or brand is a pure add-on.

## Phase 2 — multi virtual device (in progress)

One ESP32 hosts several personas at once, each owning a virtual IPv4 address
on the same NIC, each with its own brand, services and filesystem overlay.

### Groundwork already landed

These are additive: the default single-persona, single-IP behaviour is
unchanged.

- **Per-session persona in events.** `mp_session_t.persona` is stamped by the
  transport from `mp_listener_cfg_t.persona` and copied into each `mp_evt_t`
  by `mp_evt_begin`; the logger prefers it over the global
  `mp_log_set_persona()` value. Services set it from `svc->persona`.
- **Persona lookups.** `mp_persona_by_vaddr()` indexes the persona table by
  `bind.vaddr`; `mp_persona_set_active()` lets the active persona be chosen
  at runtime instead of by the Kconfig choice.
- **Filesystem write interface.** `mpfs_overlay_init/write/remove()` exist as
  documented stubs (`ESP_ERR_NOT_SUPPORTED`) so services can be written
  against them before the LittleFS backing lands.

### Remaining work

- **Multi virtual IP.** Assign one non-zero `bind.vaddr` per persona (and
  give each ICMP/DHCP-less alias to the netif), then generalise
  `mp_registry` from "global service singletons" to "(persona, bind)
  instances" — every service currently owns one static listener, so a real
  second instance needs per-instance service state. Prerequisite spike:
  confirm lwIP/`esp_netif` carries multiple IPv4 addresses on one netif.
- **HTTP on `mp_xport`.** `esp_http_server` binds `INADDR_ANY` and cannot
  serve per-IP. The Apache-style server (`mp_apache`) already runs on
  `mp_xport` and binds a specific `vaddr`; phase 2 unifies HTTP there and
  drops the `esp_http_server` path. (Deferred: it would remove the vendor
  brand login pages shipped in phase 1.)
- **Writable filesystem overlay.** Turn the `mpfs_overlay_*` stubs into a
  **LittleFS** mount of the `storage` partition; make `mpfs_lookup()` /
  `mpfs_children()` consult the overlay first. Wire into the shell
  (`wget -O`, redirections) and FTP (`STOR`/`MKD`/`DELE`).
- **UDP services.** `mp_udp_listener` is ready (pseudo-sessions, PSRAM
  task); add the first brand UDP behaviours (DNS / SNMP / SSDP) and start
  them from the service registry.
- **Runtime persona selection.** `mp_persona_set_active()` is the hook; add
  a small `mp_config` layer that loads the persona set from NVS/JSON.
- **Hardware validation.** The refactor and memory changes were verified by
  build + host tests only; re-run the golden event-stream check, an nmap
  `-O`/`-sV` pass and a hydra/flood pass on the board.

## Later phases (sketch)

- Attacker-uploaded artefacts and persistence simulation on the overlay.
- More brands/protocols per persona; per-persona clock drift.
- PC-side correlation/analysis tooling over the JSONL event stream.
