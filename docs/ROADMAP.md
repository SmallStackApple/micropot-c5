# Roadmap

## Phase 1 — single virtual device (done)

Single device IP hosting concurrent, brand-driven honeypot services
(Telnet + HTTP + banner SSH + vsftpd/Apache/OpenSSH for the Linux persona)
with structured JSON event logging to a PC collector. The architecture is
protocol- and brand-agnostic: adding a protocol or brand is a pure add-on.

## Phase 2 — multi virtual device (in progress)

One ESP32 hosts several personas at once, each owning a virtual IPv4 address
on the same NIC, each with its own brand, services and filesystem overlay.

Work items:

- **Multi virtual IP.** Extend the persona table to one entry per
  `bind.vaddr`, add `mp_persona_by_vaddr()`, and generalise `mp_registry`
  from "global service singletons" to "(persona, bind) instances".
  Prerequisite spike: confirm lwIP/`esp_netif` can carry multiple IPv4
  addresses on one netif.
- **HTTP on `mp_xport`.** `esp_http_server` binds `INADDR_ANY` and cannot
  serve per-IP. The Apache-style server (`mp_apache`) already runs on
  `mp_xport` and binds a specific `vaddr`; phase 2 unifies HTTP there and
  drops the `esp_http_server` path.
- **Per-session persona.** Add persona to `mp_session_t` and stamp it in
  `mp_evt_begin`, replacing the global persona string in `mp_log`.
- **Writable filesystem overlay.** Add write primitives to `mp_linuxfs`
  (create/write/unlink) backed by a **LittleFS** mount of the `storage`
  partition; the read-only brand tree stays the fallback. Wire into the
  shell (`wget -O`, redirections) and FTP (`STOR`/`MKD`/`DELE`).
- **UDP services.** Wire `mp_udp_listener` into the registry/boot path and
  add the first brand UDP behaviours (DNS / SNMP / SSDP).
- **Runtime persona selection.** Load the persona set from NVS/JSON via a
  small `mp_config` layer; Kconfig becomes the default-only source.

## Later phases (sketch)

- Attacker-uploaded artefacts and persistence simulation on the overlay.
- More brands/protocols per persona; per-persona clock drift.
- PC-side correlation/analysis tooling over the JSONL event stream.
