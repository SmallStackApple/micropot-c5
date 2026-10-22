# MicroPot-C5

Phase 1 of a resource-constrained, multi-virtual-device honeypot running on an
ESP32-C5 (module N16R8: 16 MB flash + 8 MB PSRAM). All experiments run only on
an isolated lab network.

Phase 1 delivers a single device IP hosting concurrent brand-driven honeypot
services (Telnet + HTTP + banner-level SSH) with structured JSON event logging
to a PC collector. The architecture is protocol- and brand-agnostic: adding a
new protocol or a new brand is a pure add-on — no edits to shared code.

> **Documentation**
> - [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — component layering, transport & event model
> - [`docs/MEMORY.md`](docs/MEMORY.md) — HP SRAM/PSRAM/flash budget and allocation policy
> - [`docs/ROADMAP.md`](docs/ROADMAP.md) — phase 1 → phase 2 (multi virtual device)
> - [`docs/EXTENDING.md`](docs/EXTENDING.md) — adding a brand / protocol / persona

## Architecture

```
                       +-------------------------------+
  persona (instance)   |            mp_core            |
       +-------------> |  service registry             |
                       |  brand registry (open, keyed  |
                       |    by protocol name)          |
                       |  mp_xport: transport backends |
                       |  + global session budget      |
                       +-------------------------------+
                              ^              ^
             brand-agnostic   |              |   brand modules (data + hooks)
       +----------------------+              +---------------------+
       |                 |                    |                     |
  mp_telnet        mp_http_ui           mp_brand_hikvision / _router / _printer
  mp_ftpd          mp_apache            mp_brand_linux419 (+fs, +host keys)
                   mp_ssh_banner
                   mp_ssh_server
       |
       |  mp_stack419: Linux 4.19 wire behaviour (raw-PCB TCP/IP:
       |  ISN/options/resets/ICMP per v4.19 sources; "s419" backend)
       v
  mp_log: generic event bus (mp_evt_*) --UDP/TCP--> log_collector.py

  mp_linekit: line/echo/IAC toolkit shared by text protocols
  mp_linuxfs/mp_linuxsh: fake filesystem + bash-flavoured shell
```

Two invariants keep the system extensible:

- **Services are brand-agnostic interpreters.** Vendor bytes live only in
  brand tables. `mp_brand.h` names no protocol; brands publish behaviours in
  an open `{"proto", behavior}` table and services look theirs up with
  `mp_brand_behavior(brand, "telnet")`.
- **The event bus is protocol-agnostic.** Services emit events via
  `mp_evt_begin/str/int/bool/send`; `mp_log` knows no event names.

Services never touch sockets: they run on `mp_xport` connections. The default
backend is lwIP (the vendor brands); the `linux-419` persona switches to the
`s419` backend, where every packet is crafted by the stack419 engine instead
of lwIP's TCP (see below).

### Component layout

| Path | Responsibility |
|------|----------------|
| `components/mp_core` | service registry, `mp_xport` transport abstraction + lwIP backend, global session budget, persona & brand registries |
| `components/mp_stack419` | Linux 4.19 TCP/IP behaviour engine: raw-PCB intercept, ISN per `secure_tcp_sequence_number`, SYN-ACK options per `tcp_options_write`, closed-port resets, ICMP, mini TCP session machine, `s419` xport backend |
| `components/mp_log` | generic event bus: builder (`mp_evt`), FreeRTOS queue, UDP/TCP transport |
| `components/mp_net` | WiFi STA (+ reconnect backoff), optional static IP, MAC spoofing |
| `components/mp_linekit` | line reader (echo/backspace/IAC), send helpers, canned-command lookup |
| `components/mp_linuxfs` | fake filesystem primitives (static tree, lookup, path normalisation) |
| `components/mp_linuxsh` | bash-flavoured shell: real cwd, fs commands, live ifconfig/ip/route, wget/curl URL harvest |
| `components/mp_telnet` | Telnet honeypot interpreter (canned or shell-hook driven) |
| `components/mp_http_ui` | HTTP management-page honeypot (`esp_http_server`, lwIP brands) |
| `components/mp_apache` | Apache/2.4.38-style HTTP server on mp_xport |
| `components/mp_ssh_banner` | banner-level SSH honeypot (client-banner harvester) |
| `components/mp_ssh_server` | real SSH-2.0 transport (wolfSSH), OpenSSH 7.9p1 identity, password capture + shell |
| `components/mp_ftpd` | vsftpd 3.0.3-style FTP honeypot, read-only fs, PASV pool |
| `components/brands/mp_brand_*` | HIKVISION camera / TP-LINK router / HP printer / Linux 4.19 server behaviour tables (+ file tree, SSH host keys) |
| `main` | Kconfig + boot sequence |
| `tools` | PC-side collector, management CLI + web UI, mock attacker, golden regression check |
| `test/host` | host unit tests for the pure sources (no hardware needed) |

## Prerequisites

ESP-IDF **v6.1** (locked). On this machine it has a dedicated activation script:

```sh
source /home/xiaoboluo/.espressif/tools/activate_idf_v6.1.sh
```

## Build & flash

```sh
source /home/xiaoboluo/.espressif/tools/activate_idf_v6.1.sh
cd micropot-c5
idf.py set-target esp32c5     # first time only
idf.py build
idf.py -p /dev/ttyACM0 flash monitor
```

## Run it

1. Start the collector on the PC (same isolated LAN):

   ```sh
   python3 tools/log_collector.py --host 0.0.0.0 --port 9999 --proto both
   ```

2. Enter `idf.py menuconfig` → *MicroPot-C5 honeypot* and set:
   - WiFi SSID / password
   - collector IPv4 address (`Log host`) and port
   - active persona (camera / router / printer)

3. Flash. The serial log prints the obtained IP, e.g.
   `honeypot online at 192.168.1.100`.

4. Exercise it (watch events appear live):

   ```sh
   python3 tools/mock_client.py --host 192.168.1.100 --persona camera --mode all
   # or with real tools:
   nmap -sV -p 22,23,80 192.168.1.100
   ssh root@192.168.1.100        # banner harvested, then the line goes quiet
   ```

   Events are appended to `logs/micropot-YYYYMMDD.jsonl`.

## Event schema

One JSON object per line:

```json
{"v":1,"ts":123456,"boot":7,"seq":1042,"sid":33,"evt":"telnet.login_attempt",
 "proto":"telnet","persona":"ipcam-01",
 "sip":"192.168.1.66","sport":51023,"dip":"192.168.1.100","dport":23,
 "data":{"user":"admin","pass":"12345","result":"fail","attempt":1}}
```

`ts` is milliseconds since boot; `boot` increments in NVS every boot; `sid` is
a per-session id so connect/login/command/disconnect events of one attacker
session can be correlated (UDP pseudo-sessions keyed by peer are prepared for
phase 2).

Event types: `net.up`, `svc`, `svc.overload`, `telnet.connect`,
`telnet.login_attempt`, `telnet.command`, `telnet.disconnect`, `http.request`,
`http.login_attempt`, `http.notfound`, `ssh.connect`, `ssh.banner`,
`ssh.disconnect`, `log.dropped`.

Notable `data` fields: `telnet.disconnect.reason` is one of `logout`,
`reboot`, `timeout`, `closed`, `auth_failed`, `send_error`; `ssh.banner.client`
holds the attacker's own version string (scanner fingerprint);
`svc.overload` fires when the global session budget
(`CONFIG_MICROPOT_MAX_SESSIONS`) is exhausted under a flood.

## Honeypot behaviours worth knowing

- **Telnet echo**: the server negotiates WILL ECHO and echoes input busybox
  style — username and shell commands visible, passwords not.
- **`reboot` sells**: `reboot`/`shutdown` replies with the brand's canned
  message, lingers ~1 s, then drops the session (`reason:"reboot"`).
- **Consistent identity**: the spoofed station MAC (vendor OUI + eFuse tail)
  is the same address that `ifconfig` reports in the shell — ARP table and
  application layer tell one story.
- **Brand-coherent HTTP**: `Server` header *and* the 404 page's address line
  both come from the active brand.
- **Flood safety**: all TCP listeners share one session budget; excess
  connections are accepted and closed immediately (`svc.overload`), and the
  log transport uses bounded connect/send timeouts so a dead collector can
  never stall the honeypot. No code path logs per packet from the tcpip
  thread (a blocking UART write there starves the idle task and trips the
  task watchdog), and the events-to-console echo is **off by default**
  (`CONFIG_MICROPOT_LOG_CONSOLE`); the collector is the event sink. Turn the
  echo on in `menuconfig` only when actively developing, not while flood
  testing.

## Configuration

Two layers:

- **Build time** (`menuconfig`, `main/Kconfig.projbuild`): WiFi defaults,
  static IP, service-port defaults, session budget ceiling, primary persona,
  vdev alias defaults, management-plane defaults, log transport defaults.
  Build-time defaults are in `sdkconfig.defaults`.
- **Runtime** (`mp_cfg`, NVS namespace `mpc`, overrides win over Kconfig):
  managed remotely over the control channel or locally on the serial CLI.
  Every change is validated, persisted, and audited (`system.config` event).
  Keys marked `needs_reboot` (WiFi, ports, vdev table, mgmt address, log
  transport) apply after the `reboot` command; the rest are live.

| Live-immediate keys | Reboot-applied keys |
|---|---|
| `log.console`, `perf.int_s`, `perf.heap_kb` | `wifi.ssid`, `wifi.pass`, `net.mac`, `net.hostname` |
| `cred.root`, `cred.admin` (shadow re-hashes on change) | `persona` (primary persona id; empty = Kconfig) |
| `ctl.psk`, `ctl.admin` | `vdev1..7.ip/persona`, `mgmt.ip`, `ctl.port`, `log.host/port/tcp` |
| `ssh.preauth_max` (1–8, KEX concurrency gate) | `log.queue` (8–128 events), `log.ring` (SPIFFS spillover) |
| `sess.idle_s` (0=off; reaps parked connections) | `stack.tcbs` (16–256), `stack.synrecv` (8–128) |
| `probe.enabled` (**default off**), `probe.int_s` | `stack.rx_cap` (1–16 KiB), `stack.tx_cap` (4–64 KiB) |

## Memory & connection budget

Three independent pools; all tunables above, measured values from the
on-device perf event (`system.perf` / mgmt `status`):

| Pool | Holds | Cost model | Watch |
|---|---|---|---|
| **s419 TCBs** (PSRAM) | every honeypot + mgmt TCP connection | open TCB = `rx_cap + tx_cap` (default 20 KiB); TIME_WAIT drops its rings | `tcb_estab/syn_recv/time_wait`, `tcbs` |
| **wolfSSL/wolfSSH** | SSH KEX working set, channel buffers | tens of KiB per in-flight KEX; gated by `ssh.preauth_max` | `wolf_cur`, `wolf_peak` (exact, via the XMALLOC shim) |
| **internal SRAM** | lwIP (log socket ~12 KiB, DHCP, gw probe), task stacks, small wolf allocs | fixed-ish footprint | `heap_free`, `heap_min`, `lwip_tcp_pcb/pbuf` |

Rules of thumb:

- worst-case PSRAM ≈ `stack.tcbs` × (`stack.rx_cap` + `stack.tx_cap`);
  defaults 96 × 20 KiB ≈ 1.9 MiB of the 8 MiB
- `stack.rx_cap` shapes the advertised TCP window growth on the wire —
  it is part of the nmap fingerprint; change it only deliberately
- `sess.idle_s` (default 0 = off, like a real sshd) silently kills
  connections idle longer than N seconds and logs `session.reaped`
- the link probes (`probe.*`) are compiled-in but **silent by default**:
  periodic ICMP/ARP to the gateway is traffic no real host emits

## Management plane

The control service never shares a honeypot IP: it binds a **dedicated vdev
address** (`mgmt.ip`, no persona attached) and answers only signed requests
from `ctl.admin` (0.0.0.0 = PSK-only). To anyone else, that address is a
Linux host with every port closed and the control port filtered.

- **Channel**: UDP or TCP on `ctl.port` (default 55555), one request per
  datagram/line:
  `id=1 ts=1730000000 cmd=set k=log.port v=514 mac=<hmac-sha256>`
  (HMAC key = `ctl.psk`, message = everything before ` mac=`, monotonic
  `ts` per boot). JSON replies.
- **Client**: `python3 tools/micropotctl.py --host <mgmt-ip> --psk ... status`
  (`--tcp`, `--raw`; commands `ping status list get set unset reset
  log.stats log.test reboot`).
- **Serial CLI**: `micropot>` REPL on the UART with the same command set,
  no HMAC — the rescue path when the network is misconfigured.
- Default PSK `change-me` triggers a `system.config_warn` event at boot.

### Management web UI

`tools/micropot_web.py` is a zero-dependency (stdlib-only) multi-device
dashboard that speaks the same signed control protocol and tails the
collector's JSONL logs:

```sh
cp tools/devices.example.json tools/devices.json   # edit hosts + PSKs
python3 tools/log_collector.py --host 0.0.0.0 --port 9999 &   # event source
python3 tools/micropot_web.py                      # http://127.0.0.1:8080
```

- per-device status (uptime / heap / sessions / TCBs / log drops),
  JSONL event viewer with live tail and filters, runtime config editor with
  per-key explanations and sensitive-key warnings, `log.test` / `reset` /
  `reboot` with tiered confirmations;
- `devices.json` is git-ignored; a PSK written as `"${ENV_VAR}"` is read
  from the environment instead of being stored in plaintext;
- binds `127.0.0.1` by default. Use `--bind 0.0.0.0 --token <secret>`
  (or env `MICROPOT_WEB_TOKEN`) if it must be reachable from the LAN.

## Multi virtual devices

One station MAC, up to 8 virtual devices (IP aliasing — 802.11 cannot source
a second MAC): the primary address plus alias vdevs and the management
address. `mp_vif` answers ARP for aliases (netif input wrapper) and diverts
alias-destined IP traffic into the wire engine via esp-lwip's
`LWIP_HOOK_IP4_INPUT` before lwIP drops it as not-for-us. Listeners match
(vaddr, port) with the wildcard bound to the primary. Persona (L7 identity)
and wire profile (L3/L4 behaviour, `mp_wprof`) are separate axes a vdev
binds freely; mixing brand vendors on one MAC logs a narrative-coherence
warning at boot.

## L2 identity: MAC & DHCP hostname spoofing

Each brand declares a vendor OUI in `mp_brand_meta_t.mac_oui`. At boot,
`mp_net_init()` builds the station MAC from that OUI plus the unique tail of
the chip's factory eFuse MAC (so every board stays distinct on the wire) and
calls `esp_wifi_set_mac()` while the interface is still disabled. The DHCP
hostname comes from `mp_persona_t.hostname` via `esp_netif_set_hostname()`.
Both are runtime-overridable: `net.mac` (full `aa:bb:cc:dd:ee:ff`, wins over
the OUI path) and `net.hostname`.

| Brand | Vendor OUI | nmap prefix lookup | Hostname |
|-------|-----------|--------------------|----------|
| `hikvision_ipcam` | `44:19:B6` | Hangzhou Hikvision | IPCAM-01 |
| `tplink_router`   | `00:1D:0F` | TP-Link Technologies | TP-LINK_WR841N |
| `hp_printer`      | `00:01:E6` | Hewlett Packard | HP-LaserJet-M428 |
| `linux_419`       | `00:E0:4C` | Realtek | linux |

To advertise a different vendor, just edit the brand's `mac_oui` (the first
byte must have bit 0 clear, i.e. an even first octet). Other examples:
`00:00:48` Seiko Epson, `00:00:85` Canon, `00:00:39` Toshiba, `00:00:01` Xerox.

> Only use this on your own isolated lab network.

## Linux 4.19 simulation persona

The `linux-419` persona (brand `linux_419`, hostname `linux`) simulates a
plain, distro-neutral x86_64 Linux 4.19 server end to end — wire, services
and shell. Select it in `menuconfig` → *MicroPot-C5 honeypot* →
*Device persona* → *Generic Linux 4.19 server*.

**TCP/IP wire behaviour (`mp_stack419`).** lwIP raw PCBs intercept inbound
TCP/UDP/ICMP ahead of lwIP's own stack; every reply is built complete (IP
header included) and emitted verbatim through an IP_HDRINCL PCB, modelled on
the v4.19 kernel sources (`~/linux`, tag `v4.19`):

- ISN per `secure_tcp_sequence_number` (SipHash-2-4 over the 4-tuple +
  64 ns clock), SYN-ACK option layout per `tcp_options_write`
  (`MSS|NNS|NW` → nmap `M5B4NNSNW6`), LISTEN-state probe handling per
  `tcp_rcv_state_process` (nmap T2/T3 drop, T4 RST), closed-port resets per
  `tcp_v4_send_reset` (T5–T7), ICMP echo / port-unreachable per `icmp.c`
  (IE/U1) — targeting the generic `Fingerprint Linux 4.19` nmap-os-db
  record (no distro). Timestamps disabled (`TS=U`), TCP IP-ID 0,
  window 64240 (`FAF0`), TTL 64, DF set.
- A mini TCP session machine (handshake, seq/ack, delayed ACK, RTO
  retransmit, FIN/RST, TIME_WAIT) carries real sessions, so services run
  unchanged on top through the `s419` mp_xport backend. lwIP keeps ARP and
  the honeypot's own outbound log traffic.

**Services.** All four run on the 4.19 stack:

- **telnet** → bash-flavoured shell (`mp_linuxsh`) over the fake filesystem:
  real cwd, `ls/cd/cat/grep` from the tree, live `ifconfig/ip/route` from
  the device's actual IP/MAC, `ps/df/free/ss/netstat` canned, `wget/curl`
  harvest payload URLs as `telnet.download` events.
- **httpd** → Apache/2.4.38 style (`~/httpd` tag `2.4.38`): upstream default
  *It works!* index, exact error documents and `<address>` signature,
  keep-alive, 400 on missing Host, 405 on POST/TRACE to static content.
- **sshd** → real SSH-2.0 transport (wolfSSH): `SSH-2.0-OpenSSH_7.9p1`,
  KEXINIT trimmed from `V_7_9_P1:myproposal.h`, stable RSA-2048 + ECDSA
  P-256 host keys, password attempts as `ssh.auth_attempt`; valid creds get
  the same shell over the encrypted channel (`ssh.command` events).
- **ftpd** → vsftpd 3.0.3 (`~/vsftpd-3.0.3`): `220 (vsFTPd 3.0.3)`, FEAT/
  SYST/HELP texts from source, read-only RETR/LIST from the fake fs, PASV
  data channels, `ftp.login_attempt` / `ftp.download` events, 421 past
  `max_clients` (CVE-2021-30047's connection-limit signature, no crash).

**Fake filesystem** (`linux419_fs.c`): distro-neutral tree — `/etc/passwd`,
`/etc/shadow` (root-readable hashes), `/etc/ssh/sshd_config`, `/proc/*`,
`/var/log/auth.log` with plausible brute-force traces, `/root/.bash_history`.
The reserved `storage` partition stays free for a phase-2 writable overlay
(attacker uploads, persistence), to be mounted with LittleFS behind the
`mpfs_overlay_*` interface.

### Validation (real pentest tools, from the LAN)

```sh
ip=<device-ip>
nmap -O --osscan-guess $ip          # expect: Linux 4.19 guesses
nmap -sV -p21,22,23,80 $ip          # vsftpd 3.0.3 / OpenSSH 7.9p1 / Apache 2.4.38
nmap --script ssh2-enum-algos -p22 $ip
ssh root@$ip                        # password: toor (see brand creds)
hydra -l root -P wordlist.txt ssh://$ip
lftp -u root,toor $ip -e "ls /etc; get /etc/passwd; bye"
curl -i http://$ip/nonexistent      # Apache-style 404 + Server header
```
## Testing & regression

```sh
# host unit tests (event builder, form parser, line reader incl. echo/IAC)
make -C test/host

# golden behaviour check (needs the hardware): capture a baseline with the
# old firmware, re-run with the new one, diff the event streams
python3 tools/log_collector.py --out logs/baseline &     # old firmware
python3 tools/mock_client.py --host <ip> --persona camera --mode all
python3 tools/log_collector.py --out logs/candidate &    # new firmware
python3 tools/mock_client.py --host <ip> --persona camera --mode all
python3 tools/golden_check.py logs/baseline/micropot-*.jsonl \
                              logs/candidate/micropot-*.jsonl --ignore sid
```

## Extending

- **New brand**: add `components/brands/mp_brand_xxx/` with a `behaviors[]`
  table (+ `www/` pages), add it to `main`'s `REQUIRES` and register it in
  `register_all()`.
- **New protocol**: copy `components/mp_ssh_banner/` as the template — define a
  behaviour struct in the component's own header, interpret it from brand
  data, emit events via `mp_evt_*`, register in `main` with one line. Text
  protocols should build on `mp_linekit`. No core/header edits needed.
- **New wire personality**: add a parameter block + `mp_wprof_t` next to the
  engine (see `mp_wprof_linux419`) and register one line in `register_all()`;
  personas bind it by id, per vdev.
- **New config knob**: register an `mp_cfg_key_t` in the owning component;
  it becomes reachable from mp_ctl and the serial CLI for free, with
  validation, persistence, audit and an optional `on_change` hook.

### Known limitations

- All vdevs share one MAC (802.11 infrastructure constraint; IP aliasing is
  the real-world look). Mixing brand vendors across vdevs is warned about at
  boot (`system.config_warn`) but not forbidden.
- Alias vdevs must use a packet-engine wire profile (stack419); lwIP-socket
  services (`mp_http_ui`) only serve the primary address. The ftpd PASV pool
  is shared and wildcard-bound.
- Remote changes marked `needs_reboot` are stored but applied on restart —
  the engines have no listener teardown, and a clean reboot beats a
  half-rebound listener table.
- The persona clock is a fixed base plus uptime (HTTP `Date`, shell `date`):
  the box simply looks like its RTC drifted.
- The fake filesystem is read-only; uploads/uploads-via-shell are faked
  (backlog: writable overlay). FTP PASV uses a fixed 4-port pool
  (40021–40024) instead of kernel ephemeral ports.
- UDP log transport cannot detect a silently dead collector; use
  `log.tcp=true` when the SPIFFS ring spillover must guarantee coverage.
