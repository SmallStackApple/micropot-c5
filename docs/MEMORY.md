# Memory budget & policy

The ESP32-C5 (N16R8) has **320 KB HP SRAM**, **8 MB PSRAM** and **16 MB
flash**. HP SRAM is the scarce resource: every task stack, the FreeRTOS
objects, lwIP buffers and wolfSSH working memory compete for it. PSRAM is
plentiful but slower, and its stacks must not be touched while the flash
cache is disabled (NVS commit, OTA).

Measure with:

```sh
source /home/xiaoboluo/.espressif/tools/activate_idf_v6.1.sh
idf.py size
```

## Partition table (`partitions.csv`)

| Name | Type | Offset | Size | Use |
|------|------|--------|------|-----|
| `nvs` | data/nvs | 0x9000 | 24 KB | boot counter, config |
| `phy_init` | data/phy | 0xf000 | 4 KB | PHY calibration |
| `factory` | app | 0x10000 | 3 MB | application image |
| `storage` | data/spiffs | 0x310000 | 4 MB | reserved for the phase-2 writable overlay |

## Static usage (baseline, phase 1)

| Region | Used | Total | Free |
|--------|------|-------|------|
| Flash (`.text`+`.rodata`+…) | ~1.23 MB | 3 MB app | 57% |
| HP SRAM (`.text`+`.data`+`.bss`) | ~138 KB | 320 KB | ~182 KB |
| LP SRAM | 24 B | 16 KB | — |
| PSRAM | s419 session rings | 8 MB | ~all |

## Dynamic allocations

| Consumer | Size | Where | Notes |
|----------|------|-------|-------|
| lwIP connection task stack | 4 KB × sessions | HP SRAM | one per accepted TCP connection |
| s419 connection task stack | 8 KB × sessions | HP SRAM | `S419_CONN_TASK_STACK` |
| accept-loop task stack | 4 KB × listener | HP SRAM | one per listening socket |
| logger task stack | 6 KB | HP SRAM | does NVS + sockets, stays internal |
| event queue | 24 × `sizeof(mp_evt_t)` ≈ 11 KB | heap | bounded drop-on-full |
| s419 RX/TX rings | 4 KB + 16 KB per TCB | PSRAM (fallback HP) | `s419_tcb_alloc()` |
| UDP listener task stack | 4 KB × listener | HP SRAM | phase-2 UDP services |
| wolfSSH KEX + channel | several KiB per in-flight KEX | HP SRAM by default | capped by `PREAUTH_MAX` (3) |

### Policy

- **Connection stacks may live in PSRAM** (`xTaskCreateWithCaps`): the
  connection/accept/UDP tasks never touch flash, so the cache-disable
  window is not a hazard. The logger task deliberately stays on HP SRAM.
- **The internal reserve** `CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=32768`
  keeps `malloc()` from starving the WiFi/lwIP internal pool.
- **Large, short-lived allocations** (wolfSSH KEX bignums, 16 KiB channel
  windows) are steered to PSRAM via `CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL`
  and/or explicit `heap_caps_malloc(MALLOC_CAP_SPIRAM)`.
- **Session budget.** With HP SRAM free `F` bytes after static usage and a
  per-session cost `c` (stacks + buffers), the safe budget is roughly
  `min(CONFIG_MICROPOT_MAX_SESSIONS, F / c)`. Keep headroom for a burst of
  KEX working memory; `PREAUTH_MAX` in `mp_ssh_server.c` bounds that.
- Run `idf.py size` after any change to stacks/buffers and compare the
  `HP SRAM` row. Runtime health is on the `stats:` serial line (free/min
  heap, PSRAM, live sessions).
