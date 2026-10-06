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
| lwIP connection task stack | 4 KB × sessions | **PSRAM** | `xTaskCreateWithCaps`, freed with `vTaskDeleteWithCaps` |
| s419 connection task stack | 8 KB × sessions | **PSRAM** | `S419_CONN_TASK_STACK`, same mechanism |
| accept-loop task stack | 4 KB × listener | **PSRAM** | lwIP backend |
| UDP listener task stack | 4 KB × listener | **PSRAM** | phase-2 UDP services |
| event queue | 24 × `sizeof(mp_evt_t)` ≈ 11 KB | **PSRAM** | `xQueueCreateWithCaps`, bounded drop-on-full |
| s419 RX/TX rings | 4 KB + 16 KB per TCB | **PSRAM** (fallback HP) | allocated at SYN, freed early — see below |
| wolfSSH KEX + channel | several KiB per in-flight KEX | **PSRAM for ≥2 KB**, else HP | `XMALLOC_USER` override, see below |
| logger task stack | 6 KB | HP SRAM | does NVS + sockets, deliberately internal |

### Policy

- **Connection stacks live in PSRAM** (`xTaskCreateWithCaps`): the
  connection/accept/UDP tasks never touch flash, so the cache-disable
  window is not a hazard. The logger task deliberately stays on HP SRAM
  because it commits the NVS boot counter.
- **wolfSSH allocations are PSRAM-aware.** On ESP-IDF the vendored wolfSSL
  defaults `XMALLOC` to `pvPortMalloc()` (internal only). The sshd component
  defines `XMALLOC_USER` for the wolfSSL/wolfSSH targets and provides
  `XMALLOC`/`XREALLOC`/`XFREE` in `components/mp_ssh_server/mp_wolfmem.c`:
  requests ≥ `MP_WOLFMEM_PSRAM_MIN` (2 KB) try PSRAM first and fall back to
  internal memory, smaller ones stay internal. `mp_wolfmem_anchor()` is
  called from `sshd_start()` to keep the object in the link.
- **The internal reserve** `CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=32768`
  keeps `malloc()` from starving the WiFi/lwIP internal pool.
- **s419 TCB rings are released early, not at TIME_WAIT expiry.** A closed
  connection used to keep its 20 KB rings in PSRAM for the full 60 s
  `TIME_WAIT`/`FIN_WAIT_2`, so connection-churn floods (e.g. `ab` without
  keep-alive) pinned off PSRAM and then made `raw_sendto()` fail with
  `ERR_MEM`. Now `s419_tcb_free_rx()` drops the rx ring when the app
  detaches and `s419_tcb_free_tx()` drops the tx ring once every byte is
  acked, so a lingering TCB costs bytes. A hard cap (`S419_MAX_TCBS = 96`,
  all states) bounds the TCB table; excess SYNs are dropped like a full
  Linux SYN queue. `stats:` reports `tcbs` alongside `sessions`/`psram` so
  a pinned TCB count is visible.
- **Session budget.** With HP SRAM free `F` bytes after static usage and a
  per-session cost `c` (stacks + buffers), the safe budget is roughly
  `min(CONFIG_MICROPOT_MAX_SESSIONS, F / c)`. Keep headroom for a burst of
  KEX working memory; `PREAUTH_MAX` in `mp_ssh_server.c` bounds that.
- Run `idf.py size` after any change to stacks/buffers and compare the
  `HP SRAM` row. Runtime health is on the `stats:` serial line (free/min
  heap, PSRAM, live sessions).
