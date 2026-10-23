# Building MicroPot-C5 on Windows

Native Windows 10/11 x64 is supported for the firmware build, flashing and
the Python PC tools. The host unit tests are POSIX-only; run those in WSL2
(see the bottom of this page).

The build does **not** need Git Bash, `sh`, `sed`, MSYS2 or WSL. The
wolfSSL/wolfSSH registry patches are applied by a CMake script
(`tools/patch_wolfssl.cmake`) during the normal CMake configure step.

## 1. Prerequisites

- **ESP-IDF 6.1** installed with the Espressif installer. Open the
  *ESP-IDF 6.1 PowerShell* shortcut (or run `export.ps1` in a normal
  PowerShell). The Linux activation script mentioned in the README is not
  used on Windows.
- **Python 3.10+** (the installer's bundled Python is fine).
- **Git for Windows**.
- A USB driver for the board:
  - ESP32-C5 dev boards normally expose **USB-Serial/JTAG**, which
    Windows 10/11 recognises natively as a COM port.
  - If your board uses a separate UART bridge (CP210x, CH343, ...), install
    the vendor driver.

## 2. Use a short, ASCII-only path

wolfSSL has deep source paths and Windows still has a 260-character limit
in many tools. Clone to something like `C:\esp\micropot-c5`, not under a
long `C:\Users\<name>\Documents\...` path, and avoid spaces/non-ASCII.

Enable long paths as a safety net:

```powershell
git config --global core.longpaths true

# Administrator PowerShell:
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem `
  -Name LongPathsEnabled -Value 1 -PropertyType DWORD -Force
```

## 3. Build

```powershell
cd C:\esp\micropot-c5

idf.py set-target esp32c5      # first time only
idf.py build
```

On the first build the component manager downloads `managed_components/`
and the top-level `CMakeLists.txt` runs `tools/patch_wolfssl.cmake`. You do
not need to run any patch script manually. If the patch script reports an
anchor error, the wolfSSL/wolfSSH versions have drifted: keep the exact
versions pinned in `main/idf_component.yml` (or update the patch script).

The pinned wolfSSL 5.8.2~1 predates both ESP-IDF 6.1 and the ESP32-C5, so
the script also makes it build on this target:

- ESP-IDF 6.1 compiles C as `gnu23`, where `thread_local` is a keyword;
  the `esp_sdk_mem_lib.c` enum member is renamed.
- `esp32_util.c` gets an ESP32-C5 watchdog branch so it uses
  `esp_task_wdt_*()` instead of the ESP32/S2-only `rtc_wdt_*()`.
- `user_settings.h` gets an ESP32-C5 branch that defines `WOLFSSL_ESP32`
  (software crypto only). Without it `random.c` provides no
  `wc_GenerateSeed()` and the link fails.

If you ever delete `managed_components/`, re-run:

```powershell
idf.py reconfigure
```

Do **not** reuse a Linux `build/` directory on Windows. Delete `build/`
when switching hosts. `sdkconfig` can be reused, but it is not committed
because it may contain WiFi credentials and a local collector address.

## 4. Configure and flash

```powershell
idf.py menuconfig
```

Set at least:

- WiFi SSID / password
- *Structured logging* → collector IPv4 (`Log host`) and port
- *Device persona* (camera / router / printer / Linux 4.19)

Then find the COM port in Device Manager (*Ports (COM & LPT)*) and flash:

```powershell
idf.py -p COM5 flash monitor
```

Notes:

- If flashing cannot connect, hold **BOOT**, tap **RESET**, release BOOT,
  and retry. Close any other serial monitor first.
- `idf.py monitor` exits with `Ctrl+]`.
- The serial console prints the obtained IP, e.g.
  `honeypot online at 192.168.1.100`.
- `CONFIG_MICROPOT_LOG_CONSOLE` is off by default; events go to the
  collector, not to the serial console.

## 5. PC-side tools

Use `python`, not `python3`:

```powershell
# Collector (allow it through Windows Firewall on private networks)
python tools\log_collector.py --host 0.0.0.0 --port 9999 --proto both

# Management web UI
copy tools\devices.example.json tools\devices.json
python tools\micropot_web.py
```

The web UI binds `127.0.0.1` by default. If you bind it to a LAN address,
`--token` (or `MICROPOT_WEB_TOKEN`) is now **required**; otherwise the
process refuses to start.

Set the PSK for a device through an environment variable if you do not want
it in `devices.json`:

```powershell
$env:MICROPOT_PSK = "your-psk"
$env:MICROPOT_WEB_TOKEN = "your-web-token"
python tools\micropot_web.py --bind 0.0.0.0
```

The log collector's terminal output uses ANSI colours only when the
terminal is known to support them. Use `--no-color` to force plain text.

## 6. Host unit tests (WSL2)

The sources under `test/host` use `socketpair`, `<unistd.h>`, GNU make and
OpenSSL. They do not build with native Windows toolchains. Use WSL2:

```sh
sudo apt update
sudo apt install build-essential libssl-dev make
cd /mnt/c/esp/micropot-c5
make -C test/host
```

MSYS2 can build some of the targets, but `test_linekit` needs
`socketpair()` and may not link. WSL2 is the supported path.

## 7. Shell helpers

Only these scripts remain POSIX shell:

- `tools/gen_host_keys.sh` — host keys are committed, so this is only
  needed when regenerating them.
- `tools/fingerprint_check.sh` — needs nmap; `-O` needs Npcap and an
  Administrator shell on Windows.

Run them from WSL2 or Git Bash. `tools/patch_wolfssl.sh` is only a
compatibility wrapper around the CMake implementation.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `sh: not found`, `sed: command not found` during configure | an old checkout still runs the shell patch script; update to the CMake hook (`tools/patch_wolfssl.cmake`) |
| `patch_wolfssl: anchor not found` | wolfSSL/wolfSSH version drift; restore the pinned versions in `main/idf_component.yml` or update the anchors |
| `No such file or directory: .../managed_components/...` | dependencies were deleted; run `idf.py reconfigure` |
| `FileNotFoundError` / path too long | move the project to a short path and enable long paths |
| `could not open port COMx` | another monitor is open, or the wrong COM port is selected |
| firewall prompt / events never arrive | allow Python on private networks for the collector port (default 9999) |
| `stale ts` from the control plane | two clients sent commands in the same millisecond; update the tools (monotonic ts) or retry |
| raw `\033[...]` in collector output | terminal without VT support; use `--no-color` or Windows Terminal |

## 9. Isolation

Only run this firmware on an isolated lab network. It spoofs vendor OUIs,
serves fake login pages and captures credentials; using it on networks you
do not own is illegal in most jurisdictions.
