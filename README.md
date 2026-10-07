# Rolling Log Monitor

A single-file, real-time system activity monitor for Windows that renders a live, scrolling
log in your terminal. It runs **33 independent monitor threads** — covering DNS, processes,
network, services, registry, event logs, firewall, USB, scheduled tasks, clipboard, power,
Defender, print jobs, WiFi, LAN and more — funnels every observation into one event bus, and
displays it as a minimalist black-and-white rolling log with filtering, searching and
statistics.

No web server, no database, no external API. Everything is collected from the local machine
using the Python standard library, `psutil`, `pywin32`, and built-in Windows utilities
(`sc`, `schtasks`, `arp`, `net`, `netsh`, `driverquery`, `powershell`).

```
Rolling Log Monitor | Uptime: 12m04s | QPS: 3.0 | Events: 2188
================================================================================
Filter: None
--------------------------------------------------------------------------------
[LIVE] 4312 buffered
--------------------------------------------------------------------------------
[14:22:07.481] 🌐 NETWORK    Connection: 192.168.1.20:52114 -> 142.250.72.14:443 [ESTABLISHED] | pid=8812
[14:22:06.903] → DNS        Resolved: github.com | ipv4=140.82.114.4 | domain=github.com
[14:22:05.117] ⚙ PROCESS     Process started: notepad.exe (PID 14220) | user=DESKTOP-A1\alice
[14:22:04.002] 💻 SYSTEM     CPU:14% RAM:63% Swap:12% Disk:48% | cpu_detail=user:9.1% sys:4.2% idle:86.0%
[14:22:01.556] 📋 CLIPBOARD  Clipboard: https://example.com/some/copied/text | text=https://exa...
--------------------------------------------------------------------------------
Controls: ↑/↓ Scroll | PgUp/PgDn | Home/End | Space Pause | C Clear | D Toggle Data | F Filter | S Source | / Search | H Help | Q Quit
```

---

## Table of Contents

- [Highlights](#highlights)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command-Line Reference](#command-line-reference)
- [Interactive Controls](#interactive-controls)
- [Understanding the Display](#understanding-the-display)
- [Feature Reference: All 33 Monitors](#feature-reference-all-33-monitors)
- [Event Model and Severity Levels](#event-model-and-severity-levels)
- [Writing Events to a Log File](#writing-events-to-a-log-file)
- [Statistics and Shutdown Summary](#statistics-and-shutdown-summary)
- [Architecture](#architecture)
- [Adding Your Own Monitor](#adding-your-own-monitor)
- [Performance and Resource Usage](#performance-and-resource-usage)
- [Privacy, Security and Safety Notes](#privacy-security-and-safety-notes)
- [Known Limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout)

---

## Highlights

- **One file, zero setup.** `rolling_log_monitor.py` is self-contained (~2,300 lines). Copy it
  anywhere and run it.
- **Real data only.** Every event comes from an actual system call, a real Windows utility, or
  a genuine network resolution. Nothing is simulated or randomly generated.
- **33 monitors, all optional.** Each one runs on its own daemon thread and can be disabled
  with a single `--no-*` flag.
- **Graceful degradation.** If `psutil`, `pywin32` or `wmi` is missing, only the monitors that
  need it quietly exit. The rest keep running — the app never crashes on a missing dependency.
- **Unified event bus.** All monitors publish a common `Event` object, so adding a new data
  source is a ~20-line change.
- **Live TUI.** Scroll, pause, clear, filter by source, full-text search, toggle detail —
  all from the keyboard, no dependencies beyond `msvcrt`.
- **Optional file logging** with automatic size-based rotation.
- **Minimalist monochrome design.** Uses only ANSI bold/dim/underline; no color codes, so it
  reads cleanly in any console theme, including Windows Terminal and legacy `conhost`.

---

## Requirements

| Item | Requirement | Notes |
|---|---|---|
| OS | Windows 10 / 11 (or Windows Server) | Most monitors are Windows-only and no-op elsewhere |
| Python | 3.9+ (tested on 3.12.10) | Must be on `PATH` as `python` for `run_monitor.bat` |
| Console | ANSI escape-sequence support | Enabled automatically at startup via `SetConsoleMode` |
| Privileges | Standard user works; **Administrator recommended** | See the table below |

### Optional Python packages

The script imports these lazily inside each monitor thread, so none of them are hard
requirements.

| Package | Install | Enables |
|---|---|---|
| `psutil` | `pip install psutil` | PROCESS, NETWORK, SYSTEM, MEMORY, MODULE, PROCESS_TREE, THREAT |
| `pywin32` | `pip install pywin32` | EVENTLOG, CLIPBOARD, INPUT, IDLE, POWER |
| `WMI` | `pip install WMI` | WMI process-start tracing |

```powershell
pip install psutil pywin32 WMI
```

Without any of them you still get the standard-library monitors: DNS, ARP, LAN, SERVICE,
SERVICE_DETAIL, FIREWALL, REGISTRY, DEVICE, TASK, APPLICATION, SECURITY, SHARE, WIFI, PRINT,
DEFENDER, DRIVER, SCREENSHOT, MRU, API.

### Why Administrator helps

| Capability | Standard user | Administrator |
|---|---|---|
| Process list & command lines | Partial (some `AccessDenied`) | Full, including other users' processes |
| `psutil.net_connections()` | Often empty | Full connection table with PIDs |
| Security event log (ID 4625 failed logins) | Denied | Works |
| Windows Firewall `pfirewall.log` | Usually not readable | Readable **if** logging is enabled |
| Per-process memory maps (MODULE) | Partial | Full |

---

## Installation

There is nothing to install. Clone or copy the two files into a folder:

```
webdnsviewer/
├── rolling_log_monitor.py
└── run_monitor.bat
```

Optionally install the extra packages for maximum coverage:

```powershell
python -m pip install psutil pywin32 WMI
```

Verify the script loads and prints its help:

```powershell
python rolling_log_monitor.py --help
```

---

## Quick Start

### Option 1 — Double-click

Run `run_monitor.bat`. It `cd`s into its own folder, launches the monitor with any arguments
you pass through, and `pause`s at the end so the window stays open.

### Option 2 — Terminal

```powershell
cd your location
python rolling_log_monitor.py
```

Press `Q` (or `Ctrl+C`) to quit. On exit you get a summary of uptime, total events, QPS and
the top event sources.

### Option 3 — Elevated terminal (recommended)

Open **Windows Terminal / PowerShell as Administrator**, then:

```powershell
cd your location
python rolling_log_monitor.py --log monitor.log --interval 1.0
```

### Common recipes

```powershell
# Record everything to a rotating log file
python rolling_log_monitor.py --log D:\logs\monitor.log

# Fast polling (1s base interval)
python rolling_log_monitor.py --interval 1.0

# Network diagnostics only — DNS, connections, ARP, LAN, WiFi, shares
python rolling_log_monitor.py --no-processes --no-system --no-services --no-service-detail `
  --no-firewall --no-eventlog --no-registry --no-wmi --no-devices --no-tasks `
  --no-applications --no-security --no-memory --no-modules --no-clipboard --no-input `
  --no-browser --no-idle --no-power --no-threat --no-api --no-defender --no-mru `
  --no-screenshot --no-print --no-drivers --no-process-tree

# Watch only your own domains
python rolling_log_monitor.py --domains "example.com,api.example.com,cdn.example.com"

# Quiet run: no clipboard, no input, no browser-history, no MRU monitoring
python rolling_log_monitor.py --no-clipboard --no-input --no-browser --no-mru --no-screenshot

# Do NOT delete *.html files in the working directory at startup
python rolling_log_monitor.py --no-html-delete
```

> ⚠️ **Read this before the first run:** unless you pass `--no-html-delete`, the program
> deletes every `*.html` file in the **current working directory** at startup. Run it from a
> dedicated folder, or always pass `--no-html-delete`. See
> [Privacy, Security and Safety Notes](#privacy-security-and-safety-notes).

---

## Command-Line Reference

### General options

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--log` | `-l` | path | *(none — no file logging)* | Append every event to this file. Created/truncated at startup. Parent directories are created automatically. |
| `--max-lines` | `-n` | int | `50` | Display height in lines. **See [Known Limitations](#known-limitations)** — currently not wired to the renderer. |
| `--interval` | `-i` | float | `2.0` | Base polling interval in seconds. Each monitor derives its own interval from this value (see below). |
| `--no-html-delete` | — | flag | off | Skip the startup deletion of `*.html` in the working directory. |
| `--domains` | `-d` | string | 37 built-in domains | Comma-separated list of domains for the DNS monitor to resolve. |
| `--help` | `-h` | — | — | Print usage, examples and the control key list. |

### How `--interval` maps to per-monitor polling

Each monitor computes `max(base_interval × multiplier, floor)`. The floor prevents cheap
monitors from hammering the system, so lowering `--interval` below ~2.0 mostly stops having
an effect for the slow monitors.

At the default `--interval 2.0`:

| Poll (s) | Monitors |
|---|---|
| 2 | DNS, CLIPBOARD |
| 3 | NETWORK |
| 4 | PROCESS |
| 5 | SYSTEM, INPUT, IDLE, API |
| 10 | SERVICE, MEMORY, POWER, PROCESS_TREE |
| 15 | FIREWALL, APPLICATION, MODULE, BROWSER, THREAT, SERVICE_DETAIL |
| 20 | REGISTRY, DEVICE, SECURITY, MRU, PRINT, WIFI |
| 30 | EVENTLOG, WMI, ARP, DEFENDER, SCREENSHOT, DRIVER, SHARE, LAN |
| 60 | TASK |

With `--interval 1.0` the 2s tier stays at its floor (2s), the 3s tier drops to 2s, and so
on. With `--interval 5.0` everything scales up roughly 2.5×.

### Monitor disable flags

Every flag is `store_true`; omit it to keep the monitor enabled.

| Flag | Disables |
|---|---|
| `--no-dns` | DNS resolution polling |
| `--no-processes` | Process start/end detection |
| `--no-network` | TCP/UDP connections + interface traffic |
| `--no-system` | CPU / RAM / swap / disk statistics |
| `--no-services` | Windows service state changes |
| `--no-service-detail` | Detailed service state transitions |
| `--no-firewall` | Windows Firewall packet log tailing |
| `--no-eventlog` | Application / System / Security event logs |
| `--no-registry` | Autorun & service registry key watching |
| `--no-wmi` | WMI `Win32_ProcessStartTrace` |
| `--no-devices` | USB / PnP device enumeration |
| `--no-tasks` | Scheduled task inventory |
| `--no-applications` | Application cache/log file changes |
| `--no-security` | Failed login attempts (event ID 4625) |
| `--no-memory` | Per-process high memory usage |
| `--no-modules` | DLL / memory-mapped module loads |
| `--no-arp` | ARP table changes |
| `--no-clipboard` | Clipboard text changes |
| `--no-input` | Keyboard/mouse activity counter |
| `--no-browser` | Browser history file modification times |
| `--no-idle` | Idle ↔ active state transitions |
| `--no-power` | AC/battery power status |
| `--no-threat` | Suspicious process name matching |
| `--no-api` | API monitor heartbeat |
| `--no-defender` | Windows Defender status |
| `--no-mru` | Most-recently-used registry entries |
| `--no-screenshot` | New screenshot/capture files |
| `--no-print` | Print queue jobs |
| `--no-drivers` | Driver inventory |
| `--no-process-tree` | Parent/child process relationships |
| `--no-shares` | Network share inventory |
| `--no-wifi` | Saved WiFi profiles |
| `--no-lan` | LAN device discovery via ARP |

---

## Interactive Controls

Keys are read from `msvcrt` on Windows; on other platforms the handler falls back to blocking
`stdin` reads.

| Key | Action |
|---|---|
| `↑` / `↓` | Scroll one event older / newer |
| `PgUp` / `PgDn` | Scroll 15 events older / newer |
| `Home` | Jump to the **newest** events |
| `End` | Jump to the **oldest** buffered events |
| `Space` | Toggle the `LIVE` / `PAUSED` indicator (see note below) |
| `C` | Clear the entire event buffer |
| `D` | Toggle the inline `key=value` data payload on each line |
| `F` | Prompt for a source filter (exact source tag, case-insensitive) |
| `S` | Same source-filter prompt (quick access) |
| `/` | Prompt for a substring search across event messages and source tags |
| `H` | Full-screen help: controls + a one-line description of every monitor |
| `Q` | Quit, print the run summary |

Notes:

- `F`, `S` and `/` open a small inline prompt. Type your text and press `Enter`. Submitting an
  **empty** string clears that filter. Filters combine: a source filter and a text search are
  applied together.
- The text search is a case-insensitive literal substring match (`re.escape`d), not a regex.
- Whenever a prompt or flash message is shown, the header switches to `PAUSED` for the
  duration and then restores your previous state.
- `Space` in the current build only flips the header label. Monitors keep publishing and the
  buffer keeps filling — to genuinely freeze a moment, scroll up (`End`/`PgUp`) or press `C`
  after pausing your investigation. See [Known Limitations](#known-limitations).

---

## Understanding the Display

The screen is redrawn roughly 20 times per second (only when the rendered frame actually
changes) and is laid out as five sections:

1. **Header** — `Rolling Log Monitor | Uptime: … | QPS: … | Events: …`
   - *Uptime* — wall-clock time since start, formatted `1h02m03s` / `5m07s` / `42s`.
   - *QPS* — events published in the last second.
   - *Events* — total events since start.
2. **Filter line** — `Filter: None`, or the active source and/or text filter.
3. **Status line** — `[LIVE]` or `[PAUSED]` plus the buffer depth, e.g. `4312 buffered`.
4. **Event list** — newest at the **top**, oldest at the bottom. Each line is:

   ```
   [HH:MM:SS.mmm] <icon> <SOURCE>    <message> | key=value | key=value…
   ```

   - The icon is looked up per source tag (`→` DNS, `⚙` PROCESS, `🌐` NETWORK, `📁` FILE,
     `🛡` FIREWALL/DEFENDER, `📋` CLIPBOARD/EVENTLOG, `👁` MONITOR, and so on); unknown
     sources fall back to `•`.
   - The data payload is truncated to 60 characters; lists longer than 3 items are shown as
     the first two entries followed by `...`.
   - The whole line is hard-truncated to the render width (120 columns) with a trailing `...`.
     Widen your terminal or press `D` to hide the payload for a cleaner view.
5. **Footer** — the control key cheat-sheet, always visible.

The in-memory display buffer holds the most recent **10,000** events.

---

## Feature Reference: All 33 Monitors

The "Default poll" column assumes `--interval 2.0`.

### Network & name resolution

| Source tag | Default poll | What it reports | How it collects data |
|---|---|---|---|
| `DNS` | 2s | Picks one domain at random per tick, publishes a `QUERY` (DEBUG) event, then a `RESULT` event with resolved IPv4 and IPv6 addresses. Failures are `WARNING`. | `socket.getaddrinfo()` for `AF_INET` and `AF_INET6`, going through the system resolver. Results are cached for 300s (cache capped at 500 domains). |
| `NETWORK` | 3s | New/changed TCP & UDP connections (`local -> remote [state]` with owning PID), plus per-interface byte and packet counters whenever they change. | `psutil.net_connections(kind='inet')` and `psutil.net_io_counters(pernic=True)`. |
| `ARP` | 30s | New ARP entries (`IP -> MAC`) and MAC address changes for an existing IP. | `arp -a`. |
| `LAN` | 30s | LAN device discovery — reports each `IP (MAC)` pair seen for the first time. | `arp -a`. |
| `WIFI` | 20s | Saved WiFi profiles (SSIDs) as they appear. | `netsh wlan show profiles`. |
| `SHARE` | 30s | Newly created network shares (`share -> path`). | `net share`. |

**Default DNS domain list** (override with `--domains`): `google.com`, `github.com`,
`microsoft.com`, `cloudflare.com`, `amazon.com`, `facebook.com`, `netflix.com`, `youtube.com`,
`wikipedia.org`, `stackoverflow.com`, `reddit.com`, `twitter.com`, `linkedin.com`, `apple.com`,
`adobe.com`, `oracle.com`, `ibm.com`, `intel.com`, `cisco.com`, `dell.com`, `hp.com`,
`python.org`, `mozilla.org`, `nginx.org`, `docker.com`, `kubernetes.io`, `rust-lang.org`,
`golang.org`, `nodejs.org`, `apache.org`, `linux.org`, `ubuntu.com`, `debian.org`,
`fedora.org`, `redhat.com`, `centos.org`, `archlinux.org`.

### Processes & resources

| Source tag | Default poll | What it reports | How it collects data |
|---|---|---|---|
| `PROCESS` | 4s | Process start (`START`) with name, PID, truncated command line and owner; process end (`END`). | Diffing `psutil.process_iter(['pid','name','cmdline','username'])` snapshots. |
| `PROCESS_TREE` | 10s | Newly observed processes with their parent PID and parent name. | `psutil.process_iter(['pid','name','ppid'])`. |
| `SYSTEM` | 5s | `CPU:x% RAM:y% Swap:z% Disk:w%` plus a user/system/idle breakdown and total/used memory. CPU ≥ 90% or memory > 90% raises a `WARNING`. | `psutil.cpu_percent`, `cpu_times_percent`, `virtual_memory`, `swap_memory`, `disk_usage('/')` (the drive containing the working directory). |
| `MEMORY` | 10s | Any process whose resident set size exceeds 100 MB; ≥ 500 MB is a `WARNING`. | `psutil.process_iter(['pid','name','memory_info'])`. |
| `MODULE` | 15s | Newly loaded DLLs / memory-mapped files per process. | `psutil` `memory_maps(grouped=False)`. |
| `THREAT` | 15s | Processes whose name or command line contains `keylogger`, `rat`, `trojan`, `backdoor`, `miner` or `cryptonight`. Always `WARNING`. | `psutil.process_iter(['pid','name','cmdline'])` keyword match. Heuristic only — expect false positives and false negatives. |
| `API` | 5s | A periodic `HEALTH` heartbeat confirming the monitor loop is alive. | Placeholder — no real API/ETW tracing is performed. |

### Windows services, drivers & tasks

| Source tag | Default poll | What it reports | How it collects data |
|---|---|---|---|
| `SERVICE` | 10s | Services seen for the first time, and state changes (`RUNNING -> STOPPED`). | `sc query type= service state= all`. |
| `SERVICE_DETAIL` | 15s | The same inventory with explicit old→new state transition events. | `sc query type= service state= all`. |
| `DRIVER` | 30s | Drivers appearing in the inventory, with status. | `driverquery /v`. |
| `TASK` | 60s | Newly created scheduled tasks and task status changes. | `schtasks /query /fo CSV /nh`. |

### Registry, WMI & configuration

| Source tag | Default poll | What it reports | How it collects data |
|---|---|---|---|
| `REGISTRY` | 20s | Values added or changed in persistence-sensitive keys: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `…\RunOnce`, `…\Policies\Explorer\Run`, `HKLM\SYSTEM\CurrentControlSet\Services`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`. | `winreg.OpenKey` + `EnumValue` snapshot diffing (read-only). |
| `WMI` | 30s | Process-start events raised through WMI, with PID, name and command line. | The `wmi` Python package querying `Win32_ProcessStartTrace`. Requires `pip install WMI`; without it the monitor exits silently. |
| `MRU` | 20s | New entries in `HKCU\…\Explorer\ComDlg32\OpenSavePidlMRU` and `HKCU\…\Explorer\RecentDocs` (the Open/Save dialog and Recent Documents history). | `winreg` snapshot diffing (read-only). |

### Logs, security & defense

| Source tag | Default poll | What it reports | How it collects data |
|---|---|---|---|
| `EVENTLOG` | 30s | The most recent 10 records from each of the **Application**, **System** and **Security** logs, with event ID and source name. Errors map to `ERROR`, warnings to `WARNING`. | `win32evtlog.OpenEventLog` / `ReadEventLog` (pywin32). Security log requires Administrator. |
| `FIREWALL` | 15s | `DROP` and `ALLOW` packet entries appended to the firewall log. `DROP` is a `WARNING`. | Incrementally tails `%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`. Only produces events if Windows Firewall logging is turned on and the file is readable. |
| `SECURITY` | 20s | Failed logon attempts (Security event ID **4625**). Always `WARNING`. | `powershell Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}`. Requires Administrator. |
| `DEFENDER` | 30s | Real-time protection / antivirus enablement and signature last-updated timestamp. | `powershell Get-MpComputerStatus`. |
| `APPLICATION` | 15s | Files appearing or changing size under `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations` (Jump Lists), `%LOCALAPPDATA%\Microsoft\Windows\INetCache`, and the Explorer thumbcache delete folder. | `Path.stat()` size/mtime polling — file **contents are never read**. |

### Devices, power & user activity

| Source tag | Default poll | What it reports | How it collects data |
|---|---|---|---|
| `DEVICE` | 20s | USB-class PnP devices and their status. | `powershell Get-PnpDevice -Class USB`. |
| `POWER` | 10s | AC vs. battery state and battery level percentage. | `win32api.GetSystemPowerStatus()`. |
| `IDLE` | 5s | State transitions when input idle time crosses the 60-second threshold (`IDLE` ↔ `ACTIVE`). | `win32api.GetLastInputInfo()` / `GetTickCount()`. |
| `INPUT` | 5s | A periodic activity counter — how many polls detected recent input. An event fires every 10th active poll. | `win32api.GetLastInputInfo()`. **No keystrokes or mouse coordinates are captured.** |
| `CLIPBOARD` | 2s | New clipboard text (truncated to 200 characters), published whenever the content changes. | `win32clipboard` with `CF_UNICODETEXT`. ⚠️ This includes passwords copied from password managers — see the privacy notes. |
| `BROWSER` | 15s | When the Chrome / Edge `History` database or the Firefox profile directory is modified. Reports file path, size and mtime only. | `Path.stat()`. **History contents and URLs are never read.** |
| `SCREENSHOT` | 30s | New `.png` / `.jpg` files appearing in `%USERPROFILE%\Pictures\Screenshots` or `%USERPROFILE%\Videos\Captures`. | `Path.glob()` + filename set diffing. File contents are not read or transmitted. |
| `PRINT` | 20s | New print jobs with job ID, document name, printer and status. | `powershell Get-PrintJob`. |
| `MONITOR` | once | A `STARTUP` event recording how many monitors were launched. Emitted only when `--log` is set. | Internal. |

---

## Event Model and Severity Levels

Every monitor publishes the same object:

```python
Event(source, category, message, severity=Severity.INFO, data={...})
```

| Field | Meaning |
|---|---|
| `ts` | Capture time (epoch), auto-set |
| `source` | Monitor tag, e.g. `DNS`, `PROCESS` — this is what `F`/`S` filter on |
| `category` | Event kind within the monitor, e.g. `START`, `END`, `QUERY`, `RESULT`, `CHANGE`, `ERROR` |
| `message` | Human-readable one-liner |
| `severity` | One of six levels (below) |
| `data` | Arbitrary dict of structured detail; rendered inline in the TUI and **omitted** from the log file |

Severity levels, lowest to highest:

| Level | Value | Typical use |
|---|---|---|
| `DEBUG` | 0 | Verbose tracing (traffic counters, module loads, DNS query start) |
| `INFO` | 1 | Normal observations |
| `NOTICE` | 2 | State transitions worth flagging (service state change, ARP change) |
| `WARNING` | 3 | Firewall DROP, failed DNS, failed login, high CPU/memory, suspicious process |
| `ERROR` | 4 | Monitor-internal failures, event-log error records |
| `CRITICAL` | 5 | Reserved — defined but not currently emitted by any monitor |

The display does not colour-code by severity; the level appears only in the log file. Use the
message wording and the `!` / `⚠` icons to spot problems on screen.

---

## Writing Events to a Log File

File logging is **off by default**. Enable it with `--log`:

```powershell
python rolling_log_monitor.py --log monitor.log
```

Behaviour:

- The parent directory is created if missing.
- The file is opened in **write mode at startup**, so an existing file at that path is
  **truncated and replaced**. Pick a fresh name or move the old file first.
- A header comment block is written, then one line per event, appended synchronously under a
  lock.
- **Rotation:** every 1,000 writes the file size is checked. If it exceeds 10,000,000 bytes
  (~9.5 MiB) it is renamed to `<stem>_YYYYmmdd_HHMMSS<suffix>` and a fresh file is started.
  Old rotated files are never deleted automatically.

Line format:

```
DATE TIME | SEVERITY | SOURCE | CATEGORY | MESSAGE
```

Example:

```
2026-10-06 14:22:06.903 | INFO     | DNS        | RESULT       | Resolved: github.com
2026-10-06 14:22:07.481 | INFO     | NETWORK    | CONN         | Connection: 192.168.1.20:52114 -> 142.250.72.14:443 [ESTABLISHED]
2026-10-06 14:25:11.002 | WARNING  | FIREWALL   | DROP         | Firewall DROP packet
```

The `data` dict is intentionally excluded, which keeps lines fixed-width and greppable. If you
need the structured fields, read them from the TUI (`D` to show data) or extend
`Event.as_log()` — it is a two-line change:

```python
def as_log(self) -> str:
    return (f"{self.date_str()} {self.time_str()} | "
            f"{SEV_NAME.get(self.severity, 'INFO'):<8} | "
            f"{self.source:<10} | {self.category:<12} | {self.message} | {self.data}")
```

Grepping a log afterwards:

```powershell
Select-String -Path .\monitor.log -Pattern "WARNING|ERROR"
Select-String -Path .\monitor.log -Pattern "\| DNS " 
```

---

## Statistics and Shutdown Summary

A dedicated thread refreshes statistics every 0.5s and pushes them to the header:

- **Uptime** since start.
- **QPS** — events in the trailing one-second window (computed from a 600-entry timestamp
  deque).
- **Total events**, plus per-severity, per-source and per-category counters. The source and
  category snapshots expose the top 10.

On quit (`Q` or `Ctrl+C`) all monitor threads are stopped and joined, the screen is cleared,
and a final report is printed:

```
Rolling Log Monitor stopped.
Uptime: 12m04s
Total events: 2188
QPS: 3.0
Events by source:
  NETWORK             812
  DNS                 401
  SYSTEM              144
  PROCESS             133
  ...
Log file: D:\logs\monitor.log
```

---

## Architecture

```
                    ┌──────────────────────────────────────┐
                    │  33 × BaseMonitor (daemon threads)   │
                    │  each: while not stopped → collect   │
                    │        → bus.publish(Event)          │
                    └──────────────────┬───────────────────┘
                                       │
                              ┌────────▼────────┐
                              │    EventBus     │  publish/subscribe,
                              │  (thread-safe)  │  monotonic sequence numbers
                              └────────┬────────┘
                                       │  _on_event()
             ┌─────────────────────────┼─────────────────────────┐
             │                         │                         │
   ┌─────────▼────────┐    ┌───────────▼─────────┐   ┌───────────▼─────────┐
   │   Statistics     │    │  RollingLogDisplay  │   │     FileLogger      │
   │ counters + QPS   │    │ deque(maxlen=10000) │   │ append + rotate     │
   └─────────┬────────┘    └───────────┬─────────┘   └─────────────────────┘
             │  _stats_loop 0.5s       │  render()
             └───────────────►─────────┤
                                       │  _render_loop ~20 fps
                              ┌────────▼────────┐
                              │     stdout      │  ANSI clear + frame
                              └─────────────────┘
                                       ▲
                              ┌────────┴────────┐
                              │  InputHandler   │  msvcrt.kbhit()/getch()
                              └─────────────────┘
```

Key classes:

| Class | Responsibility |
|---|---|
| `Severity` / `SEV_NAME` | Severity constants and their display names |
| `Event` | The universal record; formats itself for both screen (`line()`) and file (`as_log()`) |
| `EventBus` | Thread-safe pub/sub; assigns a monotonically increasing sequence number |
| `Statistics` | Locked counters for totals, severity/source/category breakdowns, and QPS |
| `FileLogger` | Locked append writer with size-based rotation |
| `BaseMonitor` | Thread lifecycle (`start()` / `stop()` with a 2s join timeout) and the `_run()` contract |
| `RollingLogDisplay` | The 10,000-event ring buffer, filtering, scrolling and frame rendering |
| `InputHandler` | Non-blocking keyboard loop and the inline filter/search prompts |
| `RollingLogMonitor` | Argument parsing, monitor construction, thread orchestration, shutdown report |

Threading model: one daemon thread per monitor, plus a render thread, a stats thread and an
input thread. All shared state is guarded by `threading.Lock` / `RLock`. Because the threads
are daemons, the process exits promptly even if a monitor is mid-`subprocess.run()`.

Failure isolation: every monitor wraps its loop body in `try/except`. A raised exception
publishes an `ERROR` event and sleeps before retrying; a missing import (`psutil`, `win32api`,
`wmi`) breaks out of the loop and disables just that monitor.

---

## Adding Your Own Monitor

Three small edits, all in `rolling_log_monitor.py`.

**1. Write the monitor class** (place it next to the others, before `RollingLogDisplay`):

```python
class DiskSmartMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("SMART", bus, interval)
        self._prev: Dict[str, str] = {}

    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command",
                     "Get-PhysicalDisk | Select-Object FriendlyName,HealthStatus"],
                    capture_output=True, encoding="utf-8",
                    errors="replace", timeout=10)

                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        name, health = parts[0], parts[-1]
                        if self._prev.get(name) not in (None, health):
                            self.bus.publish(Event(
                                "SMART", "HEALTH",
                                f"Disk {name}: {self._prev[name]} -> {health}",
                                severity=Severity.WARNING if health != "Healthy"
                                         else Severity.NOTICE,
                                data={"disk": name, "health": health}))
                        self._prev[name] = health

                time.sleep(self.interval)
            except Exception as e:
                self.bus.publish(Event("SMART", "ERROR", str(e),
                                       severity=Severity.ERROR))
                time.sleep(10.0)
```

**2. Register it** in `RollingLogMonitor._build_monitors()`:

```python
if not self.args.no_smart:
    monitors.append(DiskSmartMonitor(self.bus, max(interval * 30, 60.0)))
```

and add the flag in `parse_args()`:

```python
p.add_argument("--no-smart", action="store_true", help="Disable disk SMART monitor")
```

**3. (Optional) Give it an icon** in `Event.line()`'s `icons` dict:

```python
"SMART": "💽",
```

Rules of thumb: keep the source tag ≤ 10 characters (the display pads to 10), always guard the
loop body with `try/except`, always `time.sleep()` on the error path, and prefer diffing
snapshots over re-reporting unchanged state — otherwise you will flood the buffer.

---

## Performance and Resource Usage

- **Threads:** 33 monitors + render + stats + input ≈ 36 threads. All are daemon threads
  sleeping most of the time.
- **Redraw cost:** the render loop wakes every 50 ms but only writes to stdout when the frame
  string actually changed, so an idle system produces no terminal traffic.
- **Subprocess cost is the dominant factor.** `SERVICE`, `SERVICE_DETAIL`, `DRIVER`, `TASK`,
  `DEVICE`, `SHARE`, `WIFI`, `PRINT`, `DEFENDER` and `SECURITY` each spawn a child process per
  poll. At default intervals that averages well under one process spawn per second, but
  `--interval 1.0` multiplies it. If CPU usage bothers you, disable the utility-backed monitors
  rather than lowering the interval.
- **Memory:** the display ring buffer caps at 10,000 events; each event is a few hundred bytes,
  so the buffer stays in the low single-digit megabytes.
- **Network:** the DNS monitor issues one real resolution per tick (default every 2s, ~30
  lookups/minute) subject to a 300s cache. Nothing else in the tool makes outbound network
  calls; the network monitors only *read* the local connection table.
- **Disk:** without `--log` there is no disk writing at all.

---

## Privacy, Security and Safety Notes

Please read this section. This tool observes genuinely sensitive activity and has two
destructive startup behaviours.

**1. It deletes `*.html` files in the working directory at startup.**
`RollingLogMonitor.run()` calls `_delete_html()`, which globs `Path(".").glob("*.html")` and
unlinks every match — permanently, without confirmation. Because `run_monitor.bat` first does
`cd /d "%~dp0"`, double-clicking the batch file will delete any `.html` file sitting next to
the script. **Always pass `--no-html-delete`** unless you specifically want this, and never run
the tool from a folder containing HTML you care about.

**2. `--log` truncates the target file at startup.**
`FileLogger.__init__` opens the path with mode `"w"`. Pointing `--log` at an existing file
destroys its previous contents.

**3. It records clipboard contents.**
The `CLIPBOARD` monitor publishes the first 200 characters of every new clipboard value to the
screen and, with `--log`, to disk in plaintext. Passwords, tokens, private messages and
financial data all pass through the clipboard. Disable it with `--no-clipboard` whenever the
session is recorded, screen-shared, or logged.

**4. It records user activity and recently-used files.**
`INPUT` (activity counts only — never key contents), `IDLE`, `MRU` (Open/Save and Recent Docs
history), `BROWSER` (history file timestamps), `SCREENSHOT` (new capture filenames) and
`APPLICATION` (cache file changes) together build a fairly detailed picture of what a person
did on this machine. Disable the ones you do not need.

**5. It generates outbound DNS traffic.**
By default the DNS monitor resolves well-known third-party domains every couple of seconds.
Your DNS resolver, and potentially upstream resolvers, will see these queries. Use
`--domains` to point it at your own infrastructure, or `--no-dns` to stop it entirely.

**6. Run it only on machines you own or are authorised to monitor.**
Monitoring another person's session, clipboard, browsing or logon activity without their
knowledge and consent is likely to violate law, employment policy or terms of service in your
jurisdiction. This tool is intended for diagnosing and observing **your own** systems.

**7. Nothing leaves the machine except DNS.**
There is no telemetry, no HTTP client, no upload path and no external API key. Log files stay
where you put them.

**8. It is an observation tool, not a security product.**
`THREAT` is a six-keyword substring match; `SECURITY` and `FIREWALL` depend on logs that are
often disabled by default. Absence of events is **not** evidence that a system is clean. Do not
use this as your antivirus, EDR or audit system.

---

## Known Limitations

These are honest gaps in the current build.

- **`--max-lines` / `-n` is accepted but has no effect.** `RollingLogDisplay` is constructed
  with its default `max_lines=50` in `RollingLogMonitor.__init__`, before `parse_args()` runs,
  and the parsed value is never assigned back. Fix: in `run()`, after `self.parse_args()`, add
  `self.display.max_lines = self.args.max_lines`.
- **`Space` does not freeze the stream.** It only flips the `LIVE`/`PAUSED` label; `add()` and
  `render()` never consult `_paused`, so new events keep arriving and the visible window keeps
  shifting.
- **`EVENTLOG` can duplicate events.** `self._prev_records` is a single dict that is
  *reassigned* inside the per-log-type loop, so the Application pass forgets what the System
  pass recorded and the Security pass forgets both. Keying it by `(log_type, record_number)`
  fixes this.
- **`API` is a placeholder.** It emits a periodic heartbeat and performs no API or ETW tracing,
  despite the label.
- **The display width is hard-coded to 120 columns.** It does not adapt to your terminal size;
  lines are truncated rather than wrapped.
- **`CRITICAL` severity is never emitted** by any monitor.
- **`EventBus._queue` is allocated but unused.** Dispatch is a synchronous callback loop, so a
  slow subscriber (a slow disk under `--log`) briefly blocks publishers.
- **`Set` is used in type annotations without being imported** from `typing`. This is harmless
  only because of `from __future__ import annotations`; removing that import would raise
  `NameError`.
- **`FIREWALL` needs logging enabled.** Windows Firewall does not write `pfirewall.log` unless
  you turn on logging in the firewall profile, so this monitor is typically silent.
- **Windows-only in practice.** Non-Windows platforms keep only DNS, NETWORK, SYSTEM, MEMORY,
  MODULE, PROCESS, PROCESS_TREE, THREAT and APPLICATION; every other monitor returns
  immediately from `_run()`.
- **Extended-key detection assumes the `0xE0` prefix.** On consoles that emit `0x00` instead,
  arrow keys, PgUp/PgDn and Home/End will not respond; letter keys still work.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `'python' is not recognized` | Python not on `PATH` | Install Python and tick *Add to PATH*, or edit `run_monitor.bat` to use the full interpreter path |
| Console shows `←[2J←[H` garbage | ANSI escape sequences unsupported | Use Windows Terminal, PowerShell 7, or a modern `conhost`; the script enables VT mode at startup but very old consoles ignore it |
| No PROCESS / NETWORK / SYSTEM events | `psutil` missing | `python -m pip install psutil` |
| No CLIPBOARD / IDLE / POWER / EVENTLOG events | `pywin32` missing | `python -m pip install pywin32` |
| No WMI events | `WMI` package missing | `python -m pip install WMI` |
| NETWORK connection list is empty | Insufficient privilege | Run as Administrator |
| SECURITY never reports failed logins | Security log access denied | Run as Administrator; verify audit policy logs event 4625 |
| FIREWALL is silent | Firewall logging disabled | Enable logging for the active profile in Windows Defender Firewall with Advanced Security |
| `ModuleNotFoundError` right at start | Running a stale/partial copy | Re-run `python rolling_log_monitor.py --help` to confirm the file is intact |
| Log file keeps growing | Rotation only triggers above ~9.5 MiB and every 1,000 events | Lower `FileLogger(max_size=…)` or prune rotated `*_YYYYmmdd_HHMMSS.log` files yourself |
| My HTML files vanished | `_delete_html()` ran at startup | Always pass `--no-html-delete`; restore from Recycle Bin only if the files were deleted by Explorer, not by this script (it uses `unlink()`, which is permanent) |
| Event lines are cut off at `...` | 120-column hard truncation | Press `D` to hide the data payload, or raise `RollingLogDisplay(width=…)` |
| High CPU | Too many subprocess-backed monitors | Disable `--no-services --no-service-detail --no-drivers --no-tasks --no-print --no-defender --no-security` |

---

## Project Layout

```
realtime-monitor-windowscomputer/
├── rolling_log_monitor.py   # The entire application — 2,306 lines, no local imports
├── run_monitor.bat          # Convenience launcher: cd to script dir, run, pause
└── README.md                # This file
```

Internal section order of `rolling_log_monitor.py`:

| Lines (approx.) | Section |
|---|---|
| 1–70 | Console VT setup, ANSI constants, `Severity` |
| 71–160 | `Event`, `EventBus` |
| 160–250 | `Statistics`, `FileLogger`, `BaseMonitor` |
| 275–1607 | The 33 monitor classes |
| 1612–1745 | `RollingLogDisplay` |
| 1749–2009 | `InputHandler` (keys, prompts, help screen) |
| 2014–2300 | `RollingLogMonitor` (args, wiring, run/stop) |
| 2301–2306 | `main()` entry point |

---

## Disclaimer

Provided as-is, for diagnostic and educational use on systems you own or are explicitly
authorised to monitor. There is no warranty. Reviewing the source before running it is
strongly recommended — it reads registry keys, tails system logs, enumerates processes and
connections, inspects the clipboard, and deletes `*.html` files from its working directory at
startup.
