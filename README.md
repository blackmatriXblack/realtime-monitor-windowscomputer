# Windows Monitor

Comprehensive real-time Windows system monitoring with rolling log display.

## Features

### 100+ Monitors

#### System Monitoring
- **DNS** - Real DNS queries with IP resolution
- **PROCESS** - Process start/end with command lines
- **PROCESS_TREE** - Process parent-child relationships
- **NETWORK** - Connections, traffic, ARP table
- **SYSTEM** - CPU, RAM, Swap, Disk
- **CPU_CORE** - Per-core CPU usage
- **BANDWIDTH** - Network bandwidth usage
- **PROC_RES** - Top resource processes

#### Windows Services
- **SERVICE** - Windows service state changes
- **SERVICE_DETAIL** - Detailed service monitoring
- **FIREWALL** - Firewall packet events
- **FW_RULES** - Firewall rules changes

#### Event Logging
- **EVENTLOG** - Windows Event Log entries
- **EVENTLOG_CH** - Event log channels
- **WEF** - Windows Event Forwarding
- **WER** - Windows Error Reporting
- **WER_DETAIL** - Detailed WER reports

#### Security
- **DEFENDER** - Windows Defender status
- **DEF_EXCL** - Defender exclusions
- **DEF_SCAN** - Defender scans
- **DEF_BEHAV** - Defender behavior
- **DEF_ATP** - Defender ATP alerts
- **THREAT** - Suspicious process detection
- **UAC** - UAC settings
- **SMARTSCREEN** - SmartScreen status
- **HELLO** - Windows Hello/BitLocker
- **TPM_BL** - TPM/BitLocker
- **LAPS** - LAPS passwords
- **CRED** - Credential manager
- **AUTORUN** - Autorun entries
- **APPLOCKER** - AppLocker events
- **APPCOMPAT** - App compatibility
- **SECURITY** - Failed login attempts

#### Registry & Configuration
- **REGISTRY** - Registry changes
- **WMI** - WMI events
- **HOSTS** - Hosts file changes
- **PROXY** - Proxy settings
- **AUTOPILOT** - Autopilot status
- **GP** - Group Policy changes
- **BOOT** - Boot configuration
- **TZ** - Timezone changes

#### Hardware
- **DEVICE** - USB device changes
- **USB_DETAIL** - Detailed USB devices
- **DRIVER** - Driver load/unload
- **BATTERY** - Battery status and charge
- **TEMP** - CPU/GPU temperature
- **DISK_HEALTH** - Disk SMART status
- **FAN** - Fan speed
- **THERMAL** - Thermal zones
- **GPU** - GPU info
- **DISPLAY** - Display settings
- **AUDIO** - Audio devices
- **BT** - Bluetooth
- **PRINTER** - Printer queue

#### Network
- **LAN** - LAN device discovery
- **WIFI** - WiFi network profiles
- **SHARE** - Network share changes
- **NETADAPTER** - Network adapters
- **TCPSTATS** - TCP statistics
- **NET_CONN** - New network connections
- **NETPROF** - Network profiles
- **DNS_CACHE** - DNS cache
- **PORT** - Port monitoring
- **WEB** - Website availability

#### Files & Applications
- **FILE** - File changes
- **DIR** - Directory changes
- **APPLICATION** - Application log changes
- **RECENT** - Recent documents
- **JUMPLIST** - Jump lists
- **TYPEDURL** - Typed URLs
- **USERASSIST** - User assist
- **BAGMRU** - Bag MRU
- **PREFETCH** - Prefetch files
- **AMCACHE** - Amcache
- **LOGTAIL** - Log file tailing

#### Windows Features
- **WUPDATE** - Windows updates
- **WU_LOG** - Windows Update log
- **WU_TELE** - Update telemetry
- **FEATUPDATE** - Feature updates
- **SOFTWARE** - Installed software
- **WINFEAT** - Windows features
- **STORE_APPS** - Store apps
- **RECOVERY** - Recovery status
- **SANDBOX** - Windows Sandbox
- **WSL** - WSL distros
- **DOCKER** - Docker containers
- **HYPERV** - Hyper-V VMs
- **IIS** - IIS websites
- **SQL** - SQL Server services
- **EXCHANGE** - Exchange services
- **AD** - Active Directory events

#### Advanced
- **POWERSHELL** - PowerShell execution
- **WINRM** - WinRM events
- **SYSMON** - Sysmon events
- **SCHED_TASK** - Scheduled tasks
- **TASK_EXEC** - Task execution
- **CLOUD** - Cloud sync (OneDrive, Dropbox, Google Drive)
- **WAC** - Windows Admin Center
- **WPR** - Windows Performance Recorder
- **MEMDIAG** - Memory diagnostic
- **RESET** - Windows Reset
- **CRYPTO** - Crypto keys
- **CERT** - Certificates
- **SETUPAPI** - SetupAPI log
- **PERFMON** - Performance counters

### Rich Event Details
Every event includes:
- Timestamp with millisecond precision
- Source monitor name
- Event category
- Severity level (DEBUG/INFO/NOTICE/WARNING/ERROR/CRITICAL)
- Detailed message
- Structured data fields with location information
- Bookmark and highlight support

### Multiple View Modes
- **Normal** - Standard scrolling log
- **Dashboard** - Statistics overview
- **Alerts** - Filtered warnings and errors
- **Tree** - Process tree view
- **Compact** - Condensed one-line format

### Advanced Features
- **Dated Folder Logging** - Organize logs by date and time
- **30-Day Auto-Cleanup** - Automatic log rotation and cleanup
- **Auto-Start** - Add to Windows startup
- **EXE Build** - Compile to standalone executable
- **Sound Alerts** - Audio alerts for warnings and errors
- **Event Export** - Export to JSON/CSV
- **Full-Screen Display** - No gaps, continuous scrolling
- **Slow Mode** - Comfortable reading speed
- **Event Deduplication** - 5-second window to reduce noise
- **Regex Search** - Advanced text filtering
- **Source Filtering** - Filter by monitor source
- **Bookmarks** - Mark important events
- **Highlights** - Highlight specific sources

## Installation

```bash
pip install windows-monitor
```

## Quick Start

```bash
# Run with all monitors
windows-monitor

# Run with specific monitors disabled
windows-monitor --no-dns --no-services

# Enable dated folder logging
windows-monitor --log-dir D:/RollingLogMonitor

# Auto-start on boot
windows-monitor --auto-start

# Build EXE
windows-monitor --build-exe
```

## Controls

- `↑/↓` - Scroll up/down
- `PgUp/PgDn` - Page scroll
- `Home/End` - Jump to newest/oldest
- `Enter` - View event detail
- `Space` - Pause/resume
- `C` - Clear events
- `D` - Toggle data display
- `M` - Toggle compact mode
- `B` - Bookmark event
- `A` - Toggle alerts
- `E` - Export events
- `V` - Cycle view mode
- `F` - Filter by source
- `S` - Quick source filter
- `/` - Search text
- `H` - Help
- `Q` - Quit

## Configuration

Create a `config.json` file:

```json
{
  "interval": 1.0,
  "max_lines": 100,
  "domains": ["google.com", "github.com"],
  "disabled": ["dns", "browser"]
}
```

Run with: `windows-monitor --config config.json`

## Log Structure

```
D:/RollingLogMonitor/
├── 2024-01-01/
│   ├── 10-30-00/
│   │   ├── dns.log
│   │   ├── process.log
│   │   └── network.log
│   └── 10-31-00/
│       └── ...
└── 2024-01-02/
    └── ...
```

## Requirements

- Windows 10/11
- Python 3.8+
- psutil

## Building from Source

```bash
git clone https://github.com/example/windows-monitor.git
cd windows-monitor
pip install -e .
```

## Building EXE

```bash
pip install windows-monitor[exe]
windows-monitor --build-exe
```

## License

MIT

