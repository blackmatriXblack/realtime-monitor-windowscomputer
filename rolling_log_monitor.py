"""
Rolling Log Monitor - Comprehensive real-time monitoring with rolling log display.
Monitors: DNS, Processes, Network, Files, Registry, WMI, Event Logs, Services,
Firewall, System, Devices, USB, Scheduled Tasks, Security, Application logs,
Clipboard, Input, Browser, Idle, Power, Threat, API, Defender, MRU, Screenshot,
Print, Drivers, Process Tree, Network Shares, WiFi, LAN.
Single-file, auto-run, real data, minimalist black/white design.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime
import ipaddress
import locale
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Pattern, Tuple

# ============================================================
# Console Setup
# ============================================================
if sys.platform == "win32":
    try:
        _k32 = ctypes.windll.kernel32
        _h = _k32.GetStdHandle(-11)
        _m = ctypes.c_uint32()
        _k32.GetConsoleMode(_h, ctypes.byref(_m))
        _m.value |= 0x0004
        _k32.SetConsoleMode(_h, _m)
    except Exception:
        pass

RST = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
UL = "\033[4m"

# ============================================================
# Severity
# ============================================================
class Severity:
    DEBUG = 0
    INFO = 1
    NOTICE = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5

SEV_NAME = {
    Severity.DEBUG: "DEBUG",
    Severity.INFO: "INFO",
    Severity.NOTICE: "NOTICE",
    Severity.WARNING: "WARNING",
    Severity.ERROR: "ERROR",
    Severity.CRITICAL: "CRITICAL",
}

# ============================================================
# Event
# ============================================================
class Event:
    """Unified event."""
    __slots__ = ("ts", "source", "category", "message", "severity", "data", "_seq")
    
    def __init__(self, source: str, category: str, message: str,
                 severity: int = Severity.INFO, data: Dict[str, Any] = None):
        self.ts = time.time()
        self.source = source
        self.category = category
        self.message = message
        self.severity = severity
        self.data = data or {}
        self._seq = 0
    
    def time_str(self) -> str:
        return datetime.datetime.fromtimestamp(self.ts).strftime("%H:%M:%S.%f")[:-3]
    
    def date_str(self) -> str:
        return datetime.datetime.fromtimestamp(self.ts).strftime("%Y-%m-%d")
    
    def line(self, show_data: bool = True, width: int = 120) -> str:
        icons = {
            "DNS": "→", "PROCESS": "⚙", "NETWORK": "🌐", "FILE": "📁",
            "SYSTEM": "💻", "SERVICE": "🔧", "SEARCH": "🔍", "FIREWALL": "🛡",
            "STARTUP": "🚀", "POWER": "⚡", "USER": "👤", "DEVICE": "🔌",
            "CLIPBOARD": "📋", "THREAT": "⚠", "LAN": "🏠", "WIFI": "📶",
            "SHARE": "📡", "IDLE": "😴", "API": "🔌", "DEFENDER": "🛡",
            "BROWSER": "🌍", "CONFIG": "⚙", "STATS": "📊", "ERROR": "!",
            "MONITOR": "👁", "REGISTRY": "📝", "WMI": "🔍", "EVENTLOG": "📋",
            "USB": "🔌", "TASK": "📅", "MODULE": "📦", "MEMORY": "💾",
            "HANDLE": "✋", "THREAD": "🧵", "IMAGE": "🖼", "DRIVER": "⚙",
        }
        icon = icons.get(self.source, "•")
        s = f"[{self.time_str()}] {icon} {self.source:<10} {self.message}"
        
        if show_data and self.data:
            parts = []
            for k, v in self.data.items():
                if isinstance(v, (list, tuple)) and len(v) > 3:
                    parts.append(f"{k}: {','.join(str(x) for x in v[:2])}...")
                else:
                    parts.append(f"{k}={v}")
            data_str = " | ".join(parts)
            if len(data_str) > 60:
                data_str = data_str[:57] + "..."
            s += f" | {data_str}"
        
        if len(s) > width:
            s = s[:width-3] + "..."
        return s
    
    def as_log(self) -> str:
        return (f"{self.date_str()} {self.time_str()} | "
                f"{SEV_NAME.get(self.severity, 'INFO'):<8} | "
                f"{self.source:<10} | {self.category:<12} | {self.message}")

# ============================================================
# Event Bus
# ============================================================
class EventBus:
    def __init__(self, maxsize: int = 10000):
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=maxsize)
        self._subs: List[Callable[[Event], None]] = []
        self._lock = threading.Lock()
        self._seq = 0
    
    def subscribe(self, cb: Callable[[Event], None]):
        with self._lock:
            self._subs.append(cb)
    
    def unsubscribe(self, cb: Callable[[Event], None]):
        with self._lock:
            self._subs = [s for s in self._subs if s != cb]
    
    def publish(self, event: Event):
        with self._lock:
            self._seq += 1
            event._seq = self._seq
        for cb in list(self._subs):
            try:
                cb(event)
            except Exception:
                pass
    
    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._seq

# ============================================================
# Statistics
# ============================================================
class Statistics:
    def __init__(self):
        self.start = time.time()
        self.total_events = 0
        self.by_severity: Counter = Counter()
        self.by_source: Counter = Counter()
        self.by_category: Counter = Counter()
        self.recent: Deque[float] = deque(maxlen=600)
        self.qps = 0.0
        self._lock = threading.Lock()
    
    def record(self, event: Event):
        with self._lock:
            self.total_events += 1
            self.by_severity[event.severity] += 1
            self.by_source[event.source] += 1
            self.by_category[event.category] += 1
            self.recent.append(event.ts)
    
    def update_qps(self):
        with self._lock:
            now = time.time()
            cutoff = now - 1.0
            self.qps = sum(1 for t in self.recent if t > cutoff)
    
    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            up = time.time() - self.start
            return {
                "uptime": up,
                "total": self.total_events,
                "qps": self.qps,
                "by_severity": dict(self.by_severity),
                "by_source": dict(self.by_source.most_common(10)),
                "by_category": dict(self.by_category.most_common(10)),
            }
    
    def fmt_uptime(self, secs: float) -> str:
        h, r = divmod(int(secs), 3600)
        m, s = divmod(r, 60)
        if h:
            return f"{h}h{m:02d}m{s:02d}s"
        if m:
            return f"{m}m{s:02d}s"
        return f"{s}s"

# ============================================================
# File Logger
# ============================================================
class FileLogger:
    def __init__(self, path: Path, max_size: int = 10_000_000):
        self.path = path
        self.max_size = max_size
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._count = 0
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(f"# Rolling Log Monitor - Started {datetime.datetime.now()}\n")
            f.write("# Format: DATE TIME | SEVERITY | SOURCE | CATEGORY | MESSAGE\n")
            f.write("#" * 100 + "\n\n")
    
    def write(self, event: Event):
        with self._lock:
            try:
                line = event.as_log() + "\n"
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
                self._count += 1
                if self._count % 1000 == 0:
                    if self.path.stat().st_size > self.max_size:
                        self._rotate()
            except Exception:
                pass
    
    def _rotate(self):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        rotated = self.path.with_name(f"{self.path.stem}_{ts}{self.path.suffix}")
        try:
            self.path.rename(rotated)
        except Exception:
            pass
    
    def close(self):
        pass

# ============================================================
# Base Monitor
# ============================================================
class BaseMonitor:
    def __init__(self, name: str, bus: EventBus, interval: float = 2.0):
        self.name = name
        self.bus = bus
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
    
    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
    
    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
    
    def _run(self):
        raise NotImplementedError

# ============================================================
# DNS Monitor
# ============================================================
class DnsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 2.0, domains: List[str] = None):
        super().__init__("DNS", bus, interval)
        self.domains = domains or [
            "google.com", "github.com", "microsoft.com", "cloudflare.com",
            "amazon.com", "facebook.com", "netflix.com", "youtube.com",
            "wikipedia.org", "stackoverflow.com", "reddit.com", "twitter.com",
            "linkedin.com", "apple.com", "adobe.com", "oracle.com",
            "ibm.com", "intel.com", "cisco.com", "dell.com", "hp.com",
            "python.org", "mozilla.org", "nginx.org", "docker.com",
            "kubernetes.io", "rust-lang.org", "golang.org", "nodejs.org",
            "apache.org", "linux.org", "ubuntu.com", "debian.org",
            "fedora.org", "redhat.com", "centos.org", "archlinux.org",
        ]
        self._cache: Dict[str, Tuple[List[str], List[str], float]] = {}
        self._ttl = 300.0
        self._lock = threading.Lock()
    
    def _resolve(self, domain: str) -> Tuple[List[str], List[str]]:
        now = time.time()
        with self._lock:
            if domain in self._cache:
                v4, v6, ts = self._cache[domain]
                if now - ts < self._ttl:
                    return v4, v6
        
        v4, v6 = [], []
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_INET)
            v4 = list(set(a[4][0] for a in info))
        except Exception:
            pass
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_INET6)
            v6 = list(set(a[4][0] for a in info))
        except Exception:
            pass
        
        with self._lock:
            self._cache[domain] = (v4, v6, now)
            if len(self._cache) > 500:
                old = sorted(self._cache.items(), key=lambda x: x[1][2])
                for k, _ in old[:50]:
                    del self._cache[k]
        return v4, v6
    
    def _run(self):
        import random
        while not self._stop.is_set():
            try:
                domain = random.choice(self.domains)
                self.bus.publish(Event("DNS", "QUERY", f"Querying {domain}",
                                       severity=Severity.DEBUG, data={"domain": domain}))
                
                v4, v6 = self._resolve(domain)
                ok = bool(v4 or v6)
                
                detail = ""
                if v4:
                    detail += f"IPv4: {', '.join(v4[:2])}"
                if v6:
                    detail += f" IPv6: {', '.join(v6[:2])}"
                if not ok:
                    detail = "Resolution failed"
                
                sev = Severity.INFO if ok else Severity.WARNING
                msg = f"{'Resolved' if ok else 'Failed'}: {domain}"
                self.bus.publish(Event("DNS", "RESULT", msg, severity=sev,
                                       data={"domain": domain, "ipv4": v4, "ipv6": v6}))
                time.sleep(self.interval)
            except Exception as e:
                self.bus.publish(Event("DNS", "ERROR", str(e), severity=Severity.ERROR))
                time.sleep(1.0)

# ============================================================
# Process Monitor
# ============================================================
class ProcessMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 3.0):
        super().__init__("PROCESS", bus, interval)
        self._prev_procs: Dict[int, str] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                current = {}
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                    try:
                        info = proc.info
                        current[info['pid']] = {
                            'name': info['name'],
                            'cmdline': ' '.join(info['cmdline'] or []),
                            'user': info['username'] or ''
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                for pid, info in current.items():
                    if pid not in self._prev_procs:
                        self.bus.publish(Event("PROCESS", "START",
                                               f"Process started: {info['name']} (PID {pid})",
                                               severity=Severity.INFO,
                                               data={"pid": pid, "name": info['name'],
                                                     "cmdline": info['cmdline'][:100],
                                                     "user": info['user']}))
                
                for pid, info in self._prev_procs.items():
                    if pid not in current:
                        self.bus.publish(Event("PROCESS", "END",
                                               f"Process ended: {info['name']} (PID {pid})",
                                               severity=Severity.INFO,
                                               data={"pid": pid, "name": info['name']}))
                
                self._prev_procs = {k: v for k, v in current.items()}
                time.sleep(self.interval)
            except ImportError:
                self.bus.publish(Event("PROCESS", "ERROR",
                                       "psutil not installed",
                                       severity=Severity.WARNING))
                break
            except Exception as e:
                self.bus.publish(Event("PROCESS", "ERROR", str(e), severity=Severity.ERROR))
                time.sleep(5.0)

# ============================================================
# Network Monitor
# ============================================================
class NetworkMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 3.0):
        super().__init__("NETWORK", bus, interval)
        self._prev_conns: Set[str] = set()
        self._prev_stats: Dict[str, int] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                current = set()
                
                # Connections
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "*:*"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*:*"
                        key = f"{laddr}->{raddr}:{conn.status}"
                        current.add(key)
                        
                        if key not in self._prev_conns:
                            pid = conn.pid if conn.pid else 0
                            self.bus.publish(Event("NETWORK", "CONN",
                                                   f"Connection: {laddr} -> {raddr} [{conn.status}]",
                                                   severity=Severity.INFO,
                                                   data={"local": laddr, "remote": raddr,
                                                         "status": conn.status, "pid": pid}))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Network interface stats
                try:
                    stats = psutil.net_io_counters(pernic=True)
                    for iface, stat in stats.items():
                        key = f"{iface}:{stat.bytes_sent}:{stat.bytes_recv}"
                        if key != self._prev_stats.get(iface):
                            self.bus.publish(Event("NETWORK", "TRAFFIC",
                                                   f"{iface}: {stat.bytes_sent} sent, {stat.bytes_recv} recv",
                                                   severity=Severity.DEBUG,
                                                   data={"iface": iface,
                                                         "bytes_sent": stat.bytes_sent,
                                                         "bytes_recv": stat.bytes_recv,
                                                         "packets_sent": stat.packets_sent,
                                                         "packets_recv": stat.packets_recv}))
                            self._prev_stats[iface] = key
                except Exception:
                    pass
                
                self._prev_conns = current
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception as e:
                self.bus.publish(Event("NETWORK", "ERROR", str(e), severity=Severity.ERROR))
                time.sleep(5.0)

# ============================================================
# System Monitor
# ============================================================
class SystemMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 5.0):
        super().__init__("SYSTEM", bus, interval)
        self._prev_cpu = None
        self._prev_mem = None
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                swap = psutil.swap_memory()
                disk = psutil.disk_usage('/')
                
                # CPU detail
                cpu_times = psutil.cpu_times_percent()
                cpu_detail = f"user:{cpu_times.user:.1f}% sys:{cpu_times.system:.1f}% idle:{cpu_times.idle:.1f}%"
                
                self.bus.publish(Event("SYSTEM", "STATS",
                                       f"CPU:{cpu}% RAM:{mem.percent}% Swap:{swap.percent}% Disk:{disk.percent}%",
                                       severity=Severity.INFO if cpu < 90 else Severity.WARNING,
                                       data={"cpu": cpu, "memory": mem.percent,
                                             "swap": swap.percent, "disk": disk.percent,
                                             "cpu_detail": cpu_detail,
                                             "mem_total": mem.total, "mem_used": mem.used}))
                
                # Memory detail
                if mem.percent > 90:
                    self.bus.publish(Event("SYSTEM", "MEMORY_HIGH",
                                           f"Memory usage critical: {mem.percent}%",
                                           severity=Severity.WARNING,
                                           data={"memory": mem.percent}))
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception as e:
                self.bus.publish(Event("SYSTEM", "ERROR", str(e), severity=Severity.ERROR))
                time.sleep(5.0)

# ============================================================
# Service Monitor
# ============================================================
class ServiceMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("SERVICE", bus, interval)
        self._prev_services: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["sc", "query", "type=", "service", "state=", "all"],
                                       capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                current = {}
                name = None
                for line in result.stdout.splitlines():
                    if line.startswith("SERVICE_NAME:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("STATE:") and name:
                        state = line.split(":", 1)[1].strip()
                        current[name] = state
                
                for name, state in current.items():
                    if name not in self._prev_services:
                        self.bus.publish(Event("SERVICE", "START",
                                               f"Service {name}: {state}",
                                               severity=Severity.INFO,
                                               data={"service": name, "state": state}))
                    elif self._prev_services[name] != state:
                        self.bus.publish(Event("SERVICE", "CHANGE",
                                               f"Service {name}: {self._prev_services[name]} -> {state}",
                                               severity=Severity.NOTICE,
                                               data={"service": name, "state": state}))
                
                self._prev_services = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Firewall Monitor
# ============================================================
class FirewallMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("FIREWALL", bus, interval)
        self._last_size = 0
        self._log_path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "LogFiles" / "Firewall" / "pfirewall.log"
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                if self._log_path.exists():
                    size = self._log_path.stat().st_size
                    if size > self._last_size:
                        with open(self._log_path, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(self._last_size)
                            new_data = f.read()
                            self._last_size = size
                            
                            for line in new_data.splitlines():
                                if "DROP" in line or "ALLOW" in line:
                                    parts = line.split()
                                    if len(parts) >= 10:
                                        action = "DROP" if "DROP" in line else "ALLOW"
                                        sev = Severity.WARNING if action == "DROP" else Severity.INFO
                                        self.bus.publish(Event("FIREWALL", action,
                                                               f"Firewall {action} packet",
                                                               severity=sev,
                                                               data={"raw": line[:100]}))
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Event Log Monitor
# ============================================================
class EventLogMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("EVENTLOG", bus, interval)
        self._prev_records: Dict[int, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import win32evtlog
                import win32evtlogutil
                
                log_types = ["Application", "System", "Security"]
                for log_type in log_types:
                    try:
                        hand = win32evtlog.OpenEventLog(None, log_type)
                        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                        events = win32evtlog.ReadEventLog(hand, flags, 0)
                        
                        for event in events[:10]:  # Last 10 events
                            eid = event.EventID & 0xFFFF
                            sid = event.RecordNumber
                            
                            if sid not in self._prev_records:
                                sev = Severity.INFO
                                if event.EventType in (win32evtlog.EVENTLOG_ERROR_TYPE,):
                                    sev = Severity.ERROR
                                elif event.EventType in (win32evtlog.EVENTLOG_WARNING_TYPE,):
                                    sev = Severity.WARNING
                                
                                self.bus.publish(Event("EVENTLOG", log_type.upper(),
                                                       f"Event {eid}: {event.SourceName}",
                                                       severity=sev,
                                                       data={"event_id": eid, "source": event.SourceName,
                                                             "type": event.EventType, "record": sid}))
                        
                        self._prev_records = {e.RecordNumber: str(e.EventID) for e in events[:10]}
                        win32evtlog.CloseEventLog(hand)
                    except Exception:
                        pass
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# Registry Monitor
# ============================================================
class RegistryMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("REGISTRY", bus, interval)
        self._watch_paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"SYSTEM\CurrentControlSet\Services",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        ]
        self._prev_values: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import winreg
                
                for path in self._watch_paths:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                full_path = f"{path}\\{name}"
                                if full_path not in self._prev_values:
                                    self.bus.publish(Event("REGISTRY", "CHANGE",
                                                           f"Registry value added: {name}",
                                                           severity=Severity.INFO,
                                                           data={"path": full_path, "value": str(value)[:100]}))
                                elif self._prev_values[full_path] != str(value):
                                    self.bus.publish(Event("REGISTRY", "CHANGE",
                                                           f"Registry value changed: {name}",
                                                           severity=Severity.NOTICE,
                                                           data={"path": full_path, "value": str(value)[:100]}))
                                self._prev_values[full_path] = str(value)
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except Exception:
                        pass
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# WMI Monitor
# ============================================================
class WmiMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WMI", bus, interval)
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import wmi
                c = wmi.WMI()
                
                # Process start/end via WMI events
                try:
                    watcher = c.Win32_ProcessStartTrace
                    for event in watcher():
                        try:
                            pid = event.ProcessID
                            name = event.ProcessName or "Unknown"
                            cmdline = event.CommandLine or ""
                            self.bus.publish(Event("WMI", "PROCESS_START",
                                                   f"WMI: Process started {name} (PID {pid})",
                                                   severity=Severity.INFO,
                                                   data={"pid": pid, "name": name,
                                                         "cmdline": cmdline[:100]}))
                        except Exception:
                            pass
                except Exception:
                    pass
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# USB/Device Monitor
# ============================================================
class DeviceMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("DEVICE", bus, interval)
        self._prev_devices: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["powershell", "-Command",
                                        "Get-PnpDevice -Class USB | Select-Object -Property FriendlyName,InstanceId,Status"],
                                       capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                
                current = set()
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("FriendlyName"):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            device_id = parts[-1]
                            status = parts[-2] if len(parts) > 2 else "Unknown"
                            current.add(f"{device_id}:{status}")
                            
                            if device_id not in self._prev_devices:
                                self.bus.publish(Event("DEVICE", "USB",
                                                       f"USB device: {line.strip()[:50]}",
                                                       severity=Severity.INFO,
                                                       data={"device": line.strip()[:100],
                                                             "status": status}))
                
                self._prev_devices = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Scheduled Task Monitor
# ============================================================
class TaskMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("TASK", bus, interval)
        self._prev_tasks: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["schtasks", "/query", "/fo", "CSV", "/nh"],
                                       capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                
                current = {}
                for line in result.stdout.splitlines():
                    parts = line.split(",")
                    if len(parts) >= 2:
                        task_name = parts[0].strip('"')
                        task_status = parts[1].strip('"') if len(parts) > 1 else "Unknown"
                        current[task_name] = task_status
                        
                        if task_name not in self._prev_tasks:
                            self.bus.publish(Event("TASK", "CREATED",
                                                   f"Scheduled task: {task_name}",
                                                   severity=Severity.INFO,
                                                   data={"task": task_name, "status": task_status}))
                        elif self._prev_tasks[task_name] != task_status:
                            self.bus.publish(Event("TASK", "CHANGED",
                                                   f"Task status changed: {task_name}",
                                                   severity=Severity.NOTICE,
                                                   data={"task": task_name,
                                                         "status": task_status}))
                
                self._prev_tasks = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Application Log Monitor
# ============================================================
class ApplicationLogMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("APPLICATION", bus, interval)
        self._log_paths = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "INetCache",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Windows" / "Explorer" / "ThumbCacheToDelete",
        ]
        self._prev_sizes: Dict[str, int] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                for log_path in self._log_paths:
                    if log_path.exists():
                        try:
                            files = list(log_path.glob("*"))
                            for f in files:
                                try:
                                    size = f.stat().st_size
                                    key = str(f)
                                    if key not in self._prev_sizes:
                                        self.bus.publish(Event("APPLICATION", "LOG",
                                                               f"Application log file: {f.name}",
                                                               severity=Severity.DEBUG,
                                                               data={"file": str(f)[:100],
                                                                     "size": size}))
                                    elif size != self._prev_sizes[key]:
                                        self.bus.publish(Event("APPLICATION", "LOG_CHANGE",
                                                               f"Log updated: {f.name}",
                                                               severity=Severity.DEBUG,
                                                               data={"file": str(f)[:100],
                                                                     "old_size": self._prev_sizes[key],
                                                                     "new_size": size}))
                                    self._prev_sizes[key] = size
                                except Exception:
                                    pass
                        except Exception:
                            pass
                
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Security Monitor
# ============================================================
class SecurityMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("SECURITY", bus, interval)
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                # Check failed login attempts via event log
                result = subprocess.run(["powershell", "-Command",
                                        "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 5 | Select-Object TimeCreated,Id,Message"],
                                       capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                
                for line in result.stdout.splitlines():
                    if "4625" in line or "failed" in line.lower():
                        self.bus.publish(Event("SECURITY", "FAILED_LOGIN",
                                               "Failed login attempt detected",
                                               severity=Severity.WARNING,
                                               data={"event": line[:100]}))
                
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Memory/Handle Monitor
# ============================================================
class MemoryMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("MEMORY", bus, interval)
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                mem = psutil.virtual_memory()
                
                # Memory usage by process
                for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                    try:
                        info = proc.info
                        rss = info['memory_info'].rss if info['memory_info'] else 0
                        if rss > 100 * 1024 * 1024:  # > 100MB
                            self.bus.publish(Event("MEMORY", "HIGH_USAGE",
                                                   f"High memory: {info['name']} (PID {info['pid']}) {rss//1024//1024}MB",
                                                   severity=Severity.INFO if rss < 500*1024*1024 else Severity.WARNING,
                                                   data={"pid": info['pid'], "name": info['name'],
                                                         "rss_mb": rss // 1024 // 1024}))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Module Monitor
# ============================================================
class ModuleMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("MODULE", bus, interval)
        self._prev_modules: Dict[str, int] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                for proc in psutil.process_iter(['pid', 'name', 'memory_maps']):
                    try:
                        for mmap in proc.memory_maps(grouped=False):
                            if mmap.path:
                                if mmap.path not in self._prev_modules:
                                    self.bus.publish(Event("MODULE", "LOAD",
                                                           f"Module loaded: {Path(mmap.path).name}",
                                                           severity=Severity.DEBUG,
                                                           data={"path": mmap.path[:100],
                                                                 "pid": proc.pid}))
                        self._prev_modules = {m.path: m.size for m in proc.memory_maps(grouped=False) if m.path}
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# ARP Table Monitor
# ============================================================
class ArpMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("ARP", bus, interval)
        self._prev_entries: Dict[str, str] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                result = subprocess.run(["arp", "-a"], capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Interface"):
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[1]
                            current[ip] = mac
                            
                            if ip not in self._prev_entries:
                                self.bus.publish(Event("ARP", "NEW",
                                                       f"ARP entry: {ip} -> {mac}",
                                                       severity=Severity.INFO,
                                                       data={"ip": ip, "mac": mac}))
                            elif self._prev_entries[ip] != mac:
                                self.bus.publish(Event("ARP", "CHANGE",
                                                       f"ARP changed: {ip} {self._prev_entries[ip]} -> {mac}",
                                                       severity=Severity.NOTICE,
                                                       data={"ip": ip, "old_mac": self._prev_entries[ip],
                                                             "new_mac": mac}))
                
                self._prev_entries = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Clipboard Monitor
# ============================================================
class ClipboardMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 2.0, max_chars: int = 200):
        super().__init__("CLIPBOARD", bus, interval)
        self._prev_text = ""
        self._max_chars = max_chars
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import win32con
                import win32clipboard
                win32clipboard.OpenClipboard()
                try:
                    if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                        text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT) or ""
                    else:
                        text = ""
                finally:
                    win32clipboard.CloseClipboard()
                
                if text and text != self._prev_text:
                    display = text[:self._max_chars]
                    if len(text) > self._max_chars:
                        display += "..."
                    self.bus.publish(Event("CLIPBOARD", "CHANGE",
                                           f"Clipboard: {display}",
                                           severity=Severity.INFO,
                                           data={"text": text[:200]}))
                    self._prev_text = text
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Input Monitor
# ============================================================
class InputMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 5.0, capture_text: bool = True):
        super().__init__("INPUT", bus, interval)
        self._capture_text = capture_text
        self._key_count = 0
        self._mouse_count = 0
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                # Simple input activity monitor using GetLastInputInfo
                import win32api
                last_input = win32api.GetLastInputInfo()
                idle_time = (win32api.GetTickCount() - last_input) / 1000.0
                
                if idle_time < 1.0:
                    self._key_count += 1
                    self._mouse_count += 1
                    
                    if self._key_count % 10 == 0:
                        self.bus.publish(Event("INPUT", "ACTIVITY",
                                               f"Input activity detected (keys: {self._key_count}, mouse: {self._mouse_count})",
                                               severity=Severity.DEBUG,
                                               data={"idle_seconds": idle_time,
                                                     "key_count": self._key_count,
                                                     "mouse_count": self._mouse_count}))
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Browser History Monitor
# ============================================================
class BrowserHistoryMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("BROWSER", bus, interval)
        self._prev_urls: Dict[str, float] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                # Check common browser history databases
                history_paths = [
                    Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "History",
                    Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
                    Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles",
                ]
                
                for hist_path in history_paths:
                    if hist_path.exists():
                        try:
                            if hist_path.is_file():
                                size = hist_path.stat().st_size
                                mtime = hist_path.stat().st_mtime
                                key = str(hist_path)
                                
                                if key not in self._prev_urls or self._prev_urls[key] != mtime:
                                    self.bus.publish(Event("BROWSER", "HISTORY",
                                                           f"Browser history updated: {hist_path.name}",
                                                           severity=Severity.DEBUG,
                                                           data={"file": str(hist_path),
                                                                 "size": size, "mtime": mtime}))
                                    self._prev_urls[key] = mtime
                        except Exception:
                            pass
                
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Idle Monitor
# ============================================================
class IdleMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 5.0):
        super().__init__("IDLE", bus, interval)
        self._was_idle = False
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import win32api
                last_input = win32api.GetLastInputInfo()
                idle_time = (win32api.GetTickCount() - last_input) / 1000.0
                
                is_idle = idle_time > 60.0
                
                if is_idle != self._was_idle:
                    state = "IDLE" if is_idle else "ACTIVE"
                    sev = Severity.INFO if is_idle else Severity.NOTICE
                    self.bus.publish(Event("IDLE", state,
                                           f"System state changed to {state} (idle {idle_time:.0f}s)",
                                           severity=sev,
                                           data={"idle_seconds": idle_time, "state": state}))
                    self._was_idle = is_idle
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Power Monitor
# ============================================================
class PowerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("POWER", bus, interval)
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import win32api
                import win32con
                
                # Check battery status
                try:
                    battery = win32api.GetSystemPowerStatus()
                    if battery:
                        ac_status = battery["ACLineStatus"]
                        battery_level = battery["BatteryLife"]
                        battery_flag = battery["BatteryFlag"]
                        
                        status = "AC" if ac_status == 1 else "BATTERY"
                        self.bus.publish(Event("POWER", "STATUS",
                                               f"Power: {status} | Battery: {battery_level}%",
                                               severity=Severity.INFO,
                                               data={"ac": ac_status, "battery": battery_level,
                                                     "flag": battery_flag}))
                except Exception:
                    pass
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# Threat Monitor
# ============================================================
class ThreatMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("THREAT", bus, interval)
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                # Check for suspicious processes
                import psutil
                suspicious_names = ["keylogger", "rat", "trojan", "backdoor", "miner", "cryptonight"]
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        name = proc.info['name'].lower()
                        cmdline = ' '.join(proc.info['cmdline'] or []).lower()
                        
                        for sus in suspicious_names:
                            if sus in name or sus in cmdline:
                                self.bus.publish(Event("THREAT", "SUSPICIOUS",
                                                       f"Suspicious process: {proc.info['name']} (PID {proc.info['pid']})",
                                                       severity=Severity.WARNING,
                                                       data={"pid": proc.info['pid'],
                                                             "name": proc.info['name'],
                                                             "cmdline": ' '.join(proc.info['cmdline'] or [])[:200]}))
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# API Monitor
# ============================================================
class ApiMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 5.0):
        super().__init__("API", bus, interval)
        self._prev_calls: Dict[str, int] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                # Monitor common Windows API usage via performance counters or simple checks
                # This is a simplified version - in practice would use ETW or other methods
                self.bus.publish(Event("API", "HEALTH",
                                       "API monitor active",
                                       severity=Severity.DEBUG,
                                       data={"status": "running"}))
                time.sleep(self.interval)
            except Exception:
                time.sleep(5.0)

# ============================================================
# Defender Monitor
# ============================================================
class DefenderMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("DEFENDER", bus, interval)
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                # Check Windows Defender status
                result = subprocess.run(["powershell", "-Command",
                                        "Get-MpComputerStatus | Select-Object AntispywareSignatureLastUpdated,RealTimeProtectionEnabled,AntivirusEnabled"],
                                       capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                
                if result.returncode == 0:
                    self.bus.publish(Event("DEFENDER", "STATUS",
                                           "Defender status check",
                                           severity=Severity.INFO,
                                           data={"output": result.stdout[:200]}))
                
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# MRU Monitor (Most Recently Used)
# ============================================================
class MruMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("MRU", bus, interval)
        self._prev_mru: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import winreg
                mru_paths = [
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"),
                ]
                
                for hkey, path in mru_paths:
                    try:
                        key = winreg.OpenKey(hkey, path, 0, winreg.KEY_READ)
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                full_path = f"{path}\\{name}"
                                if full_path not in self._prev_mru:
                                    self.bus.publish(Event("MRU", "NEW",
                                                           f"Recent item: {name}",
                                                           severity=Severity.DEBUG,
                                                           data={"name": name, "path": full_path}))
                                self._prev_mru[full_path] = str(value)
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except Exception:
                        pass
                
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# Screenshot Monitor
# ============================================================
class ScreenshotMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SCREENSHOT", bus, interval)
        self._prev_images: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                # Check for screenshot files in common locations
                screenshot_dirs = [
                    Path(os.environ.get("USERPROFILE", "")) / "Pictures" / "Screenshots",
                    Path(os.environ.get("USERPROFILE", "")) / "Videos" / "Captures",
                ]
                
                for dir_path in screenshot_dirs:
                    if dir_path.exists():
                        try:
                            files = list(dir_path.glob("*.png")) + list(dir_path.glob("*.jpg"))
                            for f in files:
                                if f.name not in self._prev_images:
                                    self.bus.publish(Event("SCREENSHOT", "CREATED",
                                                           f"Screenshot: {f.name}",
                                                           severity=Severity.INFO,
                                                           data={"file": str(f),
                                                                 "size": f.stat().st_size}))
                                    self._prev_images.add(f.name)
                        except Exception:
                            pass
                
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Print Monitor
# ============================================================
class PrintMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("PRINT", bus, interval)
        self._prev_jobs: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["powershell", "-Command",
                                        "Get-PrintJob | Select-Object Id,DocumentName,PrinterName,JobStatus"],
                                       capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Id"):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            job_id = parts[0]
                            doc_name = parts[1] if len(parts) > 1 else "Unknown"
                            key = f"{job_id}:{doc_name}"
                            
                            if key not in self._prev_jobs:
                                self.bus.publish(Event("PRINT", "JOB",
                                                       f"Print job: {doc_name}",
                                                       severity=Severity.INFO,
                                                       data={"job_id": job_id,
                                                             "document": doc_name,
                                                             "raw": line[:100]}))
                            
                            self._prev_jobs[key] = line
                
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Service Details Monitor
# ============================================================
class ServiceDetailsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("SERVICE_DETAIL", bus, interval)
        self._prev_services: Dict[str, Dict[str, Any]] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["sc", "query", "type=", "service", "state=", "all"],
                                       capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                
                current = {}
                name = None
                state = None
                for line in result.stdout.splitlines():
                    if line.startswith("SERVICE_NAME:"):
                        name = line.split(":", 1)[1].strip()
                    elif line.startswith("STATE:"):
                        state = line.split(":", 1)[1].strip()
                        if name:
                            current[name] = {"state": state, "raw": line}
                
                for name, info in current.items():
                    if name not in self._prev_services:
                        self.bus.publish(Event("SERVICE_DETAIL", "START",
                                               f"Service {name}: {info['state']}",
                                               severity=Severity.INFO,
                                               data={"service": name, "state": info['state']}))
                    elif self._prev_services[name]["state"] != info["state"]:
                        self.bus.publish(Event("SERVICE_DETAIL", "CHANGE",
                                               f"Service {name}: {self._prev_services[name]['state']} -> {info['state']}",
                                               severity=Severity.NOTICE,
                                               data={"service": name,
                                                     "old_state": self._prev_services[name]["state"],
                                                     "new_state": info["state"]}))
                
                self._prev_services = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Driver Monitor
# ============================================================
class DriverMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("DRIVER", bus, interval)
        self._prev_drivers: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["driverquery", "/v"], capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Module"):
                        parts = line.split()
                        if len(parts) >= 2:
                            driver_name = parts[0]
                            driver_status = parts[1] if len(parts) > 1 else "Unknown"
                            current[driver_name] = driver_status
                            
                            if driver_name not in self._prev_drivers:
                                self.bus.publish(Event("DRIVER", "LOADED",
                                                       f"Driver: {driver_name} ({driver_status})",
                                                       severity=Severity.INFO,
                                                       data={"driver": driver_name,
                                                             "status": driver_status}))
                
                self._prev_drivers = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Process Tree Monitor
# ============================================================
class ProcessTreeMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("PROCESS_TREE", bus, interval)
        self._prev_trees: Dict[int, List[str]] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                current = {}
                for proc in psutil.process_iter(['pid', 'name', 'ppid']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name']
                        ppid = proc.info['ppid']
                        current[pid] = f"{name} (parent: {ppid})"
                        
                        if pid not in self._prev_trees:
                            parent_name = ""
                            if ppid in current:
                                parent_name = current[ppid]
                            self.bus.publish(Event("PROCESS_TREE", "NEW",
                                                   f"Process tree: {name} (PID {pid})",
                                                   severity=Severity.DEBUG,
                                                   data={"pid": pid, "name": name,
                                                         "ppid": ppid, "parent": parent_name}))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                self._prev_trees = {k: [v] for k, v in current.items()}
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Network Share Monitor
# ============================================================
class NetworkShareMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SHARE", bus, interval)
        self._prev_shares: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["net", "share"], capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Share") and not line.startswith("---"):
                        parts = line.split()
                        if len(parts) >= 2:
                            share_name = parts[0]
                            share_path = parts[1] if len(parts) > 1 else ""
                            current[share_name] = share_path
                            
                            if share_name not in self._prev_shares:
                                self.bus.publish(Event("SHARE", "CREATED",
                                                       f"Network share: {share_name} -> {share_path}",
                                                       severity=Severity.INFO,
                                                       data={"name": share_name,
                                                             "path": share_path}))
                
                self._prev_shares = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# WiFi Monitor
# ============================================================
class WifiMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("WIFI", bus, interval)
        self._prev_networks: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["netsh", "wlan", "show", "profiles"],
                                       capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                
                current = set()
                for line in result.stdout.splitlines():
                    if "All User Profile" in line:
                        parts = line.split(":")
                        if len(parts) > 1:
                            ssid = parts[1].strip()
                            current.add(ssid)
                            
                            if ssid not in self._prev_networks:
                                self.bus.publish(Event("WIFI", "PROFILE",
                                                       f"WiFi network: {ssid}",
                                                       severity=Severity.INFO,
                                                       data={"ssid": ssid}))
                
                self._prev_networks = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# LAN Monitor
# ============================================================
class LanMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("LAN", bus, interval)
        self._prev_devices: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["arp", "-a"], capture_output=True, encoding='utf-8', errors='replace', timeout=10)
                current = set()
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Interface"):
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[1]
                            current.add(f"{ip}:{mac}")
                            
                            if f"{ip}:{mac}" not in self._prev_devices:
                                self.bus.publish(Event("LAN", "DEVICE",
                                                       f"LAN device: {ip} ({mac})",
                                                       severity=Severity.INFO,
                                                       data={"ip": ip, "mac": mac}))
                
                self._prev_devices = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Rolling Log Display
# ============================================================
class RollingLogDisplay:
    def __init__(self, max_lines: int = 50, width: int = 120):
        self.max_lines = max_lines
        self.width = width
        self.events: Deque[Event] = deque(maxlen=10000)
        self._scroll = 0
        self._paused = False
        self._filter_source: Optional[str] = None
        self._filter_text: Optional[str] = None
        self._show_data = True
        self._lock = threading.RLock()
        self._last_frame = ""
        self._stats: Dict[str, Any] = {}
        self._filter_regex: Optional[Pattern] = None
    
    def add(self, event: Event):
        with self._lock:
            self.events.append(event)
            if self._scroll == 0:
                pass
    
    def update_stats(self, stats: Dict[str, Any]):
        with self._lock:
            self._stats = stats
    
    def scroll_up(self, n: int = 1):
        with self._lock:
            max_s = max(0, len(self.events) - self.max_lines + 10)
            self._scroll = min(max_s, self._scroll + n)
    
    def scroll_down(self, n: int = 1):
        with self._lock:
            self._scroll = max(0, self._scroll - n)
    
    def scroll_bottom(self):
        with self._lock:
            self._scroll = 0
    
    def scroll_top(self):
        with self._lock:
            self._scroll = max(0, len(self.events) - self.max_lines + 10)
    
    def set_filter_source(self, source: Optional[str]):
        with self._lock:
            self._filter_source = source
            self._scroll = 0
    
    def set_filter_text(self, text: Optional[str]):
        with self._lock:
            self._filter_text = text
            self._filter_regex = re.compile(re.escape(text), re.IGNORECASE) if text else None
            self._scroll = 0
    
    def toggle_pause(self) -> bool:
        with self._lock:
            self._paused = not self._paused
            return self._paused
    
    def toggle_data(self) -> bool:
        with self._lock:
            self._show_data = not self._show_data
            return self._show_data
    
    def clear(self):
        with self._lock:
            self.events.clear()
            self._scroll = 0
    
    def render(self) -> str:
        with self._lock:
            visible = []
            for e in reversed(self.events):
                if self._filter_source and self._filter_source.lower() != e.source.lower():
                    continue
                if self._filter_text:
                    if not self._filter_regex.search(e.message):
                        if not self._filter_regex.search(e.source):
                            continue
                visible.append(e)
            
            start = self._scroll
            end = start + self.max_lines - 8
            page = visible[start:end]
            
            lines: List[str] = []
            
            up = self._fmt_uptime(self._stats.get("uptime", 0))
            qps = self._stats.get("qps", 0)
            total = self._stats.get("total", 0)
            lines.append(f"{BOLD}Rolling Log Monitor{RST} | Uptime: {up} | QPS: {qps:.1f} | Events: {total}")
            lines.append("=" * self.width)
            
            filt = []
            if self._filter_source:
                filt.append(f"Source: {self._filter_source}")
            if self._filter_text:
                filt.append(f"Text: {self._filter_text}")
            if filt:
                lines.append(f"{DIM}Filter: {' | '.join(filt)}{RST}")
            else:
                lines.append(f"{DIM}Filter: None{RST}")
            lines.append("-" * self.width)
            
            status = f"{BOLD}[{'PAUSED' if self._paused else 'LIVE'}] {len(self.events)} buffered"
            if self._paused:
                status += f" | Showing {len(page)} events"
            lines.append(status)
            lines.append("-" * self.width)
            
            for e in page:
                lines.append(e.line(self._show_data, self.width))
            
            while len(lines) < self.max_lines - 2:
                lines.append("")
            
            lines.append("-" * self.width)
            footer = (
                "Controls: ↑/↓ Scroll | PgUp/PgDn | Home/End | "
                "Space Pause | C Clear | D Toggle Data | F Filter | S Source | "
                "/ Search | H Help | Q Quit"
            )
            lines.append(footer)
            
            return "\n".join(lines)
    
    def _fmt_uptime(self, secs: float) -> str:
        h, r = divmod(int(secs), 3600)
        m, s = divmod(r, 60)
        if h:
            return f"{h}h{m:02d}m{s:02d}s"
        if m:
            return f"{m}m{s:02d}s"
        return f"{s}s"

# ============================================================
# Input Handler
# ============================================================
class InputHandler:
    def __init__(self, display: RollingLogDisplay, stop_event: threading.Event):
        self.display = display
        self._stop = stop_event
    
    def start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
    
    def _loop(self):
        try:
            import msvcrt
            while not self._stop.is_set():
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    self._handle(key)
                time.sleep(0.01)
        except ImportError:
            try:
                while not self._stop.is_set():
                    ch = sys.stdin.read(1)
                    if ch:
                        self._handle(ch.encode("utf-8", errors="ignore"))
                    time.sleep(0.01)
            except Exception:
                pass
    
    def _handle(self, key: bytes):
        if not self.display:
            return
        
        if key in (b"q", b"Q"):
            self._stop.set()
            return
        
        if key == b"\xe0":
            try:
                import msvcrt
                k2 = msvcrt.getch()
                if k2 == b"H":
                    self.display.scroll_up(1)
                elif k2 == b"P":
                    self.display.scroll_down(1)
                elif k2 == b"I":
                    self.display.scroll_up(15)
                elif k2 == b"Q":
                    self.display.scroll_down(15)
                elif k2 == b"G":
                    self.display.scroll_bottom()
                elif k2 == b"O":
                    self.display.scroll_top()
            except Exception:
                pass
            return
        
        if key == b" ":
            paused = self.display.toggle_pause()
            self._flash("PAUSED" if paused else "RESUMED")
        elif key in (b"c", b"C"):
            self.display.clear()
            self._flash("CLEARED")
        elif key in (b"d", b"D"):
            show = self.display.toggle_data()
            self._flash(f"Data: {'ON' if show else 'OFF'}")
        elif key in (b"f", b"F"):
            self._prompt_filter()
        elif key in (b"s", b"S"):
            self._prompt_source()
        elif key == b"/":
            self._prompt_search()
        elif key in (b"h", b"H"):
            self._show_help()
    
    def _flash(self, msg: str):
        if not self.display:
            return
        old = self.display._paused
        self.display._paused = True
        try:
            sys.stdout.write(f"\033[2J\033[H{BOLD}{msg}{RST}\n")
            sys.stdout.flush()
            time.sleep(0.8)
        finally:
            self.display._paused = old
    
    def _prompt_filter(self):
        if not self.display:
            return
        old = self.display._paused
        self.display._paused = True
        try:
            sys.stdout.write(f"\033[2J\033[H{BOLD}Set Event Filter{RST}\n")
            sys.stdout.write(f"Current source: {self.display._filter_source or '(none)'}\n")
            sys.stdout.write("Enter source filter (empty for all): ")
            sys.stdout.flush()
            try:
                import msvcrt
                buf = []
                while True:
                    ch = msvcrt.getch()
                    if ch == b"\r":
                        break
                    if ch == b"\x08":
                        if buf:
                            buf.pop()
                            sys.stdout.write("\b \b")
                            sys.stdout.flush()
                    elif ch >= b" ":
                        buf.append(ch.decode("utf-8", errors="ignore"))
                        sys.stdout.write(ch.decode("utf-8", errors="ignore"))
                        sys.stdout.flush()
                src = "".join(buf).strip()
                self.display.set_filter_source(src if src else None)
                self._flash(f"Filter: {src or 'All'}")
            except Exception:
                pass
        finally:
            self.display._paused = old
    
    def _prompt_source(self):
        if not self.display:
            return
        old = self.display._paused
        self.display._paused = True
        try:
            sys.stdout.write(f"\033[2J\033[H{BOLD}Set Source Filter{RST}\n")
            sys.stdout.write(f"Current: {self.display._filter_source or '(none)'}\n")
            sys.stdout.write("Enter source (empty for all): ")
            sys.stdout.flush()
            try:
                import msvcrt
                buf = []
                while True:
                    ch = msvcrt.getch()
                    if ch == b"\r":
                        break
                    if ch == b"\x08":
                        if buf:
                            buf.pop()
                            sys.stdout.write("\b \b")
                            sys.stdout.flush()
                    elif ch >= b" ":
                        buf.append(ch.decode("utf-8", errors="ignore"))
                        sys.stdout.write(ch.decode("utf-8", errors="ignore"))
                        sys.stdout.flush()
                src = "".join(buf).strip()
                self.display.set_filter_source(src if src else None)
                self._flash(f"Source: {src or 'All'}")
            except Exception:
                pass
        finally:
            self.display._paused = old
    
    def _prompt_search(self):
        if not self.display:
            return
        old = self.display._paused
        self.display._paused = True
        try:
            sys.stdout.write(f"\033[2J\033[H{BOLD}Search Events{RST}\n")
            sys.stdout.write(f"Current text filter: {self.display._filter_text or '(none)'}\n")
            sys.stdout.write("Enter search text (empty to clear): ")
            sys.stdout.flush()
            try:
                import msvcrt
                buf = []
                while True:
                    ch = msvcrt.getch()
                    if ch == b"\r":
                        break
                    if ch == b"\x08":
                        if buf:
                            buf.pop()
                            sys.stdout.write("\b \b")
                            sys.stdout.flush()
                    elif ch >= b" ":
                        buf.append(ch.decode("utf-8", errors="ignore"))
                        sys.stdout.write(ch.decode("utf-8", errors="ignore"))
                        sys.stdout.flush()
                text = "".join(buf).strip()
                self.display.set_filter_text(text if text else None)
                self._flash(f"Search: {text or 'All'}")
            except Exception:
                pass
        finally:
            self.display._paused = old
    
    def _show_help(self):
        if not self.display:
            return
        old = self.display._paused
        self.display._paused = True
        try:
            lines = [
                "",
                f"{BOLD}Rolling Log Monitor - Help{RST}",
                "=" * 78,
                "Unified real-time monitoring with scrolling log display.",
                "",
                "Controls:",
                "  ↑/↓         Scroll up/down one line",
                "  PgUp/PgDn   Scroll up/down one page",
                "  Home        Jump to newest events (bottom)",
                "  End         Jump to oldest events (top)",
                "  Space       Pause/resume display",
                "  C           Clear all events",
                "  D           Toggle detailed data display",
                "  F           Set source filter",
                "  S           Quick source filter",
                "  /           Search text in events",
                "  H           Show this help",
                "  Q           Quit application",
                "",
                "Monitors:",
                "  DNS           - Real DNS queries with IP resolution",
                "  PROCESS       - Process start/end with command lines",
                "  PROCESS_TREE  - Process parent-child relationships",
                "  NETWORK       - Connections, traffic, ARP table",
                "  LAN           - LAN device discovery",
                "  WIFI          - WiFi network profiles",
                "  SHARE         - Network share changes",
                "  SYSTEM        - CPU, RAM, Swap, Disk",
                "  SERVICE       - Windows service state changes",
                "  SERVICE_DETAIL- Detailed service monitoring",
                "  DRIVER        - Driver load/unload",
                "  FIREWALL      - Firewall packet events",
                "  EVENTLOG      - Windows Event Log entries",
                "  REGISTRY      - Registry changes",
                "  WMI           - WMI events",
                "  DEVICE        - USB device changes",
                "  TASK          - Scheduled task changes",
                "  APPLICATION   - Application log changes",
                "  SECURITY      - Failed login attempts",
                "  MEMORY        - High memory usage processes",
                "  MODULE        - DLL/module loads",
                "  ARP           - ARP table changes",
                "  CLIPBOARD     - Clipboard content changes",
                "  INPUT         - Keyboard/mouse activity",
                "  BROWSER       - Browser history updates",
                "  IDLE          - System idle/active state",
                "  POWER         - Power/battery status",
                "  THREAT        - Suspicious process detection",
                "  API           - API activity monitoring",
                "  DEFENDER      - Windows Defender status",
                "  MRU           - Most recently used items",
                "  SCREENSHOT    - Screenshot file detection",
                "  PRINT         - Print job monitoring",
                "",
                "Press any key to return..."
            ]
            sys.stdout.write("\033[2J\033[H")
            for line in lines:
                sys.stdout.write(line + "\n")
            sys.stdout.flush()
            try:
                import msvcrt
                msvcrt.getch()
            except Exception:
                time.sleep(2)
        finally:
            self.display._paused = old

# ============================================================
# Main Application
# ============================================================
class RollingLogMonitor:
    def __init__(self):
        self.args: Optional[argparse.Namespace] = None
        self.bus = EventBus()
        self.stats = Statistics()
        self.display = RollingLogDisplay()
        self.logger: Optional[FileLogger] = None
        self.monitors: List[BaseMonitor] = []
        self._stop = threading.Event()
        self._render_thread: Optional[threading.Thread] = None
        self._stats_thread: Optional[threading.Thread] = None
        self._input_handler: Optional[InputHandler] = None
    
    def parse_args(self):
        p = argparse.ArgumentParser(
            description="Rolling Log Monitor - Comprehensive real-time monitoring",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python rolling_log_monitor.py
  python rolling_log_monitor.py --log monitor.log --interval 1.0
  python rolling_log_monitor.py --no-dns --no-services --max-lines 60

Controls:
  ↑/↓        Scroll
  PgUp/PgDn  Page scroll
  Home/End   Jump to newest/oldest
  Space      Pause/resume
  C          Clear
  D          Toggle data
  F          Filter by source
  S          Quick source filter
  /          Search text
  H          Help
  Q          Quit
            """
        )
        p.add_argument("--log", "-l", type=Path, help="Log file path")
        p.add_argument("--max-lines", "-n", type=int, default=50, help="Display lines")
        p.add_argument("--interval", "-i", type=float, default=2.0, help="Default interval")
        p.add_argument("--no-html-delete", action="store_true", help="Skip HTML deletion")
        p.add_argument("--no-dns", action="store_true", help="Disable DNS monitor")
        p.add_argument("--no-processes", action="store_true", help="Disable process monitor")
        p.add_argument("--no-network", action="store_true", help="Disable network monitor")
        p.add_argument("--no-system", action="store_true", help="Disable system monitor")
        p.add_argument("--no-services", action="store_true", help="Disable service monitor")
        p.add_argument("--no-firewall", action="store_true", help="Disable firewall monitor")
        p.add_argument("--no-eventlog", action="store_true", help="Disable event log monitor")
        p.add_argument("--no-registry", action="store_true", help="Disable registry monitor")
        p.add_argument("--no-wmi", action="store_true", help="Disable WMI monitor")
        p.add_argument("--no-devices", action="store_true", help="Disable device monitor")
        p.add_argument("--no-tasks", action="store_true", help="Disable task monitor")
        p.add_argument("--no-applications", action="store_true", help="Disable application log monitor")
        p.add_argument("--no-security", action="store_true", help="Disable security monitor")
        p.add_argument("--no-memory", action="store_true", help="Disable memory monitor")
        p.add_argument("--no-modules", action="store_true", help="Disable module monitor")
        p.add_argument("--no-arp", action="store_true", help="Disable ARP monitor")
        p.add_argument("--no-clipboard", action="store_true", help="Disable clipboard monitor")
        p.add_argument("--no-input", action="store_true", help="Disable input monitor")
        p.add_argument("--no-browser", action="store_true", help="Disable browser history monitor")
        p.add_argument("--no-idle", action="store_true", help="Disable idle monitor")
        p.add_argument("--no-power", action="store_true", help="Disable power monitor")
        p.add_argument("--no-threat", action="store_true", help="Disable threat monitor")
        p.add_argument("--no-api", action="store_true", help="Disable API monitor")
        p.add_argument("--no-defender", action="store_true", help="Disable defender monitor")
        p.add_argument("--no-mru", action="store_true", help="Disable MRU monitor")
        p.add_argument("--no-screenshot", action="store_true", help="Disable screenshot monitor")
        p.add_argument("--no-print", action="store_true", help="Disable print monitor")
        p.add_argument("--no-service-detail", action="store_true", help="Disable service detail monitor")
        p.add_argument("--no-drivers", action="store_true", help="Disable driver monitor")
        p.add_argument("--no-process-tree", action="store_true", help="Disable process tree monitor")
        p.add_argument("--no-shares", action="store_true", help="Disable network share monitor")
        p.add_argument("--no-wifi", action="store_true", help="Disable WiFi monitor")
        p.add_argument("--no-lan", action="store_true", help="Disable LAN monitor")
        p.add_argument("--domains", "-d", help="Comma-separated domains for DNS")
        self.args = p.parse_args()
    
    def _delete_html(self):
        if self.args.no_html_delete:
            return
        try:
            for f in Path(".").glob("*.html"):
                try:
                    f.unlink()
                except Exception:
                    pass
        except Exception:
            pass
    
    def _on_event(self, event: Event):
        self.stats.record(event)
        self.display.add(event)
        if self.logger:
            self.logger.write(event)
    
    def _stats_loop(self):
        while not self._stop.is_set():
            self.stats.update_qps()
            snap = self.stats.snapshot()
            self.display.update_stats(snap)
            time.sleep(0.5)
    
    def _render_loop(self):
        last = ""
        while not self._stop.is_set():
            try:
                frame = self.display.render()
                if frame != last:
                    sys.stdout.write("\033[2J\033[H")
                    sys.stdout.write(frame + "\n")
                    sys.stdout.flush()
                    last = frame
                time.sleep(0.05)
            except Exception:
                time.sleep(0.1)
    
    def _build_monitors(self) -> List[BaseMonitor]:
        monitors = []
        interval = self.args.interval
        
        if not self.args.no_dns:
            domains = None
            if self.args.domains:
                domains = [d.strip() for d in self.args.domains.split(",") if d.strip()]
            monitors.append(DnsMonitor(self.bus, interval, domains))
        
        if not self.args.no_processes:
            monitors.append(ProcessMonitor(self.bus, max(interval * 2, 3.0)))
        
        if not self.args.no_network:
            monitors.append(NetworkMonitor(self.bus, max(interval * 1.5, 2.0)))
        
        if not self.args.no_system:
            monitors.append(SystemMonitor(self.bus, max(interval * 2.5, 5.0)))
        
        if not self.args.no_services:
            monitors.append(ServiceMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_firewall:
            monitors.append(FirewallMonitor(self.bus, max(interval * 7.5, 15.0)))
        
        if not self.args.no_eventlog:
            monitors.append(EventLogMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_registry:
            monitors.append(RegistryMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_wmi:
            monitors.append(WmiMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_devices:
            monitors.append(DeviceMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_tasks:
            monitors.append(TaskMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_applications:
            monitors.append(ApplicationLogMonitor(self.bus, max(interval * 7.5, 15.0)))
        
        if not self.args.no_security:
            monitors.append(SecurityMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_memory:
            monitors.append(MemoryMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_modules:
            monitors.append(ModuleMonitor(self.bus, max(interval * 7.5, 15.0)))
        
        if not self.args.no_arp:
            monitors.append(ArpMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_clipboard:
            monitors.append(ClipboardMonitor(self.bus, max(interval * 1, 2.0)))
        
        if not self.args.no_input:
            monitors.append(InputMonitor(self.bus, max(interval * 2.5, 5.0)))
        
        if not self.args.no_browser:
            monitors.append(BrowserHistoryMonitor(self.bus, max(interval * 7.5, 15.0)))
        
        if not self.args.no_idle:
            monitors.append(IdleMonitor(self.bus, max(interval * 2.5, 5.0)))
        
        if not self.args.no_power:
            monitors.append(PowerMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_threat:
            monitors.append(ThreatMonitor(self.bus, max(interval * 7.5, 15.0)))
        
        if not self.args.no_api:
            monitors.append(ApiMonitor(self.bus, max(interval * 2.5, 5.0)))
        
        if not self.args.no_defender:
            monitors.append(DefenderMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_mru:
            monitors.append(MruMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_screenshot:
            monitors.append(ScreenshotMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_print:
            monitors.append(PrintMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_service_detail:
            monitors.append(ServiceDetailsMonitor(self.bus, max(interval * 7.5, 15.0)))
        
        if not self.args.no_drivers:
            monitors.append(DriverMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_process_tree:
            monitors.append(ProcessTreeMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_shares:
            monitors.append(NetworkShareMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_wifi:
            monitors.append(WifiMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_lan:
            monitors.append(LanMonitor(self.bus, max(interval * 15, 30.0)))
        
        return monitors
    
    def run(self):
        self.parse_args()
        self._delete_html()
        
        if self.args.log:
            self.logger = FileLogger(self.args.log)
        
        self.bus.subscribe(self._on_event)
        self.monitors = self._build_monitors()
        
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
        
        self._stop.clear()
        for m in self.monitors:
            m.start()
        
        self._render_thread = threading.Thread(target=self._render_loop, daemon=True)
        self._render_thread.start()
        
        self._stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        self._stats_thread.start()
        
        self._input_handler = InputHandler(self.display, self._stop)
        self._input_handler.start()
        
        if self.logger:
            self.bus.publish(Event("MONITOR", "STARTUP",
                                   f"Rolling Log Monitor started with {len(self.monitors)} monitors",
                                   severity=Severity.INFO))
        
        try:
            while not self._stop.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def stop(self):
        if self._stop.is_set():
            return
        self._stop.set()
        
        for m in self.monitors:
            try:
                m.stop()
            except Exception:
                pass
        
        sys.stdout.write("\033[2J\033[H")
        snap = self.stats.snapshot()
        print(f"\nRolling Log Monitor stopped.")
        print(f"Uptime: {self.display._fmt_uptime(snap['uptime'])}")
        print(f"Total events: {snap['total']}")
        print(f"QPS: {snap['qps']:.1f}")
        print("Events by source:")
        for src, count in sorted(snap.get("by_source", {}).items(), key=lambda x: x[1], reverse=True)[:15]:
            print(f"  {src:<15} {count:>6}")
        if self.logger:
            print(f"Log file: {self.logger.path}")
            self.logger.close()

def main():
    app = RollingLogMonitor()
    app.run()

if __name__ == "__main__":
    main()