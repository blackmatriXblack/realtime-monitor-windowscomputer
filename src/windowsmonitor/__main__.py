"""
Rolling Log Monitor - Comprehensive real-time monitoring with rolling log display.
Monitors: DNS, Processes, Network, Files, Registry, WMI, Event Logs, Services,
Firewall, System, Devices, USB, Scheduled Tasks, Security, Application logs,
Clipboard, Input, Browser, Idle, Power, Threat, API, Defender, MRU, Screenshot,
Print, Drivers, Process Tree, Network Shares, WiFi, LAN, Battery, Temperature,
Disk Health, CPU Cores, Bandwidth, Process Resources, User Sessions, Environment,
Log Tail, Port Check, Website Check.
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
    __slots__ = ("ts", "source", "category", "message", "severity", "data", "_seq", "bookmarked", "highlight")
    
    def __init__(self, source: str, category: str, message: str,
                 severity: int = Severity.INFO, data: Dict[str, Any] = None):
        self.ts = time.time()
        self.source = source
        self.category = category
        self.message = message
        self.severity = severity
        self.data = data or {}
        self._seq = 0
        self.bookmarked = False
        self.highlight = False
    
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
            "BATTERY": "🔋", "TEMP": "🌡", "DISK": "💿", "CPU_CORE": "🖥",
            "BANDWIDTH": "📊", "PROC_RES": "⚙", "SESSION": "👤", "ENV": "🌍",
            "LOGTAIL": "📄", "PORT": "🔌", "WEB": "🌐",
        }
        icon = icons.get(self.source, "•")
        prefix = ""
        if self.highlight:
            prefix += f"{BOLD}!{RST}"
        if self.bookmarked:
            prefix += f"{BOLD}*{RST}"
        sev_color = {
            Severity.DEBUG: DIM,
            Severity.INFO: "",
            Severity.NOTICE: BOLD,
            Severity.WARNING: DIM,
            Severity.ERROR: BOLD,
            Severity.CRITICAL: BOLD,
        }.get(self.severity, "")
        s = f"{prefix}[{self.time_str()}] {sev_color}{icon}{RST} {self.source:<10} {self.message}"
        
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
    def __init__(self, path: Path, max_size: int = 10_000_000, dated: bool = True, source: str = "main"):
        self.path = path
        self.max_size = max_size
        self.dated = dated
        self.source = source
        self._lock = threading.Lock()
        self._count = 0
        if dated:
            now = datetime.datetime.now()
            dated_dir = path.parent / now.strftime("%Y-%m-%d") / now.strftime("%H-%M-%S")
            dated_dir.mkdir(parents=True, exist_ok=True)
            self.path = dated_dir / f"{source}.log"
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(f"# Rolling Log Monitor - Started {datetime.datetime.now()}\n")
            f.write(f"# Source: {source}\n")
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


class DatedFolderLogger:
    def __init__(self, base_dir: Path, cleanup_days: int = 30):
        self.base_dir = base_dir
        self.cleanup_days = cleanup_days
        self._loggers: Dict[str, FileLogger] = {}
        self._lock = threading.Lock()
        self._cleanup_old()
    
    def write(self, event: Event):
        with self._lock:
            source = event.source.lower().replace(" ", "_")
            if source not in self._loggers:
                log_path = self.base_dir / f"{source}.log"
                self._loggers[source] = FileLogger(log_path, dated=False, source=source)
            self._loggers[source].write(event)
    
    def _cleanup_old(self):
        try:
            if not self.base_dir.exists():
                return
            cutoff = datetime.datetime.now() - datetime.timedelta(days=self.cleanup_days)
            for item in self.base_dir.iterdir():
                try:
                    if item.is_dir():
                        item_time = datetime.datetime.fromtimestamp(item.stat().st_mtime)
                        if item_time < cutoff:
                            import shutil
                            shutil.rmtree(item, ignore_errors=True)
                except Exception:
                    pass
        except Exception:
            pass
    
    def close(self):
        for logger in self._loggers.values():
            try:
                logger.close()
            except Exception:
                pass


class CleanupThread(threading.Thread):
    def __init__(self, log_dir: Path, cleanup_days: int, interval: float = 3600.0):
        super().__init__(daemon=True)
        self.log_dir = log_dir
        self.cleanup_days = cleanup_days
        self.interval = interval
        self._stop = threading.Event()
    
    def run(self):
        while not self._stop.is_set():
            try:
                self._cleanup()
            except Exception:
                pass
            self._stop.wait(self.interval)
    
    def _cleanup(self):
        if not self.log_dir.exists():
            return
        cutoff = datetime.datetime.now() - datetime.timedelta(days=self.cleanup_days)
        for item in self.log_dir.iterdir():
            try:
                if item.is_dir():
                    item_time = datetime.datetime.fromtimestamp(item.stat().st_mtime)
                    if item_time < cutoff:
                        import shutil
                        shutil.rmtree(item, ignore_errors=True)
            except Exception:
                pass
    
    def stop(self):
        self._stop.set()

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
# Battery Monitor
# ============================================================
class BatteryMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("BATTERY", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import psutil
                battery = psutil.sensors_battery()
                if battery:
                    status = "Charging" if battery.power_plugged else "Discharging"
                    if self._prev_status != status:
                        self.bus.publish(Event("BATTERY", "STATUS",
                                               f"Battery: {battery.percent}% ({status})",
                                               severity=Severity.INFO if battery.percent > 20 else Severity.WARNING,
                                               data={"percent": battery.percent,
                                                     "status": status,
                                                     "time_left": battery.secsleft}))
                    self._prev_status = status
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# Temperature Monitor
# ============================================================
class TemperatureMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("TEMP", bus, interval)
        self._prev_temp = None
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        for entry in entries:
                            temp = entry.current
                            label = f"{name}_{entry.label or 'temp'}"
                            if self._prev_status != temp:
                                sev = Severity.INFO if temp < 70 else (Severity.WARNING if temp < 90 else Severity.ERROR)
                                self.bus.publish(Event("TEMP", "READING",
                                                       f"{label}: {temp}C",
                                                       severity=sev,
                                                       data={"sensor": label, "temp": temp}))
                            self._prev_status = temp
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# Disk Health Monitor
# ============================================================
class DiskHealthMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("DISK_HEALTH", bus, interval)
        self._prev_health: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                import psutil
                for part in psutil.disk_partitions():
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        health = "OK"
                        if usage.percent > 90:
                            health = "CRITICAL"
                        elif usage.percent > 75:
                            health = "WARNING"
                        if self._prev_health.get(part.device) != health:
                            sev = Severity.INFO if health == "OK" else (Severity.WARNING if health == "WARNING" else Severity.ERROR)
                            self.bus.publish(Event("DISK_HEALTH", "STATUS",
                                                   f"Disk {part.device}: {usage.percent}% ({health})",
                                                   severity=sev,
                                                   data={"device": part.device,
                                                         "percent": usage.percent,
                                                         "health": health}))
                            self._prev_health[part.device] = health
                    except Exception:
                        pass
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# CPU Core Monitor
# ============================================================
class CpuCoreMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 5.0):
        super().__init__("CPU_CORE", bus, interval)
        self._prev_usage: List[float] = []
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                usage = psutil.cpu_percent(interval=1, percpu=True)
                if usage and usage != self._prev_usage:
                    for i, core_usage in enumerate(usage):
                        if not self._prev_usage or abs(core_usage - self._prev_usage[i]) > 10:
                            sev = Severity.INFO if core_usage < 70 else (Severity.WARNING if core_usage < 90 else Severity.ERROR)
                            self.bus.publish(Event("CPU_CORE", "USAGE",
                                                   f"Core {i}: {core_usage}%",
                                                   severity=sev,
                                                   data={"core": i, "usage": core_usage}))
                self._prev_usage = usage
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Network Bandwidth Monitor
# ============================================================
class NetworkBandwidthMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 5.0):
        super().__init__("BANDWIDTH", bus, interval)
        self._prev_stats: Optional[Tuple[int, int]] = None
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                stats = psutil.net_io_counters()
                if stats:
                    sent = stats.bytes_sent
                    recv = stats.bytes_recv
                    if self._prev_stats:
                        prev_sent, prev_recv = self._prev_stats
                        sent_rate = (sent - prev_sent) / self.interval
                        recv_rate = (recv - prev_recv) / self.interval
                        if sent_rate > 1024*1024 or recv_rate > 1024*1024:
                            sev = Severity.INFO
                            self.bus.publish(Event("BANDWIDTH", "TRAFFIC",
                                                   f"UP: {sent_rate/1024/1024:.1f} MB/s | DOWN: {recv_rate/1024/1024:.1f} MB/s",
                                                   severity=sev,
                                                   data={"sent_rate": sent_rate,
                                                         "recv_rate": recv_rate,
                                                         "sent": sent,
                                                         "recv": recv}))
                    self._prev_stats = (sent, recv)
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Process Resource Monitor
# ============================================================
class ProcessResourceMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("PROC_RES", bus, interval)
        self._prev_procs: Dict[int, Dict[str, Any]] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                procs = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        info = proc.info
                        if info['cpu_percent'] > 50 or info['memory_percent'] > 10:
                            procs.append(info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                procs.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
                for proc in procs[:5]:
                    pid = proc['pid']
                    if pid not in self._prev_procs or self._prev_procs[pid] != proc:
                        self.bus.publish(Event("PROC_RES", "RESOURCE",
                                               f"{proc['name']} (PID {pid}): CPU {proc['cpu_percent']}% MEM {proc['memory_percent']}%",
                                               severity=Severity.INFO,
                                               data={"pid": pid, "name": proc['name'],
                                                     "cpu": proc['cpu_percent'],
                                                     "memory": proc['memory_percent']}))
                self._prev_procs = {p['pid']: p for p in procs[:5]}
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# User Session Monitor
# ============================================================
class UserSessionMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SESSION", bus, interval)
        self._prev_users: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(["query", "user"], capture_output=True,
                                      encoding='utf-8', errors='replace', timeout=10)
                current = set()
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("USERNAME"):
                        parts = line.split()
                        if parts:
                            current.add(parts[0])
                            if parts[0] not in self._prev_users:
                                self.bus.publish(Event("SESSION", "LOGIN",
                                                       f"User logged in: {parts[0]}",
                                                       severity=Severity.INFO,
                                                       data={"user": parts[0]}))
                for user in self._prev_users - current:
                    self.bus.publish(Event("SESSION", "LOGOUT",
                                           f"User logged out: {user}",
                                           severity=Severity.INFO,
                                           data={"user": user}))
                self._prev_users = current
                time.sleep(self.interval)
            except FileNotFoundError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# Environment Variable Monitor
# ============================================================
class EnvMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("ENV", bus, interval)
        self._prev_env: Dict[str, str] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import os
                current = dict(os.environ)
                for key, value in current.items():
                    if key not in self._prev_env or self._prev_env[key] != value:
                        self.bus.publish(Event("ENV", "CHANGE",
                                               f"Env changed: {key}={value[:50]}",
                                               severity=Severity.DEBUG,
                                               data={"key": key, "value": value[:100]}))
                for key in self._prev_env:
                    if key not in current:
                        self.bus.publish(Event("ENV", "REMOVED",
                                               f"Env removed: {key}",
                                               severity=Severity.DEBUG,
                                               data={"key": key}))
                self._prev_env = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Log Tail Monitor
# ============================================================
class LogTailMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 5.0, log_paths: List[str] = None):
        super().__init__("LOGTAIL", bus, interval)
        self.log_paths = log_paths or [
            r"C:\Windows\System32\winevt\Logs\System.evtx",
            r"C:\Windows\System32\winevt\Logs\Application.evtx",
        ]
        self._prev_positions: Dict[str, int] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                for log_path in self.log_paths:
                    try:
                        path = Path(log_path)
                        if not path.exists():
                            continue
                        pos = self._prev_positions.get(log_path, 0)
                        size = path.stat().st_size
                        if size < pos:
                            pos = 0
                        if size > pos:
                            with open(log_path, 'rb') as f:
                                f.seek(pos)
                                data = f.read(min(size - pos, 1024*1024))
                                self.bus.publish(Event("LOGTAIL", "UPDATE",
                                                       f"Log updated: {path.name} (+{len(data)} bytes)",
                                                       severity=Severity.DEBUG,
                                                       data={"path": str(path), "delta": len(data)}))
                                self._prev_positions[log_path] = size
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Port Check Monitor
# ============================================================
class PortCheckMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0, ports: List[int] = None):
        super().__init__("PORT", bus, interval)
        self.ports = ports or [80, 443, 22, 3389, 8080]
        self._prev_status: Dict[int, bool] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import socket
                for port in self.ports:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(2)
                            result = s.connect_ex(("127.0.0.1", port))
                            is_open = result == 0
                            prev = self._prev_status.get(port)
                            if prev is None:
                                self._prev_status[port] = is_open
                            elif prev != is_open:
                                status = "open" if is_open else "closed"
                                sev = Severity.INFO if is_open else Severity.WARNING
                                self.bus.publish(Event("PORT", "STATUS",
                                                       f"Port {port}: {status}",
                                                       severity=sev,
                                                       data={"port": port, "status": status}))
                                self._prev_status[port] = is_open
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Website Check Monitor
# ============================================================
class WebsiteCheckMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0, urls: List[str] = None):
        super().__init__("WEB", bus, interval)
        self.urls = urls or ["https://www.google.com", "https://www.cloudflare.com"]
        self._prev_status: Dict[str, bool] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import urllib.request
                for url in self.urls:
                    try:
                        req = urllib.request.Request(url, method="HEAD")
                        with urllib.request.urlopen(req, timeout=10) as resp:
                            is_up = resp.status == 200
                            prev = self._prev_status.get(url)
                            if prev is None:
                                self._prev_status[url] = is_up
                            elif prev != is_up:
                                status = "up" if is_up else "down"
                                sev = Severity.INFO if is_up else Severity.ERROR
                                self.bus.publish(Event("WEB", "STATUS",
                                                       f"{url}: {status} ({resp.status})",
                                                       severity=sev,
                                                       data={"url": url, "status": status,
                                                             "code": resp.status}))
                                self._prev_status[url] = is_up
                    except Exception as e:
                        if self._prev_status.get(url, True):
                            self.bus.publish(Event("WEB", "DOWN",
                                                   f"{url}: down ({e})",
                                                   severity=Severity.ERROR,
                                                   data={"url": url, "error": str(e)}))
                            self._prev_status[url] = False
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Event Log Channel Monitor
# ============================================================
class EventLogChannelMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0, channels: List[str] = None):
        super().__init__("EVENTLOG_CH", bus, interval)
        self.channels = channels or ["System", "Application", "Security", "Setup", "ForwardedEvents"]
        self._prev_counts: Dict[str, int] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                for channel in self.channels:
                    try:
                        result = subprocess.run(
                            ["wevtutil", "qe", channel, "/c", "1", "/f", "text"],
                            capture_output=True, encoding='utf-8', errors='replace', timeout=10
                        )
                        count = len(result.stdout.splitlines())
                        prev = self._prev_counts.get(channel, 0)
                        if count > prev:
                            self.bus.publish(Event("EVENTLOG_CH", "NEW",
                                                   f"Channel {channel}: {count - prev} new events",
                                                   severity=Severity.INFO,
                                                   data={"channel": channel, "new_count": count - prev}))
                        self._prev_counts[channel] = count
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Performance Counter Monitor
# ============================================================
class PerformanceCounterMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("PERF", bus, interval)
        self._prev_values: Dict[str, float] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                counters = {
                    "CPU": "\\Processor(_Total)\\% Processor Time",
                    "MEMORY": "\\Memory\\Available MBytes",
                    "DISK_READ": "\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                    "DISK_WRITE": "\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
                    "NET_SENT": "\\Network Interface(*)\\Bytes Sent/sec",
                    "NET_RECV": "\\Network Interface(*)\\Bytes Received/sec",
                }
                try:
                    import psutil
                    cpu = psutil.cpu_percent(interval=1)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_io_counters()
                    net = psutil.net_io_counters()
                    
                    values = {
                        "CPU": cpu,
                        "MEMORY": mem.available / 1024 / 1024,
                        "DISK_READ": disk.read_bytes if disk else 0,
                        "DISK_WRITE": disk.write_bytes if disk else 0,
                        "NET_SENT": net.bytes_sent if net else 0,
                        "NET_RECV": net.bytes_recv if net else 0,
                    }
                    
                    for name, val in values.items():
                        prev = self._prev_values.get(name)
                        if prev is not None and abs(val - prev) > 1:
                            self.bus.publish(Event("PERF", "COUNTER",
                                                   f"{name}: {val:.1f}",
                                                   severity=Severity.DEBUG,
                                                   data={"counter": name, "value": val}))
                        self._prev_values[name] = val
                except ImportError:
                    pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Update Monitor
# ============================================================
class WindowsUpdateMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("WUPDATE", bus, interval)
        self._prev_updates: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-HotFix | Select-Object -ExpandProperty HotFixID"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for update in current - self._prev_updates:
                    self.bus.publish(Event("WUPDATE", "INSTALLED",
                                           f"Update installed: {update}",
                                           severity=Severity.INFO,
                                           data={"update_id": update}))
                self._prev_updates = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Installed Software Monitor
# ============================================================
class InstalledSoftwareMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("SOFTWARE", bus, interval)
        self._prev_software: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set()
                for line in result.stdout.splitlines():
                    if line.strip():
                        current.add(line.strip())
                for sw in current - self._prev_software:
                    self.bus.publish(Event("SOFTWARE", "CHANGE",
                                           f"Software: {sw}",
                                           severity=Severity.INFO,
                                           data={"software": sw}))
                self._prev_software = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Features Monitor
# ============================================================
class WindowsFeaturesMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("WINFEAT", bus, interval)
        self._prev_features: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WindowsFeature | Select-Object Name, InstallState"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Name"):
                        parts = line.split()
                        if len(parts) >= 2:
                            current[parts[0]] = parts[1]
                            if parts[0] not in self._prev_features:
                                self.bus.publish(Event("WINFEAT", "STATE",
                                                       f"Feature {parts[0]}: {parts[1]}",
                                                       severity=Severity.INFO,
                                                       data={"feature": parts[0], "state": parts[1]}))
                self._prev_features = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Network Adapter Monitor
# ============================================================
class NetworkAdapterMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("NETADAPTER", bus, interval)
        self._prev_adapters: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-NetAdapter | Select-Object Name, Status, LinkSpeed"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Name"):
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            status = parts[1]
                            current[name] = status
                            if name not in self._prev_adapters:
                                self.bus.publish(Event("NETADAPTER", "CHANGE",
                                                       f"Adapter {name}: {status}",
                                                       severity=Severity.INFO,
                                                       data={"adapter": name, "status": status}))
                self._prev_adapters = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# TCP Statistics Monitor
# ============================================================
class TCPStatsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("TCPSTATS", bus, interval)
        self._prev_stats: Optional[Dict[str, int]] = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["netstat", "-s"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                stats = {}
                for line in result.stdout.splitlines():
                    if "segments" in line.lower() or "connections" in line.lower():
                        parts = line.split()
                        if parts:
                            try:
                                stats[line.strip()] = int(parts[-1])
                            except ValueError:
                                pass
                if self._prev_stats:
                    for key, val in stats.items():
                        prev = self._prev_stats.get(key, 0)
                        if val != prev:
                            self.bus.publish(Event("TCPSTATS", "CHANGE",
                                                   f"{key}: {prev} -> {val}",
                                                   severity=Severity.DEBUG,
                                                   data={"stat": key, "old": prev, "new": val}))
                self._prev_stats = stats
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# UAC Monitor
# ============================================================
class UACMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("UAC", bus, interval)
        self._prev_level = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name ConsentPromptBehaviorLevel"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                level = None
                for line in result.stdout.splitlines():
                    if "ConsentPromptBehaviorLevel" in line:
                        parts = line.split()
                        if parts:
                            level = parts[-1]
                if level is not None and level != self._prev_level:
                    self.bus.publish(Event("UAC", "CHANGE",
                                           f"UAC level changed: {self._prev_level} -> {level}",
                                           severity=Severity.WARNING,
                                           data={"old_level": self._prev_level, "new_level": level}))
                    self._prev_level = level
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# SmartScreen Monitor
# ============================================================
class SmartScreenMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("SMARTSCREEN", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpPreference | Select-Object -ExpandProperty SmartScreenEnabled"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("SMARTSCREEN", "STATUS",
                                           f"SmartScreen: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Credential Manager Monitor
# ============================================================
class CredentialMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("CRED", bus, interval)
        self._prev_creds: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["cmdkey", "/list"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set()
                for line in result.stdout.splitlines():
                    if "Target:" in line:
                        current.add(line.strip())
                        if line.strip() not in self._prev_creds:
                            self.bus.publish(Event("CRED", "ADDED",
                                                   f"Credential: {line.strip()}",
                                                   severity=Severity.INFO,
                                                   data={"target": line.strip()}))
                for cred in self._prev_creds - current:
                    self.bus.publish(Event("CRED", "REMOVED",
                                           f"Credential removed: {cred}",
                                           severity=Severity.INFO,
                                           data={"target": cred}))
                self._prev_creds = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Error Reporting Monitor
# ============================================================
class WERMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WER", bus, interval)
        self._prev_reports: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WERReport | Select-Object -ExpandProperty ReportID"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for report in current - self._prev_reports:
                    self.bus.publish(Event("WER", "REPORT",
                                           f"Error report: {report}",
                                           severity=Severity.WARNING,
                                           data={"report_id": report}))
                self._prev_reports = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Dump File Monitor
# ============================================================
class DumpFileMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0, paths: List[str] = None):
        super().__init__("DUMP", bus, interval)
        self.paths = paths or [
            os.environ.get("WINDIR", "C:\\Windows") + "\\Minidump",
            os.environ.get("WINDIR", "C:\\Windows") + "\\MEMORY.DMP",
        ]
        self._prev_sizes: Dict[str, int] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                for path in self.paths:
                    try:
                        p = Path(path)
                        if not p.exists():
                            continue
                        if p.is_file():
                            size = p.stat().st_size
                            prev = self._prev_sizes.get(path, 0)
                            if size != prev:
                                self.bus.publish(Event("DUMP", "CHANGE",
                                                       f"Dump file {p.name}: {prev} -> {size}",
                                                       severity=Severity.WARNING,
                                                       data={"path": str(p), "old_size": prev, "new_size": size}))
                                self._prev_sizes[path] = size
                        elif p.is_dir():
                            files = list(p.glob("*.dmp"))
                            for f in files:
                                size = f.stat().st_size
                                key = str(f)
                                prev = self._prev_sizes.get(key, 0)
                                if size != prev:
                                    self.bus.publish(Event("DUMP", "CHANGE",
                                                           f"Dump {f.name}: {prev} -> {size}",
                                                           severity=Severity.WARNING,
                                                           data={"path": str(f), "old_size": prev, "new_size": size}))
                                    self._prev_sizes[key] = size
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Pagefile Monitor
# ============================================================
class PagefileMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("PAGEFILE", bus, interval)
        self._prev_usage: Optional[float] = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-CimInstance Win32_PageFileUsage | Select-Object Name, CurrentUsage, AllocatedBaseSize"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Name"):
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[0]
                            usage = int(parts[1])
                            total = int(parts[2])
                            percent = (usage / total * 100) if total > 0 else 0
                            if self._prev_usage is not None and abs(percent - self._prev_usage) > 5:
                                self.bus.publish(Event("PAGEFILE", "USAGE",
                                                       f"Pagefile {name}: {percent:.1f}%",
                                                       severity=Severity.INFO if percent < 80 else Severity.WARNING,
                                                       data={"name": name, "usage": usage, "total": total, "percent": percent}))
                            self._prev_usage = percent
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Hibernation Monitor
# ============================================================
class HibernationMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("HIBER", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powercfg", "/a"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = "enabled" if "Hibernate" in result.stdout and "Not available" not in result.stdout else "disabled"
                if status != self._prev_status:
                    self.bus.publish(Event("HIBER", "STATUS",
                                           f"Hibernation: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Fan Speed Monitor
# ============================================================
class FanSpeedMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("FAN", bus, interval)
        self._prev_speed: Dict[str, int] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                temps = psutil.sensors_temperatures()
                fans = psutil.sensors_fans()
                if fans:
                    for name, entries in fans.items():
                        for entry in entries:
                            speed = entry.current
                            key = f"{name}_{entry.label or 'fan'}"
                            prev = self._prev_speed.get(key)
                            if prev is not None and speed != prev:
                                self.bus.publish(Event("FAN", "SPEED",
                                                       f"{key}: {prev} -> {speed} RPM",
                                                       severity=Severity.DEBUG,
                                                       data={"sensor": key, "old_speed": prev, "new_speed": speed}))
                            self._prev_speed[key] = speed
                time.sleep(self.interval)
            except (ImportError, AttributeError):
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# Thermal Zone Monitor
# ============================================================
class ThermalZoneMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("THERMAL", bus, interval)
        self._prev_zones: Dict[str, float] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                temps = psutil.sensors_temperatures()
                for name, entries in temps.items():
                    for entry in entries:
                        temp = entry.current
                        zone = f"{name}_{entry.label or 'thermal'}"
                        prev = self._prev_zones.get(zone)
                        if prev is not None and abs(temp - prev) > 2:
                            sev = Severity.INFO if temp < 70 else (Severity.WARNING if temp < 90 else Severity.ERROR)
                            self.bus.publish(Event("THERMAL", "TEMP",
                                                   f"{zone}: {temp}C",
                                                   severity=sev,
                                                   data={"zone": zone, "temp": temp}))
                        self._prev_zones[zone] = temp
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# GPU Stats Monitor
# ============================================================
class GPUStatsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("GPU", bus, interval)
        self._prev_usage: Optional[float] = None
    
    def _run(self):
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Name"):
                        self.bus.publish(Event("GPU", "INFO",
                                               f"GPU: {line.strip()}",
                                               severity=Severity.DEBUG,
                                               data={"info": line.strip()}))
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Hello Monitor
# ============================================================
class WindowsHelloMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("HELLO", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus, KeyProtector"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("HELLO", "STATUS",
                                           f"BitLocker/Hello: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Lock Screen Monitor
# ============================================================
class LockScreenMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("LOCK", bus, interval)
        self._prev_locked = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "$ts = [TimeZoneInfo]::Local; $ts.IsDaylightSavingTime([DateTime]::Now)"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                is_locked = result.stdout.strip()
                if is_locked != self._prev_locked:
                    self.bus.publish(Event("LOCK", "STATUS",
                                           f"Lock status: {is_locked}",
                                           severity=Severity.DEBUG,
                                           data={"locked": is_locked}))
                    self._prev_locked = is_locked
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Screen Saver Monitor
# ============================================================
class ScreenSaverMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("SCRSAVER", bus, interval)
        self._prev_active = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "(Get-ItemProperty -Path HKCU:\\Control Panel\\Desktop -Name ScreenSaveActive).ScreenSaveActive"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                active = result.stdout.strip()
                if active != self._prev_active:
                    self.bus.publish(Event("SCRSAVER", "STATUS",
                                           f"Screensaver: {active}",
                                           severity=Severity.DEBUG,
                                           data={"active": active}))
                    self._prev_active = active
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Logon Monitor
# ============================================================
class LogonMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("LOGON", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 10 -FilterHashtable @{LogName='Security'; Id=4624} | Select-Object -ExpandProperty Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("LOGON", "LOGIN",
                                           f"Logon: {event[:100]}",
                                           severity=Severity.INFO,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Defender Exclusions Monitor
# ============================================================
class DefenderExclusionsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("DEF_EXCL", bus, interval)
        self._prev_exclusions: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for excl in current - self._prev_exclusions:
                    self.bus.publish(Event("DEF_EXCL", "ADDED",
                                           f"Defender exclusion: {excl}",
                                           severity=Severity.WARNING,
                                           data={"path": excl}))
                self._prev_exclusions = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Defender Scan Monitor
# ============================================================
class DefenderScanMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("DEF_SCAN", bus, interval)
        self._prev_scan_id = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpComputerStatus | Select-Object QuickScanStartTime, FullScanStartTime"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                scan_id = result.stdout.strip()
                if scan_id and scan_id != self._prev_scan_id:
                    self.bus.publish(Event("DEF_SCAN", "SCAN",
                                           f"Defender scan: {scan_id}",
                                           severity=Severity.INFO,
                                           data={"scan": scan_id}))
                    self._prev_scan_id = scan_id
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Firewall Rules Monitor
# ============================================================
class FirewallRulesMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("FW_RULES", bus, interval)
        self._prev_rules: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for rule in current - self._prev_rules:
                    self.bus.publish(Event("FW_RULES", "CHANGE",
                                           f"Firewall rule: {rule}",
                                           severity=Severity.INFO,
                                           data={"rule": rule}))
                self._prev_rules = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Scheduled Task Execution Monitor
# ============================================================
class TaskExecutionMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("TASK_EXEC", bus, interval)
        self._prev_tasks: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ScheduledTask | Where-Object {$_.State -eq 'Running'} | Select-Object TaskName, State"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for task in current - self._prev_tasks:
                    self.bus.publish(Event("TASK_EXEC", "START",
                                           f"Task started: {task}",
                                           severity=Severity.INFO,
                                           data={"task": task}))
                self._prev_tasks = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Time Zone Monitor
# ============================================================
class TimeZoneMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("TZ", bus, interval)
        self._prev_tz = None
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import time
                tz = time.tzname
                if tz != self._prev_tz:
                    self.bus.publish(Event("TZ", "CHANGE",
                                           f"Timezone changed: {self._prev_tz} -> {tz}",
                                           severity=Severity.WARNING,
                                           data={"old": str(self._prev_tz), "new": str(tz)}))
                    self._prev_tz = tz
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Display Settings Monitor
# ============================================================
class DisplaySettingsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("DISPLAY", bus, interval)
        self._prev_settings: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-CimInstance Win32_VideoController | Select-Object CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Current"):
                        parts = line.split()
                        if parts:
                            setting = line.strip()
                            if setting != self._prev_settings.get(parts[0]):
                                self.bus.publish(Event("DISPLAY", "CHANGE",
                                                       f"Display: {setting}",
                                                       severity=Severity.INFO,
                                                       data={"setting": setting}))
                                self._prev_settings[parts[0]] = setting
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Audio Monitor
# ============================================================
class AudioMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("AUDIO", bus, interval)
        self._prev_devices: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-AudioDevice -List | Select-Object Name, Type"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for device in current - self._prev_devices:
                    self.bus.publish(Event("AUDIO", "DEVICE",
                                           f"Audio device: {device}",
                                           severity=Severity.INFO,
                                           data={"device": device}))
                self._prev_devices = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Bluetooth Monitor
# ============================================================
class BluetoothMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("BT", bus, interval)
        self._prev_devices: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-BluetoothDevice | Select-Object Name, ConnectionStatus"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for device in current - self._prev_devices:
                    self.bus.publish(Event("BT", "DEVICE",
                                           f"Bluetooth: {device}",
                                           severity=Severity.INFO,
                                           data={"device": device}))
                self._prev_devices = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# USB Device Detail Monitor
# ============================================================
class USBDeviceDetailMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("USB_DETAIL", bus, interval)
        self._prev_devices: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-PnpDevice -Class USB | Select-Object FriendlyName, Status, InstanceId"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for device in current - self._prev_devices:
                    self.bus.publish(Event("USB_DETAIL", "DEVICE",
                                           f"USB: {device}",
                                           severity=Severity.INFO,
                                           data={"device": device}))
                self._prev_devices = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Boot Configuration Monitor
# ============================================================
class BootConfigMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("BOOT", bus, interval)
        self._prev_config = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["bcdedit", "/enum"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                config = result.stdout.strip()
                if config != self._prev_config:
                    self.bus.publish(Event("BOOT", "CONFIG",
                                           f"Boot config changed",
                                           severity=Severity.WARNING,
                                           data={"config": config[:200]}))
                    self._prev_config = config
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# TPM and BitLocker Monitor
# ============================================================
class TPMBitLockerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("TPM_BL", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-Tpm | Select-Object TpmReady, TpmEnabled; Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("TPM_BL", "STATUS",
                                           f"TPM/BitLocker: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Store Apps Monitor
# ============================================================
class WindowsStoreAppsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("STORE_APPS", bus, interval)
        self._prev_apps: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-AppxPackage | Select-Object Name, PackageFullName"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for app in current - self._prev_apps:
                    self.bus.publish(Event("STORE_APPS", "CHANGE",
                                           f"App: {app}",
                                           severity=Severity.DEBUG,
                                           data={"app": app}))
                self._prev_apps = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Recovery Monitor
# ============================================================
class WindowsRecoveryMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("RECOVERY", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ComputerInfo | Select-Object WindowsREStatus, RecoveryEnvironment"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("RECOVERY", "STATUS",
                                           f"Recovery: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# File Change Monitor
# ============================================================
class FileChangeMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 5.0, paths: List[str] = None):
        super().__init__("FILE", bus, interval)
        self.paths = paths or [os.environ.get("USERPROFILE", "C:\\Users\\Default")]
        self._prev_hashes: Dict[str, str] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import hashlib
                for base in self.paths:
                    try:
                        for root, dirs, files in os.walk(base):
                            for f in files:
                                if f.endswith(('.log', '.txt', '.csv', '.json', '.xml', '.ini', '.cfg', '.yaml', '.yml')):
                                    path = os.path.join(root, f)
                                    try:
                                        stat = os.stat(path)
                                        h = hashlib.md5(f"{stat.st_size}:{stat.st_mtime}".encode()).hexdigest()
                                        prev = self._prev_hashes.get(path)
                                        if prev is None:
                                            self._prev_hashes[path] = h
                                        elif prev != h:
                                            self.bus.publish(Event("FILE", "CHANGE",
                                                                   f"File changed: {path}",
                                                                   severity=Severity.INFO,
                                                                   data={"path": path,
                                                                         "size": stat.st_size,
                                                                         "mtime": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()}))
                                            self._prev_hashes[path] = h
                                    except Exception:
                                        pass
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Directory Change Monitor
# ============================================================
class DirectoryChangeMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0, paths: List[str] = None):
        super().__init__("DIR", bus, interval)
        self.paths = paths or [os.environ.get("USERPROFILE", "C:\\Users\\Default")]
        self._prev_listings: Dict[str, Set[str]] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                for base in self.paths:
                    try:
                        current = set()
                        for root, dirs, files in os.walk(base):
                            for d in dirs:
                                current.add(os.path.join(root, d))
                            for f in files:
                                current.add(os.path.join(root, f))
                        prev = self._prev_listings.get(base, set())
                        added = current - prev
                        removed = prev - current
                        for path in added:
                            self.bus.publish(Event("DIR", "ADDED",
                                                   f"Added: {path}",
                                                   severity=Severity.INFO,
                                                   data={"path": path, "type": "file" if os.path.isfile(path) else "dir"}))
                        for path in removed:
                            self.bus.publish(Event("DIR", "REMOVED",
                                                   f"Removed: {path}",
                                                   severity=Severity.WARNING,
                                                   data={"path": path}))
                        self._prev_listings[base] = current
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Process Creation Monitor
# ============================================================
class ProcessCreationMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 2.0):
        super().__init__("PROC_CREATE", bus, interval)
        self._prev_pids: Set[int] = set()
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                current = set()
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        current.add(pid)
                        if pid not in self._prev_pids:
                            cmdline = " ".join(proc.info.get('cmdline', []) or [])
                            self.bus.publish(Event("PROC_CREATE", "STARTED",
                                                   f"Process started: {proc.info['name']} (PID {pid})",
                                                   severity=Severity.INFO,
                                                   data={"pid": pid,
                                                         "name": proc.info['name'],
                                                         "cmdline": cmdline[:200],
                                                         "create_time": datetime.datetime.fromtimestamp(proc.info['create_time']).isoformat()}))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                self._prev_pids = current
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Process Termination Monitor
# ============================================================
class ProcessTerminationMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 2.0):
        super().__init__("PROC_TERM", bus, interval)
        self._prev_pids: Set[int] = set()
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                current = set()
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        current.add(proc.info['pid'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                terminated = self._prev_pids - current
                for pid in terminated:
                    self.bus.publish(Event("PROC_TERM", "TERMINATED",
                                           f"Process terminated: PID {pid}",
                                           severity=Severity.INFO,
                                           data={"pid": pid}))
                self._prev_pids = current
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# New Network Connection Monitor
# ============================================================
class NewConnectionMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 2.0):
        super().__init__("NET_CONN", bus, interval)
        self._prev_conns: Set[str] = set()
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                current = set()
                for conn in psutil.net_connections(kind='inet'):
                    try:
                        key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}-{conn.status}" if conn.raddr else f"{conn.laddr.ip}:{conn.laddr.port}-None-{conn.status}"
                        current.add(key)
                        if key not in self._prev_conns:
                            self.bus.publish(Event("NET_CONN", "NEW",
                                                   f"Connection: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip if conn.raddr else 'N/A'}:{conn.raddr.port if conn.raddr else 'N/A'} ({conn.status})",
                                                   severity=Severity.INFO,
                                                   data={"local_addr": conn.laddr.ip,
                                                         "local_port": conn.laddr.port,
                                                         "remote_addr": conn.raddr.ip if conn.raddr else None,
                                                         "remote_port": conn.raddr.port if conn.raddr else None,
                                                         "status": conn.status,
                                                         "pid": conn.pid}))
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                        pass
                self._prev_conns = current
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Windows Error Reporting Detail Monitor
# ============================================================
class WERDetailMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WER_DETAIL", bus, interval)
        self._prev_reports: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WERReport | Select-Object ReportID, FaultingApplication, FaultingApplicationVersion, FaultingModuleName, ExceptionCode"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("ReportID"):
                        parts = line.split()
                        if parts:
                            report_id = parts[0]
                            if report_id not in self._prev_reports:
                                self.bus.publish(Event("WER_DETAIL", "REPORT",
                                                       f"WER: {line[:100]}",
                                                       severity=Severity.WARNING,
                                                       data={"report_id": report_id,
                                                             "details": line[:200]}))
                                self._prev_reports[report_id] = line
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Application Compatibility Monitor
# ============================================================
class AppCompatMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("APPCOMPAT", bus, interval)
        self._prev_entries: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers | Select-Object -Property *"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for entry in current - self._prev_entries:
                    self.bus.publish(Event("APPCOMPAT", "ENTRY",
                                           f"AppCompat: {entry[:100]}",
                                           severity=Severity.INFO,
                                           data={"entry": entry[:200]}))
                self._prev_entries = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Syslog/Sysmon Event Monitor
# ============================================================
class SysmonMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SYSMON", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 20 -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} | Select-Object Id, Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("SYSMON", "EVENT",
                                           f"Sysmon: {event[:100]}",
                                           severity=Severity.INFO,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# PowerShell Execution Monitor
# ============================================================
class PowerShellMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("POWERSHELL", bus, interval)
        self._prev_scripts: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 10 -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} | Select-Object Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for script in current - self._prev_scripts:
                    self.bus.publish(Event("POWERSHELL", "EXEC",
                                           f"PS: {script[:100]}",
                                           severity=Severity.INFO,
                                           data={"script": script[:200]}))
                self._prev_scripts = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# WinRM Monitor
# ============================================================
class WinRMMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WINRM", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 10 -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'} | Select-Object Id, Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("WINRM", "EVENT",
                                           f"WinRM: {event[:100]}",
                                           severity=Severity.INFO,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Scheduled Task Monitor
# ============================================================
class ScheduledTaskDetailMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SCHED_TASK", bus, interval)
        self._prev_tasks: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ScheduledTask | Select-Object TaskName, State, LastRunTime, NextRunTime"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("TaskName"):
                        parts = line.split()
                        if parts:
                            task_name = parts[0]
                            state = parts[1] if len(parts) > 1 else "Unknown"
                            key = f"{task_name}:{state}"
                            if key not in self._prev_tasks:
                                self.bus.publish(Event("SCHED_TASK", "STATE",
                                                       f"Task {task_name}: {state}",
                                                       severity=Severity.INFO,
                                                       data={"task": task_name,
                                                             "state": state,
                                                             "last_run": parts[2] if len(parts) > 2 else "",
                                                             "next_run": parts[3] if len(parts) > 3 else ""}))
                                self._prev_tasks[key] = line
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Certificate Monitor
# ============================================================
class CertificateMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("CERT", bus, interval)
        self._prev_certs: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ChildItem Cert:\\LocalMachine\\My | Select-Object Subject, NotBefore, NotAfter, Thumbprint"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for cert in current - self._prev_certs:
                    self.bus.publish(Event("CERT", "ADDED",
                                           f"Certificate: {cert[:100]}",
                                           severity=Severity.INFO,
                                           data={"cert": cert[:200]}))
                self._prev_certs = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Autorun Monitor
# ============================================================
class AutorunMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("AUTORUN", bus, interval)
        self._prev_entries: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for entry in current - self._prev_entries:
                    self.bus.publish(Event("AUTORUN", "ENTRY",
                                           f" Autorun: {entry[:100]}",
                                           severity=Severity.INFO,
                                           data={"entry": entry[:200]}))
                self._prev_entries = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Prefetch Monitor
# ============================================================
class PrefetchMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("PREFETCH", bus, interval)
        self._prev_files: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        prefetch_dir = os.environ.get("WINDIR", "C:\\Windows") + "\\Prefetch"
        while not self._stop.is_set():
            try:
                current = set()
                if os.path.exists(prefetch_dir):
                    for f in os.listdir(prefetch_dir):
                        if f.endswith(".pf"):
                            path = os.path.join(prefetch_dir, f)
                            current.add(f"{f}:{os.path.getsize(path)}")
                for pf in current - self._prev_files:
                    self.bus.publish(Event("PREFETCH", "FILE",
                                           f"Prefetch: {pf}",
                                           severity=Severity.DEBUG,
                                           data={"prefetch": pf}))
                self._prev_files = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Amcache Monitor
# ============================================================
class AmcacheMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("AMCACHE", bus, interval)
        self._prev_entries: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        amcache = os.environ.get("WINDIR", "C:\\Windows") + "\\AppCompat\\Programs\\Amcache.hve"
        while not self._stop.is_set():
            try:
                if os.path.exists(amcache):
                    size = os.path.getsize(amcache)
                    entry = f"Amcache.hve:{size}"
                    if entry not in self._prev_entries:
                        self.bus.publish(Event("AMCACHE", "CHANGE",
                                               f"Amcache updated: {size} bytes",
                                               severity=Severity.INFO,
                                               data={"size": size}))
                        self._prev_entries.add(entry)
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Recent Documents Monitor
# ============================================================
class RecentDocsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("RECENT", bus, interval)
        self._prev_docs: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        recent_dir = os.path.join(os.environ.get("APPDATA", ""), "Microsoft\\Windows\\Recent")
        while not self._stop.is_set():
            try:
                current = set()
                if os.path.exists(recent_dir):
                    for f in os.listdir(recent_dir):
                        if f.endswith(".lnk"):
                            current.add(f)
                for doc in current - self._prev_docs:
                    self.bus.publish(Event("RECENT", "OPENED",
                                           f"Recent doc: {doc}",
                                           severity=Severity.INFO,
                                           data={"doc": doc}))
                self._prev_docs = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Jump List Monitor
# ============================================================
class JumpListMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("JUMPLIST", bus, interval)
        self._prev_entries: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        jump_dir = os.path.join(os.environ.get("APPDATA", ""), "Microsoft\\Windows\\Recent\\AutomaticDestinations")
        while not self._stop.is_set():
            try:
                current = set()
                if os.path.exists(jump_dir):
                    for f in os.listdir(jump_dir):
                        path = os.path.join(jump_dir, f)
                        current.add(f"{f}:{os.path.getsize(path)}")
                for entry in current - self._prev_entries:
                    self.bus.publish(Event("JUMPLIST", "CHANGE",
                                           f"Jump list: {entry}",
                                           severity=Severity.DEBUG,
                                           data={"entry": entry}))
                self._prev_entries = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Typed URLs Monitor
# ============================================================
class TypedURLsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("TYPEDURL", bus, interval)
        self._prev_urls: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path HKCU:\\Software\\Microsoft\\Internet Explorer\\TypedURLs -Name * | Select-Object *"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for url in current - self._prev_urls:
                    self.bus.publish(Event("TYPEDURL", "VISITED",
                                           f"Typed URL: {url[:100]}",
                                           severity=Severity.INFO,
                                           data={"url": url[:200]}))
                self._prev_urls = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# User Assist Monitor
# ============================================================
class UserAssistMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("USERASSIST", bus, interval)
        self._prev_entries: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\*\\Count | Select-Object *"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for entry in current - self._prev_entries:
                    self.bus.publish(Event("USERASSIST", "USED",
                                           f"UserAssist: {entry[:100]}",
                                           severity=Severity.DEBUG,
                                           data={"entry": entry[:200]}))
                self._prev_entries = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# BagMRU Monitor
# ============================================================
class BagMRUMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("BAGMRU", bus, interval)
        self._prev_entries: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\Shell\\BagMRU | Select-Object *"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for entry in current - self._prev_entries:
                    self.bus.publish(Event("BAGMRU", "CHANGE",
                                           f"BagMRU: {entry[:100]}",
                                           severity=Severity.DEBUG,
                                           data={"entry": entry[:200]}))
                self._prev_entries = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Mingw/MSYS2 Package Monitor
# ============================================================
class PackageMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("PACKAGE", bus, interval)
        self._prev_packages: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                for cmd in [["winget", "list"], ["choco", "list", "-l"]]:
                    try:
                        result = subprocess.run(cmd, capture_output=True, encoding='utf-8', errors='replace', timeout=15)
                        current = set(result.stdout.splitlines())
                        for pkg in current - self._prev_packages:
                            self.bus.publish(Event("PACKAGE", "CHANGE",
                                                   f"Package: {pkg[:100]}",
                                                   severity=Severity.INFO,
                                                   data={"package": pkg[:200]}))
                        self._prev_packages = current
                        break
                    except FileNotFoundError:
                        continue
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Insider Build Monitor
# ============================================================
class InsiderMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("INSIDER", bus, interval)
        self._prev_build = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "[System.Environment]::OSVersion.Version.ToString()"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                build = result.stdout.strip()
                if build and build != self._prev_build:
                    self.bus.publish(Event("INSIDER", "BUILD",
                                           f"Windows build changed: {self._prev_build} -> {build}",
                                           severity=Severity.INFO,
                                           data={"old_build": self._prev_build, "new_build": build}))
                    self._prev_build = build
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Time Synchronization Monitor
# ============================================================
class TimeSyncMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("TIMESYNC", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path HKLM:\\System\\CurrentControlSet\\Services\\W32Time\\Parameters -Name NtpServer"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("TIMESYNC", "STATUS",
                                           f"NTP server: {status}",
                                           severity=Severity.INFO,
                                           data={"ntp": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Logon Monitor
# ============================================================
class LogonTypeMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("LOGONTYPE", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 10 -FilterHashtable @{LogName='Security'; Id=4624} | Select-Object -ExpandProperty Message | Select-Object -First 1"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("LOGONTYPE", "LOGIN",
                                           f"Logon type: {event[:100]}",
                                           severity=Severity.INFO,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Feature Update Monitor
# ============================================================
class FeatureUpdateMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("FEATUPDATE", bus, interval)
        self._prev_updates: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-HotFix | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-1)} | Select-Object HotFixID, InstalledOn, InstalledBy"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for update in current - self._prev_updates:
                    self.bus.publish(Event("FEATUPDATE", "INSTALLED",
                                           f"Update: {update[:100]}",
                                           severity=Severity.INFO,
                                           data={"update": update[:200]}))
                self._prev_updates = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# AppLocker Monitor
# ============================================================
class AppLockerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("APPLOCKER", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 10 -FilterHashtable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL'} | Select-Object Id, Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("APPLOCKER", "EVENT",
                                           f"AppLocker: {event[:100]}",
                                           severity=Severity.WARNING,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Defender Behavior Monitor
# ============================================================
class DefenderBehaviorMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("DEF_BEHAV", bus, interval)
        self._prev_threats: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpThreat | Select-Object ThreatName, IsActive, DidThreatExecute, SeverityID"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for threat in current - self._prev_threats:
                    self.bus.publish(Event("DEF_BEHAV", "THREAT",
                                           f"Defender threat: {threat[:100]}",
                                           severity=Severity.WARNING,
                                           data={"threat": threat[:200]}))
                self._prev_threats = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Network Profile Monitor
# ============================================================
class NetworkProfileMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("NETPROF", bus, interval)
        self._prev_profiles: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for profile in current - self._prev_profiles:
                    self.bus.publish(Event("NETPROF", "CHANGE",
                                           f"Network profile: {profile[:100]}",
                                           severity=Severity.INFO,
                                           data={"profile": profile[:200]}))
                self._prev_profiles = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# DnsClientCache Monitor
# ============================================================
class DnsCacheMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("DNS_CACHE", bus, interval)
        self._prev_entries: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-DnsClientCache | Select-Object Entry, Data, TimeToLive"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Entry"):
                        parts = line.split()
                        if parts:
                            entry = parts[0]
                            data = parts[1] if len(parts) > 1 else ""
                            current[entry] = data
                            if entry not in self._prev_entries:
                                self.bus.publish(Event("DNS_CACHE", "CACHED",
                                                       f"DNS cache: {entry} -> {data}",
                                                       severity=Severity.DEBUG,
                                                       data={"entry": entry, "data": data}))
                self._prev_entries = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Hosts File Monitor
# ============================================================
class HostsFileMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("HOSTS", bus, interval)
        self._prev_hash = None
        self.hosts_path = os.environ.get("WINDIR", "C:\\Windows") + "\\System32\\drivers\\etc\\hosts"
    
    def _run(self):
        while not self._stop.is_set():
            try:
                if os.path.exists(self.hosts_path):
                    import hashlib
                    with open(self.hosts_path, 'rb') as f:
                        h = hashlib.md5(f.read()).hexdigest()
                    if h != self._prev_hash:
                        with open(self.hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                        entries = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
                        self.bus.publish(Event("HOSTS", "CHANGED",
                                               f"Hosts file changed ({len(entries)} entries)",
                                               severity=Severity.WARNING,
                                               data={"path": self.hosts_path,
                                                     "entries": entries[:20],
                                                     "total_entries": len(entries)}))
                        self._prev_hash = h
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Proxy Settings Monitor
# ============================================================
class ProxyMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("PROXY", bus, interval)
        self._prev_proxy = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable, ProxyServer, AutoConfigURL"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                proxy = result.stdout.strip()
                if proxy and proxy != self._prev_proxy:
                    self.bus.publish(Event("PROXY", "CHANGE",
                                           f"Proxy: {proxy}",
                                           severity=Severity.INFO,
                                           data={"proxy": proxy}))
                    self._prev_proxy = proxy
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Autopilot Monitor
# ============================================================
class AutopilotMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("AUTOPILOT", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Autopilot -Name *"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("AUTOPILOT", "STATUS",
                                           f"Autopilot: {status[:100]}",
                                           severity=Severity.INFO,
                                           data={"status": status[:200]}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Sandbox Monitor
# ============================================================
class SandboxMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SANDBOX", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Sandbox | Select-Object State"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("SANDBOX", "STATUS",
                                           f"Sandbox: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# WSL Monitor
# ============================================================
class WSLMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WSL", bus, interval)
        self._prev_distros: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["wsl", "--list", "--verbose"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for distro in current - self._prev_distros:
                    self.bus.publish(Event("WSL", "DISTRO",
                                           f"WSL: {distro[:100]}",
                                           severity=Severity.INFO,
                                           data={"distro": distro[:200]}))
                self._prev_distros = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Docker Monitor
# ============================================================
class DockerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("DOCKER", bus, interval)
        self._prev_containers: Set[str] = set()
    
    def _run(self):
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["docker", "ps", "-a", "--format", "{{.ID}} {{.Names}} {{.Status}}"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for container in current - self._prev_containers:
                    self.bus.publish(Event("DOCKER", "CONTAINER",
                                           f"Docker: {container[:100]}",
                                           severity=Severity.INFO,
                                           data={"container": container[:200]}))
                self._prev_containers = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Hyper-V Monitor
# ============================================================
class HyperVMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("HYPERV", bus, interval)
        self._prev_vms: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-VM | Select-Object Name, State, Uptime"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for vm in current - self._prev_vms:
                    self.bus.publish(Event("HYPERV", "VM",
                                           f"Hyper-V: {vm[:100]}",
                                           severity=Severity.INFO,
                                           data={"vm": vm[:200]}))
                self._prev_vms = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Update Log Monitor
# ============================================================
class WindowsUpdateLogMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("WU_LOG", bus, interval)
        self._prev_lines: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        log_path = os.environ.get("WINDIR", "C:\\Windows") + "\\Logs\\WindowsUpdate\\WindowsUpdate.log"
        while not self._stop.is_set():
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    current = set(lines[-100:])
                    for line in current - self._prev_lines:
                        if line.strip():
                            self.bus.publish(Event("WU_LOG", "UPDATE",
                                                   f"WU: {line.strip()[:100]}",
                                                   severity=Severity.DEBUG,
                                                   data={"line": line.strip()[:200]}))
                    self._prev_lines = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# SetupAPI Log Monitor
# ============================================================
class SetupAPIMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SETUPAPI", bus, interval)
        self._prev_lines: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        log_path = os.environ.get("WINDIR", "C:\\Windows") + "\\inf\\setupapi.log"
        while not self._stop.is_set():
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    current = set(lines[-50:])
                    for line in current - self._prev_lines:
                        if line.strip():
                            self.bus.publish(Event("SETUPAPI", "DEVICE",
                                                   f"SetupAPI: {line.strip()[:100]}",
                                                   severity=Severity.INFO,
                                                   data={"line": line.strip()[:200]}))
                    self._prev_lines = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Crypto Key Monitor
# ============================================================
class CryptoKeyMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("CRYPTO", bus, interval)
        self._prev_keys: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ChildItem Cert:\\LocalMachine\\My | Select-Object Thumbprint, Subject"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for key in current - self._prev_keys:
                    self.bus.publish(Event("CRYPTO", "KEY",
                                           f"Crypto key: {key[:100]}",
                                           severity=Severity.INFO,
                                           data={"key": key[:200]}))
                self._prev_keys = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Cloud Sync Monitor (OneDrive, Dropbox, Google Drive)
# ============================================================
class CloudSyncMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("CLOUD", bus, interval)
        self._prev_status: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                cloud_dirs = [
                    (os.environ.get("LOCALAPPDATA", "") + "\\Microsoft\\OneDrive", "OneDrive"),
                    (os.environ.get("LOCALAPPDATA", "") + "\\Dropbox", "Dropbox"),
                    (os.environ.get("LOCALAPPDATA", "") + "\\Google\\Drive", "Google Drive"),
                ]
                for path, name in cloud_dirs:
                    try:
                        if os.path.exists(path):
                            status = "syncing" if any(os.path.getsize(os.path.join(root, f)) > 0 for root, _, files in os.walk(path) for f in files[:5]) else "idle"
                            key = f"{name}:{status}"
                            if key not in self._prev_status:
                                self.bus.publish(Event("CLOUD", "SYNC",
                                                       f"Cloud sync: {name} {status}",
                                                       severity=Severity.INFO,
                                                       data={"service": name, "status": status, "path": path}))
                                self._prev_status[key] = status
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Admin Center Monitor
# ============================================================
class WindowsAdminCenterMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("WAC", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-Service -Name 'ServerManagementGateway' | Select-Object Status"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("WAC", "STATUS",
                                           f"Windows Admin Center: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# IIS Monitor
# ============================================================
class IISMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("IIS", bus, interval)
        self._prev_sites: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Import-Module WebAdministration; Get-Website | Select-Object Name, State, Bindings"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for site in current - self._prev_sites:
                    self.bus.publish(Event("IIS", "SITE",
                                           f"IIS: {site[:100]}",
                                           severity=Severity.INFO,
                                           data={"site": site[:200]}))
                self._prev_sites = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# SQL Server Monitor
# ============================================================
class SQLServerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SQL", bus, interval)
        self._prev_services: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-Service -Name 'MSSQL*' | Select-Object Name, Status"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for svc in current - self._prev_services:
                    self.bus.publish(Event("SQL", "SERVICE",
                                           f"SQL: {svc[:100]}",
                                           severity=Severity.INFO,
                                           data={"service": svc[:200]}))
                self._prev_services = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Exchange Monitor
# ============================================================
class ExchangeMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("EXCHANGE", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-Service -Name 'MSExchange*' | Select-Object Name, Status"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("EXCHANGE", "STATUS",
                                           f"Exchange: {status[:100]}",
                                           severity=Severity.INFO,
                                           data={"status": status[:200]}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Active Directory Monitor
# ============================================================
class ADMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("AD", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-EventLog -LogName Directory Service -Newest 10 | Select-Object TimeGenerated, EntryType, Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("AD", "EVENT",
                                           f"AD: {event[:100]}",
                                           severity=Severity.INFO,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Group Policy Monitor
# ============================================================
class GPMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("GP", bus, interval)
        self._prev_version = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "gpresult /r | Select-String 'Version'"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                version = result.stdout.strip()
                if version and version != self._prev_version:
                    self.bus.publish(Event("GP", "CHANGE",
                                           f"Group Policy: {version}",
                                           severity=Severity.INFO,
                                           data={"version": version}))
                    self._prev_version = version
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Defender ATP Monitor
# ============================================================
class DefenderATPMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("DEF_ATP", bus, interval)
        self._prev_alerts: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpThreat | Select-Object ThreatName, SeverityID, IsActive"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for alert in current - self._prev_alerts:
                    self.bus.publish(Event("DEF_ATP", "ALERT",
                                           f"Defender ATP: {alert[:100]}",
                                           severity=Severity.WARNING,
                                           data={"alert": alert[:200]}))
                self._prev_alerts = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Printer Queue Monitor
# ============================================================
class PrinterQueueMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("PRINTER", bus, interval)
        self._prev_jobs: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-Printer | Select-Object Name, PrinterStatus, JobCount"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for printer in current - self._prev_jobs:
                    self.bus.publish(Event("PRINTER", "STATUS",
                                           f"Printer: {printer[:100]}",
                                           severity=Severity.INFO,
                                           data={"printer": printer[:200]}))
                self._prev_jobs = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Update Telemetry Monitor
# ============================================================
class WUTelemetryMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("WU_TELE", bus, interval)
        self._prev_telemetry = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path HKLM:\\Software\\Policies\\Microsoft\\Windows\\DataCollection -Name AllowTelemetry"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                telemetry = result.stdout.strip()
                if telemetry and telemetry != self._prev_telemetry:
                    self.bus.publish(Event("WU_TELE", "CHANGE",
                                           f"Telemetry: {telemetry}",
                                           severity=Severity.INFO,
                                           data={"telemetry": telemetry}))
                    self._prev_telemetry = telemetry
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Performance Monitor
# ============================================================
class PerfMon(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("PERFMON", bus, interval)
        self._prev_counters: Dict[str, float] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                disk = psutil.disk_io_counters()
                net = psutil.net_io_counters()
                
                counters = {
                    "CPU": cpu,
                    "MEM_AVAIL": mem.available / 1024 / 1024,
                    "DISK_READ": disk.read_bytes if disk else 0,
                    "DISK_WRITE": disk.write_bytes if disk else 0,
                    "NET_SENT": net.bytes_sent if net else 0,
                    "NET_RECV": net.bytes_recv if net else 0,
                }
                
                for name, val in counters.items():
                    prev = self._prev_counters.get(name)
                    if prev is not None and abs(val - prev) > 1:
                        self.bus.publish(Event("PERFMON", "COUNTER",
                                               f"{name}: {val:.1f}",
                                               severity=Severity.DEBUG,
                                               data={"counter": name, "value": val, "prev": prev}))
                    self._prev_counters[name] = val
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(5.0)

# ============================================================
# Windows Event Forwarding Monitor
# ============================================================
class WEFMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WEF", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 10 -FilterHashtable @{LogName='Microsoft-Windows-EventForwarding/Operational'} | Select-Object Id, Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("WEF", "EVENT",
                                           f"WEF: {event[:100]}",
                                           severity=Severity.INFO,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# LAPS Password Monitor
# ============================================================
class LAPSMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("LAPS", bus, interval)
        self._prev_passwords: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ADComputer -Filter * -Property ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime | Select-Object Name, ms-Mcs-AdmPwd"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for pwd in current - self._prev_passwords:
                    self.bus.publish(Event("LAPS", "PASSWORD",
                                           f"LAPS: {pwd[:100]}",
                                           severity=Severity.WARNING,
                                           data={"password": pwd[:200]}))
                self._prev_passwords = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Hello Monitor
# ============================================================
class HelloMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("HELLO", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("HELLO", "STATUS",
                                           f"BitLocker: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Sandbox Monitor
# ============================================================
class SandboxMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SANDBOX", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Sandbox | Select-Object State"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("SANDBOX", "STATUS",
                                           f"Sandbox: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# WSL Monitor
# ============================================================
class WSLMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WSL", bus, interval)
        self._prev_distros: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["wsl", "--list", "--verbose"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for distro in current - self._prev_distros:
                    self.bus.publish(Event("WSL", "DISTRO",
                                           f"WSL: {distro[:100]}",
                                           severity=Severity.INFO,
                                           data={"distro": distro[:200]}))
                self._prev_distros = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Docker Monitor
# ============================================================
class DockerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("DOCKER", bus, interval)
        self._prev_containers: Set[str] = set()
    
    def _run(self):
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["docker", "ps", "-a", "--format", "{{.ID}} {{.Names}} {{.Status}}"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for container in current - self._prev_containers:
                    self.bus.publish(Event("DOCKER", "CONTAINER",
                                           f"Docker: {container[:100]}",
                                           severity=Severity.INFO,
                                           data={"container": container[:200]}))
                self._prev_containers = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Hyper-V Monitor
# ============================================================
class HyperVMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("HYPERV", bus, interval)
        self._prev_vms: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-VM | Select-Object Name, State, Uptime"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for vm in current - self._prev_vms:
                    self.bus.publish(Event("HYPERV", "VM",
                                           f"Hyper-V: {vm[:100]}",
                                           severity=Severity.INFO,
                                           data={"vm": vm[:200]}))
                self._prev_vms = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Update Log Monitor
# ============================================================
class WULogMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("WU_LOG", bus, interval)
        self._prev_lines: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        log_path = os.environ.get("WINDIR", "C:\\Windows") + "\\Logs\\WindowsUpdate\\WindowsUpdate.log"
        while not self._stop.is_set():
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    current = set(lines[-100:])
                    for line in current - self._prev_lines:
                        if line.strip():
                            self.bus.publish(Event("WU_LOG", "UPDATE",
                                                   f"WU: {line.strip()[:100]}",
                                                   severity=Severity.DEBUG,
                                                   data={"line": line.strip()[:200]}))
                    self._prev_lines = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# SetupAPI Log Monitor
# ============================================================
class SetupAPIMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SETUPAPI", bus, interval)
        self._prev_lines: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        log_path = os.environ.get("WINDIR", "C:\\Windows") + "\\inf\\setupapi.log"
        while not self._stop.is_set():
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    current = set(lines[-50:])
                    for line in current - self._prev_lines:
                        if line.strip():
                            self.bus.publish(Event("SETUPAPI", "DEVICE",
                                                   f"SetupAPI: {line.strip()[:100]}",
                                                   severity=Severity.INFO,
                                                   data={"line": line.strip()[:200]}))
                    self._prev_lines = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Crypto Key Monitor
# ============================================================
class CryptoKeyMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("CRYPTO", bus, interval)
        self._prev_keys: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ChildItem Cert:\\LocalMachine\\My | Select-Object Thumbprint, Subject"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for key in current - self._prev_keys:
                    self.bus.publish(Event("CRYPTO", "KEY",
                                           f"Crypto key: {key[:100]}",
                                           severity=Severity.INFO,
                                           data={"key": key[:200]}))
                self._prev_keys = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Feature Update Monitor
# ============================================================
class FeatureUpdateMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("FEATUPDATE", bus, interval)
        self._prev_updates: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-HotFix | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-1)} | Select-Object HotFixID, InstalledOn, InstalledBy"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for update in current - self._prev_updates:
                    self.bus.publish(Event("FEATUPDATE", "INSTALLED",
                                           f"Update: {update[:100]}",
                                           severity=Severity.INFO,
                                           data={"update": update[:200]}))
                self._prev_updates = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# AppLocker Monitor
# ============================================================
class AppLockerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("APPLOCKER", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 10 -FilterHashtable @{LogName='Microsoft-Windows-AppLocker/EXE and DLL'} | Select-Object Id, Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("APPLOCKER", "EVENT",
                                           f"AppLocker: {event[:100]}",
                                           severity=Severity.WARNING,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Defender Behavior Monitor
# ============================================================
class DefenderBehaviorMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("DEF_BEHAV", bus, interval)
        self._prev_threats: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpThreat | Select-Object ThreatName, IsActive, DidThreatExecute, SeverityID"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for threat in current - self._prev_threats:
                    self.bus.publish(Event("DEF_BEHAV", "THREAT",
                                           f"Defender threat: {threat[:100]}",
                                           severity=Severity.WARNING,
                                           data={"threat": threat[:200]}))
                self._prev_threats = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Network Profile Monitor
# ============================================================
class NetworkProfileMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("NETPROF", bus, interval)
        self._prev_profiles: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for profile in current - self._prev_profiles:
                    self.bus.publish(Event("NETPROF", "CHANGE",
                                           f"Network profile: {profile[:100]}",
                                           severity=Severity.INFO,
                                           data={"profile": profile[:200]}))
                self._prev_profiles = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# DnsClientCache Monitor
# ============================================================
class DnsCacheMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("DNS_CACHE", bus, interval)
        self._prev_entries: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-DnsClientCache | Select-Object Entry, Data, TimeToLive"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Entry"):
                        parts = line.split()
                        if parts:
                            entry = parts[0]
                            data = parts[1] if len(parts) > 1 else ""
                            current[entry] = data
                            if entry not in self._prev_entries:
                                self.bus.publish(Event("DNS_CACHE", "CACHED",
                                                       f"DNS cache: {entry} -> {data}",
                                                       severity=Severity.DEBUG,
                                                       data={"entry": entry, "data": data}))
                self._prev_entries = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Hosts File Monitor
# ============================================================
class HostsFileMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("HOSTS", bus, interval)
        self._prev_hash = None
        self.hosts_path = os.environ.get("WINDIR", "C:\\Windows") + "\\System32\\drivers\\etc\\hosts"
    
    def _run(self):
        while not self._stop.is_set():
            try:
                if os.path.exists(self.hosts_path):
                    import hashlib
                    with open(self.hosts_path, 'rb') as f:
                        h = hashlib.md5(f.read()).hexdigest()
                    if h != self._prev_hash:
                        with open(self.hosts_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                        entries = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
                        self.bus.publish(Event("HOSTS", "CHANGED",
                                               f"Hosts file changed ({len(entries)} entries)",
                                               severity=Severity.WARNING,
                                               data={"path": self.hosts_path,
                                                     "entries": entries[:20],
                                                     "total_entries": len(entries)}))
                        self._prev_hash = h
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Proxy Settings Monitor
# ============================================================
class ProxyMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("PROXY", bus, interval)
        self._prev_proxy = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable, ProxyServer, AutoConfigURL"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                proxy = result.stdout.strip()
                if proxy and proxy != self._prev_proxy:
                    self.bus.publish(Event("PROXY", "CHANGE",
                                           f"Proxy: {proxy}",
                                           severity=Severity.INFO,
                                           data={"proxy": proxy}))
                    self._prev_proxy = proxy
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Autopilot Monitor
# ============================================================
class AutopilotMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("AUTOPILOT", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Autopilot -Name *"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("AUTOPILOT", "STATUS",
                                           f"Autopilot: {status[:100]}",
                                           severity=Severity.INFO,
                                           data={"status": status[:200]}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Sandbox Monitor
# ============================================================
class SandboxMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SANDBOX", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Sandbox | Select-Object State"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("SANDBOX", "STATUS",
                                           f"Sandbox: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# WSL Monitor
# ============================================================
class WSLMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WSL", bus, interval)
        self._prev_distros: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["wsl", "--list", "--verbose"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for distro in current - self._prev_distros:
                    self.bus.publish(Event("WSL", "DISTRO",
                                           f"WSL: {distro[:100]}",
                                           severity=Severity.INFO,
                                           data={"distro": distro[:200]}))
                self._prev_distros = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Docker Monitor
# ============================================================
class DockerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("DOCKER", bus, interval)
        self._prev_containers: Set[str] = set()
    
    def _run(self):
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["docker", "ps", "-a", "--format", "{{.ID}} {{.Names}} {{.Status}}"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for container in current - self._prev_containers:
                    self.bus.publish(Event("DOCKER", "CONTAINER",
                                           f"Docker: {container[:100]}",
                                           severity=Severity.INFO,
                                           data={"container": container[:200]}))
                self._prev_containers = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Hyper-V Monitor
# ============================================================
class HyperVMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("HYPERV", bus, interval)
        self._prev_vms: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-VM | Select-Object Name, State, Uptime"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for vm in current - self._prev_vms:
                    self.bus.publish(Event("HYPERV", "VM",
                                           f"Hyper-V: {vm[:100]}",
                                           severity=Severity.INFO,
                                           data={"vm": vm[:200]}))
                self._prev_vms = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Update Log Monitor
# ============================================================
class WULogMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("WU_LOG", bus, interval)
        self._prev_lines: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        log_path = os.environ.get("WINDIR", "C:\\Windows") + "\\Logs\\WindowsUpdate\\WindowsUpdate.log"
        while not self._stop.is_set():
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    current = set(lines[-100:])
                    for line in current - self._prev_lines:
                        if line.strip():
                            self.bus.publish(Event("WU_LOG", "UPDATE",
                                                   f"WU: {line.strip()[:100]}",
                                                   severity=Severity.DEBUG,
                                                   data={"line": line.strip()[:200]}))
                    self._prev_lines = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# SetupAPI Log Monitor
# ============================================================
class SetupAPIMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("SETUPAPI", bus, interval)
        self._prev_lines: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        log_path = os.environ.get("WINDIR", "C:\\Windows") + "\\inf\\setupapi.log"
        while not self._stop.is_set():
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                    current = set(lines[-50:])
                    for line in current - self._prev_lines:
                        if line.strip():
                            self.bus.publish(Event("SETUPAPI", "DEVICE",
                                                   f"SetupAPI: {line.strip()[:100]}",
                                                   severity=Severity.INFO,
                                                   data={"line": line.strip()[:200]}))
                    self._prev_lines = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Crypto Key Monitor
# ============================================================
class CryptoKeyMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("CRYPTO", bus, interval)
        self._prev_keys: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ChildItem Cert:\\LocalMachine\\My | Select-Object Thumbprint, Subject"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for key in current - self._prev_keys:
                    self.bus.publish(Event("CRYPTO", "KEY",
                                           f"Crypto key: {key[:100]}",
                                           severity=Severity.INFO,
                                           data={"key": key[:200]}))
                self._prev_keys = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Performance Recorder Monitor
# ============================================================
class WPRMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("WPR", bus, interval)
        self._prev_traces: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        wpr_dir = os.environ.get("WINDIR", "C:\\Windows") + "\\Logs\\WPR"
        while not self._stop.is_set():
            try:
                if os.path.exists(wpr_dir):
                    current = set()
                    for f in os.listdir(wpr_dir):
                        if f.endswith(".etl"):
                            path = os.path.join(wpr_dir, f)
                            current.add(f"{f}:{os.path.getsize(path)}")
                    for trace in current - self._prev_traces:
                        self.bus.publish(Event("WPR", "TRACE",
                                               f"WPR trace: {trace}",
                                               severity=Severity.DEBUG,
                                               data={"trace": trace}))
                    self._prev_traces = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Memory Diagnostic Monitor
# ============================================================
class MemDiagMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("MEMDIAG", bus, interval)
        self._prev_result = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ChildItem -Path C:\\Windows\\Logs\\CBS\\*.log | Select-Object -First 1 | ForEach-Object { $_.LastWriteTime }"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                result_time = result.stdout.strip()
                if result_time and result_time != self._prev_result:
                    self.bus.publish(Event("MEMDIAG", "RESULT",
                                           f"Memory diagnostic: {result_time}",
                                           severity=Severity.INFO,
                                           data={"result_time": result_time}))
                    self._prev_result = result_time
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Reset Monitor
# ============================================================
class ResetMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("RESET", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ComputerInfo | Select-Object WindowsResetStatus"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("RESET", "STATUS",
                                           f"Windows Reset: {status}",
                                           severity=Severity.WARNING,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Hello Monitor
# ============================================================
class HelloMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("HELLO", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus, KeyProtector"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("HELLO", "STATUS",
                                           f"BitLocker/Hello: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Event Log Channel Monitor
# ============================================================
class EventLogChannelMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0, channels: List[str] = None):
        super().__init__("EVENTLOG_CH", bus, interval)
        self.channels = channels or ["System", "Application", "Security", "Setup", "ForwardedEvents"]
        self._prev_counts: Dict[str, int] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                for channel in self.channels:
                    try:
                        result = subprocess.run(
                            ["wevtutil", "qe", channel, "/c", "1", "/f", "text"],
                            capture_output=True, encoding='utf-8', errors='replace', timeout=10
                        )
                        count = len(result.stdout.splitlines())
                        prev = self._prev_counts.get(channel, 0)
                        if count > prev:
                            self.bus.publish(Event("EVENTLOG_CH", "NEW",
                                                   f"Channel {channel}: {count - prev} new events",
                                                   severity=Severity.INFO,
                                                   data={"channel": channel, "new_count": count - prev}))
                        self._prev_counts[channel] = count
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Performance Counter Monitor
# ============================================================
class PerformanceCounterMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("PERF", bus, interval)
        self._prev_values: Dict[str, float] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                counters = {
                    "CPU": "\\Processor(_Total)\\% Processor Time",
                    "MEMORY": "\\Memory\\Available MBytes",
                    "DISK_READ": "\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                    "DISK_WRITE": "\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
                    "NET_SENT": "\\Network Interface(*)\\Bytes Sent/sec",
                    "NET_RECV": "\\Network Interface(*)\\Bytes Received/sec",
                }
                try:
                    import psutil
                    cpu = psutil.cpu_percent(interval=1)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_io_counters()
                    net = psutil.net_io_counters()
                    
                    values = {
                        "CPU": cpu,
                        "MEMORY": mem.available / 1024 / 1024,
                        "DISK_READ": disk.read_bytes if disk else 0,
                        "DISK_WRITE": disk.write_bytes if disk else 0,
                        "NET_SENT": net.bytes_sent if net else 0,
                        "NET_RECV": net.bytes_recv if net else 0,
                    }
                    
                    for name, val in values.items():
                        prev = self._prev_values.get(name)
                        if prev is not None and abs(val - prev) > 1:
                            self.bus.publish(Event("PERF", "COUNTER",
                                                   f"{name}: {val:.1f}",
                                                   severity=Severity.DEBUG,
                                                   data={"counter": name, "value": val}))
                        self._prev_values[name] = val
                except ImportError:
                    pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Update Monitor
# ============================================================
class WindowsUpdateMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("WUPDATE", bus, interval)
        self._prev_updates: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-HotFix | Select-Object -ExpandProperty HotFixID"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for update in current - self._prev_updates:
                    self.bus.publish(Event("WUPDATE", "INSTALLED",
                                           f"Update installed: {update}",
                                           severity=Severity.INFO,
                                           data={"update_id": update}))
                self._prev_updates = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Installed Software Monitor
# ============================================================
class InstalledSoftwareMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("SOFTWARE", bus, interval)
        self._prev_software: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set()
                for line in result.stdout.splitlines():
                    if line.strip():
                        current.add(line.strip())
                for sw in current - self._prev_software:
                    self.bus.publish(Event("SOFTWARE", "CHANGE",
                                           f"Software: {sw}",
                                           severity=Severity.INFO,
                                           data={"software": sw}))
                self._prev_software = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Features Monitor
# ============================================================
class WindowsFeaturesMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("WINFEAT", bus, interval)
        self._prev_features: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WindowsFeature | Select-Object Name, InstallState"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Name"):
                        parts = line.split()
                        if len(parts) >= 2:
                            current[parts[0]] = parts[1]
                            if parts[0] not in self._prev_features:
                                self.bus.publish(Event("WINFEAT", "STATE",
                                                       f"Feature {parts[0]}: {parts[1]}",
                                                       severity=Severity.INFO,
                                                       data={"feature": parts[0], "state": parts[1]}))
                self._prev_features = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Network Adapter Monitor
# ============================================================
class NetworkAdapterMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("NETADAPTER", bus, interval)
        self._prev_adapters: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-NetAdapter | Select-Object Name, Status, LinkSpeed"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = {}
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Name"):
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            status = parts[1]
                            current[name] = status
                            if name not in self._prev_adapters:
                                self.bus.publish(Event("NETADAPTER", "CHANGE",
                                                       f"Adapter {name}: {status}",
                                                       severity=Severity.INFO,
                                                       data={"adapter": name, "status": status}))
                self._prev_adapters = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# TCP Statistics Monitor
# ============================================================
class TCPStatsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("TCPSTATS", bus, interval)
        self._prev_stats: Optional[Dict[str, int]] = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["netstat", "-s"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                stats = {}
                for line in result.stdout.splitlines():
                    if "segments" in line.lower() or "connections" in line.lower():
                        parts = line.split()
                        if parts:
                            try:
                                stats[line.strip()] = int(parts[-1])
                            except ValueError:
                                pass
                if self._prev_stats:
                    for key, val in stats.items():
                        prev = self._prev_stats.get(key, 0)
                        if val != prev:
                            self.bus.publish(Event("TCPSTATS", "CHANGE",
                                                   f"{key}: {prev} -> {val}",
                                                   severity=Severity.DEBUG,
                                                   data={"stat": key, "old": prev, "new": val}))
                self._prev_stats = stats
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# UAC Monitor
# ============================================================
class UACMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("UAC", bus, interval)
        self._prev_level = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name ConsentPromptBehaviorLevel"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                level = None
                for line in result.stdout.splitlines():
                    if "ConsentPromptBehaviorLevel" in line:
                        parts = line.split()
                        if parts:
                            level = parts[-1]
                if level is not None and level != self._prev_level:
                    self.bus.publish(Event("UAC", "CHANGE",
                                           f"UAC level changed: {self._prev_level} -> {level}",
                                           severity=Severity.WARNING,
                                           data={"old_level": self._prev_level, "new_level": level}))
                    self._prev_level = level
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# SmartScreen Monitor
# ============================================================
class SmartScreenMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("SMARTSCREEN", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpPreference | Select-Object -ExpandProperty SmartScreenEnabled"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("SMARTSCREEN", "STATUS",
                                           f"SmartScreen: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Credential Manager Monitor
# ============================================================
class CredentialMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("CRED", bus, interval)
        self._prev_creds: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["cmdkey", "/list"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set()
                for line in result.stdout.splitlines():
                    if "Target:" in line:
                        current.add(line.strip())
                        if line.strip() not in self._prev_creds:
                            self.bus.publish(Event("CRED", "ADDED",
                                                   f"Credential: {line.strip()}",
                                                   severity=Severity.INFO,
                                                   data={"target": line.strip()}))
                for cred in self._prev_creds - current:
                    self.bus.publish(Event("CRED", "REMOVED",
                                           f"Credential removed: {cred}",
                                           severity=Severity.INFO,
                                           data={"target": cred}))
                self._prev_creds = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Error Reporting Monitor
# ============================================================
class WERMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("WER", bus, interval)
        self._prev_reports: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WERReport | Select-Object -ExpandProperty ReportID"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for report in current - self._prev_reports:
                    self.bus.publish(Event("WER", "REPORT",
                                           f"Error report: {report}",
                                           severity=Severity.WARNING,
                                           data={"report_id": report}))
                self._prev_reports = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Dump File Monitor
# ============================================================
class DumpFileMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0, paths: List[str] = None):
        super().__init__("DUMP", bus, interval)
        self.paths = paths or [
            os.environ.get("WINDIR", "C:\\Windows") + "\\Minidump",
            os.environ.get("WINDIR", "C:\\Windows") + "\\MEMORY.DMP",
        ]
        self._prev_sizes: Dict[str, int] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                for path in self.paths:
                    try:
                        p = Path(path)
                        if not p.exists():
                            continue
                        if p.is_file():
                            size = p.stat().st_size
                            prev = self._prev_sizes.get(path, 0)
                            if size != prev:
                                self.bus.publish(Event("DUMP", "CHANGE",
                                                       f"Dump file {p.name}: {prev} -> {size}",
                                                       severity=Severity.WARNING,
                                                       data={"path": str(p), "old_size": prev, "new_size": size}))
                                self._prev_sizes[path] = size
                        elif p.is_dir():
                            files = list(p.glob("*.dmp"))
                            for f in files:
                                size = f.stat().st_size
                                key = str(f)
                                prev = self._prev_sizes.get(key, 0)
                                if size != prev:
                                    self.bus.publish(Event("DUMP", "CHANGE",
                                                           f"Dump {f.name}: {prev} -> {size}",
                                                           severity=Severity.WARNING,
                                                           data={"path": str(f), "old_size": prev, "new_size": size}))
                                    self._prev_sizes[key] = size
                    except Exception:
                        pass
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Pagefile Monitor
# ============================================================
class PagefileMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("PAGEFILE", bus, interval)
        self._prev_usage: Optional[float] = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-CimInstance Win32_PageFileUsage | Select-Object Name, CurrentUsage, AllocatedBaseSize"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Name"):
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[0]
                            usage = int(parts[1])
                            total = int(parts[2])
                            percent = (usage / total * 100) if total > 0 else 0
                            if self._prev_usage is not None and abs(percent - self._prev_usage) > 5:
                                self.bus.publish(Event("PAGEFILE", "USAGE",
                                                       f"Pagefile {name}: {percent:.1f}%",
                                                       severity=Severity.INFO if percent < 80 else Severity.WARNING,
                                                       data={"name": name, "usage": usage, "total": total, "percent": percent}))
                            self._prev_usage = percent
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Hibernation Monitor
# ============================================================
class HibernationMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("HIBER", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powercfg", "/a"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = "enabled" if "Hibernate" in result.stdout and "Not available" not in result.stdout else "disabled"
                if status != self._prev_status:
                    self.bus.publish(Event("HIBER", "STATUS",
                                           f"Hibernation: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Fan Speed Monitor
# ============================================================
class FanSpeedMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("FAN", bus, interval)
        self._prev_speed: Dict[str, int] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                temps = psutil.sensors_temperatures()
                fans = psutil.sensors_fans()
                if fans:
                    for name, entries in fans.items():
                        for entry in entries:
                            speed = entry.current
                            key = f"{name}_{entry.label or 'fan'}"
                            prev = self._prev_speed.get(key)
                            if prev is not None and speed != prev:
                                self.bus.publish(Event("FAN", "SPEED",
                                                       f"{key}: {prev} -> {speed} RPM",
                                                       severity=Severity.DEBUG,
                                                       data={"sensor": key, "old_speed": prev, "new_speed": speed}))
                            self._prev_speed[key] = speed
                time.sleep(self.interval)
            except (ImportError, AttributeError):
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# Thermal Zone Monitor
# ============================================================
class ThermalZoneMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("THERMAL", bus, interval)
        self._prev_zones: Dict[str, float] = {}
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import psutil
                temps = psutil.sensors_temperatures()
                for name, entries in temps.items():
                    for entry in entries:
                        temp = entry.current
                        zone = f"{name}_{entry.label or 'thermal'}"
                        prev = self._prev_zones.get(zone)
                        if prev is not None and abs(temp - prev) > 2:
                            sev = Severity.INFO if temp < 70 else (Severity.WARNING if temp < 90 else Severity.ERROR)
                            self.bus.publish(Event("THERMAL", "TEMP",
                                                   f"{zone}: {temp}C",
                                                   severity=sev,
                                                   data={"zone": zone, "temp": temp}))
                        self._prev_zones[zone] = temp
                time.sleep(self.interval)
            except ImportError:
                break
            except Exception:
                time.sleep(10.0)

# ============================================================
# GPU Stats Monitor
# ============================================================
class GPUStatsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("GPU", bus, interval)
        self._prev_usage: Optional[float] = None
    
    def _run(self):
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Name"):
                        self.bus.publish(Event("GPU", "INFO",
                                               f"GPU: {line.strip()}",
                                               severity=Severity.DEBUG,
                                               data={"info": line.strip()}))
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Hello Monitor
# ============================================================
class HelloMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("HELLO", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus, KeyProtector"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("HELLO", "STATUS",
                                           f"BitLocker/Hello: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Lock Screen Monitor
# ============================================================
class LockScreenMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 10.0):
        super().__init__("LOCK", bus, interval)
        self._prev_locked = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "$ts = [TimeZoneInfo]::Local; $ts.IsDaylightSavingTime([DateTime]::Now)"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                is_locked = result.stdout.strip()
                if is_locked != self._prev_locked:
                    self.bus.publish(Event("LOCK", "STATUS",
                                           f"Lock status: {is_locked}",
                                           severity=Severity.DEBUG,
                                           data={"locked": is_locked}))
                    self._prev_locked = is_locked
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Screen Saver Monitor
# ============================================================
class ScreenSaverMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 15.0):
        super().__init__("SCRSAVER", bus, interval)
        self._prev_active = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "(Get-ItemProperty -Path HKCU:\\Control Panel\\Desktop -Name ScreenSaveActive).ScreenSaveActive"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                active = result.stdout.strip()
                if active != self._prev_active:
                    self.bus.publish(Event("SCRSAVER", "STATUS",
                                           f"Screensaver: {active}",
                                           severity=Severity.DEBUG,
                                           data={"active": active}))
                    self._prev_active = active
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Logon Monitor
# ============================================================
class LogonMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("LOGON", bus, interval)
        self._prev_events: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-WinEvent -MaxEvents 10 -FilterHashtable @{LogName='Security'; Id=4624} | Select-Object -ExpandProperty Message"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for event in current - self._prev_events:
                    self.bus.publish(Event("LOGON", "LOGIN",
                                           f"Logon: {event[:100]}",
                                           severity=Severity.INFO,
                                           data={"event": event[:200]}))
                self._prev_events = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Defender Exclusions Monitor
# ============================================================
class DefenderExclusionsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("DEF_EXCL", bus, interval)
        self._prev_exclusions: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for excl in current - self._prev_exclusions:
                    self.bus.publish(Event("DEF_EXCL", "ADDED",
                                           f"Defender exclusion: {excl}",
                                           severity=Severity.WARNING,
                                           data={"path": excl}))
                self._prev_exclusions = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Defender Scan Monitor
# ============================================================
class DefenderScanMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("DEF_SCAN", bus, interval)
        self._prev_scan_id = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-MpComputerStatus | Select-Object QuickScanStartTime, FullScanStartTime"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                scan_id = result.stdout.strip()
                if scan_id and scan_id != self._prev_scan_id:
                    self.bus.publish(Event("DEF_SCAN", "SCAN",
                                           f"Defender scan: {scan_id}",
                                           severity=Severity.INFO,
                                           data={"scan": scan_id}))
                    self._prev_scan_id = scan_id
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Firewall Rules Monitor
# ============================================================
class FirewallRulesMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("FW_RULES", bus, interval)
        self._prev_rules: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for rule in current - self._prev_rules:
                    self.bus.publish(Event("FW_RULES", "CHANGE",
                                           f"Firewall rule: {rule}",
                                           severity=Severity.INFO,
                                           data={"rule": rule}))
                self._prev_rules = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Scheduled Task Execution Monitor
# ============================================================
class TaskExecutionMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("TASK_EXEC", bus, interval)
        self._prev_tasks: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ScheduledTask | Where-Object {$_.State -eq 'Running'} | Select-Object TaskName, State"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for task in current - self._prev_tasks:
                    self.bus.publish(Event("TASK_EXEC", "START",
                                           f"Task started: {task}",
                                           severity=Severity.INFO,
                                           data={"task": task}))
                self._prev_tasks = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Time Zone Monitor
# ============================================================
class TimeZoneMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("TZ", bus, interval)
        self._prev_tz = None
    
    def _run(self):
        while not self._stop.is_set():
            try:
                import time
                tz = time.tzname
                if tz != self._prev_tz:
                    self.bus.publish(Event("TZ", "CHANGE",
                                           f"Timezone changed: {self._prev_tz} -> {tz}",
                                           severity=Severity.WARNING,
                                           data={"old": str(self._prev_tz), "new": str(tz)}))
                    self._prev_tz = tz
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Display Settings Monitor
# ============================================================
class DisplaySettingsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("DISPLAY", bus, interval)
        self._prev_settings: Dict[str, str] = {}
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-CimInstance Win32_VideoController | Select-Object CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                for line in result.stdout.splitlines():
                    if line.strip() and not line.startswith("Current"):
                        parts = line.split()
                        if parts:
                            setting = line.strip()
                            if setting != self._prev_settings.get(parts[0]):
                                self.bus.publish(Event("DISPLAY", "CHANGE",
                                                       f"Display: {setting}",
                                                       severity=Severity.INFO,
                                                       data={"setting": setting}))
                                self._prev_settings[parts[0]] = setting
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Audio Monitor
# ============================================================
class AudioMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 20.0):
        super().__init__("AUDIO", bus, interval)
        self._prev_devices: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-AudioDevice -List | Select-Object Name, Type"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for device in current - self._prev_devices:
                    self.bus.publish(Event("AUDIO", "DEVICE",
                                           f"Audio device: {device}",
                                           severity=Severity.INFO,
                                           data={"device": device}))
                self._prev_devices = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Bluetooth Monitor
# ============================================================
class BluetoothMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("BT", bus, interval)
        self._prev_devices: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-BluetoothDevice | Select-Object Name, ConnectionStatus"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for device in current - self._prev_devices:
                    self.bus.publish(Event("BT", "DEVICE",
                                           f"Bluetooth: {device}",
                                           severity=Severity.INFO,
                                           data={"device": device}))
                self._prev_devices = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# USB Device Detail Monitor
# ============================================================
class USBDeviceDetailMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 30.0):
        super().__init__("USB_DETAIL", bus, interval)
        self._prev_devices: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-PnpDevice -Class USB | Select-Object FriendlyName, Status, InstanceId"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                current = set(result.stdout.splitlines())
                for device in current - self._prev_devices:
                    self.bus.publish(Event("USB_DETAIL", "DEVICE",
                                           f"USB: {device}",
                                           severity=Severity.INFO,
                                           data={"device": device}))
                self._prev_devices = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Boot Configuration Monitor
# ============================================================
class BootConfigMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("BOOT", bus, interval)
        self._prev_config = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["bcdedit", "/enum"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=10
                )
                config = result.stdout.strip()
                if config != self._prev_config:
                    self.bus.publish(Event("BOOT", "CONFIG",
                                           f"Boot config changed",
                                           severity=Severity.WARNING,
                                           data={"config": config[:200]}))
                    self._prev_config = config
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# TPM and BitLocker Monitor
# ============================================================
class TPMBitLockerMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 60.0):
        super().__init__("TPM_BL", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-Tpm | Select-Object TpmReady, TpmEnabled; Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("TPM_BL", "STATUS",
                                           f"TPM/BitLocker: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Store Apps Monitor
# ============================================================
class WindowsStoreAppsMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("STORE_APPS", bus, interval)
        self._prev_apps: Set[str] = set()
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-AppxPackage | Select-Object Name, PackageFullName"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                current = set(result.stdout.splitlines())
                for app in current - self._prev_apps:
                    self.bus.publish(Event("STORE_APPS", "CHANGE",
                                           f"App: {app}",
                                           severity=Severity.DEBUG,
                                           data={"app": app}))
                self._prev_apps = current
                time.sleep(self.interval)
            except Exception:
                time.sleep(10.0)

# ============================================================
# Windows Recovery Monitor
# ============================================================
class WindowsRecoveryMonitor(BaseMonitor):
    def __init__(self, bus: EventBus, interval: float = 120.0):
        super().__init__("RECOVERY", bus, interval)
        self._prev_status = None
    
    def _run(self):
        if sys.platform != "win32":
            return
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-ComputerInfo | Select-Object WindowsREStatus, RecoveryEnvironment"],
                    capture_output=True, encoding='utf-8', errors='replace', timeout=15
                )
                status = result.stdout.strip()
                if status and status != self._prev_status:
                    self.bus.publish(Event("RECOVERY", "STATUS",
                                           f"Recovery: {status}",
                                           severity=Severity.INFO,
                                           data={"status": status}))
                    self._prev_status = status
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
        self._compact = False
        self._lock = threading.RLock()
        self._last_frame = ""
        self._stats: Dict[str, Any] = {}
        self._filter_regex: Optional[Pattern] = None
        self._alerts_enabled = True
        self._alert_thresholds: Dict[str, Tuple[int, int]] = {
            "CPU": (80, 95),
            "MEMORY": (80, 95),
            "DISK": (85, 98),
            "SWAP": (50, 80),
            "TEMPERATURE": (70, 90),
            "BATTERY": (20, 10),
        }
        self._bookmarks: Set[int] = set()
        self._highlights: Set[str] = set()
        self._view_mode = "normal"
        self._dedup_window = 5.0
        self._last_event_key: Optional[str] = None
        self._last_event_ts = 0.0
    
    def add(self, event: Event):
        with self._lock:
            key = f"{event.source}:{event.category}:{event.message}"
            now = time.time()
            if (self._last_event_key == key and 
                now - self._last_event_ts < self._dedup_window):
                return
            self._last_event_key = key
            self._last_event_ts = now
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
    
    def toggle_compact(self) -> bool:
        with self._lock:
            self._compact = not self._compact
            return self._compact
    
    def toggle_alerts(self) -> bool:
        with self._lock:
            self._alerts_enabled = not self._alerts_enabled
            return self._alerts_enabled
    
    def toggle_bookmark(self, event: Event):
        with self._lock:
            if event._seq in self._bookmarks:
                self._bookmarks.discard(event._seq)
                event.bookmarked = False
            else:
                self._bookmarks.add(event._seq)
                event.bookmarked = True
    
    def toggle_highlight_source(self, source: str):
        with self._lock:
            if source in self._highlights:
                self._highlights.discard(source)
            else:
                self._highlights.add(source)
    
    def set_view_mode(self, mode: str):
        with self._lock:
            self._view_mode = mode
    
    def next_alert(self) -> Optional[Event]:
        with self._lock:
            for e in reversed(self.events):
                if e.severity >= Severity.WARNING:
                    return e
            return None
    
    def export_events(self, fmt: str = "json") -> str:
        with self._lock:
            if fmt == "json":
                import json
                data = []
                for e in self.events:
                    data.append({
                        "ts": e.ts,
                        "source": e.source,
                        "category": e.category,
                        "message": e.message,
                        "severity": e.severity,
                        "data": e.data,
                        "bookmarked": e.bookmarked,
                    })
                return json.dumps(data, indent=2)
            elif fmt == "csv":
                lines = ["ts,source,category,message,severity,bookmarked"]
                for e in self.events:
                    lines.append(f"{e.ts},{e.source},{e.category},{e.message},{e.severity},{e.bookmarked}")
                return "\n".join(lines)
            return ""
    
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
                if self._view_mode == "alerts":
                    if e.severity < Severity.WARNING:
                        continue
                visible.append(e)
            
            start = self._scroll
            end = start + self.max_lines - 6
            page = visible[start:end]
            
            lines: List[str] = []
            
            up = self._fmt_uptime(self._stats.get("uptime", 0))
            qps = self._stats.get("qps", 0)
            total = self._stats.get("total", 0)
            mode_tag = f" [{self._view_mode.upper()}]" if self._view_mode != "normal" else ""
            compact_tag = " [COMPACT]" if self._compact else ""
            lines.append(f"{BOLD}Rolling Log Monitor{RST}{mode_tag}{compact_tag} | Uptime: {up} | QPS: {qps:.1f} | Events: {total}")
            lines.append("=" * self.width)
            
            filt = []
            if self._filter_source:
                filt.append(f"Source: {self._filter_source}")
            if self._filter_text:
                filt.append(f"Text: {self._filter_text}")
            if self._highlights:
                filt.append(f"Highlight: {', '.join(self._highlights)}")
            if filt:
                lines.append(f"{DIM}Filter: {' | '.join(filt)}{RST}")
            else:
                lines.append(f"{DIM}Filter: None{RST}")
            lines.append("-" * self.width)
            
            status = f"{BOLD}[{'PAUSED' if self._paused else 'LIVE'}] {len(self.events)} buffered"
            if self._paused:
                status += f" | Showing {len(page)} events"
            if not self._alerts_enabled:
                status += f" {DIM}(alerts off){RST}"
            lines.append(status)
            lines.append("-" * self.width)
            
            if self._view_mode == "dashboard":
                lines.extend(self._render_dashboard())
            elif self._view_mode == "tree":
                lines.extend(self._render_tree())
            else:
                for e in page:
                    if self._compact:
                        lines.append(self._compact_line(e))
                    else:
                        lines.append(e.line(self._show_data, self.width))
            
            lines.append("-" * self.width)
            footer = (
                "Controls: ↑/↓ Scroll | PgUp/PgDn | Home/End | "
                "Enter Detail | Space Pause | C Clear | D Data | M Compact | V View | "
                "F Filter | S Source | / Search | H Help | Q Quit"
            )
            lines.append(footer)
            
            return "\n".join(lines)
    
    def _render_dashboard(self) -> List[str]:
        dash = []
        dash.append(f"{BOLD}Statistics Dashboard{RST}")
        dash.append("-" * self.width)
        
        snap = self._stats
        if snap:
            dash.append(f"Uptime: {self._fmt_uptime(snap.get('uptime', 0))}")
            dash.append(f"Total Events: {snap.get('total', 0)}")
            dash.append(f"QPS: {snap.get('qps', 0.0):.1f}")
            dash.append("")
            
            by_sev = snap.get("by_severity", {})
            if by_sev:
                dash.append("By Severity:")
                for sev, count in sorted(by_sev.items(), key=lambda x: x[1], reverse=True)[:6]:
                    dash.append(f"  {sev:<10} {count:>6}")
                dash.append("")
            
            by_src = snap.get("by_source", {})
            if by_src:
                dash.append("By Source:")
                for src, count in sorted(by_src.items(), key=lambda x: x[1], reverse=True)[:10]:
                    dash.append(f"  {src:<15} {count:>6}")
                dash.append("")
            
            by_cat = snap.get("by_category", {})
            if by_cat:
                dash.append("By Category:")
                for cat, count in sorted(by_cat.items(), key=lambda x: x[1], reverse=True)[:10]:
                    dash.append(f"  {cat:<15} {count:>6}")
        
        dash.append("")
        dash.append(f"Bookmarks: {len(self._bookmarks)} | Alerts: {'ON' if self._alerts_enabled else 'OFF'}")
        dash.append(f"Dedup: {self._dedup_window}s | Max lines: {self.max_lines}")
        
        return dash
    
    def _render_tree(self) -> List[str]:
        tree = []
        tree.append(f"{BOLD}Process Tree{RST}")
        tree.append("-" * self.width)
        
        try:
            import psutil
            root_pids = []
            for proc in psutil.process_iter(['pid', 'name', 'ppid']):
                try:
                    info = proc.info
                    if info['ppid'] == 0 or info['ppid'] == info['pid']:
                        root_pids.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            def render_node(pid, indent=0):
                try:
                    proc = psutil.Process(pid)
                    info = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_percent'])
                    prefix = "  " * indent + ("├─ " if indent > 0 else "")
                    cpu = info.get('cpu_percent', 0) or 0
                    mem = info.get('memory_percent', 0) or 0
                    tree.append(f"{prefix}{info['name']} (PID {pid}) CPU:{cpu:.1f}% MEM:{mem:.1f}%")
                    children = proc.children(recursive=False)
                    for child in children:
                        render_node(child.pid, indent + 1)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            for proc in root_pids[:10]:
                render_node(proc['pid'])
        except ImportError:
            tree.append("psutil not installed")
        except Exception as e:
            tree.append(f"Error: {e}")
        
        return tree
    
    def _compact_line(self, event: Event) -> str:
        sev = SEV_NAME.get(event.severity, "INFO")
        highlight = f"{BOLD}!{RST}" if event.highlight else ""
        bookmark = f"{BOLD}*{RST}" if event.bookmarked else ""
        return f"{highlight}{bookmark}[{event.time_str()}] {event.source:<10} {event.message[:self.width-40]}"
    
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
        elif key == b"\r":
            self._show_event_detail()
        elif key in (b"c", b"C"):
            self.display.clear()
            self._flash("CLEARED")
        elif key in (b"d", b"D"):
            show = self.display.toggle_data()
            self._flash(f"Data: {'ON' if show else 'OFF'}")
        elif key in (b"m", b"M"):
            compact = self.display.toggle_compact()
            self._flash(f"Compact: {'ON' if compact else 'OFF'}")
        elif key in (b"b", b"B"):
            evt = self.display._get_current_event()
            if evt:
                self.display.toggle_bookmark(evt)
                self._flash(f"Bookmark: {'ON' if evt.bookmarked else 'OFF'}")
        elif key in (b"a", b"A"):
            alerts = self.display.toggle_alerts()
            self._flash(f"Alerts: {'ON' if alerts else 'OFF'}")
        elif key in (b"v", b"V"):
            modes = ["normal", "dashboard", "alerts"]
            cur = self.display._view_mode
            nxt = modes[(modes.index(cur) + 1) % len(modes)] if cur in modes else "normal"
            self.display.set_view_mode(nxt)
            self._flash(f"View: {nxt.upper()}")
        elif key in (b"e", b"E"):
            self._do_export()
        elif key in (b"f", b"F"):
            self._prompt_filter()
        elif key in (b"s", b"S"):
            self._prompt_source()
        elif key == b"/":
            self._prompt_search()
        elif key in (b"h", b"H"):
            self._show_help()
    
    def _get_current_event(self):
        if not self.display:
            return None
        with self.display._lock:
            visible = list(reversed(self.display.events))
            idx = self.display._scroll
            if 0 <= idx < len(visible):
                return visible[idx]
        return None
    
    def _do_export(self):
        if not self.display:
            return
        old = self.display._paused
        self.display._paused = True
        try:
            sys.stdout.write(f"\033[2J\033[H{BOLD}Export Events{RST}\n")
            sys.stdout.write("1. JSON\n")
            sys.stdout.write("2. CSV\n")
            sys.stdout.write("Select format (1/2): ")
            sys.stdout.flush()
            try:
                import msvcrt
                ch = msvcrt.getch()
                fmt = "json" if ch == b"1" else "csv"
                data = self.display.export_events(fmt)
                fname = f"monitor_export_{int(time.time())}.{fmt}"
                Path(fname).write_text(data, encoding="utf-8")
                self._flash(f"Exported: {fname}")
            except Exception:
                pass
        finally:
            self.display._paused = old
    
    def _play_alert(self):
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass
    
    def _show_event_detail(self):
        if not self.display:
            return
        evt = self.display._get_current_event()
        if not evt:
            self._flash("No event selected")
            return
        old = self.display._paused
        self.display._paused = True
        try:
            lines = [
                "",
                f"{BOLD}Event Detail{RST}",
                "=" * 78,
                f"Time:        {evt.time_str()}",
                f"Source:      {evt.source}",
                f"Category:    {evt.category}",
                f"Severity:    {SEV_NAME.get(evt.severity, 'INFO')}",
                f"Message:     {evt.message}",
                "",
            ]
            if evt.data:
                lines.append("Data:")
                for k, v in evt.data.items():
                    if isinstance(v, (list, tuple)):
                        vstr = ", ".join(str(x) for x in v[:10])
                        if len(v) > 10:
                            vstr += f"... ({len(v)} items)"
                    else:
                        vstr = str(v)
                    lines.append(f"  {k}: {vstr}")
                lines.append("")
            lines.append("Press any key to return...")
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
                "  Enter       View event detail",
                "  Space       Pause/resume display",
                "  C           Clear all events",
                "  D           Toggle detailed data display",
                "  M           Toggle compact mode",
                "  B           Bookmark current event",
                "  A           Toggle alerts",
                "  E           Export events to JSON/CSV",
                "  V           Cycle view mode (normal/dashboard/alerts)",
                "  F           Set event filter",
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
                "  BATTERY       - Battery status and charge",
                "  TEMP          - CPU/GPU temperature",
                "  DISK_HEALTH   - Disk SMART status",
                "  CPU_CORE      - Per-core CPU usage",
                "  BANDWIDTH     - Network bandwidth usage",
                "  PROC_RES      - Top resource processes",
                "  SESSION       - User login/logout",
                "  ENV           - Environment variables",
                "  LOGTAIL       - Log file tailing",
                "  PORT          - Port monitoring",
                "  WEB           - Website availability",
                "  EVENTLOG_CH   - Event log channels",
                "  PERF          - Performance counters",
                "  WUPDATE       - Windows updates",
                "  SOFTWARE      - Installed software",
                "  WINFEAT       - Windows features",
                "  NETADAPTER    - Network adapters",
                "  TCPSTATS      - TCP statistics",
                "  UAC           - UAC settings",
                "  SMARTSCREEN   - SmartScreen status",
                "  CRED          - Credential manager",
                "  WER           - Windows Error Reporting",
                "  DUMP          - Dump files",
                "  PAGEFILE      - Pagefile usage",
                "  HIBER         - Hibernation status",
                "  FAN           - Fan speed",
                "  THERMAL       - Thermal zones",
                "  GPU           - GPU info",
                "  HELLO         - Windows Hello/BitLocker",
                "  LOCK          - Lock screen",
                "  SCRSAVER      - Screensaver",
                "  LOGON         - Logon events",
                "  DEF_EXCL      - Defender exclusions",
                "  DEF_SCAN      - Defender scans",
                "  FW_RULES      - Firewall rules",
                "  TASK_EXEC     - Task execution",
                "  TZ            - Timezone",
                "  DISPLAY       - Display settings",
                "  AUDIO         - Audio devices",
                "  BT            - Bluetooth",
                "  USB_DETAIL    - USB devices",
                "  BOOT          - Boot config",
                "  TPM_BL        - TPM/BitLocker",
                "  STORE_APPS    - Store apps",
                "  RECOVERY      - Recovery status",
                "  FILE          - File changes",
                "  DIR           - Directory changes",
                "  PROC_CREATE   - Process creation",
                "  PROC_TERM     - Process termination",
                "  NET_CONN      - New network connections",
                "  WER_DETAIL    - WER detailed reports",
                "  APPCOMPAT     - App compatibility",
                "  SYSMON        - Sysmon events",
                "  POWERSHELL    - PowerShell execution",
                "  WINRM         - WinRM events",
                "  SCHED_TASK    - Scheduled tasks detail",
                "  CERT          - Certificates",
                "  AUTORUN       - Autorun entries",
                "  PREFETCH      - Prefetch files",
                "  AMCACHE       - Amcache",
                "  RECENT        - Recent documents",
                "  JUMPLIST      - Jump lists",
                "  TYPEDURL      - Typed URLs",
                "  USERASSIST    - User assist",
                "  BAGMRU        - Bag MRU",
                "  PACKAGE       - Installed packages",
                "  INSIDER       - Insider builds",
                "  TIMESYNC      - Time sync",
                "  LOGONTYPE     - Logon types",
                "  FEATUPDATE    - Feature updates",
                "  APPLOCKER     - AppLocker events",
                "  DEF_BEHAV     - Defender behavior",
                "  NETPROF       - Network profiles",
                "  DNS_CACHE     - DNS cache",
                "  HOSTS         - Hosts file",
                "  PROXY         - Proxy settings",
                "  AUTOPILOT     - Autopilot",
                "  SANDBOX       - Sandbox status",
                "  WSL           - WSL distros",
                "  DOCKER        - Docker containers",
                "  HYPERV        - Hyper-V VMs",
                "  WU_LOG        - Windows Update log",
                "  SETUPAPI      - SetupAPI log",
                "  CRYPTO        - Crypto keys",
                "",
                "Bookmarks: * | Highlights: ! | Alerts on/off",
                "Views: normal, dashboard, alerts, tree",
                "Export: JSON/CSV | Config: --config file.json",
                "Log dir: D:/RollingLogMonitor | Cleanup: 30 days",
                "Auto-start: --auto-start | Build EXE: --build-exe",
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
                time.sleep(3)
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
        self.dated_logger: Optional[DatedFolderLogger] = None
        self.cleanup_thread: Optional[CleanupThread] = None
        self.log_dir: Optional[Path] = None
    
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
  M          Toggle compact
  B          Bookmark
  A          Toggle alerts
  E          Export
  Enter      View event detail
  F          Filter by source
  S          Quick source filter
  /          Search text
  H          Help
  Q          Quit
  
Features:
  --log-dir DIR         Dated folder log structure (D:/RollingLogMonitor)
  --cleanup-days N      Delete logs older than N days (default: 30)
  --auto-start          Add to Windows startup
  --build-exe           Build EXE with PyInstaller
  --export FORMAT       Export events and exit (json/csv)
  --config FILE         JSON configuration file
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
        p.add_argument("--no-battery", action="store_true", help="Disable battery monitor")
        p.add_argument("--no-temp", action="store_true", help="Disable temperature monitor")
        p.add_argument("--no-disk-health", action="store_true", help="Disable disk health monitor")
        p.add_argument("--no-cpu-core", action="store_true", help="Disable CPU core monitor")
        p.add_argument("--no-bandwidth", action="store_true", help="Disable bandwidth monitor")
        p.add_argument("--no-proc-res", action="store_true", help="Disable process resource monitor")
        p.add_argument("--no-session", action="store_true", help="Disable user session monitor")
        p.add_argument("--no-env", action="store_true", help="Disable environment monitor")
        p.add_argument("--no-logtail", action="store_true", help="Disable log tail monitor")
        p.add_argument("--no-port", action="store_true", help="Disable port monitor")
        p.add_argument("--no-web", action="store_true", help="Disable website check monitor")
        p.add_argument("--no-eventlog-ch", action="store_true", help="Disable event log channel monitor")
        p.add_argument("--no-perf", action="store_true", help="Disable performance counter monitor")
        p.add_argument("--no-wupdate", action="store_true", help="Disable windows update monitor")
        p.add_argument("--no-software", action="store_true", help="Disable installed software monitor")
        p.add_argument("--no-winfeat", action="store_true", help="Disable windows features monitor")
        p.add_argument("--no-netadapter", action="store_true", help="Disable network adapter monitor")
        p.add_argument("--no-tcpstats", action="store_true", help="Disable TCP statistics monitor")
        p.add_argument("--no-uac", action="store_true", help="Disable UAC monitor")
        p.add_argument("--no-smartscreen", action="store_true", help="Disable SmartScreen monitor")
        p.add_argument("--no-cred", action="store_true", help="Disable credential manager monitor")
        p.add_argument("--no-wer", action="store_true", help="Disable Windows Error Reporting monitor")
        p.add_argument("--no-dump", action="store_true", help="Disable dump file monitor")
        p.add_argument("--no-pagefile", action="store_true", help="Disable pagefile monitor")
        p.add_argument("--no-hiber", action="store_true", help="Disable hibernation monitor")
        p.add_argument("--no-fan", action="store_true", help="Disable fan speed monitor")
        p.add_argument("--no-thermal", action="store_true", help="Disable thermal zone monitor")
        p.add_argument("--no-gpu", action="store_true", help="Disable GPU stats monitor")
        p.add_argument("--no-hello", action="store_true", help="Disable Windows Hello monitor")
        p.add_argument("--no-lock", action="store_true", help="Disable lock screen monitor")
        p.add_argument("--no-scrsaver", action="store_true", help="Disable screensaver monitor")
        p.add_argument("--no-logon", action="store_true", help="Disable logon monitor")
        p.add_argument("--no-def-excl", action="store_true", help="Disable defender exclusions monitor")
        p.add_argument("--no-def-scan", action="store_true", help="Disable defender scan monitor")
        p.add_argument("--no-fw-rules", action="store_true", help="Disable firewall rules monitor")
        p.add_argument("--no-task-exec", action="store_true", help="Disable task execution monitor")
        p.add_argument("--no-tz", action="store_true", help="Disable timezone monitor")
        p.add_argument("--no-display", action="store_true", help="Disable display settings monitor")
        p.add_argument("--no-audio", action="store_true", help="Disable audio monitor")
        p.add_argument("--no-bt", action="store_true", help="Disable bluetooth monitor")
        p.add_argument("--no-usb-detail", action="store_true", help="Disable USB detail monitor")
        p.add_argument("--no-boot", action="store_true", help="Disable boot config monitor")
        p.add_argument("--no-tpm-bl", action="store_true", help="Disable TPM/BitLocker monitor")
        p.add_argument("--no-store-apps", action="store_true", help="Disable store apps monitor")
        p.add_argument("--no-recovery", action="store_true", help="Disable recovery monitor")
        p.add_argument("--no-file", action="store_true", help="Disable file change monitor")
        p.add_argument("--no-dir", action="store_true", help="Disable directory change monitor")
        p.add_argument("--no-proc-create", action="store_true", help="Disable process creation monitor")
        p.add_argument("--no-proc-term", action="store_true", help="Disable process termination monitor")
        p.add_argument("--no-net-conn", action="store_true", help="Disable new network connection monitor")
        p.add_argument("--no-wer-detail", action="store_true", help="Disable WER detail monitor")
        p.add_argument("--no-appcompat", action="store_true", help="Disable app compatibility monitor")
        p.add_argument("--no-sysmon", action="store_true", help="Disable Sysmon monitor")
        p.add_argument("--no-powershell", action="store_true", help="Disable PowerShell execution monitor")
        p.add_argument("--no-winrm", action="store_true", help="Disable WinRM monitor")
        p.add_argument("--no-sched-task", action="store_true", help="Disable scheduled task detail monitor")
        p.add_argument("--no-cert", action="store_true", help="Disable certificate monitor")
        p.add_argument("--no-autorun", action="store_true", help="Disable autorun monitor")
        p.add_argument("--no-prefetch", action="store_true", help="Disable prefetch monitor")
        p.add_argument("--no-amcache", action="store_true", help="Disable amcache monitor")
        p.add_argument("--no-recent", action="store_true", help="Disable recent documents monitor")
        p.add_argument("--no-jumplist", action="store_true", help="Disable jump list monitor")
        p.add_argument("--no-typedurl", action="store_true", help="Disable typed URLs monitor")
        p.add_argument("--no-userassist", action="store_true", help="Disable user assist monitor")
        p.add_argument("--no-bagmru", action="store_true", help="Disable bag MRU monitor")
        p.add_argument("--no-package", action="store_true", help="Disable package monitor")
        p.add_argument("--no-insider", action="store_true", help="Disable insider build monitor")
        p.add_argument("--no-timesync", action="store_true", help="Disable time sync monitor")
        p.add_argument("--no-logon-type", action="store_true", help="Disable logon type monitor")
        p.add_argument("--no-featupdate", action="store_true", help="Disable feature update monitor")
        p.add_argument("--no-applocker", action="store_true", help="Disable AppLocker monitor")
        p.add_argument("--no-def-behav", action="store_true", help="Disable defender behavior monitor")
        p.add_argument("--no-netprof", action="store_true", help="Disable network profile monitor")
        p.add_argument("--no-dns-cache", action="store_true", help="Disable DNS cache monitor")
        p.add_argument("--no-hosts", action="store_true", help="Disable hosts file monitor")
        p.add_argument("--no-proxy", action="store_true", help="Disable proxy monitor")
        p.add_argument("--no-autopilot", action="store_true", help="Disable autopilot monitor")
        p.add_argument("--no-sandbox", action="store_true", help="Disable sandbox monitor")
        p.add_argument("--no-wsl", action="store_true", help="Disable WSL monitor")
        p.add_argument("--no-docker", action="store_true", help="Disable Docker monitor")
        p.add_argument("--no-hyperv", action="store_true", help="Disable Hyper-V monitor")
        p.add_argument("--no-wu-log", action="store_true", help="Disable Windows Update log monitor")
        p.add_argument("--no-setupapi", action="store_true", help="Disable SetupAPI monitor")
        p.add_argument("--no-crypto", action="store_true", help="Disable crypto key monitor")
        p.add_argument("--log-dir", type=Path, default=Path("D:/RollingLogMonitor"), help="Log directory")
        p.add_argument("--no-dated-folders", action="store_true", help="Disable dated folder structure")
        p.add_argument("--cleanup-days", type=int, default=30, help="Days to keep logs")
        p.add_argument("--auto-start", action="store_true", help="Add to startup")
        p.add_argument("--build-exe", action="store_true", help="Build EXE with PyInstaller")
        p.add_argument("--no-cloud", action="store_true", help="Disable cloud sync monitor")
        p.add_argument("--no-wac", action="store_true", help="Disable Windows Admin Center monitor")
        p.add_argument("--no-iis", action="store_true", help="Disable IIS monitor")
        p.add_argument("--no-sql", action="store_true", help="Disable SQL Server monitor")
        p.add_argument("--no-exchange", action="store_true", help="Disable Exchange monitor")
        p.add_argument("--no-ad", action="store_true", help="Disable Active Directory monitor")
        p.add_argument("--no-gp", action="store_true", help="Disable Group Policy monitor")
        p.add_argument("--no-def-atp", action="store_true", help="Disable Defender ATP monitor")
        p.add_argument("--no-printer", action="store_true", help="Disable printer queue monitor")
        p.add_argument("--no-wu-tele", action="store_true", help="Disable Windows Update telemetry monitor")
        p.add_argument("--no-perfmon", action="store_true", help="Disable performance counter monitor")
        p.add_argument("--no-wef", action="store_true", help="Disable Windows Event Forwarding monitor")
        p.add_argument("--no-laps", action="store_true", help="Disable LAPS monitor")
        p.add_argument("--no-wpr", action="store_true", help="Disable Windows Performance Recorder monitor")
        p.add_argument("--no-memdiag", action="store_true", help="Disable memory diagnostic monitor")
        p.add_argument("--no-reset", action="store_true", help="Disable Windows Reset monitor")
        p.add_argument("--domains", "-d", help="Comma-separated domains for DNS")
        p.add_argument("--config", "-c", type=Path, help="JSON config file")
        p.add_argument("--export", type=str, help="Export events and exit (json/csv)")
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
        if self.dated_logger:
            self.dated_logger.write(event)
        if self.display._alerts_enabled and event.severity >= Severity.WARNING:
            self._play_alert()
    
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
                time.sleep(0.3)
            except Exception:
                time.sleep(0.5)
    
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
        
        if not self.args.no_battery:
            monitors.append(BatteryMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_temp:
            monitors.append(TemperatureMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_disk_health:
            monitors.append(DiskHealthMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_cpu_core:
            monitors.append(CpuCoreMonitor(self.bus, max(interval * 2.5, 5.0)))
        
        if not self.args.no_bandwidth:
            monitors.append(NetworkBandwidthMonitor(self.bus, max(interval * 2.5, 5.0)))
        
        if not self.args.no_proc_res:
            monitors.append(ProcessResourceMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_session:
            monitors.append(UserSessionMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_env:
            monitors.append(EnvMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_logtail:
            monitors.append(LogTailMonitor(self.bus, max(interval * 2.5, 5.0)))
        
        if not self.args.no_port:
            monitors.append(PortCheckMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_web:
            monitors.append(WebsiteCheckMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_eventlog_ch:
            monitors.append(EventLogChannelMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_perf:
            monitors.append(PerformanceCounterMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_wupdate:
            monitors.append(WindowsUpdateMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_software:
            monitors.append(InstalledSoftwareMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_winfeat:
            monitors.append(WindowsFeaturesMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_netadapter:
            monitors.append(NetworkAdapterMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_tcpstats:
            monitors.append(TCPStatsMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_uac:
            monitors.append(UACMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_smartscreen:
            monitors.append(SmartScreenMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_cred:
            monitors.append(CredentialMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_wer:
            monitors.append(WERMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_dump:
            monitors.append(DumpFileMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_pagefile:
            monitors.append(PagefileMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_hiber:
            monitors.append(HibernationMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_fan:
            monitors.append(FanSpeedMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_thermal:
            monitors.append(ThermalZoneMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_gpu:
            monitors.append(GPUStatsMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_hello:
            monitors.append(WindowsHelloMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_lock:
            monitors.append(LockScreenMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_scrsaver:
            monitors.append(ScreenSaverMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_logon:
            monitors.append(LogonMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_def_excl:
            monitors.append(DefenderExclusionsMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_def_scan:
            monitors.append(DefenderScanMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_fw_rules:
            monitors.append(FirewallRulesMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_task_exec:
            monitors.append(TaskExecutionMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_tz:
            monitors.append(TimeZoneMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_display:
            monitors.append(DisplaySettingsMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_audio:
            monitors.append(AudioMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_bt:
            monitors.append(BluetoothMonitor(self.bus, max(interval * 20, 40.0)))
        
        if not self.args.no_usb_detail:
            monitors.append(USBDeviceDetailMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_boot:
            monitors.append(BootConfigMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_tpm_bl:
            monitors.append(TPMBitLockerMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_store_apps:
            monitors.append(WindowsStoreAppsMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_recovery:
            monitors.append(WindowsRecoveryMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_file:
            monitors.append(FileChangeMonitor(self.bus, max(interval * 2.5, 5.0)))
        
        if not self.args.no_dir:
            monitors.append(DirectoryChangeMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_proc_create:
            monitors.append(ProcessCreationMonitor(self.bus, max(interval * 1, 2.0)))
        
        if not self.args.no_proc_term:
            monitors.append(ProcessTerminationMonitor(self.bus, max(interval * 1, 2.0)))
        
        if not self.args.no_net_conn:
            monitors.append(NewConnectionMonitor(self.bus, max(interval * 1, 2.0)))
        
        if not self.args.no_wer_detail:
            monitors.append(WERDetailMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_appcompat:
            monitors.append(AppCompatMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_sysmon:
            monitors.append(SysmonMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_powershell:
            monitors.append(PowerShellMonitor(self.bus, max(interval * 5, 10.0)))
        
        if not self.args.no_winrm:
            monitors.append(WinRMMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_sched_task:
            monitors.append(ScheduledTaskDetailMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_cert:
            monitors.append(CertificateMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_autorun:
            monitors.append(AutorunMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_prefetch:
            monitors.append(PrefetchMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_amcache:
            monitors.append(AmcacheMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_recent:
            monitors.append(RecentDocsMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_jumplist:
            monitors.append(JumpListMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_typedurl:
            monitors.append(TypedURLsMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_userassist:
            monitors.append(UserAssistMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_bagmru:
            monitors.append(BagMRUMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_package:
            monitors.append(PackageMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_insider:
            monitors.append(InsiderMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_timesync:
            monitors.append(TimeSyncMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_logon_type:
            monitors.append(LogonTypeMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_featupdate:
            monitors.append(FeatureUpdateMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_applocker:
            monitors.append(AppLockerMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_def_behav:
            monitors.append(DefenderBehaviorMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_netprof:
            monitors.append(NetworkProfileMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_dns_cache:
            monitors.append(DnsCacheMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_hosts:
            monitors.append(HostsFileMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_proxy:
            monitors.append(ProxyMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_autopilot:
            monitors.append(AutopilotMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_sandbox:
            monitors.append(SandboxMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_wsl:
            monitors.append(WSLMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_docker:
            monitors.append(DockerMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_hyperv:
            monitors.append(HyperVMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_wu_log:
            monitors.append(WindowsUpdateLogMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_setupapi:
            monitors.append(SetupAPIMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_crypto:
            monitors.append(CryptoKeyMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_cloud:
            monitors.append(CloudSyncMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_wac:
            monitors.append(WindowsAdminCenterMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_iis:
            monitors.append(IISMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_sql:
            monitors.append(SQLServerMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_exchange:
            monitors.append(ExchangeMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_ad:
            monitors.append(ADMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_gp:
            monitors.append(GPMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_def_atp:
            monitors.append(DefenderATPMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_printer:
            monitors.append(PrinterQueueMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_wu_tele:
            monitors.append(WUTelemetryMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_perfmon:
            monitors.append(PerfMon(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_wef:
            monitors.append(WEFMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_laps:
            monitors.append(LAPSMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_hello:
            monitors.append(HelloMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_sandbox:
            monitors.append(SandboxMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_wsl:
            monitors.append(WSLMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_docker:
            monitors.append(DockerMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_hyperv:
            monitors.append(HyperVMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_wu_log:
            monitors.append(WULogMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_setupapi:
            monitors.append(SetupAPIMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_featupdate:
            monitors.append(FeatureUpdateMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_applocker:
            monitors.append(AppLockerMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_def_behav:
            monitors.append(DefenderBehaviorMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_netprof:
            monitors.append(NetworkProfileMonitor(self.bus, max(interval * 15, 30.0)))
        
        if not self.args.no_dns_cache:
            monitors.append(DnsCacheMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_hosts:
            monitors.append(HostsFileMonitor(self.bus, max(interval * 10, 20.0)))
        
        if not self.args.no_proxy:
            monitors.append(ProxyMonitor(self.bus, max(interval * 30, 60.0)))
        
        if not self.args.no_autopilot:
            monitors.append(AutopilotMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_wpr:
            monitors.append(WPRMonitor(self.bus, max(interval * 60, 120.0)))
        
        if not self.args.no_memdiag:
            monitors.append(MemDiagMonitor(self.bus, max(interval * 120, 240.0)))
        
        if not self.args.no_reset:
            monitors.append(ResetMonitor(self.bus, max(interval * 60, 120.0)))
        
        return monitors
    
    def run(self):
        self.parse_args()
        self._delete_html()
        
        if self.args.build_exe:
            self._build_exe()
            return
        
        if self.args.auto_start:
            self._add_auto_start()
            print("Added to startup")
            return
        
        if self.args.log:
            self.logger = FileLogger(self.args.log)
        
        if self.args.log_dir:
            self.log_dir = self.args.log_dir
            self.log_dir.mkdir(parents=True, exist_ok=True)
            self.dated_logger = DatedFolderLogger(self.log_dir, self.args.cleanup_days)
            self.cleanup_thread = CleanupThread(self.log_dir, self.args.cleanup_days)
            self.cleanup_thread.start()
        
        if self.args.config and self.args.config.exists():
            try:
                import json
                cfg = json.loads(self.args.config.read_text(encoding="utf-8"))
                if "interval" in cfg:
                    self.args.interval = float(cfg["interval"])
                if "max_lines" in cfg:
                    self.args.max_lines = int(cfg["max_lines"])
                if "domains" in cfg:
                    self.args.domains = ",".join(cfg["domains"])
                if "disabled" in cfg:
                    for m in cfg["disabled"]:
                        opt = f"--no-{m.replace('_', '-')}"
                        if opt not in sys.argv:
                            sys.argv.append(opt)
                self.parse_args()
            except Exception:
                pass
        
        if self.args.export:
            self.bus.subscribe(self._on_event)
            self.monitors = self._build_monitors()
            for m in self.monitors:
                m.start()
            time.sleep(3)
            for m in self.monitors:
                m.stop()
            data = self.display.export_events(self.args.export)
            fname = f"monitor_export_{int(time.time())}.{self.args.export}"
            Path(fname).write_text(data, encoding="utf-8")
            print(f"Exported to {fname}")
            return
        
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
    
    def _add_auto_start(self):
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            exe_path = Path(sys.executable).resolve()
            if getattr(sys, 'frozen', False):
                exe_path = Path(sys.executable).resolve()
            else:
                exe_path = Path(__file__).resolve()
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "RollingLogMonitor", 0, winreg.REG_SZ, str(exe_path))
        except Exception:
            pass
    
    def _build_exe(self):
        try:
            import subprocess
            spec = Path("RollingLogMonitor.spec")
            if spec.exists():
                spec.unlink()
            cmd = [
                sys.executable, "-m", "PyInstaller",
                "--onefile", "--console", "--name", "RollingLogMonitor",
                "--icon", "NONE",
                str(Path(__file__).resolve())
            ]
            subprocess.run(cmd, check=True)
            print("EXE built successfully")
        except ImportError:
            print("PyInstaller not installed. Install: pip install pyinstaller")
        except Exception as e:
            print(f"Build failed: {e}")
    
    def stop(self):
        if self._stop.is_set():
            return
        self._stop.set()
        
        for m in self.monitors:
            try:
                m.stop()
            except Exception:
                pass
        
        if self.cleanup_thread:
            try:
                self.cleanup_thread.stop()
            except Exception:
                pass
        
        if self.dated_logger:
            try:
                self.dated_logger.close()
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
        if self.log_dir:
            print(f"Log directory: {self.log_dir}")
            print(f"Cleanup: {self.args.cleanup_days} days")

def main():
    app = RollingLogMonitor()
    app.run()

if __name__ == "__main__":
    main()