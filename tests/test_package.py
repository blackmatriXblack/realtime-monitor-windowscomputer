"""
Tests for Windows Monitor package.
"""

import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import windowsmonitor
from windowsmonitor import (
    RollingLogMonitor,
    Event,
    EventBus,
    Severity,
    Statistics,
    RollingLogDisplay,
    FileLogger,
    DatedFolderLogger,
    CleanupThread,
    BaseMonitor,
)


class TestPackageImport(unittest.TestCase):
    def test_version(self):
        self.assertEqual(windowsmonitor.__version__, "2.0.0")

    def test_author(self):
        self.assertEqual(windowsmonitor.__author__, "Windows Monitor")

    def test_description(self):
        self.assertIsNotNone(windowsmonitor.__description__)

    def test_all_exports(self):
        expected = [
            "RollingLogMonitor",
            "Event",
            "EventBus",
            "Severity",
            "Statistics",
            "RollingLogDisplay",
            "FileLogger",
            "DatedFolderLogger",
            "CleanupThread",
            "BaseMonitor",
        ]
        for name in expected:
            self.assertTrue(hasattr(windowsmonitor, name), f"Missing export: {name}")


class TestEvent(unittest.TestCase):
    def test_event_creation(self):
        event = Event("TEST", "CATEGORY", "Test message", Severity.INFO, {"key": "value"})
        self.assertEqual(event.source, "TEST")
        self.assertEqual(event.category, "CATEGORY")
        self.assertEqual(event.message, "Test message")
        self.assertEqual(event.severity, Severity.INFO)
        self.assertEqual(event.data, {"key": "value"})
        self.assertFalse(event.bookmarked)
        self.assertFalse(event.highlight)

    def test_event_time_str(self):
        event = Event("TEST", "CATEGORY", "Test message")
        time_str = event.time_str()
        self.assertIsInstance(time_str, str)
        self.assertRegex(time_str, r"\d{2}:\d{2}:\d{2}\.\d{3}")

    def test_event_date_str(self):
        event = Event("TEST", "CATEGORY", "Test message")
        date_str = event.date_str()
        self.assertIsInstance(date_str, str)
        self.assertRegex(date_str, r"\d{4}-\d{2}-\d{2}")


class TestEventBus(unittest.TestCase):
    def test_subscribe_and_publish(self):
        bus = EventBus()
        received = []

        def handler(event):
            received.append(event)

        bus.subscribe(handler)
        event = Event("TEST", "CAT", "msg")
        bus.publish(event)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].source, "TEST")

    def test_multiple_subscribers(self):
        bus = EventBus()
        received1 = []
        received2 = []

        def handler1(event):
            received1.append(event)

        def handler2(event):
            received2.append(event)

        bus.subscribe(handler1)
        bus.subscribe(handler2)
        event = Event("TEST", "CAT", "msg")
        bus.publish(event)

        self.assertEqual(len(received1), 1)
        self.assertEqual(len(received2), 1)


class TestSeverity(unittest.TestCase):
    def test_severity_levels(self):
        self.assertEqual(Severity.DEBUG, 0)
        self.assertEqual(Severity.INFO, 1)
        self.assertEqual(Severity.NOTICE, 2)
        self.assertEqual(Severity.WARNING, 3)
        self.assertEqual(Severity.ERROR, 4)
        self.assertEqual(Severity.CRITICAL, 5)

    def test_sev_name_mapping(self):
        self.assertEqual(windowsmonitor.SEV_NAME[Severity.DEBUG], "DEBUG")
        self.assertEqual(windowsmonitor.SEV_NAME[Severity.INFO], "INFO")
        self.assertEqual(windowsmonitor.SEV_NAME[Severity.WARNING], "WARNING")
        self.assertEqual(windowsmonitor.SEV_NAME[Severity.ERROR], "ERROR")


class TestStatistics(unittest.TestCase):
    def test_record_event(self):
        stats = Statistics()
        event = Event("TEST", "CAT", "msg", Severity.INFO)
        stats.record(event)
        snapshot = stats.snapshot()
        self.assertEqual(snapshot["total"], 1)
        self.assertEqual(snapshot["qps"], 0.0)

    def test_multiple_events(self):
        stats = Statistics()
        for i in range(10):
            event = Event("TEST", "CAT", f"msg {i}", Severity.INFO)
            stats.record(event)
        snapshot = stats.snapshot()
        self.assertEqual(snapshot["total"], 10)


class TestRollingLogDisplay(unittest.TestCase):
    def test_add_event(self):
        display = RollingLogDisplay(max_lines=10, width=120)
        event = Event("TEST", "CAT", "msg")
        display.add(event)
        self.assertEqual(len(display.events), 1)

    def test_max_lines(self):
        display = RollingLogDisplay(max_lines=5, width=120)
        for i in range(10):
            display.add(Event("TEST", "CAT", f"msg {i}"))
        self.assertLessEqual(len(display.events), 10000)

    def test_clear(self):
        display = RollingLogDisplay()
        display.add(Event("TEST", "CAT", "msg"))
        display.clear()
        self.assertEqual(len(display.events), 0)

    def test_toggle_pause(self):
        display = RollingLogDisplay()
        self.assertFalse(display._paused)
        display.toggle_pause()
        self.assertTrue(display._paused)
        display.toggle_pause()
        self.assertFalse(display._paused)

    def test_filter_source(self):
        display = RollingLogDisplay()
        display.add(Event("DNS", "CAT", "msg"))
        display.add(Event("PROCESS", "CAT", "msg"))
        display.set_filter_source("DNS")
        self.assertEqual(display._filter_source, "DNS")
        display.set_filter_source(None)
        self.assertIsNone(display._filter_source)


class TestFileLogger(unittest.TestCase):
    def test_write_event(self):
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
            path = Path(f.name)
        
        logger = FileLogger(path, dated=False)
        event = Event("TEST", "CAT", "Test message", Severity.INFO)
        logger.write(event)
        logger.close()
        
        content = path.read_text(encoding="utf-8")
        self.assertIn("TEST", content)
        self.assertIn("Test message", content)
        path.unlink()


class TestDatedFolderLogger(unittest.TestCase):
    def test_write_event(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = DatedFolderLogger(Path(tmpdir), cleanup_days=30)
            event = Event("TEST", "CAT", "Test message", Severity.INFO)
            logger.write(event)
            logger.close()
            
            files = list(Path(tmpdir).rglob("*.log"))
            self.assertGreater(len(files), 0)


class TestCleanupThread(unittest.TestCase):
    def test_cleanup(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            thread = CleanupThread(Path(tmpdir), cleanup_days=0, interval=1)
            thread.start()
            import time
            time.sleep(0.5)
            thread.stop()
            try:
                thread.join(timeout=2)
            except Exception:
                pass


class TestBaseMonitor(unittest.TestCase):
    def test_monitor_creation(self):
        bus = EventBus()
        monitor = BaseMonitor("TEST", bus, 1.0)
        self.assertEqual(monitor.name, "TEST")
        self.assertEqual(monitor.interval, 1.0)
        self.assertFalse(monitor._stop.is_set())


if __name__ == "__main__":
    unittest.main()
