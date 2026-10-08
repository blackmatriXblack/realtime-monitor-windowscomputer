"""
Windows Monitor - Comprehensive real-time Windows system monitoring package.
"""

__version__ = "2.0.0"
__author__ = "Windows Monitor"
__description__ = "Comprehensive real-time Windows system monitoring with rolling log display"

from .__main__ import (
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
    SEV_NAME,
)

__all__ = [
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
    "SEV_NAME",
]

