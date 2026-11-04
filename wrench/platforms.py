"""Platform abstraction: one place that knows what OS wrench is on.

Everything else asks this module three kinds of questions:
  1. identity    — current_platform() -> "linux" | "macos" | "windows"
  2. locations   — default_config_dir(), default_data_dir()
  3. capability  — has(cmd), service_manager(), log_backend(), capabilities()

Design rule: core sensing uses psutil (cross-platform). OS-native tools
(journalctl, systemctl, launchctl, schtasks, ...) are optional enrichers that
degrade gracefully when absent — wrench must never crash because a binary is
missing.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def current_platform() -> str:
    """'linux', 'macos', 'windows', or 'unknown'. Kept as a function so tests can patch it."""
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p == "darwin":
        return "macos"
    if p in ("win32", "cygwin", "msys"):
        return "windows"
    return "unknown"


def is_linux() -> bool:
    return current_platform() == "linux"


def is_macos() -> bool:
    return current_platform() == "macos"


def is_windows() -> bool:
    return current_platform() == "windows"


# ---------------- locations ----------------

def default_config_dir() -> Path:
    """Per-OS config dir (WRENCH_CONFIG_DIR env override is applied in config.py)."""
    plat = current_platform()
    if plat == "windows":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "wrench"
    if plat == "macos":
        return Path.home() / "Library" / "Application Support" / "wrench"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "wrench"


def default_data_dir() -> Path:
    """Per-OS data dir (WRENCH_DATA_DIR env override is applied in config.py)."""
    plat = current_platform()
    if plat == "windows":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "wrench"
    if plat == "macos":
        return Path.home() / "Library" / "Application Support" / "wrench"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "wrench"


def primary_mount() -> str:
    """The mountpoint whose fill level counts as 'the' disk: / or the system drive."""
    if current_platform() == "windows":
        drive = os.environ.get("SystemDrive", "C:")
        return drive + "\\"
    return "/"


# ---------------- capability ----------------

def has(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def service_manager() -> str | None:
    """Which service scheduler install-service should target."""
    plat = current_platform()
    if plat == "linux" and has("systemctl"):
        return "systemd"
    if plat == "macos" and has("launchctl"):
        return "launchd"
    if plat == "windows" and has("schtasks"):
        return "schtasks"
    return None


def log_backend() -> str | None:
    """Which system-log reader read_logs should use."""
    plat = current_platform()
    if plat == "linux" and has("journalctl"):
        return "journald"
    if plat == "macos" and has("log"):
        return "unified_log"
    if plat == "windows" and has("wevtutil"):
        return "windows_event_log"
    return None


def capabilities() -> dict[str, bool | str | None]:
    """Capability census for `wrench doctor`."""
    return {
        "platform": current_platform(),
        "service_manager": service_manager(),
        "log_backend": log_backend(),
        "systemctl": has("systemctl"),
        "journalctl": has("journalctl"),
        "launchctl": has("launchctl"),
        "schtasks": has("schtasks"),
        "docker": has("docker"),
        "nvidia-smi": has("nvidia-smi"),
        "smartctl": has("smartctl"),
    }
