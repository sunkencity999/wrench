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


# ---------------- volumes ----------------

_PSEUDO_FSTYPES = {"squashfs", "tmpfs", "devtmpfs", "overlay", "devfs", "autofs",
                   "proc", "sysfs", "ramfs", "iso9660", "udf", "cdfs", "fuse.snapfuse",
                   "nullfs", "efivarfs", "tracefs", "cgroup2"}
_MACOS_SKIP_PREFIXES = ("/System/Volumes/", "/private/var/folders/", "/Volumes/Recovery",
                        "/Library/Developer/CoreSimulator/")
_LINUX_SKIP_PREFIXES = ("/snap/", "/var/lib/docker/", "/var/lib/containers/",
                        "/run/", "/sys/", "/proc/", "/dev/", "/boot/efi")


def is_monitored_volume(mountpoint: str, fstype: str = "", opts: str = "",
                        plat: str | None = None) -> bool:
    """Is this mount a real, fillable disk worth a gauge, a baseline and an alert?

    The question behind every disk alert is "can this volume run out of room and
    hurt something?" — which rules out pseudo filesystems, read-only media
    (mounted disk images, optical drives, snap squashfs: they sit at 100% by
    design), and the APFS plumbing volumes macOS mounts under /System/Volumes
    (they share one container with "/", so listing them is the same disk a
    dozen times). Pure, so every OS branch is testable.
    """
    plat = plat or current_platform()
    if (fstype or "").lower() in _PSEUDO_FSTYPES:
        return False
    is_root = mountpoint in ("/", primary_mount())
    opt_set = {o.strip() for o in (opts or "").split(",")}
    if plat == "windows":
        return "cdrom" not in opt_set and bool(fstype)
    if "ro" in opt_set and not is_root:
        return False
    if plat == "macos":
        return not mountpoint.startswith(_MACOS_SKIP_PREFIXES)
    if plat == "linux":
        return not mountpoint.startswith(_LINUX_SKIP_PREFIXES)
    return True


def volume_usage(partitions=None, usage_fn=None, plat: str | None = None) -> dict[str, float]:
    """{mountpoint: percent used} for the volumes that matter on this OS.

    On macOS "/" is the sealed system snapshot, a few GB of a shared APFS
    container — its own "used" figure says nothing about whether the Mac is
    full. For APFS the honest number is container-level: 1 − free/total.
    """
    import psutil
    plat = plat or current_platform()
    parts = partitions if partitions is not None else psutil.disk_partitions(all=False)
    usage_fn = usage_fn or psutil.disk_usage
    out: dict[str, float] = {}
    for part in parts:
        if not is_monitored_volume(part.mountpoint, part.fstype, part.opts, plat):
            continue
        try:
            u = usage_fn(part.mountpoint)
        except (PermissionError, OSError):
            continue
        if not u.total:
            continue
        if plat == "macos" and (part.fstype or "").lower() == "apfs":
            pct = (u.total - u.free) / u.total * 100.0
        else:
            pct = u.percent
        out[part.mountpoint] = round(pct, 1)
    return out


def os_label() -> str:
    """Human OS name + version: 'Ubuntu 24.04', 'macOS 15.1', 'Windows 11 (26100)'."""
    import platform as _pf
    plat = current_platform()
    try:
        if plat == "macos":
            ver = _pf.mac_ver()[0]
            return f"macOS {ver}" if ver else "macOS"
        if plat == "windows":
            rel, ver = _pf.release(), _pf.version()
            edition = getattr(_pf, "win32_edition", lambda: "")() or ""
            build = ver.split(".")[-1] if ver else ""
            # Windows 11 still reports release "10"; builds >= 22000 are 11
            if rel == "10" and build.isdigit() and int(build) >= 22000 and "Server" not in edition:
                rel = "11"
            name = f"Windows Server {rel}" if "Server" in edition else f"Windows {rel}"
            return f"{name} ({build})" if build else name
        if plat == "linux":
            info = _pf.freedesktop_os_release()
            return info.get("PRETTY_NAME") or f"{info.get('NAME', 'Linux')} {info.get('VERSION_ID', '')}".strip()
    except Exception:  # noqa: BLE001
        pass
    import platform as _pf2
    return f"{_pf2.system()} {_pf2.release()}".strip()


def is_admin() -> bool:
    """True when running with root / Administrator rights."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


# ---------------- capability ----------------

# Where package managers and admin tools live when PATH is the bare one a
# scheduler hands out (launchd: /usr/bin:/bin:/usr/sbin:/sbin; cron similar).
_EXTRA_TOOL_DIRS = ("/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
                    "/usr/local/sbin", "/usr/sbin", "/sbin", "/snap/bin")


def find_tool(cmd: str) -> str | None:
    """Absolute path of a tool, looking past a minimal scheduler PATH.

    A patrol under launchd/cron and the same patrol in a login shell must see
    the same tools — otherwise brew/docker/smartctl "vanish" on schedule and
    reappear interactively, which drift then reports as mass removal/install.
    """
    found = shutil.which(cmd)
    if found:
        return found
    if current_platform() == "windows":
        return None
    for d in _EXTRA_TOOL_DIRS:
        cand = os.path.join(d, cmd)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def has(cmd: str) -> bool:
    return find_tool(cmd) is not None


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
