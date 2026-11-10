"""Sensors: periodic sampling of os / docker / gpu / net into the sqlite store.

Every sample updates an EWMA baseline per metric and flags z-score anomalies
once the baseline has warmed up (n >= 20 samples).
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import time

import psutil

from . import platforms
from .store import Store

ANOMALY_Z = 3.0

# Log directories whose growth capacity-forecasting watches. The du is bounded
# (file-count + wall-time budget) so a patrol never stalls on a huge tree.
_LOG_DIRS_BY_OS = {
    "linux": ["/var/log"],
    "darwin": ["/var/log", "/Library/Logs"],
    "windows": [],
}
_LOG_DU_MAX_FILES = 20000
_LOG_DU_TIME_BUDGET_S = 2.5
# metrics worth baselining (sensor, key)
BASELINED = {
    "os": [
        "cpu_pct", "mem_pct", "swap_pct", "load_1m", "n_procs",
        "net_recv_rate_kbs", "net_sent_rate_kbs", "disk_root_pct",
    ],
}


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        exe = platforms.find_tool(cmd[0])
        if exe:
            cmd = [exe, *cmd[1:]]
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def log_dirs_for(system: str | None = None) -> list[str]:
    """Log directories to sample on this OS (pure; testable via `system`)."""
    return _LOG_DIRS_BY_OS.get((system or platform.system()).lower(), [])


def dir_size_bounded(path: str, max_files: int = _LOG_DU_MAX_FILES,
                     time_budget_s: float = _LOG_DU_TIME_BUDGET_S) -> dict:
    """Best-effort recursive byte count, bounded by file count and wall time.

    Returns {bytes, files, truncated}. Never raises; unreadable entries are
    skipped. ``truncated`` is True when either budget was hit — the caller can
    note that the figure is a floor, not an exact total.
    """
    total = 0
    files = 0
    truncated = False
    deadline = time.monotonic() + time_budget_s
    stack = [path]
    while stack:
        if files >= max_files or time.monotonic() > deadline:
            truncated = True
            break
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for entry in it:
                    if files >= max_files or time.monotonic() > deadline:
                        truncated = True
                        break
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                            files += 1
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue
    return {"bytes": total, "files": files, "truncated": truncated}


def sample_log_dirs(dirs: list[str] | None = None) -> dict:
    """Bounded du of each existing log directory. {path: {bytes,files,truncated}}."""
    out: dict[str, dict] = {}
    for d in (dirs if dirs is not None else log_dirs_for()):
        try:
            if os.path.isdir(d):
                out[d] = dir_size_bounded(d)
        except OSError:
            continue
    return out


def inode_usage() -> dict:
    """Inode utilization percent per mount (statvfs). {} where unsupported."""
    out: dict[str, float] = {}
    if not hasattr(os, "statvfs"):
        return out
    for part in psutil.disk_partitions(all=False):
        if not platforms.is_monitored_volume(part.mountpoint, part.fstype, part.opts):
            continue
        if (part.fstype or "").lower() in ("apfs", "ntfs", "btrfs", "zfs"):
            continue   # dynamically allocated inodes — a percentage is meaningless
        try:
            s = os.statvfs(part.mountpoint)
        except (OSError, PermissionError):
            continue
        if s.f_files <= 0:
            continue
        used = s.f_files - s.f_ffree
        out[part.mountpoint] = round(used / s.f_files * 100, 1)
    return out


def _proc_label(p) -> str:
    """A process name a human recognizes.

    Some tools install as a versioned binary (``…/claude/versions/2.1.317``),
    so the bare executable name is a number. Fall back to the parent directory
    of the executable in that case.
    """
    name = p.name() or "?"
    if name.replace(".", "").replace("-", "").isdigit():
        try:
            parts = [x for x in (p.exe() or "").replace("\\", "/").split("/") if x]
            for part in reversed(parts[:-1]):
                if part.lower() not in ("versions", "bin", "current", "macos", "contents"):
                    return f"{part} ({name})"
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass
    return name


# metrics where only an INCREASE is a problem (a CPU drop is not an incident)
_HIGH_ONLY = {"cpu_pct", "mem_pct", "swap_pct", "load_1m", "disk_root_pct", "n_procs"}
_ANOMALY_COOLDOWN_S = 1800


def _should_record_anomaly(store: Store, metric: str, z: float) -> bool:
    if abs(z) < ANOMALY_Z:
        return False
    if metric in _HIGH_ONLY and z < 0:
        return False
    # one row per excursion, not one per sample while it lasts
    for a in store.recent_anomalies(_ANOMALY_COOLDOWN_S):
        if a["metric"] == metric:
            return False
    return True


def sample_os(store: Store | None = None) -> dict:
    """One OS sample: cpu/mem/swap/load/disk/net/procs + top offenders."""
    # Per-process cpu_percent is a delta since the previous call, so the first
    # reading is always 0.0. Prime every process, let the 0.5s system sample
    # below be the measurement window, then read.
    primed = []
    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
            primed.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    cpu = psutil.cpu_percent(interval=0.5)
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    try:
        load = psutil.getloadavg()  # emulated on Windows (needs a warmup); may raise
    except (OSError, AttributeError):
        load = (0.0, 0.0, 0.0)
    disks = platforms.volume_usage()
    net = psutil.net_io_counters()

    payload = {
        "cpu_pct": cpu,
        "mem_pct": vm.percent,
        "mem_used_gb": round(vm.used / 2**30, 2),
        "mem_total_gb": round(vm.total / 2**30, 2),
        "swap_pct": sw.percent,
        "load_1m": load[0],
        "load_5m": load[1],
        "load_15m": load[2],
        "n_procs": len(psutil.pids()),
        "disk_pct": disks,
        "disk_root_pct": disks.get(platforms.primary_mount(), 0.0),
        "inode_pct": inode_usage(),
        "log_dirs": sample_log_dirs(),
        "net_bytes_recv": net.bytes_recv,
        "net_bytes_sent": net.bytes_sent,
        "uptime_s": int(time.time() - psutil.boot_time()),
    }

    # top processes by cpu and mem (names only; cheap)
    procs = []
    for p in primed:
        try:
            with p.oneshot():
                procs.append({"name": _proc_label(p), "cpu_percent": p.cpu_percent(None),
                              "memory_percent": p.memory_percent()})
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    top_cpu = sorted(procs, key=lambda x: x["cpu_percent"] or 0, reverse=True)[:5]
    top_mem = sorted(procs, key=lambda x: x["memory_percent"] or 0, reverse=True)[:5]
    payload["top_cpu"] = [
        {"name": p["name"], "cpu_pct": round(p["cpu_percent"] or 0, 1)} for p in top_cpu
    ]
    payload["top_mem"] = [
        {"name": p["name"], "mem_pct": round(p["memory_percent"] or 0, 1)} for p in top_mem
    ]

    if store is not None:
        # net rates need the previous sample
        prev = store.last_sample("os")
        if prev:
            dt = max(time.time() - prev[0], 1.0)
            payload["net_recv_rate_kbs"] = round(
                max(net.bytes_recv - prev[1].get("net_bytes_recv", net.bytes_recv), 0) / dt / 1024, 1
            )
            payload["net_sent_rate_kbs"] = round(
                max(net.bytes_sent - prev[1].get("net_bytes_sent", net.bytes_sent), 0) / dt / 1024, 1
            )
        else:
            payload["net_recv_rate_kbs"] = 0.0
            payload["net_sent_rate_kbs"] = 0.0
        store.add_sample("os", payload)
        for metric in BASELINED["os"]:
            val = payload.get(metric)
            if val is None:
                continue
            z = store.update_baseline("os", metric, float(val))
            if _should_record_anomaly(store, metric, z):
                store.add_anomaly("os", metric, float(val), round(z, 2))
    return payload


def sample_docker(store: Store | None = None) -> dict | None:
    """Docker container census, if docker is installed and running."""
    if not platforms.has("docker"):
        return None
    out = _run(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=15)
    if not out:
        return None
    containers = []
    for line in out.splitlines():
        try:
            c = json.loads(line)
            containers.append(
                {"name": c.get("Names"), "state": c.get("State"), "status": c.get("Status")}
            )
        except json.JSONDecodeError:
            continue
    payload = {
        "n_total": len(containers),
        "n_running": sum(1 for c in containers if c["state"] == "running"),
        "containers": containers[:40],
    }
    if store is not None:
        store.add_sample("docker", payload)
    return payload


def sample_gpu(store: Store | None = None) -> dict | None:
    """NVIDIA GPU census via nvidia-smi query (read-only, cheap)."""
    if not platforms.has("nvidia-smi"):
        return None
    out = _run(
        [
            "nvidia-smi",
            "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
            "--format=csv,noheader,nounits",
        ],
        timeout=10,
    )
    if not out:
        return None
    gpus = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 5:
            try:
                gpus.append(
                    {
                        "name": parts[0],
                        "util_pct": float(parts[1]),
                        "mem_used_mb": float(parts[2]),
                        "mem_total_mb": float(parts[3]),
                        "temp_c": float(parts[4]),
                    }
                )
            except ValueError:
                continue
    if not gpus:
        return None
    payload = {"gpus": gpus}
    if store is not None:
        store.add_sample("gpu", payload)
    return payload


def sample_all(store: Store | None = None) -> dict:
    """Run every available sensor; returns combined dict."""
    out = {"os": sample_os(store)}
    d = sample_docker(store)
    if d is not None:
        out["docker"] = d
    g = sample_gpu(store)
    if g is not None:
        out["gpu"] = g
    return out


def status_snapshot(store: Store | None = None) -> dict:
    """Everything `wrench status` needs in one dict (also records a sample)."""
    data = sample_all(store)
    data["anomalies_24h"] = store.recent_anomalies(86400) if store else []
    return data
