"""Sensors: periodic sampling of os / docker / gpu / net into the sqlite store.

Mechanic heritage: every sample updates an EWMA baseline per metric and flags
z-score anomalies once the baseline has warmed up (n >= 20 samples).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time

import psutil

from . import platforms
from .store import Store

ANOMALY_Z = 3.0
# metrics worth baselining (sensor, key)
BASELINED = {
    "os": [
        "cpu_pct", "mem_pct", "swap_pct", "load_1m", "n_procs",
        "net_recv_rate_kbs", "net_sent_rate_kbs", "disk_root_pct",
    ],
}


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def sample_os(store: Store | None = None) -> dict:
    """One OS sample: cpu/mem/swap/load/disk/net/procs + top offenders."""
    cpu = psutil.cpu_percent(interval=0.5)
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    try:
        load = psutil.getloadavg()  # emulated on Windows (needs a warmup); may raise
    except (OSError, AttributeError):
        load = (0.0, 0.0, 0.0)
    disks = {}
    for part in psutil.disk_partitions(all=False):
        if part.fstype in ("squashfs", "tmpfs", "devtmpfs", "overlay"):
            continue
        try:
            u = psutil.disk_usage(part.mountpoint)
            disks[part.mountpoint] = round(u.percent, 1)
        except (PermissionError, OSError):
            continue
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
        "net_bytes_recv": net.bytes_recv,
        "net_bytes_sent": net.bytes_sent,
        "uptime_s": int(time.time() - psutil.boot_time()),
    }

    # top processes by cpu and mem (names only; cheap)
    procs = []
    for p in psutil.process_iter(["name", "cpu_percent", "memory_percent"]):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
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
            if abs(z) >= ANOMALY_Z:
                store.add_anomaly("os", metric, float(val), round(z, 2))
    return payload


def sample_docker(store: Store | None = None) -> dict | None:
    """Docker container census, if docker is installed and running."""
    if not shutil.which("docker"):
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
    if not shutil.which("nvidia-smi"):
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
