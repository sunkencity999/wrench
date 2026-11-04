"""Driftscan: snapshot what the box *is* and narrate what changed.

Drift heritage: snapshots of listening ports, running services, installed
packages, users, and cron. Diffs come out as plain-English one-liners;
the agent can optionally ask the LLM to narrate significance.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

from .store import Store

SNAPSHOT_KINDS = ("ports", "services", "packages", "users", "cron")


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:  # noqa: BLE001
        return ""


# ---------------- collectors ----------------

def collect_ports() -> dict:
    """Listening TCP/UDP sockets -> {'tcp/8787': 'python3', ...}"""
    out = _run(["ss", "-tulnpH"])
    ports: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        port = local.rsplit(":", 1)[-1]
        proc = ""
        if 'users:(("' in line:
            proc = line.split('users:(("', 1)[1].split('"', 1)[0]
        key = f"{proto}/{port}"
        if key not in ports or (proc and not ports[key]):
            ports[key] = proc
    return ports


def collect_services() -> dict:
    """Running systemd services (system + user) -> {'name.service': 'running'}"""
    services: dict[str, str] = {}
    for scope in ([], ["--user"]):
        out = _run(
            ["systemctl", *scope, "list-units", "--type=service", "--state=running",
             "--no-legend", "--plain", "--no-pager"]
        )
        prefix = "user:" if scope else ""
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                services[prefix + parts[0]] = "running"
    return services


def collect_packages() -> dict:
    """Installed package census. Full list is big; store count + digest + sample of names."""
    out = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], timeout=30)
    if not out:
        out = _run(["rpm", "-qa"], timeout=30)
    lines = sorted(out.splitlines())
    digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]
    return {"count": len(lines), "digest": digest, "entries": {ln.split(" ")[0]: ln for ln in lines}}


def collect_users() -> dict:
    """Login-capable users from /etc/passwd."""
    users: dict[str, str] = {}
    try:
        for line in Path("/etc/passwd").read_text().splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                name, _, uid, _, _, _, shell = parts[:7]
                if shell not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                    users[name] = f"uid={uid} shell={shell}"
    except OSError:
        pass
    return users


def collect_cron() -> dict:
    """User crontab + system cron files (names + content digests)."""
    entries: dict[str, str] = {}
    out = _run(["crontab", "-l"])
    for i, line in enumerate(out.splitlines()):
        line = line.strip()
        if line and not line.startswith("#"):
            entries[f"user:{i}"] = line
    for d in ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly"):
        p = Path(d)
        if p.is_dir():
            for f in sorted(p.iterdir()):
                if f.is_file():
                    try:
                        h = hashlib.sha256(f.read_bytes()).hexdigest()[:12]
                        entries[str(f)] = h
                    except OSError:
                        continue
    return entries


COLLECTORS = {
    "ports": collect_ports,
    "services": collect_services,
    "packages": collect_packages,
    "users": collect_users,
    "cron": collect_cron,
}


# ---------------- diff engine ----------------

def _diff_dicts(kind: str, old: dict, new: dict) -> list[str]:
    """Plain-English change lines between two snapshot payloads."""
    changes: list[str] = []
    if kind == "packages":
        old_e, new_e = old.get("entries", {}), new.get("entries", {})
        added = sorted(set(new_e) - set(old_e))
        removed = sorted(set(old_e) - set(new_e))
        changed = sorted(k for k in set(old_e) & set(new_e) if old_e[k] != new_e[k])
        for p in added[:20]:
            changes.append(f"package installed: {p}")
        for p in removed[:20]:
            changes.append(f"package removed: {p}")
        for p in changed[:20]:
            changes.append(f"package upgraded: {new_e[p]}")
        extra = max(len(added) - 20, 0) + max(len(removed) - 20, 0) + max(len(changed) - 20, 0)
        if extra:
            changes.append(f"...and {extra} more package changes")
        return changes

    labels = {
        "ports": ("port opened", "port closed"),
        "services": ("service started", "service stopped"),
        "users": ("user added", "user removed"),
        "cron": ("cron entry added", "cron entry removed/changed"),
    }
    add_label, rm_label = labels.get(kind, ("added", "removed"))
    for k in sorted(set(new) - set(old)):
        detail = f" ({new[k]})" if new[k] else ""
        changes.append(f"{add_label}: {k}{detail}")
    for k in sorted(set(old) - set(new)):
        detail = f" ({old[k]})" if old[k] else ""
        changes.append(f"{rm_label}: {k}{detail}")
    for k in sorted(set(old) & set(new)):
        if old[k] != new[k] and kind in ("cron", "users"):
            changes.append(f"{kind} entry changed: {k}")
    return changes


def scan(store: Store, kinds: tuple[str, ...] = SNAPSHOT_KINDS) -> list[dict]:
    """Take fresh snapshots, diff vs last, record + return changes.

    Returns: [{kind, changes: [str, ...]}] only for kinds with changes.
    """
    results = []
    for kind in kinds:
        collector = COLLECTORS.get(kind)
        if collector is None:
            continue
        new = collector()
        prev = store.last_snapshot(kind)
        if prev is not None:
            changes = _diff_dicts(kind, prev[1], new)
            if changes:
                summary = f"{len(changes)} {kind} change(s)"
                store.add_diff(kind, summary, changes)
                results.append({"kind": kind, "changes": changes})
        store.add_snapshot(kind, new)
    return results


def baseline_exists(store: Store) -> bool:
    return any(store.last_snapshot(k) for k in SNAPSHOT_KINDS)
