"""Driftscan: snapshot what the box *is* and narrate what changed.

Snapshots of listening ports, running services, installed packages, users,
and scheduled jobs. Diffs come out as plain-English one-liners; the agent can
optionally ask the LLM to narrate significance.

Cross-platform strategy: psutil for ports/services where possible; OS-native
tools (systemctl, launchctl, dpkg, brew, schtasks, ...) as enrichers that
degrade gracefully to an empty snapshot when absent.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import psutil

from . import platforms
from .store import Store

SNAPSHOT_KINDS = ("ports", "services", "packages", "users", "cron")


def _run(cmd: list[str], timeout: int = 20) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout).stdout
    except Exception:  # noqa: BLE001
        return ""


# ---------------- collectors ----------------

def _ports_psutil() -> dict | None:
    """Listening sockets off Linux (psutil, netstat fallback). None = census
    unavailable — the caller must skip the diff rather than record "no ports"."""
    from . import netinfo
    rows, complete = netinfo.listeners()
    if not complete:
        return None
    ports: dict[str, str] = {}
    for r in rows:
        key = f"{r['proto']}/{r['port']}"
        if key not in ports or (r["process"] and not ports[key]):
            ports[key] = r["process"]
    return ports


def collect_ports() -> dict:
    """Listening TCP/UDP sockets -> {'tcp/8787': 'python3', ...}"""
    # Prefer ss on Linux (sees process names without root); psutil elsewhere.
    from . import netinfo
    if platforms.is_linux() and platforms.has("ss"):
        out = _run(["ss", "-tulnpH"])
        ports: dict[str, str] = {}
        floor = netinfo.ephemeral_floor()
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
            if port.isdigit() and netinfo.is_ephemeral_udp(proto, int(port), floor):
                continue    # a client's source port, not a service
            key = f"{proto}/{port}"
            if key not in ports or (proc and not ports[key]):
                ports[key] = proc
        if ports:
            return ports
    return _ports_psutil()


_EPHEMERAL_LABEL = re.compile(r"^(application\.|com\.apple\.xpc\.launchd\.oneshot\.)|\.oneshot\.0x")


def _stable_launchd_label(label: str) -> str | None:
    """A launchd label worth tracking as a service, or None.

    `launchctl list` mixes real agents with one label per running app instance
    (`application.com.microsoft.Word.31977466.32034011`) and one-shot jobs.
    Those change every time someone opens an app; they are not services.
    Trailing numeric components (per-instance ids) are stripped.
    """
    if not label or _EPHEMERAL_LABEL.search(label):
        return None
    parts = label.split(".")
    while len(parts) > 1 and parts[-1].isdigit():
        parts.pop()
    return ".".join(parts)


def collect_services() -> dict:
    """Running services -> {'name': 'running'} (systemd / launchd / Windows services)."""
    services: dict[str, str] = {}
    plat = platforms.current_platform()
    if plat == "linux" and platforms.has("systemctl"):
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
    if plat == "macos" and platforms.has("launchctl"):
        out = _run(["launchctl", "list"])
        for line in out.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) >= 3:
                pid, _status, label = parts[0], parts[1], parts[2]
                name = _stable_launchd_label(label.strip())
                if pid.strip().isdigit() and name:  # has a live process
                    services[name] = "running"
        return services
    if plat == "windows" and hasattr(psutil, "win_service_iter"):
        try:
            for svc in psutil.win_service_iter():  # pragma: no cover (Windows only)
                try:
                    if svc.status() == "running":
                        services[svc.name()] = "running"
                except (psutil.Error, OSError):
                    continue
        except (psutil.Error, OSError):
            pass
        return services
    return services


def _digest_entries(lines: list[str]) -> dict:
    lines = sorted(lines)
    digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()[:16]
    return {"count": len(lines), "digest": digest,
            "entries": {ln.split(" ")[0]: ln for ln in lines}}


def collect_packages() -> dict | None:
    """Installed package census (count + digest + entries).

    None when this OS has a package manager we know but it could not be run
    this time — "unknown", which the scan skips, is not "zero packages".
    """
    candidates: list[list[str]] = []
    plat = platforms.current_platform()
    if plat == "linux":
        candidates = [
            ["dpkg-query", "-W", "-f=${Package} ${Version}\n"],
            ["rpm", "-qa"],
            ["pacman", "-Q"],
            ["apk", "list", "--installed"],
        ]
    elif plat == "macos":
        candidates = [["brew", "list", "--versions"]]
    elif plat == "windows":
        candidates = []  # no fast, reliable package census; drift still covers services/ports/tasks
    for cmd in candidates:
        exe = platforms.find_tool(cmd[0])
        if not exe:
            continue
        out = _run([exe, *cmd[1:]], timeout=30)
        if out:
            return _digest_entries(out.splitlines())
    return None if candidates else _digest_entries([])


def collect_users() -> dict:
    """Login-capable local user accounts."""
    users: dict[str, str] = {}
    plat = platforms.current_platform()
    if plat in ("linux", "macos"):
        try:
            import pwd  # posix only

            for u in pwd.getpwall():
                if u.pw_shell in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin",
                                  "/usr/bin/false"):
                    continue
                if plat == "macos" and u.pw_name.startswith("_"):
                    continue  # macOS service accounts
                users[u.pw_name] = f"uid={u.pw_uid} shell={u.pw_shell}"
        except (ImportError, OSError):
            pass
        return users
    if plat == "windows":
        out = _run(["net", "user"])  # pragma: no cover (Windows only)
        in_body = False
        for line in out.splitlines():
            if line.startswith("---"):
                in_body = True
                continue
            if "command completed" in line.lower():
                break
            if in_body:
                for name in line.split():
                    users[name] = "local account"
    return users


def collect_cron() -> dict:
    """Scheduled jobs: crontab + cron dirs (Linux), launch agents (macOS), tasks (Windows)."""
    entries: dict[str, str] = {}
    plat = platforms.current_platform()
    if plat in ("linux", "macos") and platforms.has("crontab"):
        out = _run(["crontab", "-l"])
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # keyed by content, not line number: inserting one entry must
                # not mark every later entry as "changed"
                entries["user:" + hashlib.sha256(line.encode()).hexdigest()[:10]] = line
    if plat == "linux":
        dirs = ("/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly")
    elif plat == "macos":
        dirs = (str(Path.home() / "Library" / "LaunchAgents"), "/Library/LaunchAgents",
                "/Library/LaunchDaemons")
    else:
        dirs = ()
    for d in dirs:
        p = Path(d)
        if p.is_dir():
            for f in sorted(p.iterdir()):
                if f.is_file():
                    try:
                        h = hashlib.sha256(f.read_bytes()).hexdigest()[:12]
                        entries[str(f)] = h
                    except OSError:
                        continue
    if plat == "windows" and platforms.has("schtasks"):  # pragma: no cover (Windows only)
        out = _run(["schtasks", "/Query", "/FO", "CSV", "/NH"], timeout=30)
        for line in out.splitlines():
            parts = line.split(",")
            if parts and parts[0].strip('"'):
                name = parts[0].strip('"')
                # the row also carries Next Run Time and Status, which change on
                # every run — track the task's existence, not its clock
                entries[name] = "present"
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
        "cron": ("scheduled job added", "scheduled job removed/changed"),
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
        if new is None:
            # the census could not be taken this run (no privilege, tool not on
            # PATH under the scheduler). Recording "nothing" would report every
            # item as removed now and re-added next time — skip instead.
            continue
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
