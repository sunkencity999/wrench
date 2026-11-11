"""Agent tools: the hands wrench is allowed to use.

All execution is no-shell (shlex + subprocess list argv), policy-checked,
time-bounded, and logged. Read-only diagnostics are allowlisted; mutations go
through policy.check_repair and the actions log.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import psutil

from . import platforms, policy
from .store import Store

MAX_OUTPUT = 8000  # chars returned to the model per tool call


def _clip(text: str, n: int = MAX_OUTPUT) -> str:
    if len(text) <= n:
        return text
    return text[: n // 2] + f"\n...[{len(text) - n} chars clipped]...\n" + text[-n // 2 :]


def _exec(argv: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
        out = (r.stdout or "") + (("\n[stderr] " + r.stderr) if r.stderr.strip() else "")
        return _clip(out.strip() or f"(exit {r.returncode}, no output)")
    except subprocess.TimeoutExpired:
        return f"(timed out after {timeout}s)"
    except FileNotFoundError:
        return f"(command not found: {argv[0]})"
    except Exception as e:  # noqa: BLE001
        return f"(error: {e.__class__.__name__}: {e})"


def _exec_rc(argv: list[str], timeout: int = 30) -> tuple[int, str]:
    """Like _exec, but also returns the exit code (124 timeout, 127 missing)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, stdin=subprocess.DEVNULL)
        out = (r.stdout or "") + (("\n[stderr] " + r.stderr) if r.stderr.strip() else "")
        return r.returncode, _clip(out.strip() or f"(exit {r.returncode}, no output)")
    except subprocess.TimeoutExpired:
        return 124, f"(timed out after {timeout}s)"
    except FileNotFoundError:
        return 127, f"(command not found: {argv[0]})"
    except Exception as e:  # noqa: BLE001
        return 1, f"(error: {e.__class__.__name__}: {e})"


# ---------------- tool implementations ----------------

def run_diag(store: Store, command: str) -> str:
    """Run an allowlisted read-only diagnostic command."""
    decision = policy.check_diag(command)
    if not decision.allowed:
        store.add_action("any", "diag-denied", command, False, decision.reason)
        return f"DENIED: {decision.reason}. Stick to read-only diagnostics on the allowlist."
    out = _exec(policy.split_command(command))
    store.add_action("any", f"diag:{decision.label}", command, True, out[:500])
    return out


def read_logs(store: Store, unit: str = "", lines: int = 50, priority: str = "") -> str:
    """Read recent system logs (journald / macOS unified log / Windows event log)."""
    lines = max(1, min(int(lines), 500))
    if unit and not _safe_unit(unit):
        return "DENIED: not a valid unit/process name."
    if priority and not str(priority).isalnum():
        return "DENIED: not a valid priority."
    backend = platforms.log_backend()
    if backend == "journald":
        argv = ["journalctl", "--no-pager", "-n", str(lines)]
        if unit:
            # try system unit first, fall back to user units
            probe = _exec(["journalctl", "--no-pager", "-n", str(lines), "-u", unit], timeout=20)
            if "-- No entries --" in probe or not probe.strip():
                probe = _exec(
                    ["journalctl", "--user", "--no-pager", "-n", str(lines), "-u", unit],
                    timeout=20,
                )
            store.add_action("any", "diag:journal", f"journalctl -u {unit} -n {lines}", True, "")
            return probe
        if priority:
            argv += ["-p", priority]
        out = _exec(argv, timeout=20)
        store.add_action("any", "diag:journal", " ".join(argv), True, "")
        return out
    if backend == "unified_log":  # macOS
        argv = ["log", "show", "--last", "15m", "--style", "compact"]
        if unit:
            argv += ["--predicate", f'process == "{unit}"']
        elif priority in ("err", "error", "crit", "critical"):
            argv += ["--predicate", 'messageType == "error" || messageType == "fault"']
        out = _exec(argv, timeout=30)
        out = "\n".join(out.splitlines()[-lines:])
        store.add_action("any", "diag:journal", " ".join(argv), True, "")
        return out
    if backend == "windows_event_log":  # pragma: no cover (Windows only)
        channel = "System"
        argv = ["wevtutil", "qe", channel, f"/c:{lines}", "/rd:true", "/f:text"]
        if priority in ("err", "error", "crit", "critical"):
            argv.append("/q:*[System[(Level=1 or Level=2)]]")
        out = _exec(argv, timeout=30)
        store.add_action("any", "diag:journal", " ".join(argv), True, "")
        return out
    return ("(no system log reader available on this platform — looked for "
            "journalctl, log, wevtutil)")


_UNIT_RE = __import__("re").compile(r"[\w@][\w@.:\-]{0,200}")


def _safe_unit(unit: str) -> bool:
    """A unit/service name the model supplied: no leading "-" (it would be read
    as an option — `systemctl status -Hroot@host` opens an outbound ssh) and no
    quote/space that could break out of a log predicate."""
    return bool(_UNIT_RE.fullmatch(unit or ""))


def service_status(store: Store, unit: str) -> str:
    """Service status: systemctl / launchctl / sc query, per platform."""
    if not _safe_unit(unit):
        return "DENIED: not a valid service name."
    plat = platforms.current_platform()
    if plat == "linux" and platforms.has("systemctl"):
        out = _exec(["systemctl", "status", unit, "--no-pager", "-n", "10"])
        if "could not be found" in out or "Unit" in out and "not found" in out:
            out_user = _exec(["systemctl", "--user", "status", unit, "--no-pager", "-n", "10"])
            if "could not be found" not in out_user:
                out = "[user scope]\n" + out_user
        store.add_action("any", "diag:service", f"systemctl status {unit}", True, "")
        return out
    if plat == "macos" and platforms.has("launchctl"):
        uid = os.getuid() if hasattr(os, "getuid") else 501
        out = _exec(["launchctl", "print", f"gui/{uid}/{unit}"], timeout=15)
        if "could not find" in out.lower() or "error" in out.lower()[:80]:
            out = _exec(["launchctl", "print", f"system/{unit}"], timeout=15)
        store.add_action("any", "diag:service", f"launchctl print .../{unit}", True, "")
        return _clip(out, 4000)
    if plat == "windows":  # pragma: no cover (Windows only)
        out = _exec(["sc", "query", unit], timeout=15)
        store.add_action("any", "diag:service", f"sc query {unit}", True, "")
        return out
    return "(no service manager available on this platform)"


def _py_disk_tree(root: Path, depth: int) -> list[tuple[int, str]]:
    """Pure-Python du fallback: [(bytes, path)] for dirs up to `depth` under root."""
    sizes: dict[Path, int] = {}

    def walk(d: Path, level: int) -> int:
        total = 0
        try:
            with os.scandir(d) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                        elif entry.is_dir(follow_symlinks=False):
                            total += walk(Path(entry.path), level + 1)
                    except OSError:
                        continue
        except OSError:
            return 0
        if level <= depth:
            sizes[d] = total
        return total

    walk(root, 0)
    return sorted(((s, str(p)) for p, s in sizes.items()), reverse=True)


def _human(nbytes: int) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if nbytes < 1024 or unit == "T":
            return f"{nbytes:.1f}{unit}" if unit != "B" else f"{nbytes}B"
        nbytes /= 1024
    return f"{nbytes:.1f}T"


def disk_tree(store: Store, path: str = "/", depth: int = 1) -> str:
    """Largest directories under a path (du where available, Python walk elsewhere)."""
    p = str(Path(path).expanduser())
    depth = max(1, min(int(depth), 3))
    if platforms.has("du") and not platforms.is_windows():
        # `-d N` is understood by GNU and BSD du alike (`--max-depth` is GNU-only,
        # so macOS returned a usage error); `--` keeps a path from being an option
        out = _exec(["du", "-x", "-h", "-d", str(depth), "--", p], timeout=60)
        lines = out.splitlines()

        def size_key(ln: str) -> float:
            tok = ln.split("\t")[0] if "\t" in ln else ln.split()[0] if ln.split() else "0"
            mult = {"K": 1, "M": 1024, "G": 1024**2, "T": 1024**3}
            try:
                if tok[-1] in mult:
                    return float(tok[:-1]) * mult[tok[-1]]
                return float(tok)
            except (ValueError, IndexError):
                return 0.0

        top = sorted(lines, key=size_key, reverse=True)[:20]
        store.add_action("any", "diag:disk", f"du --max-depth={depth} {p}", True, "")
        return "\n".join(top)
    # Windows / du-less fallback
    rows = _py_disk_tree(Path(p), depth)[:20]
    store.add_action("any", "diag:disk", f"pydu depth={depth} {p}", True, "")
    return "\n".join(f"{_human(s)}\t{d}" for s, d in rows) or "(empty or unreadable)"


def net_listeners(store: Store) -> str:
    """Listening sockets with owning processes (ss on Linux, psutil elsewhere)."""
    if platforms.is_linux() and platforms.has("ss"):
        out = _exec(["ss", "-tulnpH"])
        store.add_action("any", "diag:net", "ss -tulnpH", True, "")
        return out
    from . import netinfo
    rows = ["proto  local address          pid    process"]
    census, complete = netinfo.listeners()
    if not complete:
        return "(cannot enumerate sockets on this platform without elevated rights)"
    for r in census:
        local = f"{r['addr']}:{r['port']}"
        rows.append(f"{r['proto']:<6} {local:<22} {r['pid'] or '-':<6} {r['process'] or '?'}")
    store.add_action("any", "diag:net", "listener census", True, "")
    return "\n".join(rows)


def proc_top(store: Store, sort: str = "cpu", n: int = 15) -> str:
    """Top processes by cpu or mem (psutil — identical output on every OS)."""
    n = max(1, min(int(n), 50))
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent",
                                  "memory_percent", "cmdline"]):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    key = "memory_percent" if sort == "mem" else "cpu_percent"
    procs.sort(key=lambda x: x.get(key) or 0, reverse=True)
    rows = [f"{'PID':>7} {'CPU%':>6} {'MEM%':>6} {'USER':<12} NAME"]
    for p in procs[:n]:
        cmd = " ".join(p.get("cmdline") or [])[:60] or (p.get("name") or "?")
        rows.append(f"{p['pid']:>7} {p.get('cpu_percent') or 0:>6.1f} "
                    f"{p.get('memory_percent') or 0:>6.1f} "
                    f"{(p.get('username') or '?')[:12]:<12} {cmd}")
    store.add_action("any", "diag:proc", f"proc_top sort={sort}", True, "")
    return "\n".join(rows)


def _window_block(cfg, command: str) -> str | None:
    """Reason the maintenance window forbids a mutation right now, else None.

    The CLI gates fixxer/blueprint/cert renewals on [maintenance]; the agent's
    own hands must obey the same change-control rule — an autonomous patrol
    restarting a service at 14:00 on a Tuesday is exactly what windows exist
    to prevent. There is no override on this path: nobody is present to consent.
    """
    if cfg is None:
        return None
    try:
        from . import windows as _win
        dec = _win.gate(cfg, f"agent fix `{command}`", override=False, has_consent=False)
        return None if dec.allowed else dec.reason
    except Exception as e:  # noqa: BLE001 — a broken gate must fail closed
        return f"maintenance-window check failed ({e.__class__.__name__}); refusing to mutate"


def fix_action(store: Store, command: str, tier: str, confirm_fn=None, cfg=None) -> str:
    """Attempt a mutation. Policy-gated, window-gated, confirm-gated, always logged."""
    decision = policy.check_repair(command, tier)
    if decision.allowed:
        blocked = _window_block(cfg, command)
        if blocked:
            store.add_action(tier, "fix-denied", command, False, blocked)
            return f"DENIED: {blocked}"
    if not decision.allowed:
        store.add_action(tier, "fix-denied", command, False, decision.reason)
        return (
            f"DENIED: {decision.reason}. "
            "At this policy tier, present the fix to the human instead of executing it."
        )
    if decision.needs_confirm:
        if confirm_fn is None:
            store.add_action(tier, "fix-needs-confirm", command, False, "no confirm channel")
            return "DENIED: interactive confirmation required but no confirmation channel available."
        approved = bool(confirm_fn(command, decision.label))
        try:      # learn from the answer (code-derived, no model involved)
            from . import memory
            if cfg is None or memory.settings(cfg)["learn_habits"]:
                memory.note_decision(store, command, approved, cfg=cfg)
        except Exception:  # noqa: BLE001 — learning never blocks a fix
            pass
        if not approved:
            store.add_action(tier, "fix-declined", command, False, "human declined")
            return "DECLINED: the human said no. Do not retry this action."
    code, out = _exec_rc(policy.split_command(command), timeout=60)
    ok = code == 0
    store.add_action(tier, f"fix:{decision.label}", command, ok,
                     (out if ok else f"FAILED (exit {code}): {out}")[:1000])
    if not ok:
        return f"FAILED ({decision.label}, exit {code}) — the command did not succeed:\n{out}"
    return f"EXECUTED ({decision.label}):\n{out}"


def security_intel(store: Store) -> str:
    """Cached webintel scan, formatted for the model. Never touches the network."""
    res = store.cache_get("webintel_scan", float("inf"))
    if not res:
        return ("No web-intel scan cached yet. Suggest the human runs `wrench cve` "
                "to query OSV.dev and endoflife.date.")
    import time as _t
    lines = [f"web-intel scan from {_t.strftime('%Y-%m-%d %H:%M', _t.localtime(res.get('ts', 0)))}"
             + (" (OFFLINE/cached)" if not res.get("online", True) else ""),
             f"packages checked: {res.get('packages_checked', 0)}"]
    vulns = res.get("vulns", [])
    if vulns:
        lines.append(f"known vulnerabilities ({len(vulns)}):")
        for v in vulns[:15]:
            cve = ",".join(v.get("aliases") or [v.get("vuln_id", "?")])
            fx = f" fixed in {v['fixed']}" if v.get("fixed") else ""
            lines.append(f"- {v['package']} {v['version']} ({v['source']}): {cve}"
                         f" sev={v.get('severity') or '?'}{fx} — {v.get('summary', '')[:120]}")
    else:
        lines.append("no known vulnerabilities in checked packages")
    eol = res.get("eol", [])
    if eol:
        lines.append("end-of-life status: " + "; ".join(e["label"] for e in eol))
    return "\n".join(lines)


# ---------------- tool registry (for the agent loop) ----------------

TOOL_SPECS = [
    {
        "name": "run_diag",
        "args": {"command": "string — one read-only diagnostic command (no pipes/chaining)"},
        "desc": "Run an allowlisted read-only shell diagnostic (systemctl status, journalctl, "
                "ss, df, du, ps, free, dmesg, docker ps, nvidia-smi, smartctl on Linux; "
                "launchctl, log show, vm_stat on macOS; tasklist, sc query, schtasks, netstat "
                "on Windows).",
    },
    {
        "name": "read_logs",
        "args": {"unit": "string (optional) — service/process name", "lines": "int (default 50)",
                 "priority": "string (optional) — e.g. 'err' or 'warning'"},
        "desc": "Read recent system logs (journald / macOS unified log / Windows event log), "
                "optionally scoped to one unit/process or minimum priority.",
    },
    {
        "name": "service_status",
        "args": {"unit": "string — service name"},
        "desc": "Get service status (systemctl on Linux, launchctl on macOS, sc on Windows).",
    },
    {
        "name": "disk_tree",
        "args": {"path": "string (default /)", "depth": "int 1-3 (default 1)"},
        "desc": "Show the largest directories under a path.",
    },
    {"name": "net_listeners", "args": {}, "desc": "List listening sockets with owning processes."},
    {
        "name": "proc_top",
        "args": {"sort": "'cpu' or 'mem'", "n": "int (default 15)"},
        "desc": "Top processes by CPU or memory.",
    },
    {
        "name": "security_intel",
        "args": {},
        "desc": "Cached web intelligence: known CVEs in installed packages (OSV.dev) and "
                "end-of-life status of the OS/kernel/python/node (endoflife.date). Instant, "
                "no network. If empty, suggest the human runs `wrench cve`.",
    },
    {
        "name": "remember",
        "args": {"text": "string — one self-contained sentence",
                 "kind": "preference | fact | procedure | lesson | observation"},
        "desc": "Keep a lasting note about this machine or how its operator wants things "
                "done, so future patrols and conversations start with it. Use it when the "
                "human states a preference or explains something you would otherwise "
                "re-discover. Never store secrets. Unattended, the note waits for review.",
    },
    {
        "name": "recall",
        "args": {"query": "string — words to look for"},
        "desc": "Search your memory of this machine and its operator.",
    },
    {
        "name": "schedule_task",
        "args": {"name": "string — short-kebab-name",
                 "schedule": "string — 'every 30m' | 'daily 08:30' | 'weekdays 9am' | "
                             "'in 2h' | 'at 2026-12-01 09:00' | cron",
                 "action": "patrol | brief | score | security | comply | backups | cve | "
                           "certs | drift | forecast | remind | ask",
                 "prompt": "string — for 'ask' the task, for 'remind' the reminder"},
        "desc": "Schedule recurring work or a one-off follow-up (e.g. check in 2h that a "
                "restart held). Offer this when the human would otherwise have to remember "
                "to come back. Unattended, it is only a proposal until the operator approves.",
    },
    {"name": "list_tasks", "args": {}, "desc": "List scheduled jobs and when they run next."},
    {
        "name": "fix_action",
        "args": {"command": "string — one allowlisted mutation (e.g. 'systemctl restart foo')"},
        "desc": "Execute a repair. Only works at repair/autonomous policy tiers; "
                "allowlisted commands only; may require human confirmation.",
    },
]


def dispatch(name: str, args: dict, store: Store, tier: str, confirm_fn=None,
             cfg=None) -> str:
    try:
        if name == "run_diag":
            return run_diag(store, str(args.get("command", "")))
        if name == "read_logs":
            return read_logs(
                store, str(args.get("unit", "")), int(args.get("lines", 50) or 50),
                str(args.get("priority", "")),
            )
        if name == "service_status":
            return service_status(store, str(args.get("unit", "")))
        if name == "disk_tree":
            return disk_tree(store, str(args.get("path", "/")), int(args.get("depth", 1) or 1))
        if name == "net_listeners":
            return net_listeners(store)
        if name == "proc_top":
            return proc_top(store, str(args.get("sort", "cpu")), int(args.get("n", 15) or 15))
        if name == "security_intel":
            return security_intel(store)
        if name == "fix_action":
            return fix_action(store, str(args.get("command", "")), tier, confirm_fn, cfg=cfg)
        if name == "remember":
            from . import memory
            return memory.tool_remember(store, cfg, str(args.get("text", "")),
                                        str(args.get("kind", "fact") or "fact"), confirm_fn)
        if name == "recall":
            from . import memory
            return memory.tool_recall(store, str(args.get("query", "")))
        if name == "schedule_task":
            from . import heartbeat
            return heartbeat.tool_schedule(
                store, cfg, str(args.get("name", "")), str(args.get("schedule", "")),
                str(args.get("action", "")), str(args.get("prompt", "") or ""), confirm_fn)
        if name == "list_tasks":
            from . import heartbeat
            return heartbeat.tool_jobs(store)
        return f"unknown tool: {name}"
    except Exception as e:  # noqa: BLE001
        return f"tool error: {e.__class__.__name__}: {e}"
