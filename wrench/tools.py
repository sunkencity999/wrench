"""Agent tools: the hands wrench is allowed to use.

All execution is no-shell (shlex + subprocess list argv), policy-checked,
time-bounded, and logged. Read-only diagnostics are allowlisted; mutations go
through policy.check_repair and the actions log.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from . import policy
from .store import Store

MAX_OUTPUT = 8000  # chars returned to the model per tool call


def _clip(text: str, n: int = MAX_OUTPUT) -> str:
    if len(text) <= n:
        return text
    return text[: n // 2] + f"\n...[{len(text) - n} chars clipped]...\n" + text[-n // 2 :]


def _exec(argv: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout or "") + (("\n[stderr] " + r.stderr) if r.stderr.strip() else "")
        return _clip(out.strip() or f"(exit {r.returncode}, no output)")
    except subprocess.TimeoutExpired:
        return f"(timed out after {timeout}s)"
    except FileNotFoundError:
        return f"(command not found: {argv[0]})"
    except Exception as e:  # noqa: BLE001
        return f"(error: {e.__class__.__name__}: {e})"


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
    """Read recent journal lines, optionally for one unit / min priority."""
    lines = max(1, min(int(lines), 500))
    argv = ["journalctl", "--no-pager", "-n", str(lines)]
    if unit:
        # try system unit first, fall back to user units
        probe = _exec(["journalctl", "--no-pager", "-n", str(lines), "-u", unit], timeout=20)
        if "-- No entries --" in probe or not probe.strip():
            probe = _exec(
                ["journalctl", "--user", "--no-pager", "-n", str(lines), "-u", unit], timeout=20
            )
        store.add_action("any", "diag:journal", f"journalctl -u {unit} -n {lines}", True, "")
        return probe
    if priority:
        argv += ["-p", priority]
    out = _exec(argv, timeout=20)
    store.add_action("any", "diag:journal", " ".join(argv), True, "")
    return out


def service_status(store: Store, unit: str) -> str:
    """systemctl status for a unit (system scope, then user scope)."""
    out = _exec(["systemctl", "status", unit, "--no-pager", "-n", "10"])
    if "could not be found" in out or "Unit" in out and "not found" in out:
        out_user = _exec(["systemctl", "--user", "status", unit, "--no-pager", "-n", "10"])
        if "could not be found" not in out_user:
            out = "[user scope]\n" + out_user
    store.add_action("any", "diag:service", f"systemctl status {unit}", True, "")
    return out


def disk_tree(store: Store, path: str = "/", depth: int = 1) -> str:
    """Largest directories under a path (du, bounded)."""
    p = str(Path(path).expanduser())
    depth = max(1, min(int(depth), 3))
    out = _exec(["du", "-x", "-h", f"--max-depth={depth}", p], timeout=60)
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


def net_listeners(store: Store) -> str:
    """Listening sockets with owning processes."""
    out = _exec(["ss", "-tulnpH"])
    store.add_action("any", "diag:net", "ss -tulnpH", True, "")
    return out


def proc_top(store: Store, sort: str = "cpu", n: int = 15) -> str:
    """Top processes by cpu or mem."""
    key = "-pcpu" if sort != "mem" else "-pmem"
    out = _exec(["ps", "aux", f"--sort={key}"], timeout=15)
    lines = out.splitlines()[: int(n) + 1]
    store.add_action("any", "diag:proc", f"ps aux --sort={key}", True, "")
    return "\n".join(lines)


def fix_action(store: Store, command: str, tier: str, confirm_fn=None) -> str:
    """Attempt a mutation. Policy-gated, confirm-gated, always logged."""
    decision = policy.check_repair(command, tier)
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
        if not confirm_fn(command, decision.label):
            store.add_action(tier, "fix-declined", command, False, "human declined")
            return "DECLINED: the human said no. Do not retry this action."
    out = _exec(policy.split_command(command), timeout=60)
    store.add_action(tier, f"fix:{decision.label}", command, True, out[:1000])
    return f"EXECUTED ({decision.label}):\n{out}"


# ---------------- tool registry (for the agent loop) ----------------

TOOL_SPECS = [
    {
        "name": "run_diag",
        "args": {"command": "string — one read-only diagnostic command (no pipes/chaining)"},
        "desc": "Run an allowlisted read-only shell diagnostic (systemctl status, journalctl, ss, df, du, ps, free, dmesg, docker ps, nvidia-smi, smartctl...).",
    },
    {
        "name": "read_logs",
        "args": {"unit": "string (optional) — systemd unit", "lines": "int (default 50)",
                 "priority": "string (optional) — e.g. 'err' or 'warning'"},
        "desc": "Read recent journald lines, optionally scoped to one unit or minimum priority.",
    },
    {
        "name": "service_status",
        "args": {"unit": "string — systemd unit name"},
        "desc": "Get systemctl status for a unit (checks system then user scope).",
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
        "name": "fix_action",
        "args": {"command": "string — one allowlisted mutation (e.g. 'systemctl restart foo')"},
        "desc": "Execute a repair. Only works at repair/autonomous policy tiers; "
                "allowlisted commands only; may require human confirmation.",
    },
]


def dispatch(name: str, args: dict, store: Store, tier: str, confirm_fn=None) -> str:
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
        if name == "fix_action":
            return fix_action(store, str(args.get("command", "")), tier, confirm_fn)
        return f"unknown tool: {name}"
    except Exception as e:  # noqa: BLE001
        return f"tool error: {e.__class__.__name__}: {e}"
