"""Policy: what wrench is allowed to do, and how loudly it must ask first.

Tiers (ascending trust):
  observe    — look only. No suggested commands, no mutations, ever.
  suggest    — (default) diagnose & propose fixes. Never executes mutations.
  repair     — may execute ALLOWLISTED fixes after interactive confirmation.
  autonomous — may execute allowlisted fixes unattended. Explicit opt-in only.

Every mutation attempt — allowed, denied, or awaiting confirm — is logged to
the actions table and surfaces in `wrench web`.
"""

from __future__ import annotations

import re
import shlex

TIERS = ("observe", "suggest", "repair", "autonomous")

# Allowlisted mutation patterns for repair/autonomous tiers.
# Deliberately narrow: service lifecycle + journal vacuum + tmp cleanup.
REPAIR_ALLOWLIST: list[tuple[str, str]] = [
    (r"^systemctl (--user )?(restart|start|stop|reload) [\w@.\-]+$", "service lifecycle"),
    (r"^systemctl (--user )?reset-failed( [\w@.\-]+)?$", "clear failed state"),
    (r"^journalctl --vacuum-size=\d+[MG]$", "journal vacuum"),
    (r"^sync$", "fs sync"),
    # macOS
    (r"^launchctl (start|stop|kickstart -k) [\w./\-]+$", "service lifecycle (launchd)"),
    # Windows
    (r"^sc (start|stop) [\w.\-]+$", "service lifecycle (windows)"),
    (r"^net (start|stop) [\w.\- ]+$", "service lifecycle (windows)"),
]

# Commands the agent may run freely in ANY tier (read-only diagnostics).
DIAG_ALLOWLIST: list[tuple[str, str]] = [
    (r"^systemctl (--user )?status [\w@.\-]+( --no-pager)?( -n \d+)?$", "service status"),
    (r"^systemctl (--user )?list-units.*$", "unit listing"),
    (r"^systemctl (--user )?list-timers.*$", "timer listing"),
    (r"^systemctl (--user )?cat [\w@.\-]+$", "unit file"),
    (r"^journalctl .*$", "journal read"),
    (r"^ss -[tulnpaH]+.*$", "socket census"),
    (r"^df( -[hiT]+)?( [\w/.\-]+)?$", "disk free"),
    (r"^du -[a-z]* [\w/.\-~]+.*$", "disk usage"),
    (r"^free( -[hm])?$", "memory"),
    (r"^uptime$", "uptime"),
    (r"^ps aux.*$", "process list"),
    (r"^top -b -n ?1.*$", "top snapshot"),
    (r"^ip (addr|route|link)( show)?$", "network config"),
    (r"^cat /proc/[\w/]+$", "proc read"),
    (r"^cat /etc/(os-release|fstab|hostname|hosts)$", "system file read"),
    (r"^ls (-[a-zA-Z]+ )?[\w/.\-~]+$", "dir listing"),
    (r"^stat [\w/.\-~]+$", "file stat"),
    (r"^dmesg( --level=\w+(,\w+)*)?( \| tail.*)?$", "kernel log"),
    (r"^lsblk( -[a-zA-Z]+)?$", "block devices"),
    (r"^nvidia-smi( --query-gpu=[\w,.\-]+ --format=[\w,]+)?$", "gpu status"),
    (r"^docker (ps|stats --no-stream|logs --tail \d+ [\w\-]+|inspect [\w\-]+)( -a)?.*$", "docker read"),
    (r"^uname -[a-z]+$", "kernel info"),
    (r"^last( -n \d+)?$", "login history"),
    (r"^who$", "sessions"),
    (r"^crontab -l$", "user cron"),
    (r"^lsof -i( :\d+)?$", "open sockets"),
    (r"^smartctl -[aH] /dev/\w+$", "smart status"),
    (r"^sensors$", "temperatures"),
    # macOS diagnostics
    (r"^launchctl list( [\w./\-]+)?$", "launchd listing"),
    (r"^launchctl print [\w./\-]+$", "launchd unit detail"),
    (r"^log show --last \d+[smh]( --style \w+)?( --predicate .+)?$", "unified log read"),
    (r"^vm_stat$", "memory stats (macos)"),
    (r"^sysctl -n [\w.]+$", "kernel setting read"),
    (r"^diskutil (list|info [\w/]+)$", "disk info (macos)"),
    (r"^sw_vers$", "macos version"),
    (r"^top -l 1.*$", "top snapshot (macos)"),
    # Windows diagnostics
    (r"^tasklist( /V)?$", "process list (windows)"),
    (r"^sc query( [\w.\-]+)?$", "service query (windows)"),
    (r"^schtasks /Query.*$", "scheduled tasks (windows)"),
    (r"^netstat -ano$", "socket census (windows)"),
    (r"^wevtutil qe \w+( /c:\d+)?( /rd:true)?( /f:text)?( /q:.+)?$", "event log read"),
    (r"^systeminfo$", "system info (windows)"),
    (r"^wmic (logicaldisk|cpu|os) get [\w,]+$", "wmi read"),
]

# Things no tier may ever do (wrench is a sysadmin, not a loose cannon).
FORBIDDEN = [
    r"\brm\b", r"\bmkfs", r"\bdd\b", r"\bshred\b", r">\s*/dev/", r"\bchmod\b.*777",
    r"\bcurl\b.*\|\s*(ba)?sh", r"\bwget\b.*\|\s*(ba)?sh", r"\buserdel\b", r"\bpasswd\b",
    r"\biptables\b.*-F", r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bkill\s+-9\s+1\b",
    r"\bchown\b.*-R\s*/\s*$", r"[;&|]{1,2}",  # no chaining — one command per action
    # Windows / macOS dangerous surface
    r"(?i)\bformat\s+[a-z]:", r"(?i)\bdel\b.*/[sq]", r"(?i)\brmdir\b.*/s", r"(?i)remove-item",
    r"(?i)\bdiskpart\b", r"(?i)\breg\b\s+delete", r"(?i)\bbcdedit\b", r"(?i)\bcipher\b\s+/w",
    r"(?i)set-executionpolicy", r"\bdiskutil\s+(erase|partition|reformat)",
    r"\bnvram\b", r"\bcsrutil\b", r"\blaunchctl\s+(bootout|remove)\s+system",
]


class PolicyDecision:
    def __init__(self, allowed: bool, reason: str, needs_confirm: bool = False, label: str = ""):
        self.allowed = allowed
        self.reason = reason
        self.needs_confirm = needs_confirm
        self.label = label

    def __repr__(self) -> str:  # pragma: no cover
        return f"PolicyDecision(allowed={self.allowed}, confirm={self.needs_confirm}, {self.reason})"


def _matches(command: str, patterns: list[tuple[str, str]]) -> str | None:
    for pat, label in patterns:
        if re.match(pat, command.strip()):
            return label
    return None


def check_diag(command: str) -> PolicyDecision:
    """Is this a permitted read-only diagnostic?"""
    cmd = command.strip()
    for pat in FORBIDDEN:
        if re.search(pat, cmd):
            return PolicyDecision(False, f"forbidden pattern: {pat}")
    label = _matches(cmd, DIAG_ALLOWLIST)
    if label:
        return PolicyDecision(True, "read-only diagnostic", label=label)
    return PolicyDecision(False, "not on the read-only diagnostic allowlist")


def check_repair(command: str, tier: str) -> PolicyDecision:
    """Is this mutation permitted at the current tier?"""
    cmd = command.strip()
    for pat in FORBIDDEN:
        if re.search(pat, cmd):
            return PolicyDecision(False, f"forbidden pattern: {pat}")
    label = _matches(cmd, REPAIR_ALLOWLIST)
    if not label:
        return PolicyDecision(False, "not on the repair allowlist")
    if tier in ("observe", "suggest"):
        return PolicyDecision(
            False, f"policy tier '{tier}' does not permit mutations (suggest-only)", label=label
        )
    if tier == "repair":
        return PolicyDecision(True, "allowlisted; interactive confirmation required",
                              needs_confirm=True, label=label)
    if tier == "autonomous":
        return PolicyDecision(True, "allowlisted; autonomous tier", needs_confirm=False, label=label)
    return PolicyDecision(False, f"unknown tier '{tier}'")


def split_command(command: str) -> list[str]:
    """shlex split for safe no-shell execution."""
    return shlex.split(command)
