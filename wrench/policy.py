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

# What each tier means, in the words shown to the operator (CLI + dashboard).
TIER_INFO = {
    "observe": ("Observer", "Looks only. Runs read-only diagnostics; proposes nothing, "
                            "changes nothing."),
    "suggest": ("Advisor", "Diagnoses and proposes the exact fix for you to run. "
                           "Never changes the machine itself."),
    "repair": ("Actor, with your OK", "May run allowlisted fixes (restart / start a service, "
                                      "trim the journal) — each one only after you confirm it."),
    "autonomous": ("Actor, unattended", "Runs allowlisted fixes on its own, including during "
                                        "scheduled patrols. Maintenance windows still apply."),
}


def tier_rank(tier: str) -> int:
    return TIERS.index(tier) if tier in TIERS else TIERS.index("suggest")

# A unit / service name: never starts with "-" (so it can never be read as an
# option, e.g. `systemctl status -Hroot@evil`).
_UNIT = r"[\w@][\w@.\-]*"
# A filesystem path argument: absolute or ~-relative, never an option.
# No spaces: a space would let a second token ("/ -R") ride in as an option.
_PATH = r"[/~][\w/.\-~+]*"

# Allowlisted mutation patterns for repair/autonomous tiers.
# Deliberately narrow: service lifecycle + journal vacuum. Matched with
# re.fullmatch — nothing may trail an allowed command.
REPAIR_ALLOWLIST: list[tuple[str, str]] = [
    (rf"systemctl (--user )?(restart|start|stop|reload) {_UNIT}", "service lifecycle"),
    (rf"systemctl (--user )?reset-failed( {_UNIT})?", "clear failed state"),
    (r"journalctl --vacuum-size=\d+[MG]", "journal vacuum"),
    (r"sync", "fs sync"),
    # macOS
    (r"launchctl (start|stop|kickstart -k) [\w][\w./\-]*", "service lifecycle (launchd)"),
    # Windows
    (r"sc (start|stop) [\w][\w.\-]*", "service lifecycle (windows)"),
    (r"net (start|stop) [\w][\w.\-]*", "service lifecycle (windows)"),
]

# "Starting a unit" is not always a service restart: these units ARE the
# shutdown / reboot / rescue paths (or an unauthenticated root shell), so no
# lifecycle verb may touch them at any tier.
_NEVER_UNITS = re.compile(
    r"(?i)(^|[./-])(poweroff|reboot|halt|kexec|shutdown|emergency|rescue|suspend|hibernate|"
    r"hybrid-sleep|sleep|exit|ctrl-alt-del|debug-shell|initrd-switch-root|"
    r"systemd-(poweroff|reboot|halt|kexec|suspend|hibernate|hybrid-sleep))($|[.@-])")
# Only real services are lifecycle targets — never targets, mounts or slices.
_UNIT_SUFFIX_DENY = (".target", ".mount", ".automount", ".slice", ".scope", ".swap",
                     ".device", ".path")
# Stopping these blinds the box or locks the operator out. Restart/reload stay
# allowed (that IS the repair); stop does not.
_NO_STOP_UNITS = re.compile(
    r"(?i)^(ssh|sshd|com\.openssh\.sshd|auditd|firewalld|ufw|nftables|iptables|"
    r"systemd-journald|systemd-logind|systemd-networkd|systemd-resolved|systemd-udevd|"
    r"dbus|dbus-broker|networkmanager|networking|rsyslog|syslog-ng|chronyd?|"
    r"falcon-sensor|osqueryd|wazuh-agent|auditbeat|sssd|"
    r"eventlog|windefend|mpssvc|sense|rpcss|lanmanserver|termservice|wuauserv|"
    r"wrench[\w.\-]*)(\.service|\.socket)?$")


def _lifecycle_target(command: str) -> tuple[str, str] | None:
    """(verb, unit) for a service-lifecycle command, else None."""
    m = re.fullmatch(
        r"(?:systemctl (?:--user )?|launchctl |sc |net )"
        r"(restart|start|stop|reload|kickstart -k) (.+)", command)
    return (m.group(1), m.group(2).strip()) if m else None


def _unit_denied(command: str) -> str | None:
    """Reason a lifecycle command's target is off-limits, or None."""
    tgt = _lifecycle_target(command)
    if not tgt:
        return None
    verb, unit = tgt
    if _NEVER_UNITS.search(unit):
        return f"unit {unit!r} is a shutdown/rescue/debug path — never a repair target"
    if unit.lower().endswith(_UNIT_SUFFIX_DENY):
        return f"only services may be started or stopped, not {unit!r}"
    # launchd targets can be domain-qualified (system/com.openssh.sshd) — the
    # protected name is the last path component
    leaf = unit.rsplit("/", 1)[-1]
    if verb == "stop" and (_NO_STOP_UNITS.match(unit) or _NO_STOP_UNITS.match(leaf)):
        return (f"refusing to stop {unit!r}: it is remote access, logging, or a "
                "security control (restart it instead, or do it by hand)")
    return None


# Commands the agent may run freely in ANY tier (read-only diagnostics).
# Every pattern is matched with re.fullmatch and spells out its flags: an
# allowlist that ends in ".*" is not an allowlist (`journalctl --vacuum-time=1s`,
# `ss -D /etc/shadow`, `ps auxe` all rode in on one).
_N = r"\d{1,6}"
_WHEN = r"(?:'[\w :.\-+]+'|\"[\w :.\-+]+\"|[\w:.\-+]+)"
_PROC_FILES = (r"(meminfo|loadavg|cpuinfo|uptime|version|mounts|swaps|diskstats|vmstat|stat|"
               r"mdstat|interrupts|buddyinfo|partitions|filesystems|cmdline|zoneinfo|slabinfo|"
               r"net/dev|pressure/(cpu|memory|io)|sys/[\w\-]+(?:/[\w\-]+)*)")
DIAG_ALLOWLIST: list[tuple[str, str]] = [
    (rf"systemctl (--user )?status {_UNIT}(?: (?:--no-pager|-l|--full|-n {_N}))*", "service status"),
    (r"systemctl (--user )?list-units"
     r"(?: (?:--failed|--all|--no-pager|--no-legend|--plain|--type=[\w,]+|--state=[\w,\-]+))*",
     "unit listing"),
    (r"systemctl (--user )?list-timers(?: (?:--all|--no-pager|--no-legend))*", "timer listing"),
    (r"systemctl (--user )?(--failed|is-system-running)( --no-pager)?", "unit listing"),
    (rf"systemctl (--user )?(cat|is-active|is-enabled|is-failed|show) {_UNIT}( --no-pager)?",
     "unit file"),
    (r"journalctl"
     rf"(?: (?:--no-pager|--user|--system|--dmesg|-[kbxeraq]+|--utc|--disk-usage|--list-boots"
     rf"|-n {_N}|--lines={_N}|-u {_UNIT}|--unit={_UNIT}|-t [\w.\-]+|-p [\w.]+|--priority=[\w.]+"
     rf"|-o [\w\-]+|--output=[\w\-]+|-b -?\d+|-g (?:'[^'\\]+'|[\w.]+)|_PID=\d+|_UID=\d+"
     rf"|-S {_WHEN}|-U {_WHEN}|--since[= ]{_WHEN}|--until[= ]{_WHEN}))*",
     "journal read"),
    (r"ss(?: -[tulnpaHes46]+)+", "socket census"),
    (r"df( -[hiTlP]+)?( " + _PATH + r")?", "disk free"),
    (rf"du -[a-zA-Z]+(?: (?:--max-depth={_N}|-d ?{_N}))? {_PATH}", "disk usage"),
    (r"free( -[hmgw]+)?", "memory"),
    (r"uptime", "uptime"),
    # no "e" (environment) flag: process environments carry secrets
    (r"ps (aux|auxww|-ef|-eo [\w,%=]+)( --sort=-?%?\w+)?", "process list"),
    (rf"top (?:-b -n ?1|-bn ?1)(?: (?:-o [%\w]+|-w {_N}|-c))*", "top snapshot"),
    (r"ip (-[46s] )?(addr|route|link|neigh)( show)?", "network config"),
    (r"cat /proc/" + _PROC_FILES, "proc read"),
    (r"cat /etc/(os-release|fstab|hostname|hosts|resolv\.conf|timezone)", "system file read"),
    (r"ls(?: -[alhtrSd1F]+)?(?: " + _PATH + r")?", "dir listing"),
    (r"stat " + _PATH, "file stat"),
    (r"dmesg(?: (?:--level=\w+(,\w+)*|-T|-H|--ctime|--kernel|-k))*", "kernel log"),
    (r"lsblk( -[a-zA-Z]+)?", "block devices"),
    (r"nvidia-smi( --query-gpu=[\w,.\-]+ --format=[\w,]+)?", "gpu status"),
    (r"docker ps(?: (?:-a|--all|-q|--no-trunc|-n \d+))*", "docker read"),
    (r"docker stats --no-stream(?: (?:-a|--no-trunc))*", "docker read"),
    (rf"docker logs --tail {_N}( --timestamps)? [\w][\w.\-]*", "docker read"),
    # full `docker inspect` dumps Config.Env (secrets); allow only safe projections
    (r"docker inspect (-f|--format) '\{\{json \.(State|RestartCount|HostConfig\.RestartPolicy|"
     r"NetworkSettings\.Ports|Mounts)\}\}' [\w][\w.\-]*", "docker read"),
    (r"uname -[a-z]+", "kernel info"),
    (rf"last( -n {_N})?", "login history"),
    (r"who( -[abH]+)?", "sessions"),
    (r"crontab -l", "user cron"),
    (r"lsof -i( :\d+)?( -[nP]+)?", "open sockets"),
    (r"lsof -nP -iTCP -sTCP:LISTEN", "open sockets"),
    (r"smartctl -[aHi] /dev/\w+", "smart status"),
    (r"sensors", "temperatures"),
    # macOS diagnostics
    (r"launchctl list( [\w][\w./\-]*)?", "launchd listing"),
    (r"launchctl print [\w][\w./\-]*", "launchd unit detail"),
    (r"log show --last \d+[smh]( --style \w+)?( --predicate (?:'[^']+'|\"[^\"]+\"))?",
     "unified log read"),
    (r"vm_stat", "memory stats (macos)"),
    (r"sysctl -n [\w.]+", "kernel setting read"),
    (r"diskutil (list|info [\w/]+|apfs list)", "disk info (macos)"),
    (r"sw_vers", "macos version"),
    (rf"top -l 1(?: (?:-n {_N}|-o \w+|-stats [\w,]+))*", "top snapshot (macos)"),
    (r"pmset -g( (batt|therm|assertions))?", "power state (macos)"),
    (r"softwareupdate (-l|--list)", "pending updates (macos)"),
    (r"tmutil (latestbackup|destinationinfo|listbackups)", "time machine (macos)"),
    (r"fdesetup status", "disk encryption (macos)"),
    (r"spctl --status", "gatekeeper (macos)"),
    # Windows diagnostics
    (r"tasklist( /V)?", "process list (windows)"),
    (r"sc query( [\w][\w.\-]*)?", "service query (windows)"),
    (r"schtasks /Query(?: (?:/FO (?:CSV|LIST|TABLE)|/V|/NH|/TN [\w\\\\. \-]+))*",
     "scheduled tasks (windows)"),
    (r"netstat -ano", "socket census (windows)"),
    (r"wevtutil qe \w+( /c:\d+)?( /rd:true)?( /f:text)?( /q:[^/]+)?", "event log read"),
    (r"systeminfo", "system info (windows)"),
    (r"wmic (logicaldisk|cpu|os) get [\w,]+", "wmi read"),
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
    cmd = command.strip()
    if "\n" in cmd or "\r" in cmd or "\x00" in cmd:
        return None
    for pat, label in patterns:
        if re.fullmatch(pat, cmd):
            return label
    return None


def check_diag(command: str) -> PolicyDecision:
    """Is this a permitted read-only diagnostic?"""
    cmd = command.strip()
    for pat in FORBIDDEN:
        if re.search(pat, cmd):
            return PolicyDecision(False, f"forbidden pattern: {pat}")
    if ".." in cmd:
        # no diagnostic needs a parent-directory hop; refusing it outright means
        # no path pattern can be walked out of (/proc/sys/../../etc/shadow)
        return PolicyDecision(False, "path traversal ('..') is not allowed in diagnostics")
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
    denied = _unit_denied(cmd)
    if denied:
        return PolicyDecision(False, denied, label=label)
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
