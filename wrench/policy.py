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

import os
import re
import shlex

from . import commands

TIERS = ("observe", "suggest", "repair", "autonomous")

# What each tier means, in the words shown to the operator (CLI + dashboard).
TIER_INFO = {
    "observe": ("Observer", "Looks only. Runs read-only diagnostics; proposes nothing, "
                            "changes nothing."),
    "suggest": ("Advisor", "Diagnoses and proposes the exact fix for you to run. "
                           "Never changes the machine itself."),
    "repair": ("Actor, with your OK", "May run fixes from the command catalog (restart services "
                                      "and containers, free disk space, install updates, repair "
                                      "the network, …) — each one only after you confirm it."),
    "autonomous": ("Actor, unattended", "Runs routine catalog fixes on its own, including during "
                                        "scheduled patrols. Higher-impact fixes (updates, killing "
                                        "a process, …) still wait for your yes. Maintenance "
                                        "windows still apply."),
}


def tier_rank(tier: str) -> int:
    return TIERS.index(tier) if tier in TIERS else TIERS.index("suggest")

# The allowlists themselves live in wrench/commands.py (the catalog). These two
# names remain as (pattern, label) views of it.
DIAG_ALLOWLIST: list[tuple[str, str]] = [(c.pattern, c.label) for c in commands.entries("diag")]
REPAIR_ALLOWLIST: list[tuple[str, str]] = [(c.pattern, c.label) for c in commands.entries("fix")]

# "Starting a unit" is not always a service restart: these units ARE the
# shutdown / reboot / rescue paths (or an unauthenticated root shell, an
# unattended upgrade, a relabel-and-reboot), so no lifecycle verb may touch
# them at any tier.
_NEVER_UNITS = re.compile(
    r"(?i)(^|[./-])(poweroff|reboot|halt|kexec|shutdown|emergency|rescue|suspend|hibernate|"
    r"hybrid-sleep|sleep|exit|ctrl-alt-del|debug-shell|initrd-switch-root|"
    r"systemd-(poweroff|reboot|halt|kexec|suspend|hibernate|hybrid-sleep|repart|"
    r"journal-gatewayd|journal-remote)|apt-daily(-upgrade)?|dnf-automatic[\w\-]*|packagekit|"
    r"selinux-autorelabel[\w\-]*|sendsigs|single|killall|killprocs|umount\w*|"
    r"remoteregistry|telnetd?|rsh|rexec|tftpd?)($|[.@-])", re.ASCII)
# Only real services are lifecycle targets — never targets, mounts or slices.
_UNIT_SUFFIX_DENY = (".target", ".mount", ".automount", ".slice", ".scope", ".swap",
                     ".device", ".path")
# Stopping or disabling these blinds the box or locks the operator out.
# Restart/reload stay allowed (that IS the repair). Matched on the unit name,
# on the last component of a launchd / reverse-DNS label, and as a substring
# for the vendors whose names vary.
_NO_STOP_UNITS = re.compile(
    r"(?i)^(ssh|sshd|auditd|firewalld|ufw|nftables|ip6?tables|ebtables|netfilter-persistent|"
    r"systemd-journald[\w\-]*|systemd-logind|systemd-networkd|systemd-resolved|systemd-udevd|"
    r"systemd-user-sessions|dbus|dbus-broker|networkmanager|networking|network|"
    r"wpa_supplicant|rsyslog|syslog|syslogd|syslog-ng|chronyd?|sssd|fail2ban|apparmor|"
    r"tailscaled|wg-quick@[\w\-]+|ifup@[\w\-]+|getty@[\w\-]+|user@\d+|"
    r"eventlog|windefend|wdnissvc|mpssvc|sense|rpcss|lanmanserver|lanmanworkstation|"
    r"termservice|wuauserv|bfe|winrm|dhcp|dnscache|netlogon|nsi|"
    r"wrench[\w.\-]*)$", re.ASCII)
_NO_STOP_ANYWHERE = re.compile(
    r"(?i)wrench|crowdstrike|falcon|sentinel|mdatp|defender|windefend|sysmon|carbonblack|"
    r"cbdefense|cylance|osquery|wazuh|auditbeat|auditd|crowdsec|openssh|sshd|syslog|journald",
    re.ASCII)
# Restarting these ends every login session on the machine.
_NO_RESTART_UNITS = re.compile(
    r"(?i)^(dbus|dbus-broker|display-manager|gdm\d?|sddm|lightdm|systemd-logind|user@\d+|"
    r"getty@[\w\-]+|com\.apple\.windowserver|windowserver|com\.apple\.loginwindow|loginwindow|"
    r"com\.apple\.launchd|launchd|com\.apple\.opendirectoryd|opendirectoryd|"
    r"com\.apple\.securityd|securityd)$", re.ASCII)

# Every shape of "do <verb> to <thing>" on the fix list → (verb, [targets]).
# Case-insensitive, because the Windows entries are: `SC STOP EventLog` must
# be caught too.
_F = re.I | re.ASCII
_LIFECYCLE_SHAPES = [re.compile(p, _F) for p in (
    r"systemctl (?:--user )?(?P<verb>[a-z\-]+)(?: --now)? (?P<unit>\S+)",
    r"service (?P<unit>\S+) (?P<verb>start|stop|restart|reload|force-reload)",
    r"launchctl (?P<verb>start|stop|kickstart|enable|disable)(?: -k)? (?P<unit>\S+)",
    r"brew services (?P<verb>start|stop|restart) (?P<unit>\S+)",
    r"(?:sc|net) (?P<verb>start|stop) (?P<unit>\S+)",
    r"sc config (?P<unit>\S+) start= (?P<verb>\S+)",
    r"(?:powershell|pwsh)(?:\.exe)? -NoProfile -Command (?P<verb>Restart|Start|Stop)-Service"
    r" -Name (?P<unit>\S+)(?: -Force)?",
    r"(?:supervisorctl|pm2) (?P<verb>restart|reload|start|stop) (?P<unit>\S+)",
    r"(?:docker|podman|nerdctl) (?P<verb>restart|start|stop|pause|unpause|kill) (?P<unit>.+)",
    r"schtasks /(?P<verb>Run|End) /TN (?P<unit>.+)",
    r"schtasks /Change /TN (?P<unit>.+) /(?P<verb>ENABLE|DISABLE)",
)]
_STOP_VERBS = {"stop", "disable", "disabled", "demand", "mask", "pause", "kill", "end"}
_RESTART_VERBS = {"restart", "try-restart", "reload-or-restart", "try-reload-or-restart",
                  "kickstart", "stop", "kill"}


def _lifecycle_target(command: str) -> tuple[str, list[str]] | None:
    """(verb, [targets]) for a lifecycle command, else None."""
    for rx in _LIFECYCLE_SHAPES:
        m = rx.fullmatch(command)
        if m:
            units = [u.strip("'\"") for u in m.group("unit").split()]
            return m.group("verb").lower(), units
    return None


def _bare(unit: str) -> list[str]:
    """Names a unit answers to: itself, without a launchd domain, without a
    .service/.socket/.timer suffix, and its last dotted component."""
    leaf = unit.rsplit("/", 1)[-1]
    base = re.sub(r"(?i)\.(service|socket|timer)$", "", leaf)
    return list(dict.fromkeys([unit, leaf, base, base.rsplit(".", 1)[-1]]))


def _unit_denied(command: str) -> str | None:
    """Reason a lifecycle command's target is off-limits, or None."""
    tgt = _lifecycle_target(command)
    if not tgt:
        return None
    verb, units = tgt
    if verb in ("daemon-reload", "reset-failed"):
        return None
    for unit in units:
        names = _bare(unit)
        if _NEVER_UNITS.search(unit):
            return f"unit {unit!r} is a shutdown/rescue/debug path — never a repair target"
        if unit.lower().endswith(_UNIT_SUFFIX_DENY):
            return f"only services may be started or stopped, not {unit!r}"
        if verb in _STOP_VERBS and (any(_NO_STOP_UNITS.match(n) for n in names)
                                    or _NO_STOP_ANYWHERE.search(unit)):
            return (f"refusing to {verb} {unit!r}: it is remote access, logging, a security "
                    "control, or wrench itself (restart it instead, or do it by hand)")
        if verb in _RESTART_VERBS and any(_NO_RESTART_UNITS.match(n) for n in names):
            return f"refusing to {verb} {unit!r}: that ends every login session on the machine"
    return None


_PID_SHAPES = [re.compile(p, re.I | re.ASCII) for p in (
    r"kill(?: -\w+)? (?P<pid>\d+)", r"taskkill /PID (?P<pid>\d+).*",
    r".* Stop-Process -Id (?P<pid>\d+).*")]


def _pid_denied(command: str) -> str | None:
    """wrench never signals init, itself, or the shell it was started from."""
    for rx in _PID_SHAPES:
        m = rx.fullmatch(command)
        if m:
            pid = int(m.group("pid"))
            if pid in (0, 1, os.getpid(), os.getppid()):
                return f"refusing to signal pid {pid}: it is init, or wrench itself"
    return None


# Things no tier may ever do (wrench is the sysadmin's right hand, not a loose
# cannon). Checked before the allowlists, and before an operator's own
# [policy] allow_diag / allow_fix entries — nothing overrides this list.
FORBIDDEN = [
    r"\brm\b", r"\bmkfs", r"\bdd\b", r"\bshred\b", r">\s*/dev/", r"\bchmod\b.*777",
    r"\bcurl\b.*\|\s*(ba)?sh", r"\bwget\b.*\|\s*(ba)?sh", r"\buserdel\b", r"\bpasswd\b",
    r"\biptables\b.*-F", r"\bshutdown\b", r"\breboot\b", r"\bhalt\b", r"\bkill\s+-9\s+1\b",
    r"\bchown\b.*-R\s*/\s*$", r"[;&|]{1,2}",  # no chaining — one command per action
    r"[`]|\$\(|\$\{",                         # no substitution, even though no shell runs
    # Windows / macOS dangerous surface
    r"(?i)\bformat\s+[a-z]:", r"(?i)\bdel\b.*/[sq]", r"(?i)\brmdir\b.*/s", r"(?i)remove-item",
    r"(?i)\bdiskpart\b", r"(?i)\breg\b\s+delete", r"(?i)\bbcdedit\b", r"(?i)\bcipher\b\s+/w",
    r"(?i)set-executionpolicy",
    r"(?i)\bdiskutil\s+(erase|partition|reformat|secureErase|zeroDisk|randomDisk|resetFusion)",
    r"(?i)\bdiskutil\s+(apfs|cs|appleRAID)\s+(delete|erase)",
    r"\bnvram\b", r"\bcsrutil\b(?!\s+(?:authenticated-root\s+)?status\s*$)",
    r"\blaunchctl\s+(bootout|remove)\s+system",
    # switching a protection off, or erasing the evidence, is never a repair
    r"(?i)\bwevtutil\s+cl\b", r"(?i)clear-eventlog", r"(?i)\bvssadmin\s+delete",
    r"(?i)\bwbadmin\s+delete", r"\bauditctl\s+-[De]\b", r"\bsetenforce\s+(0|permissive)",
    r"(?i)\bufw\s+(disable|reset)", r"(?i)advfirewall\s+set\s+\w+\s+state\s+off",
    r"(?i)\bmanage-bde\s+-(off|protectors\s+-(disable|delete))", r"\bfdesetup\s+disable",
    r"\bspctl\s+--(master|global)-disable", r"(?i)socketfilterfw\s+--setglobalstate\s+off",
    r"\bpfctl\s+-d\b", r"\btmutil\s+(delete|disable)\b", r"(?i)set-mppreference",
    r"(?i)\bhistory\s+-c\b", r"\bjournalctl\b.*--vacuum-time=\d+(s|m|min|h)\b",
    r"\bsoftwareupdate\b.*(\s-\w*R\w*(\s|$)|--restart)",   # an update may never reboot the box
]

_SUDO = "sudo -n "          # non-interactive only: it fails rather than prompt


class PolicyDecision:
    def __init__(self, allowed: bool, reason: str, needs_confirm: bool = False, label: str = "",
                 timeout: int = 30, pack: str = "", always_ask: bool = False):
        self.allowed = allowed
        self.reason = reason
        self.needs_confirm = needs_confirm
        self.label = label
        self.timeout = timeout
        self.pack = pack
        self.always_ask = always_ask

    def __repr__(self) -> str:  # pragma: no cover
        return f"PolicyDecision(allowed={self.allowed}, confirm={self.needs_confirm}, {self.reason})"


def settings(cfg) -> dict:
    """The operator's knobs under ``[policy]`` (beyond ``tier``).

    sudo            allow a ``sudo -n`` prefix on catalog commands (default on)
    disabled_packs  catalog packs to switch off entirely
    allow_diag      extra read-only commands, matched as EXACT strings
    allow_fix       extra fixes, matched as EXACT strings
    """
    raw = getattr(cfg, "raw", None)
    pol = raw.get("policy", {}) if isinstance(raw, dict) else {}
    if not isinstance(pol, dict):
        pol = {}

    def strs(key):
        v = pol.get(key, [])
        return [str(x).strip() for x in v if str(x).strip()] if isinstance(v, list) else []

    return {"sudo": bool(pol.get("sudo", True)),
            "disabled_packs": frozenset(x for x in strs("disabled_packs") if x in commands.PACKS),
            "allow_diag": strs("allow_diag"), "allow_fix": strs("allow_fix")}


def _prepare(command: str, cfg) -> tuple[str, dict, str | None]:
    """(command without a sudo prefix, settings, refusal-or-None)."""
    cmd = command.strip()
    st = settings(cfg)
    for pat in FORBIDDEN:
        if re.search(pat, cmd):
            return cmd, st, f"forbidden pattern: {pat}"
    if "\n" in cmd or "\r" in cmd or "\x00" in cmd:
        return cmd, st, "one command per action — no line breaks"
    if cmd.startswith("sudo "):
        if not cmd.startswith(_SUDO):
            return cmd, st, "only `sudo -n <command>` is accepted (never a prompt or other flags)"
        if not st["sudo"]:
            return cmd, st, "sudo is switched off ([policy] sudo = false)"
        cmd = cmd[len(_SUDO):].strip()
    return cmd, st, None


def _hint(command: str, kind: str) -> str:
    forms = commands.hints(command, kind)
    if not forms:
        return ""
    return " Allowed forms of this tool: " + " · ".join(f"`{f}`" for f in forms)


def check_diag(command: str, cfg=None) -> PolicyDecision:
    """Is this a permitted read-only diagnostic?"""
    cmd, st, refusal = _prepare(command, cfg)
    if refusal:
        return PolicyDecision(False, refusal)
    if ".." in cmd:
        # no diagnostic needs a parent-directory hop; refusing it outright means
        # no path pattern can be walked out of (/proc/sys/../../etc/shadow)
        return PolicyDecision(False, "path traversal ('..') is not allowed in diagnostics")
    hit = commands.match(cmd, "diag", st["disabled_packs"])
    if hit:
        return PolicyDecision(True, "read-only diagnostic", label=hit.label,
                              timeout=hit.timeout, pack=hit.pack)
    if cmd in st["allow_diag"] or command.strip() in st["allow_diag"]:
        return PolicyDecision(True, "read-only diagnostic (operator-added)",
                              label="operator-added diagnostic", timeout=60, pack="custom")
    off = commands.match(cmd, "diag")
    if off:
        return PolicyDecision(False, f"the '{off.pack}' command pack is switched off "
                                     "([policy] disabled_packs)", label=off.label, pack=off.pack)
    return PolicyDecision(False, "not on the read-only diagnostic allowlist."
                          + _hint(cmd, "diag"))


def check_repair(command: str, tier: str, cfg=None) -> PolicyDecision:
    """Is this mutation permitted at the current tier?"""
    cmd, st, refusal = _prepare(command, cfg)
    if refusal:
        return PolicyDecision(False, refusal)
    if ".." in cmd:
        return PolicyDecision(False, "path traversal ('..') is not allowed")
    hit = commands.match(cmd, "fix", st["disabled_packs"])
    if hit:
        label, timeout, pack, always = hit.label, hit.timeout, hit.pack, hit.ask
    elif cmd in st["allow_fix"] or command.strip() in st["allow_fix"]:
        label, timeout, pack, always = "operator-added fix", 300, "custom", False
    else:
        off = commands.match(cmd, "fix")
        if off:
            return PolicyDecision(False, f"the '{off.pack}' command pack is switched off "
                                         "([policy] disabled_packs)", label=off.label,
                                  pack=off.pack)
        return PolicyDecision(False, "not on the repair allowlist." + _hint(cmd, "fix"))
    denied = _unit_denied(cmd) or _pid_denied(cmd)
    if denied:
        return PolicyDecision(False, denied, label=label, pack=pack)
    if tier in ("observe", "suggest"):
        return PolicyDecision(
            False, f"policy tier '{tier}' does not permit mutations (suggest-only)",
            label=label, pack=pack)
    if tier == "repair" or (tier == "autonomous" and always):
        why = ("allowlisted; this kind of fix needs a person's yes every time" if always
               else "allowlisted; interactive confirmation required")
        return PolicyDecision(True, why, needs_confirm=True, label=label, timeout=timeout,
                              pack=pack, always_ask=always)
    if tier == "autonomous":
        return PolicyDecision(True, "allowlisted; autonomous tier", needs_confirm=False,
                              label=label, timeout=timeout, pack=pack)
    return PolicyDecision(False, f"unknown tier '{tier}'")


def split_command(command: str) -> list[str]:
    """shlex split for safe no-shell execution."""
    return shlex.split(command)
