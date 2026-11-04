"""wrench fixxer — the hands, finally.

Scans the box for programmatically correctable issues and (with consent)
corrects them. The safety architecture, in one paragraph:

    The LLM NEVER writes the commands. Every fix lives in a hand-written,
    parameterized action catalog below (CATALOG). Detection is code, the
    command is code, verification is code. The model's job is to EXPLAIN the
    findings and help the human choose — it picks FROM the catalog, it never
    adds to it. Auto mode additionally requires an explicit, recorded consent
    ceremony, applies only consented risk tiers (default: safe only), and
    writes every action to an append-only audit log.

Risk tiers:
    safe     — reversible-or-trivial housekeeping (refresh package lists,
               vacuum journal logs, clear package caches, reset stale
               failed-unit markers).
    moderate — changes real state but in well-understood ways (apply pending
               package updates, remove orphaned packages, restart failed
               services, delete stale /tmp files).
    risky    — reserved for actions that can change system behavior in ways
               that need a human in the loop. Never auto-applied unless
               explicitly consented AND explicitly configured.
"""

from __future__ import annotations

import json
import os
import platform as _platform
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import platforms

RISK_TIERS = ("safe", "moderate", "risky")
RISK_ORDER = {"safe": 0, "moderate": 1, "risky": 2}

CONSENT_FILENAME = "fixxer_consent.json"
AUDIT_FILENAME = "fixxer_audit.jsonl"


# ---------------- subprocess seam (tests monkeypatch this) ----------------

def _run(argv: list[str], timeout: int = 300, env_extra: dict | None = None) -> tuple[int, str]:
    """Run argv with no shell. Returns (exit_code, combined_output)."""
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
        out = (r.stdout or "") + (("\n[stderr] " + r.stderr.strip()) if r.stderr.strip() else "")
        return r.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return 124, f"(timed out after {timeout}s)"
    except FileNotFoundError:
        return 127, f"(command not found: {argv[0]})"
    except Exception as e:  # noqa: BLE001
        return 1, f"(error: {e.__class__.__name__}: {e})"


def _sudo_prefix(non_interactive: bool) -> list[str]:
    """How to elevate on this platform. Empty when already root or no sudo."""
    if platforms.is_windows():
        return []
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    if shutil.which("sudo"):
        # -n in auto mode: fail cleanly instead of hanging on a password prompt.
        return ["sudo", "-n"] if non_interactive else ["sudo"]
    return []


# ---------------- data model ----------------

@dataclass
class Finding:
    """One detected, correctable issue, bound to a catalog action."""
    action_id: str
    title: str
    risk: str
    detail: str                                  # human-readable evidence
    commands: list[list[str]] = field(default_factory=list)  # hand-written argv
    needs_sudo: bool = False
    rollback_hint: str = ""
    env_extra: dict = field(default_factory=dict)


@dataclass
class ApplyResult:
    finding: Finding
    ok: bool
    output: str
    verified: bool
    verify_note: str
    duration_s: float


@dataclass
class ActionSpec:
    id: str
    title: str
    risk: str
    detect: Callable[[dict], Finding | None]     # ctx -> Finding | None
    verify: Callable[[dict, Finding], tuple[bool, str]]
    platforms: tuple[str, ...] = ("linux", "macos", "windows")


# ---------------- package manager detection ----------------

def pkg_manager() -> str | None:
    plat = platforms.current_platform()
    if plat == "linux":
        for mgr in ("apt-get", "dnf", "pacman"):
            if shutil.which(mgr):
                return {"apt-get": "apt"}.get(mgr, mgr)
    if plat == "macos" and shutil.which("brew"):
        return "brew"
    if plat == "windows" and shutil.which("winget"):
        return "winget"
    return None


def _fixxer_cfg(cfg) -> dict:
    raw = getattr(cfg, "raw", {}) or {}
    sec = raw.get("fixxer", {})
    return sec if isinstance(sec, dict) else {}


# ---------------- detectors / verifiers ----------------
# Every command below is HAND-WRITTEN. Parameters are values measured from the
# system itself (unit names, sizes) — never model output.

def _detect_pkg_refresh(ctx: dict) -> Finding | None:
    mgr = ctx["pkg_manager"]
    age_h = None
    if mgr == "apt":
        lists = Path("/var/lib/apt/lists")
        if lists.exists():
            try:
                newest = max((f.stat().st_mtime for f in lists.iterdir()), default=0)
                age_h = (time.time() - newest) / 3600
            except OSError:
                age_h = None
        if age_h is not None and age_h < 24:
            return None
        return Finding(
            "pkg_refresh", "Refresh package metadata", "safe",
            f"apt package lists are {age_h:.0f}h old" if age_h else
            "apt package list age unknown — refresh to get current update info",
            commands=[["apt-get", "update"]], needs_sudo=True,
            rollback_hint="none needed (metadata only)")
    if mgr == "dnf":
        return Finding("pkg_refresh", "Refresh package metadata", "safe",
                       "refresh dnf metadata cache",
                       commands=[["dnf", "makecache", "--refresh", "-q"]], needs_sudo=True,
                       rollback_hint="none needed (metadata only)")
    if mgr == "brew":
        return Finding("pkg_refresh", "Refresh package metadata", "safe",
                       "refresh Homebrew formulae index",
                       commands=[["brew", "update"]], needs_sudo=False,
                       rollback_hint="none needed (metadata only)")
    return None


def _verify_pkg_refresh(ctx: dict, f: Finding) -> tuple[bool, str]:
    if ctx["pkg_manager"] == "apt":
        lists = Path("/var/lib/apt/lists")
        try:
            newest = max((x.stat().st_mtime for x in lists.iterdir()), default=0)
            if time.time() - newest < 600:
                return True, "package lists are fresh"
        except OSError:
            pass
        return False, "package lists still look stale"
    return True, "refresh command exited 0"


def _apt_upgradable() -> tuple[int, int, str]:
    """(total, security, sample) pending upgrades from a simulation (no sudo)."""
    code, out = _run(["apt-get", "-s", "upgrade"], timeout=120)
    if code != 0:
        return 0, 0, ""
    pkgs = [ln.split()[1] for ln in out.splitlines() if ln.startswith("Inst ")]
    sec = sum(1 for ln in out.splitlines() if ln.startswith("Inst ") and "-security" in ln)
    return len(pkgs), sec, ", ".join(pkgs[:6]) + ("…" if len(pkgs) > 6 else "")


def _detect_pkg_upgrade(ctx: dict) -> Finding | None:
    mgr = ctx["pkg_manager"]
    if mgr == "apt":
        total, sec, sample = _apt_upgradable()
        if total == 0:
            return None
        return Finding(
            "pkg_upgrade", "Apply pending package updates", "moderate",
            f"{total} packages upgradable ({sec} security): {sample}",
            commands=[["apt-get", "upgrade", "-y"]], needs_sudo=True,
            env_extra={"DEBIAN_FRONTEND": "noninteractive"},
            rollback_hint="apt rollbacks: /var/log/apt/history.log records versions; "
                          "`apt-get install pkg=old-version` reverts one package")
    if mgr == "dnf":
        code, out = _run(["dnf", "check-update", "-q"], timeout=180)
        if code != 100:  # 100 = updates available
            return None
        n = len([ln for ln in out.splitlines() if ln.strip() and not ln.startswith(" ")])
        return Finding("pkg_upgrade", "Apply pending package updates", "moderate",
                       f"~{n} packages upgradable (dnf check-update)",
                       commands=[["dnf", "upgrade", "-y"]], needs_sudo=True,
                       rollback_hint="`dnf history undo last`")
    if mgr == "pacman":
        code, out = _run(["pacman", "-Qu"], timeout=60)
        if code != 0 or not out.strip():
            return None
        n = len(out.strip().splitlines())
        return Finding("pkg_upgrade", "Apply pending package updates", "moderate",
                       f"{n} packages upgradable (pacman -Qu)",
                       commands=[["pacman", "-Syu", "--noconfirm"]], needs_sudo=True,
                       rollback_hint="pacman cache keeps old versions: "
                                     "`pacman -U /var/cache/pacman/pkg/<old>.pkg.tar.zst`")
    if mgr == "brew":
        code, out = _run(["brew", "outdated"], timeout=120)
        if code != 0 or not out.strip():
            return None
        n = len(out.strip().splitlines())
        return Finding("pkg_upgrade", "Apply pending package updates", "moderate",
                       f"{n} formulae outdated (brew outdated)",
                       commands=[["brew", "upgrade"]], needs_sudo=False,
                       rollback_hint="`brew switch <formula> <old-version>` where kept")
    if mgr == "winget":
        return Finding("pkg_upgrade", "Apply pending package updates", "moderate",
                       "check & apply pending winget upgrades",
                       commands=[["winget", "upgrade", "--all", "--silent",
                                  "--accept-package-agreements", "--accept-source-agreements"]],
                       needs_sudo=False,
                       rollback_hint="winget keeps no rollback; reinstall old version manually")
    return None


def _verify_pkg_upgrade(ctx: dict, f: Finding) -> tuple[bool, str]:
    if ctx["pkg_manager"] == "apt":
        total, _sec, _ = _apt_upgradable()
        return (total == 0), (f"{total} packages still pending" if total else "no pending upgrades remain")
    return True, "upgrade command exited 0"


def _detect_pkg_autoremove(ctx: dict) -> Finding | None:
    mgr = ctx["pkg_manager"]
    if mgr == "apt":
        code, out = _run(["apt-get", "-s", "autoremove"], timeout=120)
        if code != 0:
            return None
        pkgs = [ln.split()[1] for ln in out.splitlines() if ln.startswith("Remv ")]
        if not pkgs:
            return None
        kernels = [p for p in pkgs if p.startswith(("linux-image", "linux-headers", "linux-modules"))]
        detail = f"{len(pkgs)} orphaned packages removable: " + ", ".join(pkgs[:6]) + \
                 ("…" if len(pkgs) > 6 else "")
        if kernels:
            detail += f" (includes {len(kernels)} old kernel packages)"
        return Finding("pkg_autoremove", "Remove orphaned packages" +
                       (" & old kernels" if kernels else ""), "moderate", detail,
                       commands=[["apt-get", "autoremove", "--purge", "-y"]], needs_sudo=True,
                       env_extra={"DEBIAN_FRONTEND": "noninteractive"},
                       rollback_hint="`apt-get install <pkg>` reinstalls; "
                                     "removed list is in /var/log/apt/history.log")
    if mgr == "pacman":
        code, out = _run(["pacman", "-Qtdq"], timeout=60)
        orphans = [p for p in out.strip().splitlines() if p.strip()] if code == 0 else []
        if not orphans:
            return None
        return Finding("pkg_autoremove", "Remove orphaned packages", "moderate",
                       f"{len(orphans)} orphans: " + ", ".join(orphans[:6]) +
                       ("…" if len(orphans) > 6 else ""),
                       commands=[["pacman", "-Rns", "--noconfirm", *orphans]], needs_sudo=True,
                       rollback_hint="`pacman -S <pkg>` reinstalls")
    return None


def _verify_pkg_autoremove(ctx: dict, f: Finding) -> tuple[bool, str]:
    if ctx["pkg_manager"] == "apt":
        code, out = _run(["apt-get", "-s", "autoremove"], timeout=120)
        left = [ln for ln in out.splitlines() if ln.startswith("Remv ")] if code == 0 else []
        return (not left), (f"{len(left)} orphans remain" if left else "no orphans remain")
    return True, "autoremove exited 0"


def _journal_usage_mb() -> float | None:
    if not shutil.which("journalctl"):
        return None
    code, out = _run(["journalctl", "--disk-usage"], timeout=30)
    if code != 0:
        return None
    # "Archived and active journals take up 2.1G in the file system."
    import re
    m = re.search(r"take up ([\d.]+)([KMGT])", out)
    if not m:
        return None
    val, unit = float(m.group(1)), m.group(2)
    return val * {"K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}[unit]


def _detect_journal_vacuum(ctx: dict) -> Finding | None:
    if not platforms.is_linux():
        return None
    max_mb = float(ctx["cfg_fixxer"].get("journal_max_mb", 1024))
    target = str(ctx["cfg_fixxer"].get("journal_vacuum_to", "500M"))
    usage = _journal_usage_mb()
    if usage is None or usage <= max_mb:
        return None
    return Finding("journal_vacuum", "Shrink journald logs", "safe",
                   f"journald uses {usage:.0f} MB (threshold {max_mb:.0f} MB) — vacuum to {target}",
                   commands=[["journalctl", f"--vacuum-size={target}"]], needs_sudo=True,
                   rollback_hint="none (old log entries are gone; current logs unaffected)")


def _verify_journal_vacuum(ctx: dict, f: Finding) -> tuple[bool, str]:
    usage = _journal_usage_mb()
    if usage is None:
        return False, "could not re-measure journal usage"
    max_mb = float(ctx["cfg_fixxer"].get("journal_max_mb", 1024))
    ok = usage <= max_mb * 1.1
    return ok, f"journald now uses {usage:.0f} MB"


def _dir_size_mb(path: Path) -> float:
    total = 0
    try:
        for root, _dirs, files in os.walk(path):
            for fn in files:
                try:
                    total += (Path(root) / fn).stat().st_size
                except OSError:
                    continue
    except OSError:
        return 0.0
    return total / 1024 / 1024


def _detect_cache_clean(ctx: dict) -> Finding | None:
    mgr = ctx["pkg_manager"]
    max_mb = float(ctx["cfg_fixxer"].get("cache_max_mb", 500))
    if mgr == "apt":
        size = _dir_size_mb(Path("/var/cache/apt/archives"))
        if size <= max_mb:
            return None
        return Finding("cache_clean", "Clear package download cache", "safe",
                       f"apt archive cache holds {size:.0f} MB of downloaded .debs",
                       commands=[["apt-get", "clean"]], needs_sudo=True,
                       rollback_hint="none needed (cached installers re-download on demand)")
    if mgr == "dnf":
        return Finding("cache_clean", "Clear package download cache", "safe",
                       "clear dnf package cache",
                       commands=[["dnf", "clean", "packages"]], needs_sudo=True,
                       rollback_hint="none needed (re-download on demand)")
    if mgr == "brew":
        return Finding("cache_clean", "Clear Homebrew caches", "safe",
                       "brew cleanup removes old versions + stale downloads",
                       commands=[["brew", "cleanup"]], needs_sudo=False,
                       rollback_hint="none needed (re-download on demand)")
    return None


def _verify_cache_clean(ctx: dict, f: Finding) -> tuple[bool, str]:
    if ctx["pkg_manager"] == "apt":
        size = _dir_size_mb(Path("/var/cache/apt/archives"))
        return size < 50, f"apt cache now {size:.0f} MB"
    return True, "clean command exited 0"


def _stale_tmp(age_days: int) -> tuple[int, float]:
    """(count, MB) of plain files in /tmp older than age_days (never follows symlinks)."""
    cutoff = time.time() - age_days * 86400
    count, size = 0, 0
    try:
        for entry in os.scandir("/tmp"):
            try:
                if entry.is_file(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_mtime < cutoff:
                    count += 1
                    size += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
    except OSError:
        return 0, 0.0
    return count, size / 1024 / 1024


def _detect_tmp_clean(ctx: dict) -> Finding | None:
    if platforms.is_windows():
        return None
    age = int(ctx["cfg_fixxer"].get("tmp_age_days", 14))
    count, mb = _stale_tmp(age)
    if count == 0 or mb < 10:
        return None
    return Finding("tmp_clean", "Delete stale /tmp files", "moderate",
                   f"{count} files older than {age} days in /tmp ({mb:.0f} MB) — "
                   "top-level plain files only, never directories or sockets",
                   commands=[["find", "/tmp", "-xdev", "-mindepth", "1", "-maxdepth", "1",
                              "-type", "f", "-mtime", f"+{age}", "-delete"]],
                   needs_sudo=True,
                   rollback_hint="none (deleted files are unrecoverable — hence 'moderate')")


def _verify_tmp_clean(ctx: dict, f: Finding) -> tuple[bool, str]:
    age = int(ctx["cfg_fixxer"].get("tmp_age_days", 14))
    count, mb = _stale_tmp(age)
    return count == 0, f"{count} stale files remain ({mb:.0f} MB)"


def _failed_units(user: bool = False) -> list[str]:
    argv = ["systemctl"] + (["--user"] if user else []) + \
           ["--failed", "--no-legend", "--plain", "--no-pager"]
    code, out = _run(argv, timeout=30)
    if code not in (0, 1):
        return []
    units = []
    for ln in out.splitlines():
        parts = ln.split()
        if parts and (parts[0].endswith(".service") or parts[0].endswith(".timer")):
            units.append(parts[0])
        elif len(parts) > 1 and (parts[1].endswith(".service") or parts[1].endswith(".timer")):
            units.append(parts[1])  # tolerate the '●' bullet column
    return units


def _detect_reset_failed(ctx: dict) -> Finding | None:
    if not (platforms.is_linux() and shutil.which("systemctl")):
        return None
    sys_failed = _failed_units(user=False)
    usr_failed = _failed_units(user=True)
    if not sys_failed and not usr_failed:
        return None
    cmds: list[list[str]] = []
    if sys_failed:
        cmds.append(["systemctl", "reset-failed"])
    detail = ""
    if sys_failed:
        detail += f"system: {', '.join(sys_failed[:5])}"
    if usr_failed:
        detail += (" · " if detail else "") + f"user: {', '.join(usr_failed[:5])}"
    f = Finding("reset_failed", "Clear stale failed-unit markers", "safe",
                f"failed markers — {detail} (clears the flag; does NOT restart anything)",
                commands=cmds, needs_sudo=bool(sys_failed),
                rollback_hint="none (a unit that fails again will re-flag itself)")
    # user-scope reset runs unprivileged; appended as a separate command
    if usr_failed:
        f.commands.append(["systemctl", "--user", "reset-failed"])
    return f


def _verify_reset_failed(ctx: dict, f: Finding) -> tuple[bool, str]:
    left = _failed_units(user=False) + _failed_units(user=True)
    return (not left), (f"still failed: {', '.join(left[:5])}" if left else "no failed markers remain")


def _detect_restart_failed(ctx: dict) -> Finding | None:
    if not (platforms.is_linux() and shutil.which("systemctl")):
        return None
    failed = [u for u in _failed_units(user=False) if u.endswith(".service")]
    if not failed:
        return None
    return Finding("restart_failed", "Restart failed system services", "moderate",
                   f"{len(failed)} failed service(s): {', '.join(failed[:5])} — "
                   "attempt a clean restart of each",
                   commands=[["systemctl", "restart", u] for u in failed],
                   needs_sudo=True,
                   rollback_hint="`systemctl stop <unit>` returns it to stopped; "
                                 "a service that fails again will show in --failed")


def _verify_restart_failed(ctx: dict, f: Finding) -> tuple[bool, str]:
    left = [u for u in _failed_units(user=False) if u.endswith(".service")]
    return (not left), (f"still failed: {', '.join(left[:5])}" if left else "all services recovered")


# ---------------- web-intel driven: targeted CVE upgrades ----------------
# Uses the CACHED webintel scan only — fixxer never blocks on the network.

def _cve_affected_binaries(ctx: dict) -> tuple[list[str], list[str]]:
    """(installed binary packages whose SOURCE package has known vulns, cve ids)."""
    cfg = ctx.get("cfg")
    if cfg is None or ctx["pkg_manager"] != "apt":
        return [], []
    try:
        from . import webintel
        from .store import Store
        store = Store(cfg.db_path)
        try:
            res = store.cache_get("webintel_scan", float("inf"))
        finally:
            store.close()
        if not res:
            return [], []
        sources = set(webintel.distro_vuln_packages(res))
        if not sources:
            return [], []
        cves = sorted({a for v in res.get("vulns", []) if v.get("source") == "distro"
                       for a in (v.get("aliases") or [v.get("vuln_id", "")])})
        code, out = _run(["dpkg-query", "-W", "-f", "${Package}\t${source:Package}\n"],
                         timeout=30)
        if code != 0:
            return [], cves
        bins = sorted({ln.split("\t")[0] for ln in out.splitlines()
                       if "\t" in ln and ln.split("\t")[1].split(" ")[0] in sources})
        return bins, cves
    except Exception:  # noqa: BLE001 — web intel is an enricher, never a blocker
        return [], []


def _apt_upgradable_subset(bins: list[str]) -> list[str]:
    """Which of these binaries actually have an upgrade staged (simulation, no sudo)."""
    if not bins:
        return []
    code, out = _run(["apt-get", "-s", "install", "--only-upgrade", *bins], timeout=120)
    if code != 0:
        return []
    return [ln.split()[1] for ln in out.splitlines() if ln.startswith("Inst ")]


def _detect_cve_upgrade(ctx: dict) -> Finding | None:
    bins, cves = _cve_affected_binaries(ctx)
    if not bins:
        return None
    upgradable = _apt_upgradable_subset(bins)
    if not upgradable:
        return None  # vulns known but no fixed build shipped yet — advisory, not a fix
    cve_str = ", ".join(cves[:4]) + ("…" if len(cves) > 4 else "")
    return Finding(
        "cve_upgrade", "Apply security updates for CVE-affected packages", "moderate",
        f"OSV.dev reports known vulnerabilities ({cve_str}) in installed packages; "
        f"fixed builds are available for: {', '.join(upgradable[:8])}"
        + ("…" if len(upgradable) > 8 else ""),
        commands=[["apt-get", "install", "--only-upgrade", "-y", *upgradable]],
        needs_sudo=True,
        env_extra={"DEBIAN_FRONTEND": "noninteractive"},
        rollback_hint="apt history records versions: /var/log/apt/history.log; "
                      "`apt-get install pkg=old-version` reverts one package")


def _verify_cve_upgrade(ctx: dict, f: Finding) -> tuple[bool, str]:
    bins, _ = _cve_affected_binaries(ctx)
    left = _apt_upgradable_subset(bins)
    return (not left), (f"still upgradable: {', '.join(left[:5])}" if left
                        else "no CVE-affected packages still have pending updates")


CATALOG: list[ActionSpec] = [
    ActionSpec("pkg_refresh", "Refresh package metadata", "safe",
               _detect_pkg_refresh, _verify_pkg_refresh),
    ActionSpec("journal_vacuum", "Shrink journald logs", "safe",
               _detect_journal_vacuum, _verify_journal_vacuum, platforms=("linux",)),
    ActionSpec("cache_clean", "Clear package download cache", "safe",
               _detect_cache_clean, _verify_cache_clean),
    ActionSpec("reset_failed", "Clear stale failed-unit markers", "safe",
               _detect_reset_failed, _verify_reset_failed, platforms=("linux",)),
    ActionSpec("pkg_upgrade", "Apply pending package updates", "moderate",
               _detect_pkg_upgrade, _verify_pkg_upgrade),
    ActionSpec("pkg_autoremove", "Remove orphaned packages", "moderate",
               _detect_pkg_autoremove, _verify_pkg_autoremove),
    ActionSpec("tmp_clean", "Delete stale /tmp files", "moderate",
               _detect_tmp_clean, _verify_tmp_clean, platforms=("linux", "macos")),
    ActionSpec("restart_failed", "Restart failed system services", "moderate",
               _detect_restart_failed, _verify_restart_failed, platforms=("linux",)),
    ActionSpec("cve_upgrade", "Apply security updates for CVE-affected packages", "moderate",
               _detect_cve_upgrade, _verify_cve_upgrade, platforms=("linux",)),
]

ACTIONS_BY_ID = {a.id: a for a in CATALOG}


# ---------------- scan / apply ----------------

def build_ctx(cfg) -> dict:
    return {"pkg_manager": pkg_manager(), "platform": platforms.current_platform(),
            "cfg_fixxer": _fixxer_cfg(cfg), "cfg": cfg}


def scan(cfg, on_step=None) -> tuple[list[Finding], dict]:
    """Run every applicable detector. Returns (findings, ctx)."""
    ctx = build_ctx(cfg)
    findings: list[Finding] = []
    for spec in CATALOG:
        if ctx["platform"] not in spec.platforms:
            continue
        if on_step:
            on_step("detect", spec.title)
        try:
            f = spec.detect(ctx)
        except Exception as e:  # noqa: BLE001 — a broken detector must not kill the scan
            f = None
            if on_step:
                on_step("error", f"{spec.id} detector failed: {e}")
        if f is not None:
            findings.append(f)
    findings.sort(key=lambda f: RISK_ORDER.get(f.risk, 9))
    return findings, ctx


def apply_finding(cfg, store, ctx: dict, finding: Finding, mode: str,
                  non_interactive: bool = False, on_step=None) -> ApplyResult:
    """Execute one finding's commands, verify, audit. mode: interactive|auto|dry."""
    t0 = time.time()
    outputs: list[str] = []
    ok = True
    for argv in finding.commands:
        full = (_sudo_prefix(non_interactive) + argv) if finding.needs_sudo else argv
        if on_step:
            on_step("run", " ".join(full))
        code, out = _run(full, timeout=1800, env_extra=finding.env_extra or None)
        outputs.append(f"$ {' '.join(full)}\n(exit {code}) {out[:1500]}")
        if code != 0:
            ok = False
            break
    verified, note = False, "not verified (apply failed)"
    if ok:
        try:
            spec = ACTIONS_BY_ID[finding.action_id]
            verified, note = spec.verify(ctx, finding)
        except Exception as e:  # noqa: BLE001
            verified, note = False, f"verifier error: {e}"
    result = ApplyResult(finding, ok, "\n".join(outputs), verified, note,
                         round(time.time() - t0, 1))
    audit_write(cfg, {
        "ts": time.time(), "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "mode": mode, "action": finding.action_id, "risk": finding.risk,
        "commands": [" ".join(c) for c in finding.commands],
        "ok": ok, "verified": verified, "verify_note": note,
        "rollback_hint": finding.rollback_hint,
        "output_tail": result.output[-500:],
    })
    if store is not None:
        store.add_action(mode, f"fixxer:{finding.action_id}",
                         " && ".join(" ".join(c) for c in finding.commands),
                         ok, f"verified={verified} {note}"[:500])
    return result


# ---------------- consent (the auto-mode gate) ----------------

def consent_path(cfg) -> Path:
    from .config import CONFIG_DIR
    return CONFIG_DIR / CONSENT_FILENAME


def load_consent(cfg) -> dict | None:
    p = consent_path(cfg)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        if isinstance(data, dict) and data.get("tiers"):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return None


def write_consent(cfg, tiers: list[str]) -> Path:
    tiers = [t for t in RISK_TIERS if t in tiers]
    p = consent_path(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "granted_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": _platform.node() or "localhost",
        "tiers": tiers,
        "statement": "I authorize wrench to apply catalog fixes in these risk "
                     "tiers without asking, and I understand every action is "
                     "logged to the audit file.",
    }, indent=2))
    return p


def revoke_consent(cfg) -> bool:
    p = consent_path(cfg)
    if p.exists():
        p.unlink()
        return True
    return False


def effective_auto_tiers(cfg) -> list[str]:
    """Tiers auto mode may touch = consent ∩ config (both must agree).

    Config default is ["safe"]; widening requires BOTH a consent record that
    includes the tier AND an explicit auto_tiers entry in config.toml.
    """
    consent = load_consent(cfg)
    if not consent:
        return []
    cfg_tiers = _fixxer_cfg(cfg).get("auto_tiers", ["safe"])
    if not isinstance(cfg_tiers, list):
        cfg_tiers = ["safe"]
    return [t for t in RISK_TIERS if t in consent.get("tiers", []) and t in cfg_tiers]


def auto_scope(cfg, findings: list[Finding]) -> list[Finding]:
    tiers = set(effective_auto_tiers(cfg))
    return [f for f in findings if f.risk in tiers]


# ---------------- audit ----------------

def audit_path(cfg) -> Path:
    return cfg.data_dir / AUDIT_FILENAME


def audit_write(cfg, entry: dict) -> None:
    try:
        p = audit_path(cfg)
        with p.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # auditing must never block a fix


def audit_tail(cfg, n: int = 20) -> list[dict]:
    p = audit_path(cfg)
    if not p.exists():
        return []
    rows = []
    for ln in p.read_text().strip().splitlines()[-n:]:
        try:
            rows.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return rows
