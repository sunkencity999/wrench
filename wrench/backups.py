"""Backup verification — untested backups don't exist.

Wrench finds the backup jobs a box *actually* has (crontabs, systemd timers,
wrapper scripts), then climbs a verification ladder for each one:

    L1  did it run recently?     (systemd exec timestamps, destination mtime)
    L2  is the repository sane?  (cheap, read-only: borg/restic listing,
                                  dump freshness + size sanity)
    L3  can we restore from it?  (OPTIONAL, consent-gated --restore-test)

Everything is read-only by default; L3 never runs unless explicitly requested
and confirmed. A box with zero detected backup jobs gets a gentle warning —
that is itself a finding.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

BACKUPS_KIND = "backups_report"      # snapshot kind for the last computed report

# Tools we recognize as backup actors inside a command line.
BACKUP_TOOLS = ("borg", "restic", "rsync", "pg_dump", "pg_dumpall",
                "mysqldump", "rdiff-backup", "duplicity")

_CRON_FILES = ("/etc/crontab",)
_CRON_DIRS = ("/etc/cron.d",)
_CRON_PERIODIC = ("/etc/cron.hourly", "/etc/cron.daily",
                  "/etc/cron.weekly", "/etc/cron.monthly")

# Default expected cadence when we can't parse one (daily).
DEFAULT_CADENCE_S = 86400.0
_STALE_FACTOR = 2.0                   # stale when age > cadence * factor

_SEV_RANK = {"none": 0, "info": 1, "warning": 2, "critical": 3}


@dataclass
class BackupJob:
    """One detected backup job and its verification verdicts."""
    name: str
    tool: str
    command: str
    origin: str                       # crontab path, unit name, script path
    schedule: str = ""                # raw cron expr / OnCalendar value
    cadence_s: float = DEFAULT_CADENCE_S
    source: str = ""                  # best-effort parse of what's backed up
    dest: str = ""                    # best-effort parse of where it goes
    last_run_ts: float | None = None
    last_run_evidence: str = ""       # which evidence source produced the ts
    freshness: str = "unknown"        # fresh | stale | unknown
    integrity: str = "unknown"        # ok | locked | failed | unknown | skipped
    integrity_note: str = ""
    restore_test: str = "not-run"     # not-run | ok | failed | unsupported

    def age_s(self, now: float | None = None) -> float | None:
        if self.last_run_ts is None:
            return None
        return max(0.0, (now or time.time()) - self.last_run_ts)

    def as_dict(self) -> dict:
        d = {k: getattr(self, k) for k in (
            "name", "tool", "command", "origin", "schedule", "cadence_s",
            "source", "dest", "last_run_ts", "last_run_evidence",
            "freshness", "integrity", "integrity_note", "restore_test")}
        d["age_s"] = self.age_s()
        return d


def _run(argv: list[str], timeout: int = 20, env: dict | None = None) -> tuple[int, str]:
    """Run an allowlisted read-only command; (-1, reason) on failure."""
    try:
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, env=full_env)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return -1, f"{argv[0]}: not installed"
    except subprocess.TimeoutExpired:
        return -1, f"{argv[0]}: timed out after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return -1, f"{argv[0]}: {e}"


# ---- detection --------------------------------------------------------------


def _splittable(cmd: str) -> bool:
    try:
        shlex.split(cmd, posix=True)
        return True
    except ValueError:
        return False


def _tokens(cmd: str) -> list[str]:
    return shlex.split(cmd, posix=True) if _splittable(cmd) else cmd.split()


def _tool_in_command(cmd: str) -> str:
    """Return the first recognized backup tool named in a command line."""
    for tok in _tokens(cmd):
        base = os.path.basename(tok.strip("'\""))
        if base in BACKUP_TOOLS:
            return base
    return ""


def _follow_wrapper(cmd: str, max_bytes: int = 65536) -> tuple[str, str]:
    """If cmd invokes a readable script, look inside it for the real tool.

    Returns (tool, script_path) or ("", "").
    """
    for tok in _tokens(cmd):
        tok = tok.strip("'\"")
        if tok.startswith("-") or "=" in tok[:20]:
            continue
        p = Path(tok)
        if not (p.is_absolute() and p.is_file() and os.access(p, os.R_OK)):
            continue
        if p.suffix in (".gz", ".tar", ".sqlite", ".db", ".png", ".jpg"):
            continue
        try:
            text = p.read_text(errors="replace")[:max_bytes]
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            tool = _tool_in_command(line)
            if tool:
                return tool, str(p)
    return "", ""


_CRON_LINE = re.compile(
    r"^\s*(?P<min>\S+)\s+(?P<hour>\S+)\s+(?P<dom>\S+)\s+(?P<mon>\S+)\s+(?P<dow>\S+)\s+"
    r"(?P<rest>.+)$")
_CRON_SPECIAL = re.compile(
    r"^\s*@(?P<special>hourly|daily|weekly|monthly|reboot)\s+(?P<rest>.+)$")

_SPECIAL_CADENCE = {"hourly": 3600.0, "daily": 86400.0,
                    "weekly": 7 * 86400.0, "monthly": 30 * 86400.0,
                    "reboot": DEFAULT_CADENCE_S}


def _cadence_from_cron(minute: str, hour: str, dom: str, dow: str) -> tuple[float, str]:
    expr = f"{minute} {hour} {dom} * {dow}"
    if "*/" in minute or minute == "*":
        return 3600.0, expr
    if hour == "*" or "*/" in hour:
        return 3600.0, expr
    if dom == "*" and dow == "*":
        return 86400.0, expr
    if dow != "*":
        return 7 * 86400.0, expr
    return 30 * 86400.0, expr


def _parse_cron_text(text: str, origin: str, has_user_field: bool) -> list["BackupJob"]:
    jobs: list[BackupJob] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        first = line.split()[0]
        if "=" in first:                      # VAR=value lines
            continue
        m = _CRON_SPECIAL.match(line)
        if m:
            rest = m.group("rest")
            parts = rest.split(None, 1)
            cmd = parts[1] if has_user_field and len(parts) == 2 else rest
            cadence = _SPECIAL_CADENCE[m.group("special")]
            sched = f"@{m.group('special')}"
        else:
            m = _CRON_LINE.match(line)
            if not m:
                continue
            rest = m.group("rest")
            parts = rest.split(None, 1)
            cmd = parts[1] if has_user_field and len(parts) == 2 else rest
            cadence, sched = _cadence_from_cron(m.group("min"), m.group("hour"),
                                                m.group("dom"), m.group("dow"))
        tool = _tool_in_command(cmd)
        script = ""
        if not tool:
            tool, script = _follow_wrapper(cmd)
        if not tool:
            continue
        jobs.append(BackupJob(
            name=_job_name(tool, cmd, origin), tool=tool, command=cmd.strip(),
            origin=origin if not script else f"{origin} → {script}",
            schedule=sched, cadence_s=cadence,
            **_parse_src_dest(tool, cmd)))
    return jobs


def _job_name(tool: str, cmd: str, origin: str) -> str:
    for tok in _tokens(cmd):
        tok = tok.strip("'\"")
        if "::" in tok:                      # borg repo::archive
            repo = tok.split("::")[0]
            return f"{tool}:{os.path.basename(repo.rstrip('/')) or repo}"
    base = os.path.basename(origin.split()[0]) if origin else tool
    return f"{tool}:{base}"


def _parse_src_dest(tool: str, cmd: str) -> dict:
    """Best-effort source/destination extraction per tool. Never raises."""
    out = {"source": "", "dest": ""}
    try:
        toks = _tokens(cmd)
        args = [t for t in toks if not t.startswith("-")]
        if tool == "borg":
            for t in toks:
                if "::" in t:
                    out["dest"] = t.split("::")[0]
                    break
            paths = [t for t in args if t.startswith("/") and "::" not in t]
            out["source"] = " ".join(paths[:3])
        elif tool == "restic":
            for i, t in enumerate(toks):
                if t in ("-r", "--repo", "--repository") and i + 1 < len(toks):
                    out["dest"] = toks[i + 1]
            out["source"] = " ".join(t for t in args if t.startswith("/"))[:200]
        elif tool == "rsync":
            paths = [t for t in args if "/" in t]
            if len(paths) >= 2:
                out["source"], out["dest"] = paths[-2], paths[-1]
        elif tool in ("pg_dump", "pg_dumpall", "mysqldump"):
            for i, t in enumerate(toks):
                if t in ("-f", "--file") and i + 1 < len(toks):
                    out["dest"] = toks[i + 1]
            if not out["dest"] and ">" in cmd:
                out["dest"] = cmd.split(">", 1)[1].split()[0].strip()
    except Exception:  # noqa: BLE001
        pass
    return out


def _detect_cron() -> list[BackupJob]:
    jobs: list[BackupJob] = []
    for f in _CRON_FILES:
        p = Path(f)
        if p.is_file() and os.access(p, os.R_OK):
            jobs += _parse_cron_text(p.read_text(errors="replace"), f,
                                     has_user_field=True)
    for d in _CRON_DIRS:
        dp = Path(d)
        if dp.is_dir():
            for p in sorted(dp.iterdir()):
                if p.is_file() and os.access(p, os.R_OK):
                    jobs += _parse_cron_text(p.read_text(errors="replace"),
                                             str(p), has_user_field=True)
    rc, out = _run(["crontab", "-l"], timeout=10)
    if rc == 0:
        jobs += _parse_cron_text(out, "crontab(user)", has_user_field=False)
    for d in _CRON_PERIODIC:
        dp = Path(d)
        if not dp.is_dir():
            continue
        cadence = _SPECIAL_CADENCE.get(dp.name.split(".")[-1], DEFAULT_CADENCE_S)
        for p in sorted(dp.iterdir()):
            if not (p.is_file() and os.access(p, os.R_OK)):
                continue
            tool, script = _follow_wrapper(str(p))
            if tool:
                jobs.append(BackupJob(
                    name=f"{tool}:{p.name}", tool=tool, command=str(p),
                    origin=f"{d}/{p.name}", schedule=f"@{dp.name.split('.')[-1]}",
                    cadence_s=cadence))
    return jobs


_TIMER_CADENCE = (("hourly", 3600.0), ("daily", 86400.0),
                  ("weekly", 7 * 86400.0), ("monthly", 30 * 86400.0))


def _timer_cadence(oncal: str) -> float:
    low = oncal.lower()
    for key, s in _TIMER_CADENCE:
        if key in low:
            return s
    if re.search(r"\*-\*-\* \d", oncal):      # a daily-style OnCalendar
        return 86400.0
    if "minutely" in low:
        return 3600.0
    return DEFAULT_CADENCE_S


def _detect_systemd(user: bool = False) -> list[BackupJob]:
    scope = ["--user"] if user else []
    jobs: list[BackupJob] = []
    rc, out = _run(["systemctl", *scope, "list-timers", "--all",
                    "--no-legend", "--no-pager"], timeout=15)
    if rc != 0:
        return jobs
    timer_names = [t for line in out.splitlines()
                   for t in line.split() if t.endswith(".timer")]
    for timer in sorted(set(timer_names)):
        svc = timer[:-6] + ".service"
        rc, props = _run(["systemctl", *scope, "show", svc,
                          "--property=ExecStart", "--no-pager"], timeout=10)
        if rc != 0:
            continue
        m = re.search(r"argv\[\]=([^;]+)", props)
        cmd = m.group(1).strip() if m else ""
        if not cmd:
            m = re.search(r"ExecStart=\{?\s*([^;}\n]+)", props)
            cmd = (m.group(1).strip() if m else "")
        if not cmd:
            continue
        tool = _tool_in_command(cmd)
        script = ""
        if not tool:
            tool, script = _follow_wrapper(cmd)
        if not tool:
            continue
        rc2, tprops = _run(["systemctl", *scope, "show", timer,
                            "--property=TimersCalendar", "--no-pager"], timeout=10)
        oncal = ""
        if rc2 == 0:
            m = re.search(r"OnCalendar=([^;}\n]+)", tprops)
            oncal = m.group(1).strip() if m else ""
        jobs.append(BackupJob(
            name=f"{tool}:{timer[:-6]}", tool=tool, command=cmd,
            origin=f"{'user:' if user else ''}{timer}"
                   + (f" → {script}" if script else ""),
            schedule=oncal or "timer", cadence_s=_timer_cadence(oncal),
            **_parse_src_dest(tool, cmd)))
    return jobs


def detect_jobs() -> list[BackupJob]:
    """Find backup jobs across crontabs and systemd timers. Read-only."""
    jobs = _detect_cron() + _detect_systemd(user=False) + _detect_systemd(user=True)
    seen: dict[str, BackupJob] = {}
    for j in jobs:                      # de-dupe by (tool, command)
        seen.setdefault(f"{j.tool}|{j.command}", j)
    return list(seen.values())


# ---- verification ladder ----------------------------------------------------


def _parse_systemd_ts(raw: str) -> float | None:
    raw = raw.strip()
    if not raw or raw == "n/a":
        return None
    try:
        import datetime
        s = re.sub(r"^\w{3} ", "", raw)           # drop day-of-week
        s = re.sub(r" [A-Z]{3,5}$", "", s)        # drop timezone name (local)
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:  # noqa: BLE001
        return None


def _systemd_last_run(job: BackupJob) -> float | None:
    m = re.match(r"(user:)?(\S+\.timer)", job.origin)
    if not m:
        return None
    scope = ["--user"] if m.group(1) else []
    svc = m.group(2)[:-6] + ".service"
    rc, out = _run(["systemctl", *scope, "show", svc,
                    "--property=ExecMainExitTimestamp", "--no-pager"], timeout=10)
    if rc != 0:
        return None
    m2 = re.search(r"ExecMainExitTimestamp=(.*)", out)
    return _parse_systemd_ts(m2.group(1)) if m2 else None


def _dest_mtime(job: BackupJob) -> float | None:
    dest = (job.dest or "").split("::")[0]
    if not dest:
        return None
    if "@" in dest or re.match(r"^[\w.-]+:", dest):   # remote
        return None
    p = Path(dest)
    if not p.exists():
        return None
    try:
        if p.is_dir():
            newest = p.stat().st_mtime
            for child in list(p.iterdir())[:200]:
                try:
                    newest = max(newest, child.stat().st_mtime)
                except OSError:
                    continue
            return newest
        return p.stat().st_mtime
    except OSError:
        return None


def check_freshness(job: BackupJob, now: float | None = None) -> None:
    """L1 — mutate job with last-run evidence + freshness verdict."""
    now = now or time.time()
    ts = _systemd_last_run(job)
    if ts:
        job.last_run_ts, job.last_run_evidence = ts, "systemd"
    else:
        ts = _dest_mtime(job)
        if ts:
            job.last_run_ts, job.last_run_evidence = ts, "dest-mtime"
    if job.last_run_ts is None:
        job.freshness = "unknown"
        return
    age = now - job.last_run_ts
    job.freshness = "fresh" if age <= job.cadence_s * _STALE_FACTOR else "stale"


def check_integrity(job: BackupJob, timeout: int = 30) -> None:
    """L2 — cheap, read-only repository sanity. Mutates the job. Never raises."""
    try:
        if job.tool == "borg":
            repo = (job.dest or "").split("::")[0]
            if not repo:
                job.integrity, job.integrity_note = "unknown", "repo path not parsed"
                return
            rc, out = _run(["borg", "list", "--short", "--last", "1", repo],
                           timeout=timeout,
                           env={"BORG_RELOCATED_REPO_ACCESS_IS_OK": "yes"})
            if rc == 0 and out.strip():
                job.integrity = "ok"
                job.integrity_note = f"latest archive: {out.strip().splitlines()[-1]}"
            elif rc == 0:
                job.integrity, job.integrity_note = "failed", "repository has no archives"
            elif "passphrase" in out.lower() or "passcommand" in out.lower():
                job.integrity, job.integrity_note = \
                    "locked", "repo needs a passphrase (read check skipped)"
            else:
                job.integrity, job.integrity_note = "failed", out.strip()[:160]
        elif job.tool == "restic":
            repo = job.dest
            if not repo:
                job.integrity, job.integrity_note = "unknown", "repo not parsed"
                return
            rc, out = _run(["restic", "-r", repo, "snapshots",
                            "--latest", "1", "--no-lock"], timeout=timeout)
            if rc == 0:
                job.integrity, job.integrity_note = "ok", "snapshots listable"
            elif "password" in out.lower():
                job.integrity, job.integrity_note = \
                    "locked", "repo needs a password (read check skipped)"
            else:
                job.integrity, job.integrity_note = "failed", out.strip()[:160]
        elif job.tool in ("pg_dump", "pg_dumpall", "mysqldump"):
            p = Path(job.dest) if job.dest else None
            if p and p.exists() and p.stat().st_size > 0:
                job.integrity = "ok"
                job.integrity_note = f"dump present, {p.stat().st_size} bytes"
            elif p and p.exists():
                job.integrity, job.integrity_note = "failed", "dump file is EMPTY"
            else:
                job.integrity, job.integrity_note = "unknown", "dump path not found/parsed"
        elif job.tool == "rsync":
            if job.dest and ("@" in job.dest or "::" in job.dest
                             or re.match(r"^[\w.-]+:", job.dest)):
                job.integrity, job.integrity_note = \
                    "skipped", "remote destination (read check skipped)"
                return
            p = Path(job.dest) if job.dest else None
            if p and p.exists():
                job.integrity, job.integrity_note = "ok", "destination present"
            else:
                job.integrity, job.integrity_note = "unknown", "destination not found/parsed"
        else:
            job.integrity, job.integrity_note = "skipped", f"no cheap check for {job.tool}"
    except Exception as e:  # noqa: BLE001
        job.integrity, job.integrity_note = "unknown", str(e)[:160]


def restore_test(job: BackupJob, timeout: int = 120) -> None:
    """L3 — consent-gated sample restore proof. Read-only variants only."""
    try:
        if job.tool == "borg":
            repo = (job.dest or "").split("::")[0]
            rc, out = _run(["borg", "list", "--short", "--last", "1", repo],
                           timeout=30)
            if rc != 0 or not out.strip():
                job.restore_test = "failed"
                return
            archive = out.strip().splitlines()[-1]
            rc, _ = _run(["borg", "extract", "--dry-run", f"{repo}::{archive}"],
                         timeout=timeout)
            job.restore_test = "ok" if rc == 0 else "failed"
        elif job.tool == "restic":
            rc, _ = _run(["restic", "-r", job.dest, "check", "--no-lock"],
                         timeout=timeout)
            job.restore_test = "ok" if rc == 0 else "failed"
        else:
            job.restore_test = "unsupported"
    except Exception:  # noqa: BLE001
        job.restore_test = "failed"


# ---- report / patrol / notifications ---------------------------------------


def job_severity(job) -> str:
    """Severity ladder for one job (works on BackupJob or adapter)."""
    if job.integrity == "failed":
        return "critical"
    if job.freshness == "stale":
        return "warning"
    if job.freshness == "unknown" and job.integrity == "unknown":
        return "warning"
    if job.integrity == "locked":
        return "info"
    return "none"


def job_severity_dict(j: dict) -> str:
    class _J:
        freshness = j.get("freshness", "unknown")
        integrity = j.get("integrity", "unknown")
    return job_severity(_J)


def scan(cfg=None, store=None, persist: bool = True, on_step=None) -> dict:
    """Full detection + L1 + L2 sweep. Returns the report dict."""
    def step(msg: str) -> None:
        if on_step:
            on_step(msg)
    step("detecting backup jobs...")
    jobs = detect_jobs()
    now = time.time()
    for j in jobs:
        step(f"verifying {j.name}...")
        check_freshness(j, now)
        check_integrity(j)
    sev_counts: dict[str, int] = {}
    worst = "none"
    for j in jobs:
        s = job_severity(j)
        sev_counts[s] = sev_counts.get(s, 0) + 1
        if _SEV_RANK[s] > _SEV_RANK[worst]:
            worst = s
    report = {
        "ts": now,
        "jobs": [j.as_dict() for j in jobs],
        "count": len(jobs),
        "severity_counts": sev_counts,
        "worst": worst if jobs else "warning",
        "no_jobs": not jobs,
    }
    if store is not None and persist:
        store.add_snapshot(BACKUPS_KIND, report)
    return report


def notify_scan(cfg, report: dict) -> dict | None:
    """Fan a scan's worst finding out through the notification sinks."""
    from .notifications import emit_event
    if report.get("no_jobs"):
        return emit_event(cfg, "backups", "warning",
                          "no backup jobs detected on this box — nothing is "
                          "protecting this data (run `wrench backups`)")
    worst = report.get("worst", "none")
    if worst == "none":
        return None
    bad = [j for j in report["jobs"] if job_severity_dict(j) == worst]
    names = ", ".join(j["name"] for j in bad[:4])
    return emit_event(cfg, "backups", worst,
                      f"backup verification: {len(bad)} job(s) at {worst} — {names}")


def patrol_findings(cfg, store, cadence_s: int = 3600) -> list[dict]:
    """Cached scan for the patrol: findings list, never raises."""
    try:
        cached = store.last_snapshot(BACKUPS_KIND)
        if cached and time.time() - cached[0] < cadence_s:
            report = cached[1]
        else:
            report = scan(cfg, store, persist=True)
            notify_scan(cfg, report)
        out = []
        if report.get("no_jobs"):
            out.append({"severity": "warning", "area": "backups",
                        "summary": "no backup jobs detected on this box"})
        for j in report.get("jobs", []):
            sev = job_severity_dict(j)
            if sev == "none":
                continue
            note = f" ({j['integrity_note']})" if j.get("integrity_note") else ""
            out.append({"severity": sev, "area": "backups",
                        "summary": f"{j['name']}: freshness={j['freshness']}, "
                                   f"integrity={j['integrity']}{note}"})
        return out
    except Exception:  # noqa: BLE001
        return []


def patrol_summary_line(cfg, store, cadence_s: int = 3600) -> str:
    try:
        cached = store.last_snapshot(BACKUPS_KIND)
        report = cached[1] if cached and time.time() - cached[0] < cadence_s \
            else scan(cfg, store, persist=True)
        if report.get("no_jobs"):
            return "backups: NO backup jobs detected"
        fresh = sum(1 for j in report["jobs"] if j["freshness"] == "fresh")
        return (f"backups: {report['count']} job(s) tracked, {fresh} fresh, "
                f"worst={report.get('worst', 'none')}")
    except Exception:  # noqa: BLE001
        return "backups: check unavailable"


def narration_lines(report: dict) -> list[str]:
    """Flatten a report into briefing lines for the brain narration."""
    if report.get("no_jobs"):
        return ["No backup jobs were detected on this machine at all."]
    lines = []
    for j in report.get("jobs", []):
        age = j.get("age_s")
        age_h = f"{age / 3600:.1f}h ago" if age is not None else "never seen"
        note = f" — {j['integrity_note']}" if j.get("integrity_note") else ""
        lines.append(f"{j['name']} ({j['tool']}, {j['origin']}): "
                     f"schedule={j['schedule'] or '?'}, last run {age_h} "
                     f"[{j['last_run_evidence'] or 'no evidence'}], "
                     f"freshness={j['freshness']}, integrity={j['integrity']}{note}")
    return lines
