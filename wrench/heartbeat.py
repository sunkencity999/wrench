"""Heartbeat: the scheduled work wrench does on its own.

One OS timer (systemd / launchd / Task Scheduler, see ``install-service``)
runs ``wrench heartbeat`` every few minutes. Each beat:

  1. records a pulse — so "is wrench still alive on this box?" has an answer;
  2. runs every **job** that has come due, one at a time;
  3. now and then **reflects**: looks at what the operator does by hand and
     proposes doing it for them.

A job is a schedule plus an action from a closed registry — a patrol, one of
the scans, a brief, a reminder, or a question for the agent. There is no
"run this shell command" action: scheduled work can do nothing an interactive
``wrench`` command could not, and an agent question runs at the tier
``[heartbeat] max_tier`` allows (``suggest`` by default — read-only).

Jobs the operator adds are live at once. Jobs the *agent* proposes unattended,
or that wrench proposes from learned habits, start as ``proposed`` and do
nothing until the operator approves them.

Schedules are plain language (``every 15m``, ``daily 08:30``,
``weekdays 9am``, ``mon,thu 18:00``, ``monthly 1 06:00``, ``in 2h``,
``at 2026-12-01 09:00``) or five-field cron. Local time.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import platform
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path

PULSE_KEY = "heartbeat_pulse"
SEEDED_KEY = "_heartbeat_seeded"
REFLECT_KEY = "_heartbeat_reflect"
DEFAULT_TICK_MIN = 5
MAX_JOBS = 100
MAX_PROPOSED = 20
MAX_FAIL_STREAK = 5
MIN_INTERVAL_S = 60
REFLECT_EVERY_S = 6 * 3600
JOB_STATUSES = ("active", "paused", "proposed", "done")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,39}$")


class HeartbeatError(ValueError):
    """Human-facing refusal: bad schedule, unknown action, duplicate name."""


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------

def settings(cfg) -> dict:
    sec = (getattr(cfg, "raw", None) or {}).get("heartbeat", {})
    if not isinstance(sec, dict):
        sec = {}
    tier = str(sec.get("max_tier", "suggest")).lower()
    if tier not in ("observe", "suggest", "repair", "autonomous"):
        tier = "suggest"

    def _int(key: str, default: int, lo: int, hi: int) -> int:
        try:
            return max(lo, min(hi, int(sec.get(key, default))))
        except (TypeError, ValueError):
            return default
    return {
        "enabled": bool(sec.get("enabled", True)),
        "max_tier": tier,
        "job_timeout_s": _int("job_timeout_s", 900, 30, 6 * 3600),
        "tick_min": _int("tick_min", DEFAULT_TICK_MIN, 1, 60),
        "propose_routines": bool(sec.get("propose_routines", True)),
    }


# --------------------------------------------------------------------------
# schedules
# --------------------------------------------------------------------------

_DAYS = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
_DAY_ALIASES = {"sunday": "sun", "monday": "mon", "tuesday": "tue", "wednesday": "wed",
                "thursday": "thu", "friday": "fri", "saturday": "sat", "tues": "tue",
                "weds": "wed", "thur": "thu", "thurs": "thu"}
_UNIT_S = {"m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
           "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
           "d": 86400, "day": 86400, "days": 86400,
           "w": 604800, "week": 604800, "weeks": 604800}
_CRON_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


@dataclass(frozen=True)
class Schedule:
    kind: str                         # interval | cron | once
    text: str                         # canonical spelling, safe to re-parse
    every_s: float = 0.0
    fields: tuple = ()                # cron: 5 frozensets
    dom_any: bool = True
    dow_any: bool = True
    at: float = 0.0

    def describe(self) -> str:
        return self.text

    def next_after(self, after: float) -> float | None:
        """The first run strictly after ``after`` (None: a one-shot in the past)."""
        if self.kind == "interval":
            return after + self.every_s
        if self.kind == "once":
            return self.at if self.at > after else None
        return _cron_next(self, after)


def _parse_time(tok: str) -> tuple[int, int]:
    m = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)?", tok.strip().lower())
    if not m:
        raise HeartbeatError(f"'{tok}' is not a time — use 09:00, 9am or 17:30")
    h, mi, ap = int(m.group(1)), int(m.group(2) or 0), m.group(3)
    if ap:
        if not 1 <= h <= 12:
            raise HeartbeatError(f"'{tok}' is not a time")
        h = (h % 12) + (12 if ap == "pm" else 0)
    if h > 23 or mi > 59:
        raise HeartbeatError(f"'{tok}' is not a time")
    return h, mi


def _cron_field(spec: str, lo: int, hi: int) -> tuple[frozenset, bool]:
    out: set[int] = set()
    any_ = False
    for part in spec.split(","):
        step = 1
        if "/" in part:
            part, _, st = part.partition("/")
            if not st.isdigit() or int(st) < 1:
                raise HeartbeatError(f"bad cron step in '{spec}'")
            step = int(st)
        if part == "":
            raise HeartbeatError(f"empty value in cron field '{spec}'")
        if part == "*":
            a, b = lo, hi
            any_ = True      # like cron: a field that starts with * is unrestricted
        elif "-" in part:
            x, _, y = part.partition("-")
            if not (x.isdigit() and y.isdigit()):
                raise HeartbeatError(f"bad cron range '{part}'")
            a, b = int(x), int(y)
        elif part.isdigit():
            a = b = int(part)
        else:
            raise HeartbeatError(f"bad cron field '{spec}' (numbers only)")
        if a < lo or b > hi or a > b:
            raise HeartbeatError(f"cron value out of range in '{spec}' ({lo}-{hi})")
        out.update(range(a, b + 1, step))
    return frozenset(out), any_


def _cron(expr: str, text: str | None = None) -> Schedule:
    parts = expr.split()
    if len(parts) != 5:
        raise HeartbeatError("a cron schedule has five fields: minute hour day month weekday")
    sets, anys = [], []
    for spec, (lo, hi) in zip(parts, _CRON_RANGES):
        s, a = _cron_field(spec, lo, hi)
        sets.append(s)
        anys.append(a)
    sets[4] = frozenset(0 if d == 7 else d for d in sets[4])
    return Schedule("cron", text or expr, fields=tuple(sets), dom_any=anys[2], dow_any=anys[4])


def _cron_next(s: Schedule, after: float) -> float | None:
    """Next matching local time strictly after ``after``.

    Clock changes: a schedule that names its hours ("daily 01:30") is walked in
    wall-clock time, so it fires once on the day an hour repeats and once (an
    hour late) on the day an hour is skipped. A schedule for every hour
    ("*/10 * * * *") is walked in real time, so it neither skips the repeated
    hour nor returns a moment that has already passed."""
    minute, hour, dom, month, dow = s.fields
    if len(hour) == 24:
        return _cron_next_realtime(s, after)
    t = _dt.datetime.fromtimestamp(after).replace(second=0, microsecond=0) \
        + _dt.timedelta(minutes=1)
    for _ in range(200_000):
        if t.month not in month:
            t = (t.replace(day=1, hour=0, minute=0) + _dt.timedelta(days=32)).replace(day=1)
            continue
        dom_ok, dow_ok = t.day in dom, ((t.weekday() + 1) % 7) in dow
        # cron's rule: when both day fields are restricted, either may match
        day_ok = (dom_ok or dow_ok) if not (s.dom_any or s.dow_any) else (dom_ok and dow_ok)
        if not day_ok:
            t = t.replace(hour=0, minute=0) + _dt.timedelta(days=1)
            continue
        if t.hour not in hour:
            t = t.replace(minute=0) + _dt.timedelta(hours=1)
            continue
        if t.minute not in minute:
            t += _dt.timedelta(minutes=1)
            continue
        ts = t.timestamp()
        if ts <= after:      # the repeated hour when clocks go back: keep looking
            t += _dt.timedelta(minutes=1)
            continue
        return ts
    return None


def _cron_next_realtime(s: Schedule, after: float) -> float | None:
    minute, _hour, dom, month, dow = s.fields
    ts = (int(after) // 60 + 1) * 60
    for _ in range(200_000):
        lt = time.localtime(ts)
        dom_ok, dow_ok = lt.tm_mday in dom, ((lt.tm_wday + 1) % 7) in dow
        day_ok = (dom_ok or dow_ok) if not (s.dom_any or s.dow_any) else (dom_ok and dow_ok)
        if lt.tm_mon not in month or not day_ok:
            # jump to the next local midnight (never backwards)
            nxt = (_dt.datetime(lt.tm_year, lt.tm_mon, lt.tm_mday)
                   + _dt.timedelta(days=1)).timestamp()
            ts = max(nxt, ts + 60)
            continue
        if lt.tm_min not in minute:
            ts += 60
            continue
        return float(ts)
    return None


def _days_spec(tok: str) -> str | None:
    """'mon,thu' / 'weekdays' / 'friday' → cron day-of-week list, else None."""
    tok = tok.lower().strip(",")
    if tok in ("weekdays", "weekday"):
        return "1-5"
    if tok in ("weekends", "weekend"):
        return "0,6"
    days = []
    for d in tok.split(","):
        d = _DAY_ALIASES.get(d, d)
        if d not in _DAYS:
            return None
        days.append(str(_DAYS[d]))
    return ",".join(days) if days else None


def parse_schedule(text: str, now: float | None = None) -> Schedule:
    """Plain-language or cron schedule → Schedule. Raises HeartbeatError."""
    now = now if now is not None else time.time()
    raw = " ".join(str(text or "").lower().replace(" at ", " ").split())
    if raw.startswith("at "):
        raw = "once " + raw[3:]
    if not raw:
        raise HeartbeatError("no schedule given")
    words = raw.split()

    if re.fullmatch(r"[\d*/,\-]+( [\d*/,\-]+){4}", raw):
        return _cron(raw)

    if words[0] in ("hourly", "every"):
        if raw == "hourly":
            return Schedule("interval", "every 1h", every_s=3600)
        m = re.fullmatch(r"every (\d+) ?([a-z]+)", raw) or re.fullmatch(r"every ()([a-z]+)", raw)
        if m and m.group(2) in _UNIT_S:
            n = int(m.group(1) or 1)
            secs = n * _UNIT_S[m.group(2)]
            if secs < MIN_INTERVAL_S:
                raise HeartbeatError("the shortest interval is one minute")
            unit = "m" if secs % 3600 else ("h" if secs % 86400 else "d")
            val = secs // {"m": 60, "h": 3600, "d": 86400}[unit]
            return Schedule("interval", f"every {val}{unit}", every_s=float(secs))
        if words[0] == "every" and len(words) >= 2:      # "every monday 9am"
            words = words[1:]
        else:
            raise HeartbeatError(f"can't read '{text}' — try 'every 15m', 'every 2h', 'daily 08:30'")

    if words[0] == "in" and len(words) >= 2:
        m = re.fullmatch(r"(\d+) ?([a-z]+)", " ".join(words[1:]))
        if not m or m.group(2) not in _UNIT_S:
            raise HeartbeatError(f"can't read '{text}' — try 'in 30m' or 'in 2h'")
        at = now + int(m.group(1)) * _UNIT_S[m.group(2)]
        return Schedule("once", "at " + time.strftime("%Y-%m-%d %H:%M", time.localtime(at)), at=at)

    if words[0] in ("once", "tomorrow", "today"):
        rest = words[1:] if words[0] == "once" else words
        try:
            if rest and rest[0] in ("tomorrow", "today"):
                h, mi = _parse_time(rest[1] if len(rest) > 1 else "09:00")
                day = _dt.date.fromtimestamp(now) + _dt.timedelta(days=rest[0] == "tomorrow")
                when = _dt.datetime(day.year, day.month, day.day, h, mi)
            else:
                d = _dt.date.fromisoformat(rest[0])
                h, mi = _parse_time(rest[1] if len(rest) > 1 else "09:00")
                when = _dt.datetime(d.year, d.month, d.day, h, mi)
        except (ValueError, IndexError):
            raise HeartbeatError(
                f"can't read '{text}' — try 'at 2026-12-01 09:00' or 'tomorrow 9am'") from None
        return Schedule("once", "at " + when.strftime("%Y-%m-%d %H:%M"), at=when.timestamp())

    if words[0] == "daily":
        h, mi = _parse_time(words[1] if len(words) > 1 else "09:00")
        return _cron(f"{mi} {h} * * *", f"daily {h:02d}:{mi:02d}")
    if words[0] == "monthly":
        if len(words) < 2 or not words[1].isdigit() or not 1 <= int(words[1]) <= 28:
            raise HeartbeatError("monthly needs a day 1-28: 'monthly 1 06:00'")
        h, mi = _parse_time(words[2] if len(words) > 2 else "09:00")
        return _cron(f"{mi} {h} {int(words[1])} * *", f"monthly {int(words[1])} {h:02d}:{mi:02d}")
    if words[0] == "weekly":
        words = words[1:] or ["mon"]
    spec = _days_spec(words[0])
    if spec is not None:
        h, mi = _parse_time(words[1] if len(words) > 1 else "09:00")
        label = {"1-5": "weekdays", "0,6": "weekends"}.get(spec) or ",".join(
            next(k for k, v in _DAYS.items() if str(v) == d) for d in spec.split(","))
        return _cron(f"{mi} {h} * * {spec}", f"{label} {h:02d}:{mi:02d}")
    raise HeartbeatError(
        f"can't read '{text}'. Examples: every 15m · daily 08:30 · weekdays 9am · "
        "mon,thu 18:00 · monthly 1 06:00 · in 2h · at 2026-12-01 09:00 · */10 * * * *")


# --------------------------------------------------------------------------
# actions — a closed registry. Each returns (status, summary).
# --------------------------------------------------------------------------

def _worst_to_status(worst: str) -> str:
    return {"critical": "critical", "error": "critical", "high": "critical",
            "warning": "attention", "attention": "attention",
            "medium": "attention"}.get((worst or "").lower(), "ok")


def _act_patrol(cfg, store, args: dict) -> tuple[str, str]:
    from . import agent
    p = agent.run_patrol(cfg, store, deep=bool(args.get("deep")),
                         use_llm=not bool(args.get("no_llm")))
    return p["status"], p["summary"]


def _act_score(cfg, store, args: dict) -> tuple[str, str]:
    from . import posture
    pos = posture.compute(cfg, store)
    posture.record(cfg, store, min_gap_s=0)
    if pos.get("score") is None:
        return "ok", "health not measured yet"
    top = (pos.get("top_issues") or [{}])[0]
    tail = f" — {top.get('label')}: {top.get('detail')}" if top.get("label") else ""
    return pos.get("state", "ok"), f"health {pos['score']:.0f}/100" + (
        " (provisional)" if pos.get("provisional") else f" grade {pos.get('grade')}") + tail


def _act_security(cfg, store, args: dict) -> tuple[str, str]:
    from . import security
    rep = security.scan(cfg, store, include_cve=bool(args.get("cve", False)))
    return _worst_to_status(rep.get("worst", "")), security.patrol_summary_line(cfg, store)


def _act_comply(cfg, store, args: dict) -> tuple[str, str]:
    from . import comply
    comply.scan(store)
    new = comply.patrol_findings(cfg, store)
    worst = "critical" if any((f.get("severity") or "") == "critical" for f in new) \
        else ("warning" if new else "ok")
    return _worst_to_status(worst), comply.patrol_summary_line(cfg, store)


def _act_backups(cfg, store, args: dict) -> tuple[str, str]:
    from . import backups
    rep = backups.scan(cfg, store)
    return _worst_to_status(rep.get("worst", "")), backups.patrol_summary_line(cfg, store)


def _act_cve(cfg, store, args: dict) -> tuple[str, str]:
    from . import webintel
    res = webintel.scan(cfg, store, force=True)
    bad = bool(res.get("vulns")) or any(e.get("is_eol") for e in res.get("eol", []))
    return ("attention" if bad else "ok"), webintel.summary_line(res)


def _act_certs(cfg, store, args: dict) -> tuple[str, str]:
    from . import certs
    certs.cached_inventory(cfg, store, force=True)
    found = certs.patrol_findings(cfg, store)
    worst = "critical" if any(f.get("severity") == "critical" for f in found) else (
        "warning" if any(f.get("severity") == "warning" for f in found) else "ok")
    return _worst_to_status(worst), certs.patrol_summary_line(cfg, store)


def _act_drift(cfg, store, args: dict) -> tuple[str, str]:
    from . import driftscan
    changes = driftscan.scan(store)
    if not changes:
        return "ok", "drift: no changes since the last scan"
    n = sum(len(c.get("changes", [])) for c in changes)
    first = "; ".join((changes[0].get("changes") or [])[:3])
    return "attention", f"drift: {n} change(s) — [{changes[0].get('kind')}] {first}"


def _act_forecast(cfg, store, args: dict) -> tuple[str, str]:
    from . import forecast
    rep = forecast.feed_report(cfg, store, persist=True)
    return _worst_to_status(rep.get("worst", "")), forecast.patrol_summary_line(cfg, store)


def _act_remind(cfg, store, args: dict) -> tuple[str, str]:
    return "ok", str(args.get("text") or args.get("prompt") or "reminder")[:400]


def _act_digest(cfg, store, args: dict) -> tuple[str, str]:
    return "ok", brief(cfg, store)


ASK_GOAL = """\
This is a scheduled task the operator set up; nobody is watching right now.
Task: {prompt}

Investigate with tools as needed, then answer. Begin your answer with one line
"STATUS: ok", "STATUS: attention" or "STATUS: critical", then at most six short
lines the operator can read on a phone. If you would recommend a change, give
the exact command — do not assume it will be run.
"""


def _act_ask(cfg, store, args: dict) -> tuple[str, str]:
    from . import agent
    prompt = str(args.get("prompt") or "").strip()
    if not prompt:
        return "error", "no prompt"
    usable, why = agent.brain_status(cfg)
    if not usable:
        return "error", f"this job needs a model: {why}"
    run_cfg = copy.copy(cfg)
    run_cfg.policy_tier = _min_tier(cfg.policy_tier, settings(cfg)["max_tier"])
    res = agent.Agent(run_cfg, store).run(ASK_GOAL.format(prompt=prompt), purpose="job")
    if res.get("error"):
        return "error", f"model unreachable: {str(res['error'])[:200]}"
    answer = (res.get("answer") or "").strip()
    status = "ok"
    m = re.match(r"\s*status:\s*(ok|attention|critical)\b[^\n]*\n?", answer, re.I)
    if m:
        status = m.group(1).lower()
        answer = answer[m.end():].strip()
    return status, answer[:1200] or "(no answer)"


def _min_tier(a: str, b: str) -> str:
    order = ("observe", "suggest", "repair", "autonomous")
    ia = order.index(a) if a in order else 1
    ib = order.index(b) if b in order else 1
    return order[min(ia, ib)]


# name → (function, what it does, default notify policy)
ACTIONS: dict = {
    "patrol":   (_act_patrol, "full patrol (the patrol notifies by its own rules)", "never"),
    "brief":    (_act_digest, "a short brief: health, what changed, what waits on you", "always"),
    "score":    (_act_score, "recompute and record the health score", "attention"),
    "security": (_act_security, "security scan against the accepted baseline", "attention"),
    "comply":   (_act_comply, "compliance packs for this OS", "attention"),
    "backups":  (_act_backups, "verify backups are fresh and restorable", "attention"),
    "cve":      (_act_cve, "refresh known vulnerabilities and end-of-life data", "attention"),
    "certs":    (_act_certs, "TLS certificate inventory and expiry", "attention"),
    "drift":    (_act_drift, "what changed on this machine", "attention"),
    "forecast": (_act_forecast, "capacity projections", "attention"),
    "remind":   (_act_remind, "send the operator a reminder (text)", "always"),
    "ask":      (_act_ask, "give the agent a question or task (prompt); needs a model", "always"),
}
NOTIFY_POLICIES = ("always", "attention", "never")

# wrench commands whose habitual use suggests a job
ROUTINE_COMMANDS = {"status": "brief", "score": "brief", "security": "security",
                    "comply": "comply", "backups": "backups", "cve": "cve",
                    "certs": "certs", "forecast": "forecast", "drift": "drift"}


# --------------------------------------------------------------------------
# jobs
# --------------------------------------------------------------------------

_JOB_COLS = ("id, name, schedule, action, args, status, created, created_by, note, next_run, "
             "last_run, last_status, last_summary, runs, fail_streak")


def _job(r) -> dict:
    try:
        args = json.loads(r[4]) if r[4] else {}
    except ValueError:
        args = {}
    return {"id": r[0], "name": r[1], "schedule": r[2], "action": r[3], "args": args,
            "status": r[5], "created": r[6], "created_by": r[7], "note": r[8] or "",
            "next_run": r[9], "last_run": r[10], "last_status": r[11] or "",
            "last_summary": r[12] or "", "runs": r[13], "fail_streak": r[14]}


def list_jobs(store, status: str | None = None) -> list[dict]:
    sql = f"SELECT {_JOB_COLS} FROM jobs"
    args: tuple = ()
    if status:
        sql += " WHERE status = ?"
        args = (status,)
    sql += " ORDER BY CASE status WHEN 'proposed' THEN 0 WHEN 'active' THEN 1 " \
           "WHEN 'paused' THEN 2 ELSE 3 END, COALESCE(next_run, 9e18), name"
    return [_job(r) for r in store.db.execute(sql, args).fetchall()]


def get_job(store, ref) -> dict | None:
    """By name, or by numeric id."""
    if isinstance(ref, int):
        r = store.db.execute(f"SELECT {_JOB_COLS} FROM jobs WHERE id = ?", (ref,)).fetchone()
        return _job(r) if r else None
    ref = str(ref).strip()
    r = store.db.execute(f"SELECT {_JOB_COLS} FROM jobs WHERE name = ?", (ref.lower(),)).fetchone()
    if r is None and ref.isdigit():
        r = store.db.execute(f"SELECT {_JOB_COLS} FROM jobs WHERE id = ?", (int(ref),)).fetchone()
    return _job(r) if r else None


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")[:40].strip("-")
    return s or "job"


def add_job(store, name: str, schedule: str, action: str, args: dict | None = None,
            status: str = "active", created_by: str = "user", note: str = "",
            cfg=None, now: float | None = None) -> dict:
    now = now if now is not None else time.time()
    name = str(name or "").strip().lower()
    if not _NAME_RE.match(name):
        raise HeartbeatError("a job name is lower-case letters, digits and dashes (max 40), "
                             "e.g. 'morning-brief'")
    action = str(action or "").strip().lower()
    if action == "digest":
        action = "brief"
    if action not in ACTIONS:
        raise HeartbeatError(f"unknown action '{action}' — one of: {', '.join(ACTIONS)}")
    if status not in ("active", "proposed", "paused"):
        raise HeartbeatError(f"cannot create a job as '{status}'")
    sched = parse_schedule(schedule, now)
    args = dict(args or {})
    for key in ("prompt", "text"):
        if key in args:
            from . import memory
            args[key] = memory.clean_text(args[key])[:600]
            if memory.looks_secret(args[key]):
                raise HeartbeatError("that looks like a credential — job text is stored in "
                                     "plain text and shown to the model")
    if action == "ask" and not args.get("prompt"):
        raise HeartbeatError("an 'ask' job needs a prompt: what should the agent look into?")
    if action == "remind" and not (args.get("text") or args.get("prompt")):
        raise HeartbeatError("a 'remind' job needs the reminder text")
    if "notify" in args and args["notify"] not in NOTIFY_POLICIES:
        raise HeartbeatError(f"notify is one of: {', '.join(NOTIFY_POLICIES)}")
    if get_job(store, name) is not None and not name.isdigit():
        raise HeartbeatError(f"a job named '{name}' already exists (wrench jobs rm {name})")
    total = store.db.execute("SELECT COUNT(*) FROM jobs WHERE status != 'done'").fetchone()[0]
    if total >= MAX_JOBS:
        raise HeartbeatError(f"{total} jobs already — remove some first")
    if status == "proposed":
        n = store.db.execute("SELECT COUNT(*) FROM jobs WHERE status = 'proposed'").fetchone()[0]
        if n >= MAX_PROPOSED:
            raise HeartbeatError("too many proposals waiting — review them (wrench jobs)")
    nxt = sched.next_after(now) if status == "active" else None
    if status == "active" and nxt is None:
        raise HeartbeatError("that time is already in the past")
    stored = sched.text
    raw = " ".join(str(schedule).lower().split())
    if status == "proposed" and sched.kind == "once" and raw.split()[0] in ("in", "tomorrow",
                                                                             "today"):
        stored = raw         # "in 2h" means two hours after it is approved, not proposed
    store.db.execute(
        "INSERT INTO jobs (name, schedule, action, args, status, created, created_by, note, "
        "next_run) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (name, stored, action, json.dumps(args), status, now, created_by,
         str(note or "")[:300], nxt))
    store.db.commit()
    _audit(cfg, "job.add", {"name": name, "schedule": sched.text, "action": action,
                            "status": status, "by": created_by})
    return get_job(store, name)


def set_job_status(store, ref, status: str, cfg=None, now: float | None = None) -> dict | None:
    """approve / resume → active (next run recomputed); pause → paused."""
    job = get_job(store, ref)
    if job is None:
        return None
    if status not in ("active", "paused"):
        raise HeartbeatError(f"cannot set a job to '{status}'")
    now = now if now is not None else time.time()
    nxt, text = None, job["schedule"]
    if status == "active":
        sched = parse_schedule(job["schedule"], now)
        nxt, text = sched.next_after(now), sched.text
        if nxt is None:
            raise HeartbeatError(f"'{job['name']}' was a one-off for a time that has passed")
    store.db.execute(
        "UPDATE jobs SET status = ?, next_run = ?, schedule = ?, fail_streak = 0 WHERE id = ?",
        (status, nxt, text, job["id"]))
    store.db.commit()
    _audit(cfg, "job.approve" if job["status"] == "proposed" and status == "active"
           else f"job.{status}", {"name": job["name"]})
    return get_job(store, job["id"])


def remove_job(store, ref, cfg=None) -> bool:
    job = get_job(store, ref)
    if job is None:
        return False
    store.db.execute("DELETE FROM jobs WHERE id = ?", (job["id"],))
    store.db.commit()
    _audit(cfg, "job.remove", {"name": job["name"], "was": job["status"]})
    return True


def job_runs(store, ref=None, limit: int = 30) -> list[dict]:
    sql = "SELECT name, ts, duration_s, status, summary FROM job_runs"
    args: list = []
    if ref is not None:
        job = get_job(store, ref)
        sql += " WHERE name = ?"
        args.append(job["name"] if job else str(ref))
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(int(limit))
    return [{"name": r[0], "ts": r[1], "duration_s": r[2], "status": r[3], "summary": r[4] or ""}
            for r in store.db.execute(sql, args).fetchall()]


def _audit(cfg, kind: str, detail: dict) -> None:
    if cfg is None:
        return
    try:
        from . import audit
        audit.log_event(cfg, kind, detail)
    except Exception:  # noqa: BLE001
        pass


def ensure_defaults(cfg, store, patrol_every_min: int | None = None) -> list[dict]:
    """Seed the two jobs every install starts with: the patrol (live) and a
    morning brief (proposed — wrench offers, the operator decides)."""
    made = []
    every = patrol_every_min or int(getattr(cfg, "patrol_interval_min", 15) or 15)
    if get_job(store, "patrol") is None:
        made.append(add_job(store, "patrol", f"every {max(1, every)}m", "patrol",
                            created_by="system", note="the regular patrol", cfg=cfg))
    elif patrol_every_min:
        job = get_job(store, "patrol")
        sched = parse_schedule(f"every {max(1, every)}m")
        store.db.execute("UPDATE jobs SET schedule = ? WHERE id = ?", (sched.text, job["id"]))
        store.db.commit()
    if get_job(store, "morning-brief") is None and not store.cache_get("_brief_offered", 9e18):
        made.append(add_job(
            store, "morning-brief", "weekdays 08:30", "brief", status="proposed",
            created_by="system", cfg=cfg,
            note="A short brief each weekday morning: health, what changed overnight, "
                 "what is waiting on you."))
        store.cache_put("_brief_offered", {"ts": time.time()})
    return made


# --------------------------------------------------------------------------
# running
# --------------------------------------------------------------------------

def _notify(cfg, job: dict, status: str, summary: str) -> None:
    policy = job["args"].get("notify") or ACTIONS.get(job["action"], (None, "", "attention"))[2]
    if policy == "never":
        return
    severity = {"ok": "info", "attention": "attention", "critical": "critical",
                "error": "attention"}.get(status, "info")
    text = f"{job['name']}: {summary}"
    try:
        from . import notifications
        if policy == "always":
            notifications.deliver(cfg, "job", severity, text)
        elif notifications.severity_rank(severity) >= 1:
            notifications.emit_event(cfg, "job", severity, text)
    except Exception:  # noqa: BLE001 — delivery never fails a job
        pass


def run_job(cfg, store, job: dict, now: float | None = None, timeout_s: float | None = None,
            store_factory=None) -> dict:
    """Run one job now and record the outcome. Never raises.

    The action runs on a worker thread with its own database connection, so a
    hung job is abandoned at the timeout instead of stopping the heartbeat."""
    t0 = time.time()
    fn = ACTIONS.get(job["action"], (None,))[0]
    box: dict = {}

    def work():
        st = None
        try:
            st = store_factory() if store_factory else _open_store(cfg)
            box["result"] = fn(cfg, st, job["args"])
        except Exception as e:  # noqa: BLE001
            box["result"] = ("error", f"{e.__class__.__name__}: {e}"[:300])
        finally:
            if st is not None and store_factory is None:
                try:
                    st.close()
                except Exception:  # noqa: BLE001
                    pass

    live_key = f"{getattr(cfg, 'db_path', '')}:{job['name']}"
    earlier = _live.get(live_key)
    if fn is None:
        status, summary = "error", f"unknown action '{job['action']}'"
    elif earlier is not None and earlier.is_alive():
        # a run that passed its timeout cannot be killed (it is a thread); what
        # we can do is never start a second copy beside it
        status, summary = "error", "the previous run has not finished — skipped"
    else:
        limit = timeout_s if timeout_s is not None else settings(cfg)["job_timeout_s"]
        th = threading.Thread(target=work, name=f"wrench-job-{job['name']}", daemon=True)
        _live[live_key] = th
        th.start()
        th.join(limit)
        if th.is_alive():
            status, summary = "error", f"timed out after {int(limit)}s"
        else:
            _live.pop(live_key, None)
            status, summary = box.get("result", ("error", "no result"))
    done = time.time()
    summary = str(summary or "").strip()
    # Decide the job's next state from the row as it is NOW, not as it was when
    # the run began: the operator may have paused, approved or removed it
    # meanwhile, and their decision wins.
    current = get_job(store, job["id"])
    streak = (current or job)["fail_streak"] + 1 if status == "error" else 0
    paused_now = False
    if current is None:
        new_status, nxt = "removed", None
    elif current["status"] != "active":      # paused / proposed (a manual run): leave it be
        new_status, nxt = current["status"], current["next_run"]
    else:
        new_status, nxt = "active", None
        try:
            sched = parse_schedule(current["schedule"], done)
            nxt = sched.next_after(done) if sched.kind != "once" else None
            if sched.kind == "once":
                new_status = "done"
        except HeartbeatError:
            new_status = "paused"
        if streak >= MAX_FAIL_STREAK and new_status == "active":
            new_status, nxt, paused_now = "paused", None, True
    if current is not None:
        store.db.execute(
            "UPDATE jobs SET last_run = ?, last_status = ?, last_summary = ?, runs = runs + 1, "
            "fail_streak = ?, status = ?, next_run = ? WHERE id = ? AND status = ?",
            (done, status, summary[:1200], streak, new_status, nxt, job["id"],
             current["status"]))
    store.db.execute(
        "INSERT INTO job_runs (job_id, name, ts, duration_s, status, summary) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (job["id"], job["name"], t0, round(done - t0, 2), status, summary[:1200]))
    store.db.commit()
    _notify(cfg, job, status, summary)
    if paused_now:
        try:
            from . import notifications
            notifications.emit_event(
                cfg, "job", "attention",
                f"job '{job['name']}' failed {streak} times in a row and is paused — "
                f"last error: {summary[:160]}. Resume with: wrench jobs resume {job['name']}")
        except Exception:  # noqa: BLE001
            pass
    return {"name": job["name"], "action": job["action"], "status": status,
            "summary": summary, "duration_s": round(done - t0, 2), "next_run": nxt,
            "job_status": new_status}


_live: dict = {}        # "<db path>:<job name>" → worker thread still running (see run_job)


def _open_store(cfg):
    from .store import Store
    return Store(cfg.db_path)


class _TickLock:
    """Only one heartbeat at a time. Non-blocking: a beat that finds another
    still running (a long patrol) skips instead of queueing behind it."""

    def __init__(self, data_dir):
        self.path = Path(data_dir) / "heartbeat.lock"
        self.fh = None

    def acquire(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.fh = open(self.path, "a+")  # noqa: SIM115
        except OSError:
            return True                       # unlockable location: carry on
        try:
            import fcntl
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except ImportError:
            try:
                import msvcrt
                self.fh.seek(0)
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                self.release()
                return False
        except OSError:
            self.release()
            return False

    def release(self) -> None:
        if self.fh is not None:
            try:
                if os.name == "nt":
                    import msvcrt
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
            except (ImportError, OSError):
                pass
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None


def due_jobs(store, now: float | None = None) -> list[dict]:
    now = now if now is not None else time.time()
    return [j for j in list_jobs(store, "active")
            if j["next_run"] is not None and j["next_run"] <= now]


def tick(cfg, store, now: float | None = None, on_job=None, store_factory=None) -> dict:
    """One heartbeat. Returns {ts, ran: [...], skipped, proposals}. Never raises
    for a job's sake; a job failure is a recorded outcome."""
    now = now if now is not None else time.time()
    st = settings(cfg)
    out = {"ts": now, "ran": [], "skipped": "", "proposals": []}
    if not st["enabled"]:
        out["skipped"] = "heartbeat is disabled ([heartbeat] enabled = false)"
        return out
    lock = _TickLock(cfg.data_dir)
    if not lock.acquire():
        out["skipped"] = "another heartbeat is still running"
        return out
    try:
        # seed once per install — never again, or removing the last job would
        # bring the patrol back
        if store.cache_get(SEEDED_KEY, 9e18) is None:
            if not list_jobs(store):
                ensure_defaults(cfg, store)
            store.cache_put(SEEDED_KEY, {"ts": now})
        for due in due_jobs(store, now):
            # re-read: the operator may have paused or removed it while an
            # earlier job in this beat was running
            job = get_job(store, due["id"])
            if job is None or job["status"] != "active" or (job["next_run"] or 9e18) > now:
                continue
            if on_job:
                on_job("start", job)
            try:
                res = run_job(cfg, store, job, store_factory=store_factory)
            except Exception as e:  # noqa: BLE001 — one bad job never stops the beat
                res = {"name": job["name"], "action": job["action"], "status": "error",
                       "summary": f"{e.__class__.__name__}: {e}"[:300], "duration_s": 0.0,
                       "next_run": None, "job_status": job["status"]}
            out["ran"].append(res)
            if on_job:
                on_job("done", res)
        try:
            out["proposals"] = reflect(cfg, store, now)
        except Exception:  # noqa: BLE001 — reflection is a nicety
            pass
        prev = store.cache_get(PULSE_KEY, 9e18) or {}
        store.cache_put(PULSE_KEY, {
            "last_tick": time.time(), "ticks": int(prev.get("ticks", 0)) + 1,
            "tick_min": st["tick_min"], "host": platform.node(),
            "last_ran": [r["name"] for r in out["ran"]] or prev.get("last_ran", [])})
    finally:
        lock.release()
    return out


def run_loop(load, interval_s: float = 60.0, stop=None, on_tick=None) -> None:
    """Foreground heartbeat for hosts without a timer (containers, a tmux
    pane). ``load()`` returns a fresh (cfg, store) each beat, so config edits
    are picked up without a restart."""
    while not (stop and stop()):
        t0 = time.time()
        cfg, store = load()
        try:
            res = tick(cfg, store)
            if on_tick:
                on_tick(res)
        finally:
            store.close()
        delay = max(1.0, interval_s - (time.time() - t0))
        end = time.time() + delay
        while time.time() < end and not (stop and stop()):
            time.sleep(min(1.0, end - time.time()) if end > time.time() else 0)


def pulse(store, now: float | None = None) -> dict:
    """Is the heartbeat alive? {last_tick, age_s, alive, ticks, …} — ``alive``
    is None when it has never beaten."""
    now = now if now is not None else time.time()
    p = store.cache_get(PULSE_KEY, 9e18) or {}
    last = p.get("last_tick")
    jobs = list_jobs(store)
    active = [j for j in jobs if j["status"] == "active" and j["next_run"]]
    nxt = min(active, key=lambda j: j["next_run"]) if active else None
    grace = max(3 * int(p.get("tick_min", DEFAULT_TICK_MIN)) * 60, 900)
    return {
        "last_tick": last,
        "age_s": (now - last) if last else None,
        "alive": None if not last else (now - last) <= grace,
        "ticks": int(p.get("ticks", 0)),
        "last_ran": p.get("last_ran", []),
        "jobs": {s: sum(1 for j in jobs if j["status"] == s)
                 for s in ("active", "paused", "proposed")},
        "next": {"name": nxt["name"], "at": nxt["next_run"]} if nxt else None,
    }


# --------------------------------------------------------------------------
# reflection — anticipate: propose doing what the operator does by hand
# --------------------------------------------------------------------------

def reflect(cfg, store, now: float | None = None, force: bool = False) -> list[dict]:
    """At most every few hours: turn a learned routine into a *proposed* job.
    Returns the proposals made. Nothing here runs anything."""
    now = now if now is not None else time.time()
    if not settings(cfg)["propose_routines"]:
        return []
    if not force and store.cache_get(REFLECT_KEY, REFLECT_EVERY_S) is not None:
        return []
    store.cache_put(REFLECT_KEY, {"ts": now})
    from . import memory
    if not memory.settings(cfg)["learn_habits"]:
        return []
    made = []
    for cand in memory.routine_candidates(store, now):
        action = ROUTINE_COMMANDS.get(cand["command"])
        if not action:
            continue
        memory.mark_proposed(store, cand["command"])
        if any(j["action"] == action and j["status"] in ("active", "proposed")
               and j["created_by"] != "system" for j in list_jobs(store)) \
                or (action == "brief" and get_job(store, "morning-brief")
                    and get_job(store, "morning-brief")["status"] == "active"):
            continue                     # already being done on a schedule
        # have it ready a quarter of an hour before they usually ask
        hh, mm = (cand["hour"] - 1) % 24, 45
        name = f"auto-{action}"
        note = (f"You run `wrench {cand['command']}` around {cand['hour']:02d}:00 most days "
                f"({cand['runs']} times over {cand['days']} days). I can have it done "
                f"beforehand and tell you only what needs attention.")
        try:
            if get_job(store, name):
                continue
            job = add_job(store, name, f"daily {hh:02d}:{mm:02d}", action, status="proposed",
                          created_by="learned", note=note, cfg=cfg, now=now)
        except HeartbeatError:
            continue
        made.append(job)
        try:
            memory.add(store, f"The operator usually runs `wrench {cand['command']}` around "
                              f"{cand['hour']:02d}:00.", "observation", source="learned",
                       origin="routine", cfg=cfg, now=now)
        except memory.MemoryError_:
            pass
        try:
            from . import notifications
            notifications.record(cfg.data_dir, "info",
                                 f"proposal: {note} Approve with: wrench jobs approve {name}",
                                 kind="proposal")
        except Exception:  # noqa: BLE001
            pass
    return made


# --------------------------------------------------------------------------
# the brief
# --------------------------------------------------------------------------

def brief(cfg, store, now: float | None = None) -> str:
    """A few lines the operator can read on a phone. Deterministic: built from
    what the store already holds, no model."""
    now = now if now is not None else time.time()
    lines = []
    try:
        from . import posture
        pos = posture.compute(cfg, store)
        if pos.get("score") is not None:
            tr = posture.trend(posture.history(store, days=8), now)
            delta = tr.get("delta")
            lines.append(
                f"health {pos['score']:.0f}/100"
                + (" (provisional)" if pos.get("provisional") else f" {pos.get('grade')}")
                + (f", {delta:+.0f} this week" if delta else ""))
            for issue in (pos.get("top_issues") or [])[:3]:
                lines.append(f"• {issue['label']}: {issue['detail']} → {issue['command']}")
        else:
            lines.append("health not measured yet → wrench patrol")
    except Exception:  # noqa: BLE001
        pass
    try:
        since = now - 86400
        rows = [p for p in store.recent_patrols(400) if p["ts"] >= since]
        if rows:
            bad = [p for p in rows if p["status"] != "ok"]
            lines.append(f"{len(rows)} patrols in 24h, {len(bad)} needed attention"
                         + (f" — latest: {(bad[0].get('summary') or '')[:110]}" if bad else ""))
        else:
            lines.append("no patrol in the last 24h")
    except Exception:  # noqa: BLE001
        pass
    try:
        from . import memory
        waiting = []
        n = memory.counts(store)["pending"]
        if n:
            waiting.append(f"{n} note(s) to review (wrench memory review)")
        n = sum(1 for j in list_jobs(store) if j["status"] == "proposed")
        if n:
            waiting.append(f"{n} proposed job(s) (wrench jobs)")
        if waiting:
            lines.append("waiting on you: " + "; ".join(waiting))
    except Exception:  # noqa: BLE001
        pass
    return "\n".join(lines) or "nothing to report"


# --------------------------------------------------------------------------
# agent tools
# --------------------------------------------------------------------------

def tool_schedule(store, cfg, name: str, schedule: str, action: str, prompt: str = "",
                  confirm_fn=None) -> str:
    """The model asks for recurring or follow-up work. A present human
    confirms it; unattended it is only a proposal."""
    if cfg is not None and not settings(cfg)["enabled"]:
        return "the heartbeat is disabled on this machine."
    action = str(action or "").lower()
    args = {}
    if action in ("ask", "remind"):
        args["prompt" if action == "ask" else "text"] = prompt
    name = slug(name or f"{action}-{schedule}")
    try:
        sched = parse_schedule(schedule)
        if confirm_fn is not None:
            from . import memory
            shown = memory.clean_text(prompt)[:600]      # exactly what would be stored
            if not confirm_fn(f"{name}: {action} — {sched.text}"
                              + (f" — {shown}" if shown else ""), "schedule: add this job"):
                return "NOT SCHEDULED: the human declined. Do not ask again in this conversation."
            job = add_job(store, name, schedule, action, args, created_by="agent", cfg=cfg)
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(job["next_run"]))
            return f"scheduled '{job['name']}' ({job['schedule']}); first run {when}"
        job = add_job(store, name, schedule, action, args, status="proposed",
                      created_by="agent", cfg=cfg,
                      note="proposed by the agent during an unattended run")
        return (f"proposed as '{job['name']}' — it will not run until the operator approves "
                f"it (wrench jobs approve {job['name']}). Say so in your answer.")
    except HeartbeatError as e:
        return f"NOT SCHEDULED: {e}"


def tool_jobs(store) -> str:
    jobs = [j for j in list_jobs(store) if j["status"] != "done"]
    if not jobs:
        return "no scheduled jobs."
    out = []
    for j in jobs:
        nxt = time.strftime("%m-%d %H:%M", time.localtime(j["next_run"])) if j["next_run"] else "—"
        out.append(f"{j['name']} [{j['status']}] {j['schedule']} → {j['action']}"
                   f" · next {nxt} · last {j['last_status'] or 'never'}")
    return "\n".join(out)
