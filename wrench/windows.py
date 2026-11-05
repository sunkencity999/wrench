"""wrench maintenance windows — when is it OK to change the machine?

Enterprises don't let tools mutate production whenever they please; changes
happen inside approved windows. This module parses a small, human-readable
window grammar and answers one question: *is now inside an allowed window?*

Config (``[maintenance]`` in config.toml) — **empty/missing = no restriction**,
so a home user who never configures this sees exactly the current behavior::

    [maintenance]
    windows  = ["Sat 02:00-06:00", "Sun 02:00-06:00", "Mon-Fri 23:00-23:59"]
    timezone = "America/Los_Angeles"   # optional; local time if unset

Grammar per entry: ``<day> HH:MM-HH:MM``
  - day: ``Mon Tue Wed Thu Fri Sat Sun`` (case-insensitive, 3-letter),
    a range ``Mon-Fri``, or ``*`` / ``any`` / ``daily`` for every day;
  - time: 24-hour ``HH:MM-HH:MM``. ``end <= start`` means the window crosses
    midnight into the next day (``Fri 22:00-02:00`` = Fri 22:00 → Sat 02:00).

Only *executing* state-changing operations consult this (fixxer apply, blueprint
--execute, certs renew --execute). Everything here is pure and clock-injectable
so tests pin the time with no host dependency.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

_DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}
_DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_ANY_DAY = {"*", "any", "daily", "everyday", "all"}


@dataclass
class Window:
    days: set[int]      # weekday ints (Mon=0 .. Sun=6)
    start_min: int      # minutes since midnight, inclusive
    end_min: int        # minutes since midnight, exclusive
    spec: str = ""      # original text, for messages

    @property
    def crosses_midnight(self) -> bool:
        return self.end_min <= self.start_min


@dataclass
class MaintenanceSettings:
    windows: list[Window] = field(default_factory=list)
    timezone: str = ""
    raw_specs: list[str] = field(default_factory=list)

    @property
    def restricted(self) -> bool:
        """True when at least one valid window is configured."""
        return bool(self.windows)


def _parse_day_field(field_txt: str) -> set[int]:
    f = field_txt.strip().lower()
    if f in _ANY_DAY:
        return set(range(7))
    if "-" in f:  # range like mon-fri (inclusive, wrapping allowed: fri-mon)
        a, _, b = f.partition("-")
        if a[:3] in _DAYS and b[:3] in _DAYS:
            start, end = _DAYS[a[:3]], _DAYS[b[:3]]
            if start <= end:
                return set(range(start, end + 1))
            return set(range(start, 7)) | set(range(0, end + 1))
        raise ValueError(f"bad day range {field_txt!r}")
    if f[:3] in _DAYS:
        return {_DAYS[f[:3]]}
    raise ValueError(f"unknown day {field_txt!r}")


def _parse_hhmm(t: str) -> int:
    h, _, m = t.strip().partition(":")
    hi, mi = int(h), int(m)
    if not (0 <= hi <= 23 and 0 <= mi <= 59):
        raise ValueError(f"bad time {t!r}")
    return hi * 60 + mi


def parse_window(spec: str) -> Window:
    """Parse one ``<day> HH:MM-HH:MM`` entry. Raises ValueError on bad input."""
    parts = spec.strip().split()
    if len(parts) != 2:
        raise ValueError(f"window must be '<day> HH:MM-HH:MM', got {spec!r}")
    days = _parse_day_field(parts[0])
    lo_txt, _, hi_txt = parts[1].partition("-")
    if not hi_txt:
        raise ValueError(f"window needs a time range HH:MM-HH:MM, got {spec!r}")
    start, end = _parse_hhmm(lo_txt), _parse_hhmm(hi_txt)
    return Window(days=days, start_min=start, end_min=end, spec=spec.strip())


def parse_windows(specs: list[str]) -> tuple[list[Window], list[str]]:
    """Parse many specs → (valid windows, error-notes for the invalid ones)."""
    out: list[Window] = []
    errs: list[str] = []
    for s in specs or []:
        if not str(s).strip():
            continue
        try:
            out.append(parse_window(str(s)))
        except ValueError as e:
            errs.append(str(e))
    return out, errs


def settings_from(cfg) -> MaintenanceSettings:
    sec = (getattr(cfg, "raw", None) or {}).get("maintenance", {})
    if not isinstance(sec, dict):
        sec = {}
    specs = sec.get("windows", []) or []
    if isinstance(specs, str):
        specs = [specs]
    windows, _errs = parse_windows(list(specs))
    return MaintenanceSettings(
        windows=windows,
        timezone=str(sec.get("timezone", "") or ""),
        raw_specs=[str(s) for s in specs],
    )


def _minute_of_day(dt: datetime) -> int:
    return dt.hour * 60 + dt.minute


def window_contains(w: Window, dt: datetime) -> bool:
    """Is datetime ``dt`` inside window ``w``? Pure; handles midnight crossing."""
    minute = _minute_of_day(dt)
    wd = dt.weekday()
    if not w.crosses_midnight:
        return wd in w.days and w.start_min <= minute < w.end_min
    # crosses midnight: active late on a listed day, or early on the next day
    if wd in w.days and minute >= w.start_min:
        return True
    prev_day = (wd - 1) % 7
    return prev_day in w.days and minute < w.end_min


def in_any_window(windows: list[Window], dt: datetime) -> bool:
    return any(window_contains(w, dt) for w in windows)


def now_for(settings: MaintenanceSettings, now: datetime | float | None = None) -> datetime:
    """Resolve 'now' as a datetime in the configured timezone.

    Accepts an injected datetime (used verbatim), an epoch float, or None
    (wall clock). Falls back to local time if the tz name is unusable.
    """
    if isinstance(now, datetime):
        return now
    epoch = now if isinstance(now, (int, float)) else time.time()
    if settings.timezone:
        try:
            from zoneinfo import ZoneInfo
            return datetime.fromtimestamp(epoch, ZoneInfo(settings.timezone))
        except Exception:  # noqa: BLE001 — bad tz name → local time
            pass
    return datetime.fromtimestamp(epoch)


@dataclass
class WindowDecision:
    allowed: bool
    overridden: bool
    reason: str
    restricted: bool


def describe(settings: MaintenanceSettings) -> str:
    return ", ".join(w.spec for w in settings.windows) or "(none)"


def next_window_hint(settings: MaintenanceSettings,
                     now: datetime | None = None) -> str:
    """Human hint for when the next window opens (best-effort, 7-day scan)."""
    if not settings.windows:
        return ""
    base = now_for(settings, now)
    probe = base.replace(second=0, microsecond=0)
    for _ in range(7 * 24 * 60 // 15 + 1):  # 15-min granularity, one week
        if in_any_window(settings.windows, probe):
            return probe.strftime("%a %H:%M")
        probe = probe + timedelta(minutes=15)
    return ""


def gate(cfg, operation: str, override: bool, has_consent: bool,
         now: datetime | float | None = None) -> WindowDecision:
    """Decide whether ``operation`` may execute right now.

    - No windows configured → always allowed (home-user default, unchanged).
    - Inside a window → allowed.
    - Outside, no override → blocked.
    - Outside, --override-window WITHOUT consent → blocked (override needs consent).
    - Outside, --override-window WITH consent → allowed + overridden (audit it).
    """
    settings = settings_from(cfg)
    if not settings.restricted:
        return WindowDecision(True, False, "no maintenance windows configured", False)
    dt = now_for(settings, now)
    if in_any_window(settings.windows, dt):
        return WindowDecision(True, False, "inside an allowed maintenance window", True)
    wins = describe(settings)
    hint = next_window_hint(settings, dt)
    hint_txt = f" Next window: {hint}." if hint else ""
    if not override:
        return WindowDecision(
            False, False,
            f"{operation} blocked: outside the allowed maintenance window(s) "
            f"[{wins}].{hint_txt} Pass --override-window (with consent) to proceed.",
            True)
    if not has_consent:
        return WindowDecision(
            False, False,
            f"{operation}: --override-window requires consent. Record consent "
            f"first (the operation's --setup-consent / consent flow), then retry.",
            True)
    return WindowDecision(
        True, True,
        f"{operation} executed OUTSIDE maintenance window(s) [{wins}] via "
        f"--override-window with consent", True)
