"""wrench maintenance windows — parser + in/out-of-window logic + the gate.

All clock-injected; no host time dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import pytest

from wrench import windows as W


@dataclass
class FakeCfg:
    raw: dict = field(default_factory=dict)


# ---------------- parser ----------------

def test_parse_single_day():
    w = W.parse_window("Sat 02:00-06:00")
    assert w.days == {5}
    assert w.start_min == 120 and w.end_min == 360
    assert not w.crosses_midnight


def test_parse_day_range():
    w = W.parse_window("Mon-Fri 23:00-23:59")
    assert w.days == {0, 1, 2, 3, 4}


def test_parse_wrapping_day_range():
    w = W.parse_window("Fri-Mon 01:00-02:00")
    assert w.days == {4, 5, 6, 0}


def test_parse_any_day_tokens():
    for tok in ("*", "any", "daily"):
        assert W.parse_window(f"{tok} 00:00-01:00").days == set(range(7))


def test_parse_rejects_bad_input():
    for bad in ("", "Sat", "Funday 01:00-02:00", "Sat 25:00-26:00", "Sat 0200-0600"):
        with pytest.raises(ValueError):
            W.parse_window(bad)


def test_parse_windows_collects_errors():
    wins, errs = W.parse_windows(["Sat 02:00-06:00", "garbage", ""])
    assert len(wins) == 1 and len(errs) == 1


# ---------------- containment ----------------

def _dt(y=2026, mo=11, d=7, h=3, mi=0):  # 2026-11-07 is a Saturday
    return datetime(y, mo, d, h, mi)


def test_in_window_true():
    w = W.parse_window("Sat 02:00-06:00")
    assert W.window_contains(w, _dt(h=3))        # Sat 03:00
    assert W.window_contains(w, _dt(h=2, mi=0))  # inclusive start


def test_in_window_false_wrong_day_or_time():
    w = W.parse_window("Sat 02:00-06:00")
    assert not W.window_contains(w, _dt(h=6, mi=0))     # exclusive end
    assert not W.window_contains(w, _dt(h=1))           # before start
    assert not W.window_contains(w, _dt(d=8, h=3))      # Sunday


def test_crosses_midnight():
    w = W.parse_window("Fri 22:00-02:00")
    assert w.crosses_midnight
    # Friday 23:00 (2026-11-06 is a Friday)
    assert W.window_contains(w, datetime(2026, 11, 6, 23, 0))
    # Saturday 01:00 — the tail of Friday's window
    assert W.window_contains(w, datetime(2026, 11, 7, 1, 0))
    # Saturday 03:00 — past the tail
    assert not W.window_contains(w, datetime(2026, 11, 7, 3, 0))


# ---------------- gate ----------------

def _cfg(specs, tz=""):
    raw = {"maintenance": {"windows": specs}}
    if tz:
        raw["maintenance"]["timezone"] = tz
    return FakeCfg(raw=raw)


def test_gate_no_windows_is_unrestricted():
    d = W.gate(FakeCfg(), "fixxer apply", override=False, has_consent=False,
               now=_dt())
    assert d.allowed and not d.restricted and not d.overridden


def test_gate_inside_window_allows():
    d = W.gate(_cfg(["Sat 02:00-06:00"]), "fixxer apply",
               override=False, has_consent=False, now=_dt(h=3))
    assert d.allowed and d.restricted and not d.overridden


def test_gate_outside_window_blocks():
    d = W.gate(_cfg(["Sat 02:00-06:00"]), "fixxer apply",
               override=False, has_consent=False, now=_dt(h=12))
    assert not d.allowed
    assert "blocked" in d.reason.lower()


def test_gate_override_without_consent_blocks():
    d = W.gate(_cfg(["Sat 02:00-06:00"]), "blueprint --execute",
               override=True, has_consent=False, now=_dt(h=12))
    assert not d.allowed
    assert "consent" in d.reason.lower()


def test_gate_override_with_consent_allows_and_flags():
    d = W.gate(_cfg(["Sat 02:00-06:00"]), "certs renew --execute",
               override=True, has_consent=True, now=_dt(h=12))
    assert d.allowed and d.overridden
    assert "override-window" in d.reason


def test_gate_timezone_resolution_epoch():
    # epoch for 2026-11-07 10:00 UTC; in US/Pacific that's 02:00 → inside window
    import calendar
    epoch = calendar.timegm((2026, 11, 7, 10, 0, 0, 0, 0, 0))
    d = W.gate(_cfg(["Sat 02:00-06:00"], tz="America/Los_Angeles"),
               "fixxer apply", override=False, has_consent=False, now=epoch)
    assert d.allowed


def test_settings_restricted_flag():
    assert W.settings_from(_cfg(["Sat 02:00-06:00"])).restricted
    assert not W.settings_from(FakeCfg()).restricted


# ---------------- CLI gate wiring (_enforce_window) ----------------

@dataclass
class _GateCfg:
    raw: dict = field(default_factory=dict)
    data_dir: object = None


def test_enforce_window_blocks_with_exit(tmp_path, monkeypatch):
    import typer
    from wrench import cli, windows as win
    cfg = _GateCfg(data_dir=tmp_path)
    monkeypatch.setattr(win, "gate", lambda *a, **k: win.WindowDecision(
        False, False, "fixxer apply blocked: outside window", True))
    with pytest.raises(typer.Exit) as ei:
        cli._enforce_window(cfg, "fixxer apply", False, False)
    assert ei.value.exit_code == 2


def test_enforce_window_override_audits(tmp_path, monkeypatch):
    from wrench import cli, windows as win, audit
    cfg = _GateCfg(data_dir=tmp_path)
    monkeypatch.setattr(win, "gate", lambda *a, **k: win.WindowDecision(
        True, True, "certs renew --execute executed OUTSIDE window via --override-window", True))
    cli._enforce_window(cfg, "certs renew --execute", True, True)
    recs = audit.recent(tmp_path, 10)
    assert any(r["kind"] == "window.override" for r in recs)
    assert audit.verify(tmp_path)["intact"]


def test_enforce_window_unrestricted_noop(tmp_path):
    from wrench import cli, audit
    cfg = _GateCfg(data_dir=tmp_path)  # no [maintenance] → unrestricted
    cli._enforce_window(cfg, "fixxer apply", False, False)  # must not raise
    # no windows → no override event sealed
    assert audit.read_records(tmp_path) == []
