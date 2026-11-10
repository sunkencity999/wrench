"""Tests for the capacity-forecasting trend engine and future-incidents feed."""

from __future__ import annotations

import time

import pytest

from wrench import forecast
from wrench.store import Store


DAY = 86400.0


def _series(start_ts, n, step_s, fn):
    return [(start_ts + i * step_s, fn(i)) for i in range(n)]


# ---- linear_fit / fit_trend ------------------------------------------------


def test_linear_fit_perfect_line():
    pts = [(0, 10), (1, 12), (2, 14), (3, 16)]
    slope, intercept, r2 = forecast.linear_fit(pts)
    assert slope == pytest.approx(2.0)
    assert intercept == pytest.approx(10.0)
    assert r2 == pytest.approx(1.0)


def test_linear_fit_degenerate_single_x():
    assert forecast.linear_fit([(5, 1), (5, 2), (5, 3)]) is None
    assert forecast.linear_fit([(1, 1)]) is None


def test_fit_trend_steady_growth_per_day():
    # +0.5 %/hour → +12 %/day, hourly samples over 2 days
    now = time.time()
    s = _series(now, 48, 3600, lambda i: 50.0 + 0.5 * i)
    t = forecast.fit_trend(s)
    assert t is not None
    assert t.slope_per_day == pytest.approx(12.0, rel=1e-3)
    assert t.n == 48
    assert t.current == pytest.approx(50.0 + 0.5 * 47)
    assert t.r2 == pytest.approx(1.0, abs=1e-6)


def test_fit_trend_insufficient_samples():
    now = time.time()
    s = _series(now, 4, 3600, lambda i: float(i))
    assert forecast.fit_trend(s) is None


def test_fit_trend_insufficient_span():
    # plenty of points but all inside 1 hour (< MIN_SPAN_S)
    now = time.time()
    s = _series(now, 30, 60, lambda i: float(i))
    assert forecast.fit_trend(s) is None


def test_fit_trend_tolerates_gaps():
    # a gap in the middle must not break the fit; slope stays ~ +6/day
    now = time.time()
    first = _series(now, 12, 3600, lambda i: 10.0 + 0.25 * i)
    gap_start = now + 24 * 3600
    second = _series(gap_start, 12, 3600, lambda i: 10.0 + 0.25 * (24 + i))
    t = forecast.fit_trend(first + second)
    assert t is not None
    assert t.slope_per_day == pytest.approx(6.0, rel=1e-6)


def test_fit_trend_noise_recovers_underlying_slope():
    now = time.time()
    # +4/day underlying with deterministic zig-zag noise
    noise = [+2, -2, +1, -1, +3, -3, 0, +2, -2, +1, -1, +2,
             -2, +1, -1, +2, -2, +1, -1, 0, +1, -1, +2, -2]
    s = [(now + i * 3600, 40.0 + (4.0 / 24) * i + noise[i % len(noise)])
         for i in range(48)]
    t = forecast.fit_trend(s)
    assert t is not None
    assert t.slope_per_day == pytest.approx(4.0, abs=0.6)
    assert 0.5 < t.r2 <= 1.0


# ---- project_eta_days: the threshold ladder --------------------------------


def _trend(current, slope_per_day, n=48, span_days=2.0, r2=1.0):
    now = time.time()
    return forecast.Trend(slope_per_day=slope_per_day, intercept=current,
                          r2=r2, n=n, span_days=span_days, current=current,
                          first_ts=now - span_days * DAY, last_ts=now)


def test_project_eta_basic():
    # 90% now, +1%/day, threshold 95% → 5 days
    t = _trend(90.0, 1.0)
    assert forecast.project_eta_days(t, 95.0) == pytest.approx(5.0)


def test_project_eta_flat_series_no_risk():
    assert forecast.project_eta_days(_trend(90.0, 0.0), 95.0) is None


def test_project_eta_shrinking_series_no_risk():
    # a backup freed space — negative growth must never cry wolf
    assert forecast.project_eta_days(_trend(90.0, -2.0), 95.0) is None


def test_project_eta_already_over_threshold():
    assert forecast.project_eta_days(_trend(96.0, 1.0), 95.0) == 0.0


def test_severity_for_eta_ladder():
    assert forecast.severity_for_eta(2) == "critical"
    assert forecast.severity_for_eta(3) == "critical"
    assert forecast.severity_for_eta(5) == "warning"
    assert forecast.severity_for_eta(7) == "warning"
    assert forecast.severity_for_eta(10) == "info"
    assert forecast.severity_for_eta(14) == "info"
    assert forecast.severity_for_eta(30) == "none"
    assert forecast.severity_for_eta(None) == "none"


def test_confidence_scales_with_evidence():
    strong = forecast.confidence(_trend(50, 1, n=60, span_days=5, r2=0.95))
    weak = forecast.confidence(_trend(50, 1, n=9, span_days=0.3, r2=0.2))
    assert strong[0] == "high"
    assert weak[0] == "low"
    assert strong[1] > weak[1]


# ---- series extraction -----------------------------------------------------


def test_disk_and_inode_series_extraction():
    samples = [
        (100.0, {"disk_pct": {"/": 80.0, "/var": 50.0}, "inode_pct": {"/": 10.0}}),
        (200.0, {"disk_pct": {"/": 82.0, "/var": 51.0}, "inode_pct": {"/": 11.0}}),
    ]
    ds = forecast.disk_series(samples)
    assert ds["/"] == [(100.0, 80.0), (200.0, 82.0)]
    assert ds["/var"] == [(100.0, 50.0), (200.0, 51.0)]
    ins = forecast.inode_series(samples)
    assert ins["/"] == [(100.0, 10.0), (200.0, 11.0)]


def test_log_series_extraction():
    samples = [
        (100.0, {"log_dirs": {"/var/log": {"bytes": 1000, "files": 5}}}),
        (200.0, {"log_dirs": {"/var/log": {"bytes": 2000, "files": 6}}}),
    ]
    ls = forecast.log_series(samples)
    assert ls["/var/log"] == [(100.0, 1000.0), (200.0, 2000.0)]


# ---- capacity_incidents over a live store ----------------------------------


def _store_with_disk(tmp_path, mount, start_pct, slope_per_day, n=48):
    st = Store(tmp_path / "f.db")
    now = time.time()
    for i in range(n):
        ts = now - (n - 1 - i) * 3600  # hourly, ending ~now
        pct = start_pct + slope_per_day * ((ts - (now - (n - 1) * 3600)) / DAY)
        st.add_sample("os", {"disk_pct": {mount: round(pct, 3)}}, ts=ts)
    return st, now


def test_capacity_incident_projects_disk_fill(tmp_path):
    st, now = _store_with_disk(tmp_path, "/data", 90.0, 1.0)
    incs = forecast.capacity_incidents(st, now=now)
    disk = [i for i in incs if i.kind == "disk" and i.resource == "/data"]
    assert disk, "expected a disk projection"
    inc = disk[0]
    assert inc.eta_days is not None
    # current ~92% (90 + ~1.96 days of +1%/day), headroom ~3% → ETA ~3 days
    assert inc.eta_days == pytest.approx(3.0, abs=0.6)
    assert inc.severity in ("critical", "warning")
    assert inc.unit == "%"
    assert inc.growth_per_day == pytest.approx(1.0, abs=0.05)
    st.close()


def test_capacity_incident_flat_disk_no_eta(tmp_path):
    st, now = _store_with_disk(tmp_path, "/", 60.0, 0.0)
    incs = forecast.capacity_incidents(st, now=now)
    disk = [i for i in incs if i.resource == "/"]
    assert disk and disk[0].eta_days is None and disk[0].severity == "none"
    st.close()


def test_capacity_incident_thin_history_skipped(tmp_path):
    st = Store(tmp_path / "f.db")
    now = time.time()
    for i in range(3):
        st.add_sample("os", {"disk_pct": {"/": 90.0 + i}}, ts=now - (2 - i) * 3600)
    assert forecast.capacity_incidents(st, now=now) == []
    st.close()


# ---- cert merge + feed assembly --------------------------------------------


def test_cert_severity_ladder():
    assert forecast._cert_severity(-1) == "critical"
    assert forecast._cert_severity(2) == "critical"
    assert forecast._cert_severity(6) == "warning"
    assert forecast._cert_severity(12) == "info"
    assert forecast._cert_severity(40) == "none"
    assert forecast._cert_severity(None) == "none"


def test_cert_incidents_from_store(tmp_path, monkeypatch):
    # keep the host's own certificates out of the store
    from wrench import certs
    monkeypatch.setattr(certs, "cached_inventory", lambda *a, **k: [])
    st = Store(tmp_path / "f.db")
    st.upsert_cert({"path": "/etc/ssl/a.pem", "subject": "CN=api.example.com",
                    "days_left": 5, "not_after": time.time() + 5 * DAY,
                    "sans": ["api.example.com"]})
    st.upsert_cert({"path": "/etc/ssl/bad.pem", "subject": "CN=broken",
                    "error": "parse failed"})

    class _Cfg:
        pass
    incs = forecast.cert_incidents(_Cfg(), st)
    assert len(incs) == 1  # errored cert skipped
    inc = incs[0]
    assert inc.kind == "cert" and inc.resource == "api.example.com"
    assert inc.severity == "warning" and inc.eta_days == pytest.approx(5.0)
    assert inc.source == "certwrench"
    st.close()


def test_build_feed_sorts_by_eta_and_merges(tmp_path):
    st, now = _store_with_disk(tmp_path, "/data", 92.0, 1.0)  # ~3 days → warning/critical
    st.upsert_cert({"path": "/c.pem", "subject": "CN=soon", "days_left": 1,
                    "not_after": now + DAY, "sans": ["soon"]})

    class _Cfg:
        pass
    feed = forecast.build_feed(_Cfg(), st, now=now)
    assert feed, "feed should not be empty"
    # soonest first — the 1-day cert beats the ~3-day disk
    assert feed[0].kind == "cert"
    kinds = {i.kind for i in feed}
    assert "disk" in kinds and "cert" in kinds
    st.close()


def test_feed_report_shape_and_persist(tmp_path):
    st, now = _store_with_disk(tmp_path, "/data", 93.0, 1.0)

    class _Cfg:
        pass
    rep = forecast.feed_report(_Cfg(), st, now=now, persist=True)
    assert set(rep) >= {"worst", "counts", "incidents", "soonest", "thresholds"}
    assert rep["worst"] in ("critical", "warning", "info", "none")
    snap = st.last_snapshot(forecast.FORECAST_KIND)
    assert snap is not None and snap[1]["counts"] == rep["counts"]
    st.close()


# ---- patrol integration ----------------------------------------------------


def test_patrol_findings_capacity_only(tmp_path):
    st, now = _store_with_disk(tmp_path, "/data", 93.0, 1.0)  # ~2 days → critical
    st.upsert_cert({"path": "/c.pem", "subject": "CN=soon", "days_left": 1,
                    "not_after": now + DAY, "sans": ["soon"]})

    class _Cfg:
        pass
    findings = forecast.patrol_findings(_Cfg(), st)
    assert findings, "disk projection should raise a finding"
    # certs are paged by certwrench, not forecast — no cert text here
    assert all("cert" not in f["text"].lower() for f in findings)
    assert any(f["severity"] in ("critical", "warning") for f in findings)
    st.close()


def test_patrol_summary_line_no_incidents(tmp_path):
    st = Store(tmp_path / "f.db")
    now = time.time()
    for i in range(48):
        st.add_sample("os", {"disk_pct": {"/": 30.0}}, ts=now - (47 - i) * 3600)

    class _Cfg:
        pass
    line = forecast.patrol_summary_line(_Cfg(), st)
    assert "forecast:" in line and "no incidents" in line
    st.close()


def test_narration_lines_pure():
    rep = {"worst": "warning", "counts": {"critical": 0, "warning": 1, "info": 0},
           "incidents": [{"severity": "warning", "kind": "disk", "resource": "/data",
                          "detail": "92% now, +1/day → 95% in ~3d"}]}
    lines = forecast.narration_lines(rep)
    assert any("disk /data" in ln for ln in lines)
    assert lines[0].startswith("capacity forecast")
