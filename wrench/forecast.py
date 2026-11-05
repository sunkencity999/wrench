"""Capacity forecasting — see the incident before it happens.

A least-squares trend engine over the sensor-history sqlite (the same ``os``
samples ``wrench status`` records) projects when a resource crosses a danger
threshold, and folds certificate expiry into one unified **future-incidents
feed**:

    disk /var fills in ~6 days (92% now, +1.2%/day, high confidence)
    TLS cert api.example.com expires in 11 days
    inode table on / at current rate crosses 95% in ~40 days (low confidence)

Design rules (robust to the real, gappy, noisy history a box actually has):
- Require a minimum sample count AND a minimum time span before projecting.
- Fit on mean-centred days; report growth per day and R² goodness-of-fit.
- Clamp non-positive growth to "no risk" (a shrinking or flat series never
  produces an ETA — a backup just freed 40 GB, we don't cry wolf).
- Confidence is derived from sample count, time span, and R², never asserted.

Everything here is read-only and never raises into a patrol: a forecast is a
courtesy, not a tripwire that can wedge the sweep.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

# ---- thresholds & ladders -------------------------------------------------

# Danger thresholds per metric family (percent).
DEFAULT_THRESHOLDS = {
    "disk": 95.0,
    "inode": 95.0,
    "memory": 95.0,
    "swap": 95.0,
}

# Lead-time notification ladder (days until the projected incident).
LEAD_CRITICAL_D = 3
LEAD_WARNING_D = 7
LEAD_INFO_D = 14

# Trend-quality gates.
MIN_SAMPLES = 8          # fewer points than this → "insufficient history"
MIN_SPAN_S = 3600 * 6    # and the points must span at least this long
# Growth below this (percent/day, or bytes/day for logs) counts as flat.
FLAT_EPS_PCT = 0.01
FLAT_EPS_BYTES = 1024.0

FORECAST_KIND = "forecast_feed"  # snapshot kind for the last computed feed

_SEV_RANK = {"none": 0, "info": 1, "warning": 2, "critical": 3}


def severity_for_eta(eta_days: float | None) -> str:
    """Map days-until-incident onto the lead-time ladder."""
    if eta_days is None:
        return "none"
    if eta_days <= LEAD_CRITICAL_D:
        return "critical"
    if eta_days <= LEAD_WARNING_D:
        return "warning"
    if eta_days <= LEAD_INFO_D:
        return "info"
    return "none"


# ---- trend math -----------------------------------------------------------


@dataclass
class Trend:
    """A least-squares fit of value-vs-time, slope expressed per day."""
    slope_per_day: float
    intercept: float            # value at the first sample's time
    r2: float
    n: int
    span_days: float
    current: float
    first_ts: float
    last_ts: float

    def value_at_days(self, days_from_first: float) -> float:
        return self.intercept + self.slope_per_day * days_from_first


def linear_fit(points: list[tuple[float, float]]) -> tuple[float, float, float] | None:
    """Ordinary least squares on (x, y). Returns (slope, intercept, r2).

    ``x`` is taken as-is (caller supplies days). Returns None when there are
    fewer than two distinct x values (slope undefined).
    """
    n = len(points)
    if n < 2:
        return None
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx <= 1e-12:
        return None  # all samples at effectively one instant
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = my - slope * mx
    syy = sum((y - my) ** 2 for y in ys)
    if syy <= 1e-12:
        r2 = 1.0  # a perfectly flat series is perfectly "explained"
    else:
        ss_res = sum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys))
        r2 = max(0.0, 1.0 - ss_res / syy)
    return slope, intercept, r2


def fit_trend(series: list[tuple[float, float]], *, min_samples: int = MIN_SAMPLES,
              min_span_s: float = MIN_SPAN_S) -> Trend | None:
    """Fit a Trend to a (ts_seconds, value) series, or None if too thin.

    The x-axis is converted to *days since the first sample* so slope is a
    human-meaningful per-day growth rate and the fit is numerically stable.
    """
    pts = sorted((t, v) for t, v in series if t is not None and v is not None)
    if len(pts) < min_samples:
        return None
    t0 = pts[0][0]
    span_s = pts[-1][0] - t0
    if span_s < min_span_s:
        return None
    day_points = [((t - t0) / 86400.0, v) for t, v in pts]
    fit = linear_fit(day_points)
    if fit is None:
        return None
    slope, intercept, r2 = fit
    return Trend(
        slope_per_day=slope,
        intercept=intercept,
        r2=r2,
        n=len(pts),
        span_days=round(span_s / 86400.0, 3),
        current=pts[-1][1],
        first_ts=t0,
        last_ts=pts[-1][0],
    )


def confidence(trend: Trend) -> tuple[str, float]:
    """Confidence label + 0..1 score from sample count, span, and R².

    A projection earns trust by being backed by many points over a long window
    with a tight linear fit. Any one of those being weak drags the score down.
    """
    n_factor = min(1.0, trend.n / 48.0)        # ~48 samples saturates
    span_factor = min(1.0, trend.span_days / 3.0)  # ~3 days saturates
    fit_factor = max(0.0, min(1.0, trend.r2))
    score = round(n_factor * 0.3 + span_factor * 0.3 + fit_factor * 0.4, 3)
    if score >= 0.7 and trend.r2 >= 0.6:
        label = "high"
    elif score >= 0.4:
        label = "medium"
    else:
        label = "low"
    return label, score


def project_eta_days(trend: Trend, threshold: float, *,
                     flat_eps: float = FLAT_EPS_PCT) -> float | None:
    """Days from *now* until the trend reaches ``threshold``.

    Returns None when the series is flat/shrinking (slope ≤ eps) or already at
    or above the threshold with no growth. Negative headroom with positive
    growth (already over threshold) returns 0.0.
    """
    if trend.slope_per_day <= flat_eps:
        return None
    headroom = threshold - trend.current
    if headroom <= 0:
        return 0.0
    eta = headroom / trend.slope_per_day
    return round(eta, 2) if eta >= 0 else 0.0


# ---- future-incident model ------------------------------------------------


@dataclass
class Incident:
    kind: str                 # disk | inode | memory | swap | log | cert
    resource: str             # mount path / "memory" / cert common name
    metric: str               # disk_pct | inode_pct | mem_pct | swap_pct | bytes | days
    current: float
    unit: str                 # "%" | "bytes" | "days"
    threshold: float | None
    growth_per_day: float
    eta_days: float | None
    eta_date: str | None
    confidence: str
    confidence_score: float
    samples: int
    span_days: float
    severity: str
    source: str               # "trend" | "certwrench"
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "resource": self.resource, "metric": self.metric,
            "current": self.current, "unit": self.unit, "threshold": self.threshold,
            "growth_per_day": self.growth_per_day, "eta_days": self.eta_days,
            "eta_date": self.eta_date, "confidence": self.confidence,
            "confidence_score": self.confidence_score, "samples": self.samples,
            "span_days": self.span_days, "severity": self.severity,
            "source": self.source, "detail": self.detail,
        }


def _eta_date(eta_days: float | None, now: float | None = None) -> str | None:
    if eta_days is None:
        return None
    t = (now or time.time()) + eta_days * 86400.0
    return time.strftime("%Y-%m-%d", time.localtime(t))


# ---- series extraction from the store -------------------------------------


def _os_samples(store, since_s: float) -> list[tuple[float, dict]]:
    try:
        return store.recent_samples("os", since_s)
    except Exception:  # noqa: BLE001
        return []


def disk_series(samples: list[tuple[float, dict]]) -> dict[str, list[tuple[float, float]]]:
    """Per-mount disk-percent series from os samples."""
    out: dict[str, list[tuple[float, float]]] = {}
    for ts, p in samples:
        for mount, pct in (p.get("disk_pct") or {}).items():
            if isinstance(pct, (int, float)):
                out.setdefault(mount, []).append((ts, float(pct)))
    return out


def inode_series(samples: list[tuple[float, dict]]) -> dict[str, list[tuple[float, float]]]:
    out: dict[str, list[tuple[float, float]]] = {}
    for ts, p in samples:
        for mount, pct in (p.get("inode_pct") or {}).items():
            if isinstance(pct, (int, float)):
                out.setdefault(mount, []).append((ts, float(pct)))
    return out


def scalar_series(samples: list[tuple[float, dict]], key: str) -> list[tuple[float, float]]:
    out: list[tuple[float, float]] = []
    for ts, p in samples:
        v = p.get(key)
        if isinstance(v, (int, float)):
            out.append((ts, float(v)))
    return out


def log_series(samples: list[tuple[float, dict]]) -> dict[str, list[tuple[float, float]]]:
    """Per-log-directory byte-size series from os samples."""
    out: dict[str, list[tuple[float, float]]] = {}
    for ts, p in samples:
        for path, info in (p.get("log_dirs") or {}).items():
            b = info.get("bytes") if isinstance(info, dict) else None
            if isinstance(b, (int, float)):
                out.setdefault(path, []).append((ts, float(b)))
    return out


# ---- capacity incident builders -------------------------------------------


def _pct_incident(kind: str, resource: str, metric: str,
                  series: list[tuple[float, float]], threshold: float,
                  now: float | None = None) -> Incident | None:
    trend = fit_trend(series)
    if trend is None:
        return None
    label, score = confidence(trend)
    eta = project_eta_days(trend, threshold, flat_eps=FLAT_EPS_PCT)
    sev = severity_for_eta(eta)
    growth = round(trend.slope_per_day, 4)
    if eta is not None:
        detail = (f"{trend.current:.1f}% now, +{growth:.2f}%/day → {threshold:.0f}% "
                  f"in ~{eta:.1f}d ({label} confidence, {trend.n} samples / "
                  f"{trend.span_days:.1f}d)")
    else:
        detail = (f"{trend.current:.1f}% now, not trending toward {threshold:.0f}% "
                  f"(+{growth:.3f}%/day)")
    return Incident(
        kind=kind, resource=resource, metric=metric, current=round(trend.current, 2),
        unit="%", threshold=threshold, growth_per_day=growth, eta_days=eta,
        eta_date=_eta_date(eta, now), confidence=label, confidence_score=score,
        samples=trend.n, span_days=trend.span_days, severity=sev, source="trend",
        detail=detail,
    )


def _log_incident(path: str, series: list[tuple[float, float]],
                  now: float | None = None) -> Incident | None:
    """Informational log-growth signal (bytes/day). Never pages on its own —
    a filling log *partition* surfaces through its disk-mount projection; this
    just names the culprit directory and its rate."""
    trend = fit_trend(series)
    if trend is None:
        return None
    label, score = confidence(trend)
    growth = round(trend.slope_per_day, 1)
    if trend.slope_per_day <= FLAT_EPS_BYTES:
        return None  # flat/shrinking logs are not news
    mb_day = growth / (2 ** 20)
    detail = (f"{trend.current / 2**30:.2f} GB now, +{mb_day:.1f} MB/day "
              f"({label} confidence, {trend.n} samples / {trend.span_days:.1f}d)")
    return Incident(
        kind="log", resource=path, metric="bytes", current=round(trend.current, 0),
        unit="bytes", threshold=None, growth_per_day=growth, eta_days=None,
        eta_date=None, confidence=label, confidence_score=score, samples=trend.n,
        span_days=trend.span_days, severity="none", source="trend", detail=detail,
    )


def capacity_incidents(store, thresholds: dict | None = None,
                       since_s: float = 86400 * 30,
                       now: float | None = None) -> list[Incident]:
    """Project every capacity metric in the sensor history."""
    th = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    samples = _os_samples(store, since_s)
    out: list[Incident] = []
    for mount, series in disk_series(samples).items():
        inc = _pct_incident("disk", mount, "disk_pct", series, th["disk"], now)
        if inc:
            out.append(inc)
    for mount, series in inode_series(samples).items():
        inc = _pct_incident("inode", mount, "inode_pct", series, th["inode"], now)
        if inc:
            out.append(inc)
    inc = _pct_incident("memory", "memory", "mem_pct",
                        scalar_series(samples, "mem_pct"), th["memory"], now)
    if inc:
        out.append(inc)
    inc = _pct_incident("swap", "swap", "swap_pct",
                        scalar_series(samples, "swap_pct"), th["swap"], now)
    if inc:
        out.append(inc)
    for path, series in log_series(samples).items():
        inc = _log_incident(path, series, now)
        if inc:
            out.append(inc)
    return out


# ---- certificate incidents (unify certwrench into the feed) ---------------


def _cert_severity(days_left: int | None) -> str:
    """Forecast-feed severity for a cert, on the same lead-time ladder."""
    if days_left is None:
        return "none"
    if days_left < 0 or days_left <= LEAD_CRITICAL_D:
        return "critical"
    if days_left <= LEAD_WARNING_D:
        return "warning"
    if days_left <= LEAD_INFO_D:
        return "info"
    return "none"


def cert_incidents(cfg, store, now: float | None = None) -> list[Incident]:
    """Fold certificate days-to-expiry into the future-incidents feed."""
    rows: list[dict] = []
    try:
        from . import certs
        certs.cached_inventory(cfg, store)  # refresh TTL cache, offline-safe
    except Exception:  # noqa: BLE001
        pass
    try:
        rows = store.recent_certs()
    except Exception:  # noqa: BLE001
        rows = []
    out: list[Incident] = []
    for c in rows:
        if c.get("error"):
            continue
        days = c.get("days_left")
        if days is None:
            continue
        import re as _re
        m = _re.search(r"CN\s*=\s*([^,/]+)", c.get("subject") or "")
        cn = m.group(1).strip() if m else (c.get("sans") or [c.get("path", "cert")])[0]
        sev = _cert_severity(days)
        eta = max(0.0, float(days))
        na = c.get("not_after")
        detail = (f"TLS cert {cn} "
                  + (f"EXPIRED {-days}d ago" if days < 0 else f"expires in {days}d")
                  + f" ({c.get('path')})")
        out.append(Incident(
            kind="cert", resource=cn, metric="days", current=float(days), unit="days",
            threshold=0.0, growth_per_day=-1.0, eta_days=eta,
            eta_date=(_eta_date(eta, now) if na is None
                      else time.strftime("%Y-%m-%d", time.localtime(na))),
            confidence="high", confidence_score=1.0, samples=1, span_days=0.0,
            severity=sev, source="certwrench", detail=detail,
        ))
    return out


# ---- feed assembly --------------------------------------------------------


def _eta_sort_key(inc: Incident) -> tuple:
    # soonest, most severe first; no-ETA entries sink to the bottom
    eta = inc.eta_days if inc.eta_days is not None else float("inf")
    return (eta, -_SEV_RANK.get(inc.severity, 0))


def build_feed(cfg, store, thresholds: dict | None = None,
               include_certs: bool = True, now: float | None = None) -> list[Incident]:
    """The unified future-incidents feed: capacity projections + cert expiry."""
    feed = capacity_incidents(store, thresholds, now=now)
    if include_certs:
        feed += cert_incidents(cfg, store, now=now)
    feed.sort(key=_eta_sort_key)
    return feed


def feed_report(cfg, store, thresholds: dict | None = None,
                include_certs: bool = True, now: float | None = None,
                persist: bool = True) -> dict:
    """Compute the feed and a summary report; optionally snapshot it for metrics."""
    feed = build_feed(cfg, store, thresholds, include_certs, now)
    dicts = [i.to_dict() for i in feed]
    counts = {"critical": 0, "warning": 0, "info": 0, "none": 0}
    for i in feed:
        counts[i.severity] = counts.get(i.severity, 0) + 1
    worst = "none"
    for sev in ("critical", "warning", "info"):
        if counts.get(sev):
            worst = sev
            break
    actionable = [i for i in feed if i.severity in ("critical", "warning", "info")]
    soonest = actionable[0].to_dict() if actionable else None
    report = {
        "generated_at": now or time.time(),
        "worst": worst,
        "counts": counts,
        "incidents": dicts,
        "soonest": soonest,
        "thresholds": {**DEFAULT_THRESHOLDS, **(thresholds or {})},
        "window_days": 30,
    }
    if persist:
        try:
            store.add_snapshot(FORECAST_KIND, report)
        except Exception:  # noqa: BLE001
            pass
    return report


# ---- patrol integration ---------------------------------------------------


def patrol_findings(cfg, store, thresholds: dict | None = None) -> list[dict]:
    """Deterministic capacity findings for a patrol (certs page via certwrench).

    Only trend-sourced projections crossing the lead-time ladder are raised
    here; cert expiry is already paged by the certs patrol hook, so including
    it would double-notify. Never raises.
    """
    try:
        feed = capacity_incidents(store, thresholds)
    except Exception:  # noqa: BLE001 — a patrol never dies on a forecast
        return []
    out: list[dict] = []
    for inc in feed:
        if inc.severity in ("critical", "warning", "info"):
            out.append({"severity": inc.severity,
                        "text": f"forecast: {inc.kind} {inc.resource} — {inc.detail}"})
    return out


def patrol_summary_line(cfg, store) -> str:
    """One context line naming the soonest projected incident (capacity+certs)."""
    try:
        feed = build_feed(cfg, store)
    except Exception:  # noqa: BLE001
        return "forecast: unavailable"
    actionable = [i for i in feed if i.severity in ("critical", "warning", "info")]
    if not actionable:
        return "forecast: no incidents projected within 14 days"
    soon = actionable[0]
    extra = f" (+{len(actionable) - 1} more)" if len(actionable) > 1 else ""
    if soon.eta_days is not None:
        return (f"forecast: {soon.kind} {soon.resource} crosses threshold in "
                f"~{soon.eta_days:.0f}d [{soon.severity}]{extra}")
    return f"forecast: {soon.kind} {soon.resource} [{soon.severity}]{extra}"


def notify_feed(cfg, report: dict) -> dict | None:
    """Emit one notification summarizing the soonest actionable projection.

    One event per scan (not one per incident) so a manual ``wrench forecast``
    never spams the inbox. Returns the record or None. Never raises.
    """
    try:
        from . import notifications
        soon = report.get("soonest")
        if not soon:
            return None
        sev = soon.get("severity", "info")
        counts = report.get("counts", {})
        extra = counts.get("critical", 0) + counts.get("warning", 0) \
            + counts.get("info", 0) - 1
        summary = f"forecast: {soon['kind']} {soon['resource']} — {soon['detail']}"
        if extra > 0:
            summary += f" (+{extra} more projected)"
        return notifications.emit_event(cfg, "forecast", sev, summary)
    except Exception:  # noqa: BLE001 — a notification never breaks a forecast
        return None


def narration_lines(report: dict) -> list[str]:
    """Flatten a feed report for brain narration. Pure, read-only."""
    lines = [f"capacity forecast — worst lead-time severity: {report.get('worst')}"]
    counts = report.get("counts", {})
    lines.append(
        f"projected incidents: {counts.get('critical', 0)} critical, "
        f"{counts.get('warning', 0)} warning, {counts.get('info', 0)} info")
    for inc in report.get("incidents", [])[:20]:
        if inc.get("severity") in ("critical", "warning", "info"):
            lines.append(f"- [{inc['severity']}] {inc['kind']} {inc['resource']}: "
                         f"{inc['detail']}")
    growers = [i for i in report.get("incidents", [])
               if i.get("kind") == "log" and i.get("confidence") in ("medium", "high")]
    for g in growers[:5]:
        lines.append(f"- [log] {g['resource']}: {g['detail']}")
    if len(lines) <= 2:
        lines.append("no resource is trending toward exhaustion in the fit window.")
    return lines
