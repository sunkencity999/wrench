"""wrench posture — one number for "how is this box, really?"

Every subsystem already answers its own question (is the disk filling? are the
backups fresh? is the box hardened?). Posture folds those answers into a single
0–100 health score with a letter grade, so a human — or a fleet console
watching five hundred machines — can rank boxes without reading eight reports.

Design rules:

  - **Deterministic.** The score is arithmetic over cached scan results. The
    model is never asked how healthy the box is.
  - **Cached inputs only.** Like the fleet report, posture never triggers a
    scan; it reads the newest sample/snapshot each subsystem already stored.
  - **Unknown is not healthy.** A pillar with no data is reported as
    ``unknown`` and left out of the weighted average — and the result carries a
    ``coverage`` figure so "100, but only 2 of 8 pillars measured" is visible.
  - **Explainable.** Every pillar carries the one-line reason for its score and
    the command that improves it.

Pure helpers take plain data so tests can feed synthetic snapshots.
"""

from __future__ import annotations

import time

# pillar → weight. Weights are relative; the score renormalizes over the
# pillars that actually have data.
WEIGHTS = {
    "capacity": 20,
    "security": 20,
    "vulnerabilities": 15,
    "compliance": 15,
    "backups": 12,
    "certificates": 8,
    "forecast": 5,
    "patrol": 5,
}

LABELS = {
    "capacity": "Capacity",
    "security": "Security",
    "vulnerabilities": "Vulnerabilities",
    "compliance": "Compliance",
    "backups": "Backups",
    "certificates": "Certificates",
    "forecast": "Forecast",
    "patrol": "Patrol",
}

# what to run to (re)measure or improve each pillar
COMMANDS = {
    "capacity": "wrench status",
    "security": "wrench security",
    "vulnerabilities": "wrench cve",
    "compliance": "wrench comply",
    "backups": "wrench backups",
    "certificates": "wrench certs",
    "forecast": "wrench forecast",
    "patrol": "wrench patrol",
}

GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


def grade_for(score: float | None) -> str:
    if score is None:
        return "–"
    for floor, letter in GRADES:
        if score >= floor:
            return letter
    return "F"


def state_for(score: float | None) -> str:
    """ok / attention / critical / unknown — the same ladder patrols use."""
    if score is None:
        return "unknown"
    if score >= 80:
        return "ok"
    if score >= 60:
        return "attention"
    return "critical"


def _pillar(key: str, score: float | None, detail: str, **extra) -> dict:
    if score is not None:
        score = max(0.0, min(100.0, round(float(score), 1)))
    return {"key": key, "label": LABELS[key], "weight": WEIGHTS[key],
            "score": score, "state": state_for(score), "detail": detail,
            "command": COMMANDS[key], **extra}


# ---------------- pillar scorers (pure) ----------------

def _usage_score(pct: float) -> float:
    """100 below 70% used, sliding to 50 at 90%, to 0 at 100%."""
    if pct <= 70:
        return 100.0
    if pct <= 90:
        return 100.0 - (pct - 70) * 2.5
    return max(0.0, 50.0 - (pct - 90) * 5.0)


def score_capacity(os_sample: dict | None) -> dict:
    if not os_sample:
        return _pillar("capacity", None, "no sensor sample yet")
    disks = os_sample.get("disk_pct") or {}
    parts = []
    scores = []
    if disks:
        mount, pct = max(disks.items(), key=lambda kv: kv[1])
        scores.append(_usage_score(pct))
        parts.append(f"fullest disk {mount} at {pct:.0f}%")
    mem = os_sample.get("mem_pct")
    if mem is not None:
        # memory is elastic (caches) — only sustained >90% is a real problem
        scores.append(100.0 if mem <= 85 else max(40.0, 100.0 - (mem - 85) * 4))
        parts.append(f"memory {mem:.0f}%")
    inodes = os_sample.get("inode_pct") or {}
    if inodes:
        imount, ipct = max(inodes.items(), key=lambda kv: kv[1])
        if ipct > 70:
            scores.append(_usage_score(ipct))
            parts.append(f"inodes on {imount} at {ipct:.0f}%")
    if not scores:
        return _pillar("capacity", None, "no capacity metrics in the last sample")
    # the worst resource dominates: a full disk isn't offset by idle RAM
    score = min(scores) * 0.7 + (sum(scores) / len(scores)) * 0.3
    return _pillar("capacity", score, ", ".join(parts))


def _findings_score(critical: int, warning: int) -> float:
    return max(0.0, 100.0 - 35.0 * critical - 10.0 * warning)


def score_security(snapshot: dict | None) -> dict:
    if not snapshot:
        return _pillar("security", None, "no security scan yet")
    counts = snapshot.get("counts") or {}
    crit, warn = int(counts.get("critical") or 0), int(counts.get("warning") or 0)
    score = _findings_score(crit, warn)
    if not snapshot.get("baseline_exists"):
        score = min(score, 90.0)
        tail = " · no accepted baseline"
    else:
        tail = ""
    if crit or warn:
        detail = f"{crit} critical, {warn} warning finding(s){tail}"
    else:
        detail = f"no critical or warning findings{tail}"
    return _pillar("security", score, detail)


def score_vulnerabilities(scan: dict | None) -> dict:
    if not scan:
        return _pillar("vulnerabilities", None, "no CVE/EOL scan yet")
    vulns = scan.get("vulns") or []
    eol = [e for e in (scan.get("eol") or []) if e.get("is_eol")]
    pkgs = {v.get("package") for v in vulns}
    sev_rank = {"critical": 25.0, "high": 15.0, "medium": 6.0, "moderate": 6.0, "low": 2.0}
    worst_by_pkg: dict = {}
    for v in vulns:
        penalty = sev_rank.get(str(v.get("severity") or "").lower(), 6.0)
        worst_by_pkg[v.get("package")] = max(worst_by_pkg.get(v.get("package"), 0.0), penalty)
    score = 100.0 - sum(worst_by_pkg.values()) - 15.0 * len(eol)
    bits = []
    bits.append(f"{len(vulns)} known vulnerability(ies) in {len(pkgs)} package(s)"
                if vulns else f"no known CVEs in {scan.get('packages_checked', 0)} packages")
    if eol:
        bits.append(f"{len(eol)} end-of-life product(s)")
    if scan.get("online") is False:
        bits.append("cached (offline)")
    return _pillar("vulnerabilities", score, " · ".join(bits))


def score_compliance(snapshot: dict | None) -> dict:
    if not snapshot:
        return _pillar("compliance", None, "no compliance scan yet")
    packs = [p for p in (snapshot.get("packs") or [])
             if (p.get("counts") or {}).get("pass", 0) + (p.get("counts") or {}).get("fail", 0) > 0]
    if not packs:
        return _pillar("compliance", None, "no applicable compliance checks ran")
    score = sum(float(p.get("score") or 0) for p in packs) / len(packs)
    crit = int(snapshot.get("critical_fails") or 0)
    if crit:
        score = min(score, 59.0)   # a critical hardening failure caps the pillar
    fails = len(snapshot.get("fail_ids") or [])
    detail = f"{score:.0f}% of checks pass across {len(packs)} pack(s)"
    if fails:
        detail += f" · {fails} failing" + (f" ({crit} critical)" if crit else "")
    return _pillar("compliance", score, detail)


def score_backups(snapshot: dict | None) -> dict:
    if not snapshot:
        return _pillar("backups", None, "no backup verification yet")
    if snapshot.get("no_jobs") or not snapshot.get("jobs"):
        return _pillar("backups", 40.0, "no backup jobs detected on this box")
    counts = snapshot.get("severity_counts") or {}
    crit, warn = int(counts.get("critical") or 0), int(counts.get("warning") or 0)
    n = len(snapshot.get("jobs") or [])
    score = max(0.0, 100.0 - 50.0 * crit - 25.0 * warn)
    if crit or warn:
        detail = f"{n} job(s): {crit} failing integrity, {warn} stale or unverified"
    else:
        detail = f"{n} job(s), all fresh"
    return _pillar("backups", score, detail)


def score_certificates(certs: list[dict] | None) -> dict:
    rows = [c for c in (certs or []) if not c.get("error") and c.get("days_left") is not None]
    if not rows:
        return _pillar("certificates", None, "no certificates tracked")
    dmin = min(int(c["days_left"]) for c in rows)
    if dmin <= 0:
        score, what = 0.0, "a certificate has EXPIRED"
    elif dmin <= 7:
        score, what = 25.0, f"a certificate expires in {dmin}d"
    elif dmin <= 14:
        score, what = 60.0, f"a certificate expires in {dmin}d"
    elif dmin <= 30:
        score, what = 85.0, f"next expiry in {dmin}d"
    else:
        score, what = 100.0, f"next expiry in {dmin}d"
    return _pillar("certificates", score, f"{len(rows)} tracked · {what}")


def score_forecast(snapshot: dict | None) -> dict:
    if not snapshot:
        return _pillar("forecast", None, "not enough history to forecast yet")
    counts = snapshot.get("counts") or {}
    crit, warn = int(counts.get("critical") or 0), int(counts.get("warning") or 0)
    info = int(counts.get("info") or 0)
    score = max(0.0, 100.0 - 40.0 * crit - 20.0 * warn - 5.0 * info)
    soonest = snapshot.get("soonest") or {}
    if crit or warn or info:
        label = (" ".join(str(soonest.get(k) or "") for k in ("kind", "resource")).strip()
                 or "an incident")
        eta = soonest.get("eta_days")
        detail = (f"{crit + warn + info} projected incident(s)"
                  + (f" · soonest: {label}" + (f" in ~{eta:.0f}d" if isinstance(eta, (int, float)) else "")
                     if soonest else ""))
    else:
        detail = "no incidents projected in the next 30 days"
    return _pillar("forecast", score, detail)


def score_patrol(patrol: dict | None, interval_min: float = 15,
                 now: float | None = None) -> dict:
    if not patrol:
        return _pillar("patrol", None, "no patrol has run yet")
    now = now if now is not None else time.time()
    status = (patrol.get("status") or "ok").lower()
    base = {"ok": 100.0, "attention": 70.0, "critical": 30.0, "error": 50.0}.get(status, 70.0)
    ts = patrol.get("ts")
    age_s = max(0.0, now - float(now if ts is None else ts))
    stale_after = max(interval_min * 60 * 4, 6 * 3600)
    detail = f"last patrol {status}, {_ago(age_s)}"
    if age_s > stale_after:
        base = min(base, 60.0)
        detail += " · patrols are not running on schedule"
    return _pillar("patrol", base, detail)


def _ago(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s ago"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m ago"
    if seconds < 172800:
        return f"{seconds / 3600:.1f}h ago"
    return f"{seconds / 86400:.1f}d ago"


# ---------------- aggregate ----------------

def combine(pillars: list[dict]) -> dict:
    """Weighted average over the pillars that have data (pure)."""
    known = [p for p in pillars if p["score"] is not None]
    total_w = sum(p["weight"] for p in known)
    score = (round(sum(p["score"] * p["weight"] for p in known) / total_w, 1)
             if total_w else None)
    # one critical pillar should never hide inside a good average
    if score is not None and any(p["state"] == "critical" for p in known):
        score = min(score, 69.0)
    worst = sorted(known, key=lambda p: p["score"])[:3]
    return {
        "score": score,
        "grade": grade_for(score),
        "state": state_for(score),
        "coverage": {"measured": len(known), "total": len(pillars)},
        "pillars": pillars,
        "top_issues": [{"pillar": p["key"], "label": p["label"], "detail": p["detail"],
                        "command": p["command"]}
                       for p in worst if p["state"] in ("attention", "critical")],
    }


def compute(cfg, store, now: float | None = None) -> dict:
    """Posture from whatever each subsystem last cached. Never raises."""
    def safe(fn, default=None):
        try:
            return fn()
        except Exception:  # noqa: BLE001 — a broken subsystem is an unknown pillar
            return default

    def snap(kind):
        row = store.last_snapshot(kind)
        return row[1] if row else None

    last = safe(lambda: store.last_sample("os"))
    patrols = safe(lambda: store.recent_patrols(1), []) or []
    pillars = [
        score_capacity(last[1] if last else None),
        score_security(safe(lambda: snap("security_scan"))),
        score_vulnerabilities(safe(lambda: store.cache_get("webintel_scan", float("inf")))),
        score_compliance(safe(lambda: snap("comply_scan"))),
        score_backups(safe(lambda: snap("backups_report"))),
        score_certificates(safe(lambda: store.recent_certs(), [])),
        score_forecast(safe(lambda: snap("forecast_feed"))),
        score_patrol(patrols[0] if patrols else None,
                     interval_min=getattr(cfg, "patrol_interval_min", 15), now=now),
    ]
    out = combine(pillars)
    out["generated_at"] = now if now is not None else time.time()
    return out


def summary_line(p: dict) -> str:
    if p.get("score") is None:
        return "posture: not enough data yet"
    cov = p["coverage"]
    return (f"posture: {p['score']:.0f}/100 (grade {p['grade']}) — "
            f"{cov['measured']} of {cov['total']} pillars measured")
