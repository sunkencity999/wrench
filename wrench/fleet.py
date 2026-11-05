"""wrench fleet — many nodes, one view.

The single biggest home→enterprise jump: a lightweight push-reporting fabric so
one wrench install (the HUB) can watch a whole fleet of wrench NODES.

Architecture (stdlib-only, no new dependencies, default OFF):

  NODE   any wrench install with a ``[fleet]`` section (``hub_url`` + a shared
         ``token``) pushes a COMPACT JSON snapshot after each patrol —
         ``wrench fleet report`` one-shot, or the patrol hook. The snapshot is
         built from ALREADY-CACHED scan results (last os sample, last security/
         forecast/backup snapshots, cert inventory, latest patrol) — it NEVER
         reruns an expensive scan.

  HUB    any wrench install run with ``wrench fleet serve`` accepts signed node
         reports over HTTP POST, stores them in sqlite, and renders a fleet
         dashboard + Prometheus gauges + a dead-man's switch.

Auth: a per-node shared token lives in config (like an API key — never in the
db). The node signs the exact request body with HMAC-SHA256(token, body); the
hub verifies against its ``authorized_tokens`` with a constant-time compare.
The hub persists only the token FINGERPRINT (sha256) in sqlite, never the raw
secret. Tokens are never logged. TLS is out of scope — run the hub behind a
reverse proxy (nginx/caddy) for the public internet; see the docs.

House rules (same as audit/security/backups):
  - stdlib only;
  - pure helpers take plain data so tests feed synthetic reports/clocks;
  - the node push must NEVER break a patrol (unreachable hub → queue + retry);
  - the hub ingest path authenticates before it touches the store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import platform
import secrets
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__

# severity ladder shared with notifications (ok/info < attention/warning < error < critical)
SEVERITY_RANK = {"ok": 0, "info": 0, "recommendation": 0,
                 "attention": 1, "warning": 1,
                 "error": 2, "critical": 3}
_RANK_SEVERITY = {0: "ok", 1: "warning", 2: "error", 3: "critical"}

# node overall status ladder (what the grid colors on)
STATUS_RANK = {"ok": 0, "attention": 1, "critical": 2, "error": 2, "silent": 3}

DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 8788
DEFAULT_CADENCE_S = 900          # fallback when a node doesn't declare one
DEFAULT_SILENT_FACTOR = 2.0      # SILENT when last_seen older than factor × cadence
DEFAULT_REPORT_RETENTION = 200   # per-node history cap
DEFAULT_MAX_FINDINGS = 8         # compact: top-N findings pushed per report
REPORT_PATH = "/api/fleet/report"
OUTBOX_NAME = "fleet_outbox.json"
PUSH_TIMEOUT_S = 8

SIG_HEADER = "X-Wrench-Signature"
NODE_HEADER = "X-Wrench-Node"


# ---------------- crypto (pure) ----------------

def generate_token(nbytes: int = 32) -> str:
    """A fresh random node token (hex). Generated at runtime, never baked in."""
    return secrets.token_hex(nbytes)


def token_fingerprint(token: str) -> str:
    """Non-secret sha256 fingerprint of a token — safe to persist/show/audit."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def sign_body(token: str, body: bytes) -> str:
    """HMAC-SHA256(token, body) as hex. The node signs; the hub verifies."""
    return hmac.new((token or "").encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_body(token: str, body: bytes, signature: str) -> bool:
    """Constant-time verification of a body's HMAC signature."""
    expected = sign_body(token, body)
    return hmac.compare_digest(expected, (signature or "").strip())


def report_bytes(report: dict) -> bytes:
    """Canonical, deterministic JSON bytes of a report (stable sign/verify)."""
    return json.dumps(report, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ---------------- settings ----------------

@dataclass
class FleetSettings:
    # node side
    hub_url: str = ""
    token: str = ""
    node_id: str = ""
    # hub side
    listen_host: str = DEFAULT_LISTEN_HOST
    listen_port: int = DEFAULT_LISTEN_PORT
    authorized_tokens: list[str] = field(default_factory=list)
    # shared tunables
    cadence_s: int = DEFAULT_CADENCE_S
    silent_factor: float = DEFAULT_SILENT_FACTOR
    report_retention: int = DEFAULT_REPORT_RETENTION
    max_findings: int = DEFAULT_MAX_FINDINGS

    @property
    def node_enabled(self) -> bool:
        return bool(self.hub_url and self.token)

    @property
    def hub_enabled(self) -> bool:
        return bool(self.authorized_tokens)


def _hub_cadence_s(cfg) -> int:
    """A node's natural report cadence = its patrol interval (minutes→seconds)."""
    try:
        return max(60, int(getattr(cfg, "patrol_interval_min", 15)) * 60)
    except Exception:  # noqa: BLE001
        return DEFAULT_CADENCE_S


def settings_from(cfg) -> FleetSettings:
    """Read the ``[fleet]`` section off a loaded Config (cfg.raw)."""
    sec = (getattr(cfg, "raw", None) or {}).get("fleet", {})
    if not isinstance(sec, dict):
        sec = {}
    toks = sec.get("authorized_tokens") or []
    if isinstance(toks, str):
        toks = [toks]
    toks = [str(t) for t in toks if str(t).strip()]
    node_id = str(sec.get("node_id") or "").strip() or (platform.node() or "node")
    return FleetSettings(
        hub_url=str(sec.get("hub_url", "") or "").rstrip("/"),
        token=str(sec.get("token", "") or ""),
        node_id=node_id,
        listen_host=str(sec.get("listen_host", DEFAULT_LISTEN_HOST) or DEFAULT_LISTEN_HOST),
        listen_port=int(sec.get("listen_port", DEFAULT_LISTEN_PORT) or DEFAULT_LISTEN_PORT),
        authorized_tokens=toks,
        cadence_s=int(sec.get("cadence_s", _hub_cadence_s(cfg)) or _hub_cadence_s(cfg)),
        silent_factor=float(sec.get("silent_factor", DEFAULT_SILENT_FACTOR)
                            or DEFAULT_SILENT_FACTOR),
        report_retention=int(sec.get("report_retention", DEFAULT_REPORT_RETENTION)
                             or DEFAULT_REPORT_RETENTION),
        max_findings=int(sec.get("max_findings", DEFAULT_MAX_FINDINGS)
                         or DEFAULT_MAX_FINDINGS),
    )


# ---------------- severity helpers (pure) ----------------

def severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get((sev or "").strip().lower(), 0)


def status_from_rank(rank: int) -> str:
    """Map a worst-severity rank onto the node status ladder."""
    if rank >= 3:
        return "critical"
    if rank >= 2:
        return "critical"    # error-class findings page like critical on the grid
    if rank >= 1:
        return "attention"
    return "ok"


def worst_of(*severities: str) -> str:
    best = 0
    for s in severities:
        best = max(best, severity_rank(s))
    return _RANK_SEVERITY[best]


# ---------------- node-side report builder (reuses CACHED scans) ----------------

def build_report(cfg, store, settings: FleetSettings | None = None,
                 now: float | None = None) -> dict:
    """Assemble a compact node snapshot from already-cached scan results.

    Deliberately reuses the newest os sample + the last security/forecast/backup
    snapshots + the cert inventory + the latest patrol row. It NEVER triggers a
    fresh scan — fleet reporting is cheap by construction.
    """
    st = settings or settings_from(cfg)
    now = now if now is not None else time.time()
    gauges: dict = {}
    findings: list[dict] = []
    worst = "ok"
    status = "ok"
    summary_bits: list[str] = []

    # latest patrol (status + summary + its findings)
    try:
        patrols = store.recent_patrols(1)
    except Exception:  # noqa: BLE001
        patrols = []
    if patrols:
        p = patrols[0]
        status = (p.get("status") or "ok").lower()
        if p.get("summary"):
            summary_bits.append(p["summary"])
        for f in (p.get("findings") or []):
            sev = (f.get("severity") or "info").lower()
            if sev == "recommendation":
                continue
            findings.append({"severity": sev, "text": (f.get("text") or "")[:240]})
            worst = worst_of(worst, sev)

    # newest os sample → disk/mem/swap gauges
    try:
        last = store.last_sample("os")
    except Exception:  # noqa: BLE001
        last = None
    if last:
        osd = last[1]
        gauges["mem_pct"] = osd.get("mem_pct")
        gauges["swap_pct"] = osd.get("swap_pct")
        gauges["disk_pct"] = osd.get("disk_pct") or {}
        gauges["load_1m"] = osd.get("load_1m")

    # security worst (cached scan snapshot)
    try:
        from .security import LASTSCAN_KIND
        snap = store.last_snapshot(LASTSCAN_KIND)
        if snap:
            counts = snap[1].get("counts", {}) or {}
            sev = ("critical" if counts.get("critical") else
                   "warning" if counts.get("warning") else "info")
            gauges["security_worst"] = sev
            worst = worst_of(worst, sev)
    except Exception:  # noqa: BLE001
        pass

    # cert worst (min days to expiry across the inventory)
    try:
        certs = store.recent_certs()
        days = [c.get("days_left") for c in certs
                if not c.get("error") and c.get("days_left") is not None]
        if days:
            dmin = min(days)
            gauges["cert_worst_days"] = dmin
            sev = ("critical" if dmin <= 7 else "warning" if dmin <= 14 else "info")
            gauges["cert_worst"] = sev
            if dmin <= 14:
                worst = worst_of(worst, sev)
    except Exception:  # noqa: BLE001
        pass

    # forecast worst (cached feed snapshot)
    try:
        from .forecast import FORECAST_KIND
        snap = store.last_snapshot(FORECAST_KIND)
        if snap:
            counts = snap[1].get("counts", {}) or {}
            sev = ("critical" if counts.get("critical") else
                   "warning" if counts.get("warning") else "info")
            gauges["forecast_worst"] = sev
            if counts.get("critical") or counts.get("warning"):
                worst = worst_of(worst, sev)
    except Exception:  # noqa: BLE001
        pass

    # backup worst (cached verification snapshot)
    try:
        from .backups import BACKUPS_KIND, job_severity_dict
        snap = store.last_snapshot(BACKUPS_KIND)
        if snap:
            jobs = snap[1].get("jobs", []) or []
            bworst = "ok"
            for j in jobs:
                bworst = worst_of(bworst, job_severity_dict(j))
            gauges["backup_worst"] = bworst
            if severity_rank(bworst) >= 1:
                worst = worst_of(worst, bworst)
    except Exception:  # noqa: BLE001
        pass

    # overall status = max(patrol status, worst subsystem severity)
    status = _status_of(status, worst)

    findings.sort(key=lambda f: -severity_rank(f.get("severity")))
    report = {
        "node_id": st.node_id,
        "hostname": platform.node() or "localhost",
        "wrench_version": __version__,
        "ts": round(now, 3),
        "status": status,
        "worst_severity": worst,
        "cadence_s": st.cadence_s,
        "summary": ("; ".join(summary_bits)[:300]) or "no patrol yet",
        "findings": findings[: st.max_findings],
        "gauges": gauges,
    }
    return report


def _status_of(status: str, worst: str) -> str:
    """Overall node status = max(patrol status, worst subsystem severity)."""
    rank = max(STATUS_RANK.get((status or "ok").lower(), 0),
               1 if severity_rank(worst) == 1 else 2 if severity_rank(worst) >= 2 else 0)
    if rank >= 2:
        return "critical"
    if rank >= 1:
        return "attention"
    return "ok"


# ---------------- hub-side ingest ----------------

def identify_token(settings: FleetSettings, body: bytes, signature: str) -> str | None:
    """Return the authorized token whose HMAC matches the body, else None.

    Constant-time comparison per candidate; a forged/absent signature matches
    nothing. This is the hub's entire authentication gate.
    """
    for tok in settings.authorized_tokens:
        if verify_body(tok, body, signature):
            return tok
    return None


def parse_report(body: bytes) -> dict | None:
    """Decode a report body to a dict, or None if malformed."""
    try:
        obj = json.loads(body.decode("utf-8"))
        return obj if isinstance(obj, dict) and obj.get("node_id") else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def ingest(store, settings: FleetSettings, report: dict, token: str,
           now: float | None = None) -> dict:
    """Authenticated report → upsert node + append history + prune. Returns row.

    Caller MUST have already verified the signature with ``identify_token``.
    """
    now = now if now is not None else time.time()
    node_id = str(report.get("node_id"))[:120]
    row = store.upsert_fleet_node(
        node_id=node_id,
        hostname=str(report.get("hostname") or node_id)[:200],
        token_hash=token_fingerprint(token),
        status=str(report.get("status") or "ok")[:20],
        worst_severity=str(report.get("worst_severity") or "ok")[:20],
        summary=str(report.get("summary") or "")[:400],
        cadence_s=_coerce_float(report.get("cadence_s")),
        wrench_version=str(report.get("wrench_version") or "")[:40],
        findings=report.get("findings") if isinstance(report.get("findings"), list) else [],
        gauges=report.get("gauges") if isinstance(report.get("gauges"), dict) else {},
        now=now,
    )
    try:
        store.prune_fleet_reports(node_id, settings.report_retention)
    except Exception:  # noqa: BLE001
        pass
    return row


def _coerce_float(v) -> float | None:
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


# ---------------- dead-man's switch (pure) ----------------

def effective_cadence(node: dict, settings: FleetSettings) -> float:
    c = _coerce_float(node.get("cadence_s"))
    if c and c > 0:
        return c
    return float(settings.cadence_s or DEFAULT_CADENCE_S)


def is_silent(node: dict, now: float, settings: FleetSettings) -> bool:
    """A node is SILENT when its last report is older than factor × cadence."""
    last = _coerce_float(node.get("last_seen")) or 0.0
    deadline = effective_cadence(node, settings) * settings.silent_factor
    return (now - last) > deadline


def node_color(node: dict, now: float, settings: FleetSettings) -> str:
    """Grid color: silent > red > yellow > green."""
    if is_silent(node, now, settings):
        return "silent"
    status = (node.get("status") or "ok").lower()
    rank = STATUS_RANK.get(status, 0)
    if rank >= 2:
        return "red"
    if rank >= 1:
        return "yellow"
    return "green"


def node_states(store, settings: FleetSettings, now: float | None = None) -> list[dict]:
    """All nodes enriched with age/silent/color for status + dashboard + metrics."""
    now = now if now is not None else time.time()
    out = []
    for n in store.fleet_nodes():
        age = now - (_coerce_float(n.get("last_seen")) or now)
        silent = is_silent(n, now, settings)
        out.append({
            **n,
            "age_s": round(age, 1),
            "silent": silent,
            "color": node_color(n, now, settings),
            "effective_cadence_s": effective_cadence(n, settings),
        })
    return out


def fleet_summary(states: list[dict]) -> dict:
    """Counts by color for the status header + Prometheus rollup."""
    counts = {"green": 0, "yellow": 0, "red": 0, "silent": 0}
    for s in states:
        counts[s.get("color", "green")] = counts.get(s.get("color", "green"), 0) + 1
    return {"total": len(states), **counts}
