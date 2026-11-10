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

Auth — two generations, both accepted by a hub:

  v2 (enrollment keys, the default from 3.0)
      ``wrench fleet enroll`` on the hub mints a token (``wfl_…``) and stores
      only a *derived* signing key under a short key id. ``wrench fleet join``
      on the node saves the token. Each report carries ``X-Wrench-Key`` (key
      id), ``X-Wrench-Timestamp`` and ``X-Wrench-Signature: v2=<hmac>`` where
      the HMAC covers ``"<timestamp>." + body``. The hub looks the key up by id
      (no scan over every secret), rejects revoked keys, rejects timestamps
      outside ``max_skew_s``, and rejects any report that is not newer than the
      last one it accepted for that node — a captured request cannot be
      replayed to keep a dead box looking alive.

  v1 (legacy shared tokens in ``authorized_tokens``)
      HMAC-SHA256(token, body) in ``X-Wrench-Signature``. Still accepted so a
      2.x node keeps reporting through a hub upgrade; the same freshness and
      replay checks are applied using the ``ts`` inside the signed body.

Either way a node id is **bound** to the credential that first registered it:
a different key cannot overwrite another node's row. Secrets are never logged.
The hub can terminate TLS itself (``[fleet] tls_cert`` / ``tls_key``) or sit
behind a reverse proxy.

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
import math
import platform
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
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
KEY_HEADER = "X-Wrench-Key"
TS_HEADER = "X-Wrench-Timestamp"
TOKEN_PREFIX = "wfl_"
DEFAULT_MAX_SKEW_S = 300         # accepted clock difference node↔hub (0 = don't check)
MAX_REPORT_BYTES = 64 * 1024     # a compact report is ~2 KB; anything bigger is not one
SWEEP_INTERVAL_S = 30            # hub dead-man sweep cadence


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
    # bytes, not str: compare_digest raises on non-ASCII str input
    return hmac.compare_digest(expected.encode(), (signature or "").strip().encode("utf-8", "replace"))


# ---- v2: enrollment keys ----

def generate_enrollment_token(nbytes: int = 32) -> str:
    """A fresh v2 enrollment token. The prefix lets a node pick the protocol."""
    return TOKEN_PREFIX + secrets.token_hex(nbytes)


def is_v2_token(token: str) -> bool:
    return (token or "").startswith(TOKEN_PREFIX)


def key_id_of(token: str) -> str:
    """Short public identifier for a token — safe to log, show and audit."""
    return hashlib.sha256(b"wrench-fleet-id\0" + (token or "").encode("utf-8")).hexdigest()[:16]


def derive_key(token: str) -> str:
    """The HMAC signing key derived from a token (hex).

    The hub stores this, never the token. It is still a secret (it can sign
    reports), which is why the store is owner-only — but it cannot be turned
    back into the token an operator pasted, and its id reveals nothing.
    """
    return hashlib.sha256(b"wrench-fleet-v2\0" + (token or "").encode("utf-8")).hexdigest()


def sign_v2(hmac_key_hex: str, ts: str, body: bytes) -> str:
    msg = str(ts).encode("ascii", "replace") + b"." + body
    return hmac.new(bytes.fromhex(hmac_key_hex), msg, hashlib.sha256).hexdigest()


def enroll(store, label: str = "", single_node: bool = False,
           now: float | None = None) -> dict:
    """Hub side: mint a token, persist its derived key. Returns {token, key_id}."""
    token = generate_enrollment_token()
    key_id = key_id_of(token)
    store.add_fleet_key(key_id, label, derive_key(token),
                        now if now is not None else time.time(), single_node)
    return {"token": token, "key_id": key_id, "label": label, "single_node": single_node}


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
    max_skew_s: int = DEFAULT_MAX_SKEW_S
    tags: list[str] = field(default_factory=list)
    # transport security
    ca_file: str = ""          # node: trust this CA bundle for an https hub
    tls_cert: str = ""         # hub: serve https with this certificate …
    tls_key: str = ""          # … and private key
    hub: bool = False          # hub: explicit opt-in without legacy tokens

    @property
    def node_enabled(self) -> bool:
        return bool(self.hub_url and self.token)

    @property
    def hub_enabled(self) -> bool:
        """Config alone says this box is a hub (legacy tokens or ``hub = true``).

        Enrollment keys live in the store, so prefer ``hub_active(store, st)``
        wherever a store is at hand.
        """
        return bool(self.authorized_tokens or self.hub)


def hub_active(store, settings: "FleetSettings") -> bool:
    """True when this install should accept node reports."""
    if settings.hub_enabled:
        return True
    try:
        return any(not k.get("revoked") for k in store.fleet_keys())
    except Exception:  # noqa: BLE001
        return False


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
        max_skew_s=_int_or(sec.get("max_skew_s"), DEFAULT_MAX_SKEW_S),
        tags=_clean_tags(sec.get("tags")),
        ca_file=str(sec.get("ca_file", "") or ""),
        tls_cert=str(sec.get("tls_cert", "") or ""),
        tls_key=str(sec.get("tls_key", "") or ""),
        hub=bool(sec.get("hub", False)),
    )


def _int_or(v, default: int) -> int:
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _clean_tags(v) -> list[str]:
    """Normalize ``tags`` (list or comma string) to short, safe labels."""
    if isinstance(v, str):
        v = v.split(",")
    if not isinstance(v, (list, tuple)):
        return []
    out = []
    for t in v:
        t = "".join(ch for ch in str(t).strip().lower()
                    if ch.isalnum() or ch in "-_.:")[:32]
        if t and t not in out:
            out.append(t)
    return out[:12]


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
        gauges["cpu_pct"] = osd.get("cpu_pct")
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

    # inventory + posture: what an operator needs to find, group and rank boxes
    meta: dict = {"tags": list(st.tags)}
    try:
        from . import platforms
        meta["os"] = platforms.current_platform()
        meta["os_label"] = platforms.os_label()
        meta["arch"] = platform.machine()
    except Exception:  # noqa: BLE001
        pass
    if last:
        meta["uptime_s"] = last[1].get("uptime_s")
        meta["mem_total_gb"] = last[1].get("mem_total_gb")
    try:
        from . import posture
        pos = posture.compute(cfg, store, now=now)
        meta["score"] = pos["score"]
        meta["grade"] = pos["grade"]
        meta["pillars"] = {p["key"]: p["score"] for p in pos["pillars"]}
        gauges["comply_score"] = meta["pillars"].get("compliance")
    except Exception:  # noqa: BLE001
        pass
    try:
        meta["policy_tier"] = str(getattr(cfg, "policy_tier", "") or "")[:20]
        meta["brain"] = str(getattr(cfg, "provider", "") or "")[:20]
    except Exception:  # noqa: BLE001
        pass

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
        "meta": meta,
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
    """Return the legacy (v1) authorized token whose HMAC matches the body, else None.

    Every candidate is checked (no early exit) so timing does not reveal which
    position matched.
    """
    found = None
    for tok in settings.authorized_tokens:
        if verify_body(tok, body, signature) and found is None:
            found = tok
    return found


@dataclass
class AuthResult:
    ok: bool
    code: int = 200
    error: str = ""
    credential: str = ""      # fingerprint persisted on the node row (binding)
    key_id: str = ""          # v2 key id ("" for legacy tokens)
    version: int = 0
    signed_ts: float | None = None   # v2: the timestamp covered by the signature


def authenticate(store, settings: FleetSettings, headers, body: bytes,
                 now: float | None = None) -> AuthResult:
    """The hub's entire authentication gate. Pure w.r.t. the clock (``now``).

    ``headers`` is anything with ``.get(name, default)``.
    """
    now = now if now is not None else time.time()
    sig = (headers.get(SIG_HEADER, "") or "").strip()
    key_id = (headers.get(KEY_HEADER, "") or "").strip()
    if sig.startswith("v2=") or key_id:
        if not (sig.startswith("v2=") and key_id):
            return AuthResult(False, 401, "invalid signature")
        key = None
        try:
            key = store.get_fleet_key(key_id[:64])
        except Exception:  # noqa: BLE001
            key = None
        ts_raw = (headers.get(TS_HEADER, "") or "").strip()[:32]
        # Compute against a dummy key when the id is unknown so an unknown id
        # and a bad signature are indistinguishable by timing.
        key_hex = key["hmac_key"] if key else "00" * 32
        try:
            expected = sign_v2(key_hex, ts_raw, body)
        except ValueError:
            expected = ""
        good = hmac.compare_digest(expected.encode(),
                                   sig[3:].encode("utf-8", "replace")) and key is not None
        if not good:
            return AuthResult(False, 401, "invalid signature")
        if key.get("revoked"):
            return AuthResult(False, 403, "enrollment key revoked")
        ts = _coerce_float(ts_raw)
        if ts is None:
            return AuthResult(False, 400, "missing timestamp")
        if settings.max_skew_s and abs(now - ts) > settings.max_skew_s:
            return AuthResult(False, 401,
                              f"timestamp outside the accepted window "
                              f"(±{settings.max_skew_s}s) — check the node's clock")
        return AuthResult(True, credential="key:" + key["key_id"], key_id=key["key_id"],
                          version=2, signed_ts=ts)
    token = identify_token(settings, body, sig)
    if token is None:
        return AuthResult(False, 401, "invalid signature")
    return AuthResult(True, credential=token_fingerprint(token), version=1)


def parse_report(body: bytes) -> dict | None:
    """Decode a report body to a dict, or None if malformed."""
    try:
        obj = json.loads(body.decode("utf-8"))
        return obj if isinstance(obj, dict) and obj.get("node_id") else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


class IngestRejected(Exception):
    """An authenticated report the hub still refuses (replay, binding, skew)."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _bounded_json(value, max_bytes: int, fallback):
    """Keep a nested report field only if it serializes small — the hub stores
    what nodes send, so a node must not be able to bloat the hub's database."""
    try:
        return value if len(json.dumps(value)) <= max_bytes else fallback
    except (TypeError, ValueError):
        return fallback


def ingest(store, settings: FleetSettings, report: dict, token: str | AuthResult,
           now: float | None = None) -> dict:
    """Authenticated report → upsert node + append history + prune. Returns row.

    Caller MUST have already authenticated the request (``authenticate``).
    ``token`` may be the AuthResult, or — for the legacy call shape — the raw
    v1 token. Raises ``IngestRejected`` for replays, stale reports, and node ids
    bound to a different credential.
    """
    now = now if now is not None else time.time()
    if isinstance(token, AuthResult):
        auth = token
    else:
        auth = AuthResult(True, credential=token_fingerprint(token), version=1)
    node_id = str(report.get("node_id"))[:120]
    report_ts = auth.signed_ts if auth.signed_ts is not None else _coerce_float(report.get("ts"))
    if report_ts is None:
        # no usable timestamp = no replay protection; never accept one
        raise IngestRejected(400, "report carries no valid timestamp")

    # check-then-write must be one transaction: two first reports racing each
    # other could otherwise both pass the binding / single-node checks
    with store.immediate():
        return _ingest_locked(store, settings, report, auth, node_id, report_ts, now)


MAX_NODES_PER_KEY = 5000


def _ingest_locked(store, settings: FleetSettings, report: dict, auth: AuthResult,
                   node_id: str, report_ts: float, now: float) -> dict:
    existing = store.get_fleet_node(node_id)
    if existing:
        bound = existing.get("token_hash") or ""
        if bound and bound != auth.credential:
            raise IngestRejected(
                409, f"node id {node_id!r} is registered to a different credential — "
                     "pick another node_id, or `wrench fleet forget` it on the hub first")
        last_ts = _coerce_float(existing.get("report_ts"))
        if last_ts is None:
            # a row from before replay tracking: its hub-side arrival time is the floor
            last_ts = _coerce_float(existing.get("last_seen"))
            if last_ts is not None and report_ts is not None and report_ts > last_ts - 1:
                last_ts = None
        if report_ts is not None and last_ts is not None and report_ts <= last_ts:
            raise IngestRejected(409, "stale or replayed report (not newer than the last accepted one)")
    elif auth.key_id:
        key = store.get_fleet_key(auth.key_id)
        if key and key.get("single_node"):
            others = [n for n in store.fleet_nodes_for_key(auth.key_id) if n != node_id]
            if others:
                raise IngestRejected(
                    403, "this enrollment key is single-node and already bound to "
                         f"{others[0]!r}")
    if not existing and auth.key_id and \
            len(store.fleet_nodes_for_key(auth.key_id)) >= MAX_NODES_PER_KEY:
        raise IngestRejected(403, f"this enrollment key already has {MAX_NODES_PER_KEY} "
                                  "nodes — mint another key")
    if auth.version == 1 and settings.max_skew_s and report_ts is not None \
            and abs(now - report_ts) > settings.max_skew_s:
        raise IngestRejected(401, f"report timestamp outside the accepted window "
                                  f"(±{settings.max_skew_s}s) — check the node's clock")

    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    findings = [{"severity": str(f.get("severity") or "info")[:20],
                 "text": str(f.get("text") or "")[:300]}
                for f in findings[:32] if isinstance(f, dict)]
    gauges = sanitize_gauges(report.get("gauges"))
    meta = sanitize_meta(report.get("meta"))
    row = store.upsert_fleet_node(
        node_id=node_id,
        hostname=str(report.get("hostname") or node_id)[:200],
        token_hash=auth.credential,
        status=str(report.get("status") or "ok")[:20],
        worst_severity=str(report.get("worst_severity") or "ok")[:20],
        summary=str(report.get("summary") or "")[:400],
        cadence_s=_coerce_float(report.get("cadence_s")),
        wrench_version=str(report.get("wrench_version") or "")[:40],
        findings=findings,
        gauges=gauges,
        now=now,
        meta=meta,
        report_ts=report_ts,
        key_id=auth.key_id or None,
    )
    if auth.key_id:
        try:
            store.touch_fleet_key(auth.key_id, now)
        except Exception:  # noqa: BLE001
            pass
    try:
        store.prune_fleet_reports(node_id, settings.report_retention)
    except Exception:  # noqa: BLE001
        pass
    return row


def _coerce_float(v) -> float | None:
    """A finite float, or None. NaN/inf are rejected: `nan` passes every
    comparison-based check (skew, replay) and is not valid JSON for a browser."""
    try:
        f = float(v) if v is not None and not isinstance(v, bool) else None
    except (TypeError, ValueError):
        return None
    return f if f is not None and math.isfinite(f) else None


def _short(v, n: int = 80) -> str:
    return str(v)[:n] if isinstance(v, (str, int, float)) and not isinstance(v, bool) else ""


def _pct_map(v, limit: int = 32) -> dict:
    """{name: finite percent} from a node-supplied mapping; anything else is dropped."""
    out: dict[str, float] = {}
    if isinstance(v, dict):
        for k, val in list(v.items())[:limit]:
            f = _coerce_float(val)
            if f is not None:
                out[str(k)[:120]] = max(0.0, min(f, 100.0))
    return out


def sanitize_gauges(g) -> dict:
    """Keep only the gauges the hub understands, each coerced to its type.

    The hub renders, sorts, averages and exports what nodes send. A node is an
    authenticated peer, not a trusted one: a string where a number belongs, a
    list where a map belongs, or a NaN must not be able to break the console
    for every other node.
    """
    if not isinstance(g, dict):
        return {}
    out: dict = {"disk_pct": _pct_map(g.get("disk_pct"))}
    for k in ("mem_pct", "swap_pct", "cpu_pct", "comply_score"):
        f = _coerce_float(g.get(k))
        if f is not None:
            out[k] = max(0.0, min(f, 100.0))
    for k in ("load_1m", "cert_worst_days"):
        f = _coerce_float(g.get(k))
        if f is not None:
            out[k] = f
    for k in ("security_worst", "cert_worst", "forecast_worst", "backup_worst"):
        if g.get(k) is not None:
            out[k] = _short(g.get(k), 20)
    return out


def sanitize_meta(m) -> dict:
    if not isinstance(m, dict):
        return {}
    out: dict = {"tags": _clean_tags(m.get("tags"))}
    for k, n in (("os", 20), ("os_label", 80), ("arch", 20), ("grade", 2),
                 ("policy_tier", 20), ("brain", 20)):
        if m.get(k) is not None:
            out[k] = _short(m.get(k), n)
    score = _coerce_float(m.get("score"))
    if score is not None:
        out["score"] = max(0.0, min(score, 100.0))
    for k in ("uptime_s", "mem_total_gb"):
        f = _coerce_float(m.get(k))
        if f is not None:
            out[k] = f
    pillars = m.get("pillars")
    if isinstance(pillars, dict):
        out["pillars"] = {str(k)[:24]: (None if _coerce_float(v) is None
                                        else max(0.0, min(_coerce_float(v), 100.0)))
                          for k, v in list(pillars.items())[:16]}
    return out


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


# ---------------- node-side push (never breaks a patrol) ----------------

def _outbox_path(data_dir) -> Path:
    return Path(data_dir) / OUTBOX_NAME


def _save_outbox(data_dir, report: dict) -> None:
    try:
        _outbox_path(data_dir).write_text(json.dumps(report))
    except OSError:
        pass


def _load_outbox(data_dir) -> dict | None:
    p = _outbox_path(data_dir)
    if not p.exists():
        return None
    try:
        obj = json.loads(p.read_text())
        return obj if isinstance(obj, dict) and obj.get("node_id") else None
    except (OSError, json.JSONDecodeError):
        return None


def _clear_outbox(data_dir) -> None:
    try:
        _outbox_path(data_dir).unlink()
    except OSError:
        pass


def signed_headers(settings: FleetSettings, body: bytes, node_id: str = "",
                   now: float | None = None) -> dict:
    """Request headers for a report — v2 for enrollment tokens, v1 otherwise."""
    headers = {"Content-Type": "application/json",
               "User-Agent": f"wrench-fleet/{__version__}",
               # HTTP headers are latin-1: percent-encode so any node name works
               NODE_HEADER: urllib.parse.quote(str(node_id)[:120], safe="")}
    if is_v2_token(settings.token):
        ts = f"{(now if now is not None else time.time()):.3f}"
        headers[KEY_HEADER] = key_id_of(settings.token)
        headers[TS_HEADER] = ts
        headers[SIG_HEADER] = "v2=" + sign_v2(derive_key(settings.token), ts, body)
    else:
        headers[SIG_HEADER] = sign_body(settings.token, body)
    return headers


def _tls_context(settings: FleetSettings) -> ssl.SSLContext | None:
    """Verification context for an https hub (optionally a private CA bundle)."""
    if not settings.hub_url.lower().startswith("https://"):
        return None
    ctx = ssl.create_default_context()
    if settings.ca_file:
        ctx.load_verify_locations(cafile=settings.ca_file)
    return ctx


def push_once(settings: FleetSettings, report: dict,
              timeout: float = PUSH_TIMEOUT_S, opener=None,
              now: float | None = None) -> tuple[bool, str]:
    """Sign + POST one report to the hub. Returns (ok, detail). Never raises."""
    if not settings.node_enabled:
        return False, "fleet node not configured (need hub_url + token)"
    if not settings.hub_url.lower().startswith(("http://", "https://")):
        return False, "hub_url must start with http:// or https://"
    body = report_bytes(report)
    url = settings.hub_url.rstrip("/") + REPORT_PATH
    try:
        req = urllib.request.Request(
            url, data=body, method="POST",
            headers=signed_headers(settings, body, report.get("node_id", ""), now=now))
        if opener is not None:
            cm = opener(req, timeout=timeout)
        else:
            cm = urllib.request.urlopen(req, timeout=timeout,  # noqa: S310 — scheme checked above
                                        context=_tls_context(settings))
        with cm as resp:
            code = getattr(resp, "status", 200)
        return (200 <= int(code) < 300), f"HTTP {code}"
    except urllib.error.HTTPError as e:
        # surface the hub's reason ("node id is registered to a different …")
        reason = ""
        try:
            reason = json.loads(e.read(2048).decode("utf-8", "replace")).get("error", "")
        except Exception:  # noqa: BLE001
            pass
        return False, f"HTTP {e.code}" + (f": {reason}" if reason else "")
    except Exception as e:  # noqa: BLE001 — a push must never break a patrol
        return False, f"{e.__class__.__name__}: {e}"


def is_permanent_rejection(detail: str) -> bool:
    """A 4xx the hub will keep giving — retrying the same report can't succeed."""
    return detail.startswith(("HTTP 400", "HTTP 401", "HTTP 403", "HTTP 409", "HTTP 413"))


def node_push(cfg, store, settings: FleetSettings | None = None,
              now: float | None = None, opener=None) -> dict:
    """Build the current report and push it; queue + retry on failure.

    Any previously-queued report is superseded by the fresh one (the hub only
    cares about the latest state), so the outbox holds at most the last unsent
    report. Returns {ok, detail, queued}.
    """
    st = settings or settings_from(cfg)
    if not st.node_enabled:
        return {"ok": False, "detail": "fleet node not configured", "queued": False}
    # Offline guarantee: fleet is LAN by design, so a hub on a private CIDR is
    # fine even in offline mode. A hub on a PUBLIC host is refused (don't queue
    # — it would never drain while offline).
    from . import offline as _offline
    if _offline.is_offline(cfg) and not _offline.egress_allowed(cfg, st.hub_url):
        return {"ok": False, "queued": False,
                "detail": "offline mode (offline = true): hub is not a local/"
                          "private address — fleet push skipped"}
    data_dir = cfg.data_dir
    report = build_report(cfg, store, st, now=now)
    ok, detail = push_once(st, report, opener=opener)
    if ok:
        _clear_outbox(data_dir)
        return {"ok": True, "detail": detail, "queued": False, "report": report}
    if is_permanent_rejection(detail):
        # the hub understood us and said no (bad key, clock skew, id conflict):
        # queueing would just replay the same refusal — surface it instead
        _clear_outbox(data_dir)
        return {"ok": False, "detail": detail, "queued": False, "report": report,
                "rejected": True}
    _save_outbox(data_dir, report)
    return {"ok": False, "detail": detail, "queued": True, "report": report}


def node_patrol_hook(cfg, store) -> dict | None:
    """Called at the end of a patrol: push this node's report if configured.

    Never fatal — an unreachable hub queues the report for the next patrol.
    """
    try:
        st = settings_from(cfg)
        if not st.node_enabled:
            return None
        return node_push(cfg, store, st)
    except Exception:  # noqa: BLE001 — fleet reporting never breaks a patrol
        return None


# ---------------- hub-side registration + dead-man notifications ----------------

def audit_registration(cfg, store, row: dict) -> bool:
    """On a node's FIRST report, seal a registration event + info notification.

    Returns True when this was a new registration. Never fatal.
    """
    try:
        if int(row.get("report_count") or 0) != 1:
            return False
        node_id = row.get("node_id")
        detail = {"node_id": node_id, "hostname": row.get("hostname"),
                  "token_fp": (row.get("token_hash") or "")[:16],
                  "wrench_version": row.get("wrench_version")}
        try:
            from . import audit
            audit.log_event(cfg, "fleet.register", detail)
        except Exception:  # noqa: BLE001
            pass
        try:
            from . import notifications
            notifications.emit_event(
                cfg, "fleet.register", "info",
                f"fleet: node {node_id} ({row.get('hostname')}) registered")
        except Exception:  # noqa: BLE001
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


def check_silent_nodes(cfg, store, settings: FleetSettings | None = None,
                       now: float | None = None, notify: bool = True) -> list[dict]:
    """Detect SILENT⇄live transitions, raise notifications, seal audit, persist.

    A node crossing live→silent raises a CRITICAL notification through the
    existing channel and seals ``fleet.silent``; silent→live raises an info
    recovery event. Returns the list of transitions. Never fatal.
    """
    st = settings or settings_from(cfg)
    now = now if now is not None else time.time()
    transitions: list[dict] = []
    try:
        states = node_states(store, st, now=now)
    except Exception:  # noqa: BLE001
        return transitions
    for s in states:
        # node_states carries the live 'silent' computation; the persisted flag
        # (set on the last transition) is the raw node row's 'silent' column.
        stored = bool(store_silent_flag(store, s["node_id"]))
        now_silent = bool(s["silent"])
        if now_silent and not stored:
            transitions.append({"node_id": s["node_id"], "to": "silent",
                                "age_s": s["age_s"]})
            _record_silent_transition(cfg, store, s, silent=True, notify=notify)
        elif (not now_silent) and stored:
            transitions.append({"node_id": s["node_id"], "to": "live",
                                "age_s": s["age_s"]})
            _record_silent_transition(cfg, store, s, silent=False, notify=notify)
    return transitions


def store_silent_flag(store, node_id: str) -> bool:
    row = store.get_fleet_node(node_id)
    return bool(row and row.get("silent"))


def _record_silent_transition(cfg, store, state: dict, silent: bool,
                              notify: bool) -> None:
    node_id = state["node_id"]
    try:
        store.set_fleet_silent(node_id, silent)
    except Exception:  # noqa: BLE001
        pass
    kind = "fleet.silent" if silent else "fleet.recovered"
    mins = int((state.get("age_s") or 0) // 60)
    if silent:
        msg = (f"fleet: node {node_id} is SILENT — no report for ~{mins}m "
               f"(cadence {int(state.get('effective_cadence_s') or 0)}s)")
        sev = "critical"
    else:
        msg = f"fleet: node {node_id} is reporting again (recovered)"
        sev = "info"
    try:
        from . import audit
        audit.log_event(cfg, kind, {"node_id": node_id, "age_s": state.get("age_s"),
                                    "hostname": state.get("hostname")})
    except Exception:  # noqa: BLE001
        pass
    if notify:
        try:
            from . import notifications
            notifications.emit_event(cfg, kind, sev, msg)
        except Exception:  # noqa: BLE001
            pass


def hub_patrol_hook(cfg, store) -> list[dict]:
    """Called at the end of a patrol on a HUB box: sweep for silent nodes."""
    try:
        st = settings_from(cfg)
        if not hub_active(store, st):
            return []
        return check_silent_nodes(cfg, store, st)
    except Exception:  # noqa: BLE001
        return []


def start_sweeper(cfg, db_path, interval_s: float = SWEEP_INTERVAL_S,
                  stop: threading.Event | None = None) -> threading.Thread:
    """Run the dead-man sweep inside the hub process.

    Before 3.0 silence was only noticed when the hub box happened to run a
    patrol. A hub's whole job is to notice a node going quiet, so the server
    sweeps on its own clock: a node crossing live→silent pages within a minute.
    """
    from .store import Store
    stop = stop or threading.Event()

    def loop():
        while not stop.wait(interval_s):
            try:
                store = Store(db_path)
                try:
                    check_silent_nodes(cfg, store, settings_from(cfg))
                finally:
                    store.close()
            except Exception:  # noqa: BLE001 — the sweeper must outlive any one error
                pass

    t = threading.Thread(target=loop, name="wrench-fleet-sweeper", daemon=True)
    t.stop_event = stop  # type: ignore[attr-defined]
    t.start()
    return t
