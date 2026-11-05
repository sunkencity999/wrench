"""wrench bundle — a portable evidence bundle for sneakernet.

The air-gap answer to "email me the state of the box." On a disconnected,
classified, or industrial host you cannot screen-share or SSH out — but you can
carry a USB stick. ``wrench bundle`` collects everything wrench knows into a
single, self-contained tar.gz: the latest patrol, a live status snapshot, drift
changes, security findings, compliance results, backups report, the forecast
feed, the tamper-evident audit chain (plus its verify result), a notifications
tail, versions, and the offline posture — as deterministic-named JSON files plus
one human-readable SUMMARY.md.

Safety:
  - No secrets. The config snapshot is walked and every key-ish field
    (api_key / token / secret / password / credential ...) is redacted; the
    live api_key is never touched at all.
  - Every collector is isolated: one failing subsystem records an error stub,
    the bundle still builds.
  - stdlib only (tarfile, gzip, json). Deterministic member names + fixed member
    metadata so the same inputs produce the same archive bytes.
"""

from __future__ import annotations

import gzip
import io
import json
import platform
import re
import tarfile
import time
from pathlib import Path

from . import __version__, offline

# Deterministic, sorted member filenames (prefixed so SUMMARY.md sorts first in
# a plain `tar tzf`). Order here is also the SUMMARY section order.
VERSIONS_FILE = "versions.json"
OFFLINE_FILE = "offline.json"
CONFIG_FILE = "config.redacted.json"
STATUS_FILE = "status.json"
PATROL_FILE = "patrol.json"
DRIFT_FILE = "drift.json"
SECURITY_FILE = "security.json"
COMPLY_FILE = "comply.json"
BACKUPS_FILE = "backups.json"
FORECAST_FILE = "forecast.json"
AUDIT_FILE = "audit.json"
NOTIFICATIONS_FILE = "notifications.json"

# Secret-ish config key names → redacted. Walk is recursive; value dropped.
_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|key|token|secret|password|passwd|credential)", re.IGNORECASE
)
_REDACTED = "<redacted>"


def redact(obj):
    """Recursively replace values under key-ish field names with <redacted>.

    Matches on the KEY name (not the value), so structure is preserved and an
    auditor can see a field existed while its secret is gone.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k):
                out[k] = _REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def _safe(fn, label: str):
    """Run a collector; on any error return an error stub instead of raising."""
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 — a bundle must survive a broken subsystem
        return {"error": f"{label} unavailable: {e.__class__.__name__}: {e}"}


def collect(cfg, store, now: float | None = None) -> dict[str, dict]:
    """Gather every section as a JSON-able dict keyed by bundle filename.

    Read-mostly: it samples sensors and reads the local store/audit/inbox. It
    does NOT reach the network (status/drift/comply/forecast/backups/audit are
    local; security/webintel honour offline mode and fail soft).
    """
    now = now or time.time()
    host = platform.node() or "localhost"

    def _versions():
        return {
            "wrench": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "hostname": host,
            "provider": cfg.provider,
            "base_url": cfg.base_url,
            "model": cfg.model,
            "deep_model": cfg.deep_model,
            "policy_tier": cfg.policy_tier,
        }

    def _status():
        from . import sensors
        return sensors.status_snapshot(store)

    def _patrol():
        patrols = store.recent_patrols(1)
        return patrols[0] if patrols else {"note": "no patrol runs recorded yet"}

    def _drift():
        from . import driftscan
        return {"changes": driftscan.scan(store)}

    def _security():
        from . import security
        return security.scan(cfg, store)

    def _comply():
        from . import comply
        return comply.scan(store)

    def _backups():
        from . import backups
        return backups.scan(cfg, store, persist=False)

    def _forecast():
        from . import forecast
        return forecast.feed_report(cfg, store, now=now, persist=False)

    def _audit():
        from . import audit
        return {
            "verify": audit.verify(cfg.data_dir),
            "entries": audit.read_records(cfg.data_dir),
        }

    def _notifications():
        from . import notifications
        rows = notifications.read_all(cfg.data_dir)
        # tail: most recent 100, newest last
        return {"count": len(rows), "tail": rows[-100:]}

    def _config():
        return redact(dict(getattr(cfg, "raw", {}) or {}))

    return {
        VERSIONS_FILE: _safe(_versions, "versions"),
        OFFLINE_FILE: offline.status_summary(cfg),
        CONFIG_FILE: _safe(_config, "config"),
        STATUS_FILE: _safe(_status, "status"),
        PATROL_FILE: _safe(_patrol, "patrol"),
        DRIFT_FILE: _safe(_drift, "drift"),
        SECURITY_FILE: _safe(_security, "security"),
        COMPLY_FILE: _safe(_comply, "comply"),
        BACKUPS_FILE: _safe(_backups, "backups"),
        FORECAST_FILE: _safe(_forecast, "forecast"),
        AUDIT_FILE: _safe(_audit, "audit"),
        NOTIFICATIONS_FILE: _safe(_notifications, "notifications"),
    }


# ---------------- SUMMARY.md ----------------

def _one_line(name: str, obj: dict) -> str:
    """A compact human headline for one section."""
    if isinstance(obj, dict) and obj.get("error"):
        return f"{name}: ⚠ {obj['error']}"
    if name == STATUS_FILE:
        os_ = obj.get("os", {}) if isinstance(obj, dict) else {}
        return (f"status: cpu {os_.get('cpu_pct', '?')}% · mem {os_.get('mem_pct', '?')}% · "
                f"{len(obj.get('anomalies_24h', []))} anomaly(ies) in 24h")
    if name == PATROL_FILE:
        if obj.get("note"):
            return f"patrol: {obj['note']}"
        n = len(obj.get("findings", []))
        return (f"patrol: {obj.get('status', '?')} · {n} finding(s) · "
                f"{obj.get('summary', '')[:80]}")
    if name == DRIFT_FILE:
        return f"drift: {len(obj.get('changes', []))} change(s) since last snapshot"
    if name == SECURITY_FILE:
        c = obj.get("counts", {})
        return (f"security: worst={obj.get('worst', '?')} · "
                + ", ".join(f"{k}:{v}" for k, v in c.items() if v) or "clean")
    if name == COMPLY_FILE:
        packs = obj.get("packs", [])
        bits = [f"{p.get('pack')}={p.get('score')}%" for p in packs]
        cf = obj.get("critical_fails", 0)
        cf = len(cf) if isinstance(cf, (list, tuple)) else cf
        return ("comply: " + (", ".join(bits) if bits else "no packs")
                + f" · {cf} critical fail(s)")
    if name == BACKUPS_FILE:
        if obj.get("no_jobs"):
            return "backups: no backup jobs detected"
        return f"backups: {obj.get('count', 0)} job(s) · worst={obj.get('worst', '?')}"
    if name == FORECAST_FILE:
        s = obj.get("soonest")
        tail = f" · soonest: {s.get('label')} in ~{s.get('eta_days')}d" if s else ""
        return f"forecast: worst={obj.get('worst', '?')}{tail}"
    if name == AUDIT_FILE:
        v = obj.get("verify", {})
        return (f"audit: {v.get('count', 0)} record(s) · "
                f"chain {'INTACT' if v.get('intact') else 'BROKEN'}")
    if name == NOTIFICATIONS_FILE:
        return f"notifications: {obj.get('count', 0)} in inbox (tail of {len(obj.get('tail', []))})"
    if name == VERSIONS_FILE:
        return (f"versions: wrench {obj.get('wrench')} · python {obj.get('python')} · "
                f"provider {obj.get('provider')}")
    if name == OFFLINE_FILE:
        return f"offline mode: {'ON — egress blocked' if obj.get('offline') else 'off'}"
    return name


def summary_md(sections: dict[str, dict], now: float | None = None) -> str:
    now = now or time.time()
    host = platform.node() or "localhost"
    when = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(now))
    off = sections.get(OFFLINE_FILE, {}) or {}
    lines = [
        f"# wrench evidence bundle — {host}",
        "",
        f"- generated: {when}",
        f"- wrench version: {__version__}",
        f"- offline mode: {'ON (zero egress enforced)' if off.get('offline') else 'off'}",
        "",
        "This bundle is a point-in-time snapshot of everything wrench knows about",
        "this machine, for air-gapped / sneakernet review. No secrets are included",
        "(config key material is redacted). Each line below has a matching JSON file.",
        "",
        "## At a glance",
        "",
    ]
    # Fixed, readable order
    order = [VERSIONS_FILE, OFFLINE_FILE, STATUS_FILE, PATROL_FILE, DRIFT_FILE,
             SECURITY_FILE, COMPLY_FILE, BACKUPS_FILE, FORECAST_FILE, AUDIT_FILE,
             NOTIFICATIONS_FILE]
    for name in order:
        if name in sections:
            lines.append(f"- **{name}** — {_one_line(name, sections[name])}")
    lines += [
        "",
        "## Files",
        "",
        "| file | contents |",
        "| --- | --- |",
        f"| SUMMARY.md | this file |",
        f"| {VERSIONS_FILE} | wrench/python/platform/provider versions |",
        f"| {OFFLINE_FILE} | offline posture: what's blocked / still allowed |",
        f"| {CONFIG_FILE} | config.toml snapshot, secrets redacted |",
        f"| {STATUS_FILE} | live sensor snapshot (cpu/mem/disk/docker/gpu + anomalies) |",
        f"| {PATROL_FILE} | most recent patrol report |",
        f"| {DRIFT_FILE} | config/port/service/user/package drift vs last snapshot |",
        f"| {SECURITY_FILE} | auth anomalies, access drift, listeners, CVEs |",
        f"| {COMPLY_FILE} | compliance pack results + scores |",
        f"| {BACKUPS_FILE} | detected backup jobs + freshness/integrity |",
        f"| {FORECAST_FILE} | capacity/cert future-incidents feed |",
        f"| {AUDIT_FILE} | tamper-evident audit chain + verify result |",
        f"| {NOTIFICATIONS_FILE} | notification inbox tail |",
        "",
        "— generated by wrench bundle 🔧",
        "",
    ]
    return "\n".join(lines)


# ---------------- archive writer ----------------

def default_out_path(now: float | None = None) -> Path:
    now = now or time.time()
    host = (platform.node() or "localhost").split(".")[0]
    date = time.strftime("%Y%m%d", time.localtime(now))
    return Path.cwd() / f"wrench-bundle-{host}-{date}.tar.gz"


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mtime: int) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = mtime       # fixed → deterministic archive for identical inputs
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    tar.addfile(info, io.BytesIO(data))


def write_bundle(sections: dict[str, dict], out_path: Path,
                 now: float | None = None) -> Path:
    """Write SUMMARY.md + one JSON file per section into a gzip'd tar at out_path.

    Deterministic: members are added in sorted order with fixed mtime/owner, and
    gzip's own mtime header is zeroed, so identical inputs produce identical
    bytes.
    """
    now = now or time.time()
    mtime = int(now)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    members: dict[str, bytes] = {
        "SUMMARY.md": summary_md(sections, now).encode("utf-8"),
    }
    for name, obj in sections.items():
        members[name] = (json.dumps(obj, ensure_ascii=False, indent=2,
                                    sort_keys=True, default=str) + "\n").encode("utf-8")

    # gzip with mtime=0 so the header is stable across runs
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for name in sorted(members):            # SUMMARY.md sorts first
                _add_bytes(tar, name, members[name], mtime)
    out_path.write_bytes(raw.getvalue())
    return out_path


def build(cfg, store, out_path: Path | str | None = None,
          now: float | None = None) -> tuple[Path, dict[str, dict]]:
    """Collect + write in one call. Returns (path, sections)."""
    now = now or time.time()
    out = Path(out_path) if out_path else default_out_path(now)
    sections = collect(cfg, store, now=now)
    write_bundle(sections, out, now=now)
    return out, sections
