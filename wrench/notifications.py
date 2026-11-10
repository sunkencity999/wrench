"""wrench taps you on the shoulder — the notification channel.

After a patrol completes, if its findings meet the configured severity
threshold, a notification record lands in a JSONL inbox in the data dir and is
fanned out to best-effort sinks (desktop notification, generic JSON webhook).
The CLI, the web dashboard, and `wrench watch` all read the same inbox.

Everything here is stdlib-only and never fatal: a notification failure must
never break a patrol.

Config (``[notify]`` in config.toml):
    enabled      = true          # master switch
    min_severity = "attention"   # ok|info < attention < error < critical
    desktop      = true          # notify-send / osascript / powershell toast
    webhook_url  = ""            # generic JSON POST (ntfy, Slack, Discord, ...)

    # syslog / SIEM sink (RFC 5424)
    syslog_address      = ""     # "/dev/log", "udp://host:514", "tcp://host:514"
    syslog_min_severity = ""     # per-sink threshold (defaults to min_severity)

    # JSON-lines-over-HTTP sink (Splunk HEC-style / ELK http input / vector)
    http_jsonl_url          = ""  # POST one JSON object per line (ndjson)
    http_jsonl_min_severity = ""  # per-sink threshold (defaults to min_severity)
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import time
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

INBOX_NAME = "notifications.jsonl"
LOG_NAME = "notifications.log"
WEBHOOK_TIMEOUT_S = 5

# severity ladder — patrol statuses and finding severities both map onto it
SEVERITY_RANK = {
    "ok": 0, "info": 0, "recommendation": 0,
    "attention": 1, "warning": 1,
    "error": 2,
    "critical": 3,
}


def severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get((sev or "").strip().lower(), 0)


@dataclass
class NotifySettings:
    enabled: bool = True
    min_severity: str = "attention"
    desktop: bool = True
    webhook_url: str = ""
    syslog_address: str = ""
    syslog_min_severity: str = ""
    http_jsonl_url: str = ""
    http_jsonl_min_severity: str = ""


def settings_from(cfg) -> NotifySettings:
    """Read the [notify] section off a loaded Config (cfg.raw)."""
    sec = (getattr(cfg, "raw", None) or {}).get("notify", {})
    if not isinstance(sec, dict):
        sec = {}
    return NotifySettings(
        enabled=bool(sec.get("enabled", True)),
        min_severity=str(sec.get("min_severity", "attention")).lower(),
        desktop=bool(sec.get("desktop", True)),
        webhook_url=str(sec.get("webhook_url", "") or ""),
        syslog_address=str(sec.get("syslog_address", "") or ""),
        syslog_min_severity=str(sec.get("syslog_min_severity", "") or "").lower(),
        http_jsonl_url=str(sec.get("http_jsonl_url", "") or ""),
        http_jsonl_min_severity=str(sec.get("http_jsonl_min_severity", "") or "").lower(),
    )


def should_notify(severity: str, min_severity: str = "attention") -> bool:
    return severity_rank(severity) >= max(severity_rank(min_severity), 1)


def patrol_severity(patrol: dict) -> str:
    """Overall severity of a patrol = max(status, worst finding)."""
    best = severity_rank(patrol.get("status", "ok"))
    name = (patrol.get("status") or "ok").lower()
    if name not in SEVERITY_RANK:
        name, best = "ok", 0
    for f in patrol.get("findings") or []:
        sev = (f.get("severity") or "").lower()
        if severity_rank(sev) > best and sev in SEVERITY_RANK:
            best, name = severity_rank(sev), sev
    return name


# ---------------- inbox (JSONL) ----------------

def inbox_path(data_dir: Path) -> Path:
    return Path(data_dir) / INBOX_NAME


def _log(data_dir: Path, line: str) -> None:
    """Failures are logged, never fatal."""
    try:
        path = Path(data_dir) / LOG_NAME
        if path.exists() and path.stat().st_size > 2_000_000:   # keep the log bounded
            os.replace(path, path.with_suffix(".log.1"))
        with path.open("a", encoding="utf-8", errors="replace") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {line}\n")
    except (OSError, ValueError):
        pass


INBOX_MAX_ROWS = 2000     # the inbox is a tail, not an archive (SIEM sinks keep history)
from .filelock import FileLock as _FileLock  # noqa: E402


def record(data_dir: Path, severity: str, summary: str,
           report_id: float | None = None, report_path: str = "",
           kind: str = "patrol") -> dict:
    """Append one notification record to the inbox. Returns the record."""
    rec = {
        "id": uuid.uuid4().hex[:12],
        "ts": time.time(),
        "severity": severity,
        "kind": kind,
        "summary": (summary or "")[:500],
        "report_id": report_id,
        "report_path": report_path,
        "read": False,
    }
    p = inbox_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with _FileLock(p), p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec


def read_all(data_dir: Path) -> list[dict]:
    p = inbox_path(data_dir)
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "id" in obj:
                out.append(obj)
        except json.JSONDecodeError:
            continue
    return out


def unread(data_dir: Path) -> list[dict]:
    return [r for r in read_all(data_dir) if not r.get("read")]


def mark_read(data_dir: Path, ids: list[str] | None = None) -> int:
    """Mark notifications read (all unread when ids is None). Returns count."""
    p = inbox_path(data_dir)
    with _FileLock(p):
        rows = read_all(data_dir)
        n = 0
        for r in rows:
            if not r.get("read") and (ids is None or r.get("id") in ids):
                r["read"] = True
                n += 1
        trimmed = len(rows) > INBOX_MAX_ROWS
        if n or trimmed:
            rows = rows[-INBOX_MAX_ROWS:]
            tmp = p.with_suffix(".jsonl.tmp")
            tmp.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
            os.replace(tmp, p)
    return n


# ---------------- desktop sink (plan → apply, like scheduler.py) ----------------

def desktop_plan(title: str, body: str, system: str | None = None) -> list[str] | None:
    """Pure plan step: argv for a desktop notification on this OS, or None.

    Unit-testable on any OS by passing `system` explicitly.
    """
    system = (system or platform.system()).lower()
    if system == "linux":
        return ["notify-send", "--app-name=wrench", "--urgency=normal", title, body]
    if system == "darwin":
        def q(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')
        return ["osascript", "-e",
                f'display notification "{q(body)}" with title "{q(title)}"']
    if system == "windows":
        def pq(s: str) -> str:
            return s.replace("'", "''")
        script = (
            "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,"
            "ContentType=WindowsRuntime]|Out-Null;"
            "$t=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
            "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
            "$x=$t.GetElementsByTagName('text');"
            f"$x.Item(0).AppendChild($t.CreateTextNode('{pq(title)}'))|Out-Null;"
            f"$x.Item(1).AppendChild($t.CreateTextNode('{pq(body)}'))|Out-Null;"
            "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
            "'wrench').Show([Windows.UI.Notifications.ToastNotification]::new($t))"
        )
        return ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    return None


def send_desktop(title: str, body: str, data_dir: Path, runner=None) -> bool:
    """Best-effort desktop notification. Silent no-op when unavailable."""
    argv = desktop_plan(title, body)
    if not argv or shutil.which(argv[0]) is None:
        return False
    run = runner or (lambda a: subprocess.run(a, check=False, capture_output=True, timeout=10))
    try:
        run(argv)
        return True
    except Exception as e:  # noqa: BLE001 — best-effort by contract
        _log(data_dir, f"desktop sink failed: {e.__class__.__name__}: {e}")
        return False


# ---------------- webhook sink ----------------

def webhook_payload(rec: dict) -> dict:
    """Generic JSON shape that ntfy/Slack/Discord-style receivers can digest."""
    sev = rec.get("severity", "attention")
    text = f"🔧 wrench patrol [{sev}]: {rec.get('summary', '')}"
    return {
        "title": f"wrench patrol: {sev}",
        "message": rec.get("summary", ""),
        "text": text,          # Slack
        "content": text,       # Discord
        "severity": sev,
        "host": platform.node() or "localhost",
        "ts": rec.get("ts"),
    }


def send_webhook(url: str, rec: dict, data_dir: Path,
                 timeout: float = WEBHOOK_TIMEOUT_S, opener=None) -> bool:
    """POST the record as JSON. Failures are logged, never raised."""
    if not url:
        return False
    body = json.dumps(webhook_payload(rec)).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "wrench-notify"})
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as resp:
            getattr(resp, "status", 200)
        return True
    except Exception as e:  # noqa: BLE001 — best-effort by contract
        _log(data_dir, f"webhook sink failed: {e.__class__.__name__}: {e}")
        return False


# ---------------- syslog sink (RFC 5424) ----------------

# wrench severity ladder → syslog severity numbers (RFC 5424 §6.2.1)
_SYSLOG_SEVERITY = {"ok": 6, "info": 6, "recommendation": 6,
                    "attention": 4, "warning": 4,
                    "error": 3, "critical": 2}
_SYSLOG_FACILITY = 1  # user-level messages
SYSLOG_TIMEOUT_S = 5


def parse_syslog_address(address: str) -> tuple[str, str, int]:
    """Parse a syslog_address config value.

    Returns (scheme, host_or_path, port). Schemes: unix | udp | tcp.
    Accepted forms: "/dev/log", "udp://host:514", "tcp://host:601",
    bare "host:514" (treated as udp).
    """
    a = (address or "").strip()
    if not a:
        raise ValueError("empty syslog address")
    if a.startswith("/"):
        return ("unix", a, 0)
    scheme = "udp"
    rest = a
    if "://" in a:
        scheme, rest = a.split("://", 1)
        scheme = scheme.lower()
    if scheme not in ("udp", "tcp"):
        raise ValueError(f"unsupported syslog scheme {scheme!r}")
    host, _, port_s = rest.rpartition(":")
    if not host:
        host, port_s = rest, ""
    try:
        port = int(port_s) if port_s else 514
    except ValueError:
        raise ValueError(f"bad syslog port {port_s!r}") from None
    return (scheme, host, port)


def _sd_escape(v: str) -> str:
    """Escape a value for an RFC 5424 SD-PARAM."""
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def format_rfc5424(rec: dict, hostname: str | None = None,
                   app: str = "wrench") -> str:
    """Render one notification record as an RFC 5424 syslog message.

    PRI = facility*8 + severity; structured data carries the machine fields.
    """
    sev_name = (rec.get("severity") or "attention").lower()
    pri = _SYSLOG_FACILITY * 8 + _SYSLOG_SEVERITY.get(sev_name, 5)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(rec.get("ts") or time.time()))
    ts = ts[:-2] + ":" + ts[-2:] if len(ts) >= 5 else ts  # +0000 → +00:00
    host = hostname or platform.node() or "-"
    msgid = (rec.get("kind") or "patrol").replace(" ", "_")[:32]
    sd = (f'[wrench@32473 severity="{_sd_escape(sev_name)}"'
          f' kind="{_sd_escape(rec.get("kind") or "patrol")}"'
          f' id="{_sd_escape(rec.get("id") or "-")}"]')
    msg = (rec.get("summary") or "").replace("\n", " ")[:800]
    return f"<{pri}>1 {ts} {host} {app} {os.getpid()} {msgid} {sd} {msg}"


def send_syslog(address: str, rec: dict, data_dir: Path,
                timeout: float = SYSLOG_TIMEOUT_S, sock_factory=None) -> bool:
    """Send one RFC 5424 message. Failures are logged, never raised."""
    if not address:
        return False
    try:
        scheme, host, port = parse_syslog_address(address)
        line = format_rfc5424(rec)
        data = line.encode("utf-8", "replace")
        if sock_factory is not None:
            sock = sock_factory(scheme)
        elif scheme == "unix":
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        elif scheme == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            if scheme == "unix":
                sock.connect(host)
                sock.send(data)
            elif scheme == "udp":
                sock.sendto(data, (host, port))
            else:  # tcp — RFC 6587 octet-counted framing
                sock.connect((host, port))
                sock.sendall(f"{len(data)} ".encode() + data)
        finally:
            sock.close()
        return True
    except Exception as e:  # noqa: BLE001 — best-effort by contract
        _log(data_dir, f"syslog sink failed: {e.__class__.__name__}: {e}")
        return False


# ---------------- JSON-lines-over-HTTP sink (Splunk/ELK style) ----------------

def jsonl_payload(rec: dict) -> dict:
    """Flat event shape for log collectors (one object per line)."""
    return {
        "time": rec.get("ts"),
        "host": platform.node() or "localhost",
        "source": "wrench",
        "sourcetype": "wrench:notification",
        "event": {
            "id": rec.get("id"),
            "kind": rec.get("kind", "patrol"),
            "severity": rec.get("severity"),
            "summary": rec.get("summary"),
            "report_id": rec.get("report_id"),
        },
    }


def send_http_jsonl(url: str, rec: dict, data_dir: Path,
                    timeout: float = WEBHOOK_TIMEOUT_S, opener=None) -> bool:
    """POST the record as one ndjson line. Failures are logged, never raised."""
    if not url:
        return False
    body = (json.dumps(jsonl_payload(rec)) + "\n").encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-ndjson", "User-Agent": "wrench-notify"})
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as resp:
            getattr(resp, "status", 200)
        return True
    except Exception as e:  # noqa: BLE001 — best-effort by contract
        _log(data_dir, f"http_jsonl sink failed: {e.__class__.__name__}: {e}")
        return False


# ---------------- fan-out ----------------

def fan_out(st: NotifySettings, rec: dict, data_dir: Path, title: str | None = None,
            block_public: bool = False) -> dict:
    """Deliver one record to every configured sink that meets its threshold.

    Returns {sink: bool} for sinks that were attempted. Never raises.

    ``block_public`` (offline mode): skip network sinks (webhook / remote
    syslog / http_jsonl) whose host is not local/private; the desktop sink is
    always local and unaffected."""
    sev = rec.get("severity", "attention")
    out: dict = {}
    title = title or f"🔧 wrench [{rec.get('kind', 'patrol')}]: {sev}"
    if block_public:
        from . import offline as _offline
    if st.desktop and should_notify(sev, st.min_severity):
        out["desktop"] = send_desktop(title, rec.get("summary", ""), data_dir)
    if st.webhook_url and should_notify(sev, st.min_severity):
        if block_public and not _offline.url_is_private(st.webhook_url):
            out["webhook"] = False
            _log(data_dir, "offline mode: webhook sink skipped (public host)")
        else:
            out["webhook"] = send_webhook(st.webhook_url, rec, data_dir)
    if st.syslog_address and should_notify(sev, st.syslog_min_severity or st.min_severity):
        if block_public and not _offline.host_is_private(
                parse_syslog_address(st.syslog_address)[1]):
            out["syslog"] = False
            _log(data_dir, "offline mode: syslog sink skipped (public host)")
        else:
            out["syslog"] = send_syslog(st.syslog_address, rec, data_dir)
    if st.http_jsonl_url and should_notify(
            sev, st.http_jsonl_min_severity or st.min_severity):
        if block_public and not _offline.url_is_private(st.http_jsonl_url):
            out["http_jsonl"] = False
            _log(data_dir, "offline mode: http_jsonl sink skipped (public host)")
        else:
            out["http_jsonl"] = send_http_jsonl(st.http_jsonl_url, rec, data_dir)
    return out


def emit_event(cfg, kind: str, severity: str, summary: str,
               report_id: float | None = None,
               data_dir: Path | None = None) -> dict | None:
    """Record + fan out one subsystem event (blueprint apply, cert renewal, ...).

    The inbox record always lands when any sink threshold passes; per-sink
    thresholds are honored by fan_out. Returns the record or None. Never raises.
    """
    try:
        st = settings_from(cfg)
        if not st.enabled:
            return None
        thresholds = [st.min_severity]
        if st.syslog_address:
            thresholds.append(st.syslog_min_severity or st.min_severity)
        if st.http_jsonl_url:
            thresholds.append(st.http_jsonl_min_severity or st.min_severity)
        if not any(should_notify(severity, t) for t in thresholds):
            return None
        dd = Path(data_dir) if data_dir is not None else cfg.data_dir
        rec = record(dd, severity, summary, report_id=report_id, kind=kind)
        from . import offline as _offline
        fan_out(st, rec, dd, block_public=_offline.is_offline(cfg))
        return rec
    except Exception:  # noqa: BLE001 — a notification must never break the caller
        return None


# ---------------- dispatch (hooked into patrol completion) ----------------

def dispatch(cfg, patrol: dict, report_id: float | None = None,
             data_dir: Path | None = None) -> dict | None:
    """Record + fan out one patrol's notification. Returns the record, or None
    when below threshold / disabled. Never raises."""
    try:
        st = settings_from(cfg)
        if not st.enabled:
            return None
        sev = patrol_severity(patrol)
        thresholds = [st.min_severity]
        if st.syslog_address:
            thresholds.append(st.syslog_min_severity or st.min_severity)
        if st.http_jsonl_url:
            thresholds.append(st.http_jsonl_min_severity or st.min_severity)
        if not any(should_notify(sev, t) for t in thresholds):
            return None
        dd = Path(data_dir) if data_dir is not None else cfg.data_dir
        summary = patrol.get("summary") or "(no summary)"
        rec = record(dd, sev, summary, report_id=report_id, kind="patrol")
        from . import offline as _offline
        fan_out(st, rec, dd, title=f"🔧 wrench patrol: {sev}",
                block_public=_offline.is_offline(cfg))
        return rec
    except Exception:  # noqa: BLE001 — a notification must never break a patrol
        return None
