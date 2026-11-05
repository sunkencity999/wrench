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
"""

from __future__ import annotations

import json
import os
import platform
import shutil
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
        with (Path(data_dir) / LOG_NAME).open("a") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {line}\n")
    except OSError:
        pass


def record(data_dir: Path, severity: str, summary: str,
           report_id: float | None = None, report_path: str = "") -> dict:
    """Append one notification record to the inbox. Returns the record."""
    rec = {
        "id": uuid.uuid4().hex[:12],
        "ts": time.time(),
        "severity": severity,
        "summary": (summary or "")[:500],
        "report_id": report_id,
        "report_path": report_path,
        "read": False,
    }
    p = inbox_path(data_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec


def read_all(data_dir: Path) -> list[dict]:
    p = inbox_path(data_dir)
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text().splitlines():
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
    rows = read_all(data_dir)
    n = 0
    for r in rows:
        if not r.get("read") and (ids is None or r.get("id") in ids):
            r["read"] = True
            n += 1
    if n:
        p = inbox_path(data_dir)
        tmp = p.with_suffix(".jsonl.tmp")
        tmp.write_text("".join(json.dumps(r) + "\n" for r in rows))
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
        if not should_notify(sev, st.min_severity):
            return None
        dd = Path(data_dir) if data_dir is not None else cfg.data_dir
        summary = patrol.get("summary") or "(no summary)"
        rec = record(dd, sev, summary, report_id=report_id)
        title = f"🔧 wrench patrol: {sev}"
        if st.desktop:
            send_desktop(title, summary, dd)
        if st.webhook_url:
            send_webhook(st.webhook_url, rec, dd)
        return rec
    except Exception:  # noqa: BLE001 — a notification must never break a patrol
        return None
