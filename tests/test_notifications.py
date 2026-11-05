"""Notification channel: inbox/severity/threshold logic, the sinks' plan step
(mocked subprocess/HTTP — no real network), dispatch wiring, and the dashboard
endpoints."""

from __future__ import annotations

import io
import json
import threading
import urllib.request

import pytest

from wrench import notifications as notif
from wrench.config import Config


# ---------------- severity / threshold ----------------

@pytest.mark.parametrize("sev,rank", [
    ("ok", 0), ("info", 0), ("attention", 1), ("warning", 1),
    ("error", 2), ("critical", 3), ("", 0), ("garbage", 0), ("CRITICAL", 3),
])
def test_severity_rank(sev, rank):
    assert notif.severity_rank(sev) == rank


@pytest.mark.parametrize("sev,min_sev,expected", [
    ("ok", "attention", False),
    ("attention", "attention", True),
    ("critical", "attention", True),
    ("attention", "critical", False),
    ("error", "error", True),
    ("critical", "ok", True),       # min floor is attention — ok never notifies
    ("ok", "ok", False),
])
def test_should_notify(sev, min_sev, expected):
    assert notif.should_notify(sev, min_sev) is expected


def test_patrol_severity_escalates_to_worst_finding():
    p = {"status": "attention",
         "findings": [{"severity": "info", "text": "x"},
                      {"severity": "critical", "text": "y"}]}
    assert notif.patrol_severity(p) == "critical"
    assert notif.patrol_severity({"status": "ok", "findings": []}) == "ok"
    assert notif.patrol_severity({"status": "error", "findings": [
        {"severity": "recommendation", "text": "z"}]}) == "error"


# ---------------- inbox ----------------

def test_record_unread_mark_read_roundtrip(tmp_path):
    r1 = notif.record(tmp_path, "attention", "disk at 91%", report_id=111.5)
    r2 = notif.record(tmp_path, "critical", "service down", report_id=222.5)
    rows = notif.read_all(tmp_path)
    assert [r["id"] for r in rows] == [r1["id"], r2["id"]]
    assert all(not r["read"] for r in rows)
    assert rows[0]["report_id"] == 111.5

    # mark one specific id read
    assert notif.mark_read(tmp_path, ids=[r1["id"]]) == 1
    un = notif.unread(tmp_path)
    assert [r["id"] for r in un] == [r2["id"]]

    # mark everything read
    assert notif.mark_read(tmp_path) == 1
    assert notif.unread(tmp_path) == []
    # idempotent
    assert notif.mark_read(tmp_path) == 0


def test_inbox_tolerates_garbage_lines(tmp_path):
    notif.record(tmp_path, "attention", "real")
    with notif.inbox_path(tmp_path).open("a") as fh:
        fh.write("not json\n\n{\"no_id\": true}\n")
    rows = notif.read_all(tmp_path)
    assert len(rows) == 1 and rows[0]["summary"] == "real"


def test_summary_is_truncated(tmp_path):
    rec = notif.record(tmp_path, "critical", "x" * 2000)
    assert len(rec["summary"]) == 500


# ---------------- desktop sink (plan step, per-OS) ----------------

def test_desktop_plan_linux():
    argv = notif.desktop_plan("title", "body", system="Linux")
    assert argv[0] == "notify-send" and argv[-2:] == ["title", "body"]


def test_desktop_plan_macos_quotes():
    argv = notif.desktop_plan('a "quoted" title', "body", system="Darwin")
    assert argv[0] == "osascript"
    assert '\\"quoted\\"' in argv[2]


def test_desktop_plan_windows_and_unknown():
    argv = notif.desktop_plan("t't", "body", system="Windows")
    assert argv[0] == "powershell" and "t''t" in argv[-1]
    assert notif.desktop_plan("t", "b", system="plan9") is None


def test_send_desktop_runs_plan(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(notif.shutil, "which", lambda b: "/usr/bin/" + b)
    monkeypatch.setattr(notif.platform, "system", lambda: "Linux")
    assert notif.send_desktop("t", "b", tmp_path, runner=calls.append) is True
    assert calls and calls[0][0] == "notify-send"


def test_send_desktop_noop_when_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(notif.shutil, "which", lambda b: None)
    monkeypatch.setattr(notif.platform, "system", lambda: "Linux")
    assert notif.send_desktop("t", "b", tmp_path) is False  # silent no-op


def test_send_desktop_failure_logged_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr(notif.shutil, "which", lambda b: "/usr/bin/" + b)
    monkeypatch.setattr(notif.platform, "system", lambda: "Linux")

    def boom(argv):
        raise OSError("no display")
    assert notif.send_desktop("t", "b", tmp_path, runner=boom) is False
    assert "desktop sink failed" in (tmp_path / notif.LOG_NAME).read_text()


# ---------------- webhook sink (mocked HTTP) ----------------

class _FakeResp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_send_webhook_posts_json(tmp_path):
    seen = {}

    def opener(req, timeout):
        seen["url"] = req.full_url
        seen["timeout"] = timeout
        seen["body"] = json.loads(req.data.decode())
        seen["ct"] = req.get_header("Content-type")
        return _FakeResp()

    rec = {"severity": "critical", "summary": "sda is dying", "ts": 1.0}
    assert notif.send_webhook("https://ntfy.example/topic", rec, tmp_path,
                              opener=opener) is True
    assert seen["url"] == "https://ntfy.example/topic"
    assert seen["timeout"] == notif.WEBHOOK_TIMEOUT_S
    assert seen["ct"] == "application/json"
    assert seen["body"]["severity"] == "critical"
    assert "sda is dying" in seen["body"]["message"]
    assert seen["body"]["text"] == seen["body"]["content"]  # slack + discord shapes


def test_send_webhook_failure_logged_not_fatal(tmp_path):
    def opener(req, timeout):
        raise urllib.error.URLError("refused")
    rec = {"severity": "attention", "summary": "s", "ts": 1.0}
    assert notif.send_webhook("https://down.example", rec, tmp_path, opener=opener) is False
    assert "webhook sink failed" in (tmp_path / notif.LOG_NAME).read_text()
    assert notif.send_webhook("", rec, tmp_path) is False  # no url → no-op


# ---------------- settings + dispatch ----------------

def _cfg(**notify) -> Config:
    return Config(raw={"notify": notify} if notify else {})


def test_settings_defaults_and_overrides():
    st = notif.settings_from(_cfg())
    assert st.enabled and st.desktop and st.min_severity == "attention" \
        and st.webhook_url == ""
    st = notif.settings_from(_cfg(enabled=False, min_severity="CRITICAL",
                                  desktop=False, webhook_url="https://x"))
    assert not st.enabled and not st.desktop
    assert st.min_severity == "critical" and st.webhook_url == "https://x"


def test_dispatch_below_threshold_and_disabled(tmp_path):
    patrol = {"status": "ok", "summary": "all quiet", "findings": []}
    assert notif.dispatch(_cfg(), patrol, data_dir=tmp_path) is None
    patrol = {"status": "critical", "summary": "bad", "findings": []}
    assert notif.dispatch(_cfg(enabled=False), patrol, data_dir=tmp_path) is None
    assert notif.unread(tmp_path) == []


def test_dispatch_records_and_fans_out(tmp_path, monkeypatch):
    sent = {"desktop": 0, "webhook": 0}
    monkeypatch.setattr(notif, "send_desktop",
                        lambda *a, **k: sent.__setitem__("desktop", sent["desktop"] + 1))
    monkeypatch.setattr(notif, "send_webhook",
                        lambda *a, **k: sent.__setitem__("webhook", sent["webhook"] + 1))
    patrol = {"status": "attention", "summary": "disk filling",
              "findings": [{"severity": "critical", "text": "sda"}]}
    rec = notif.dispatch(_cfg(webhook_url="https://x"), patrol,
                         report_id=42.0, data_dir=tmp_path)
    assert rec["severity"] == "critical" and rec["report_id"] == 42.0
    assert sent == {"desktop": 1, "webhook": 1}
    assert len(notif.unread(tmp_path)) == 1


def test_dispatch_respects_desktop_off(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(notif, "send_desktop", lambda *a, **k: called.append(1))
    patrol = {"status": "critical", "summary": "x", "findings": []}
    rec = notif.dispatch(_cfg(desktop=False), patrol, data_dir=tmp_path)
    assert rec is not None and not called


def test_dispatch_never_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(notif, "record", lambda *a, **k: 1 / 0)
    patrol = {"status": "critical", "summary": "x", "findings": []}
    assert notif.dispatch(_cfg(), patrol, data_dir=tmp_path) is None


# ---------------- dashboard endpoints ----------------

@pytest.fixture
def server(tmp_path):
    from wrench import webapp
    from wrench.store import Store
    db = tmp_path / "w.db"
    Store(db).close()
    httpd = webapp.serve(db, port=0, bind="127.0.0.1", sample_thread=False)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}", tmp_path
    httpd.shutdown()


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, json.loads(r.read().decode())


def test_api_notifications_and_mark_read(server):
    url, data_dir = server
    code, body = _get(url + "/api/notifications")
    assert code == 200 and body == []

    rec = notif.record(data_dir, "critical", "service down", report_id=7.0)
    code, body = _get(url + "/api/notifications")
    assert code == 200 and len(body) == 1
    assert body[0]["id"] == rec["id"] and body[0]["report_id"] == 7.0

    req = urllib.request.Request(
        url + "/api/notifications/read",
        data=json.dumps({"ids": [rec["id"]]}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        assert json.loads(r.read().decode()) == {"marked": 1}
    code, body = _get(url + "/api/notifications")
    assert body == []


def test_api_notifications_read_foreign_origin_forbidden(server):
    url, data_dir = server
    notif.record(data_dir, "critical", "x")
    req = urllib.request.Request(
        url + "/api/notifications/read", data=b"{}",
        headers={"Content-Type": "application/json",
                 "Origin": "https://evil.example"}, method="POST")
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req, timeout=10)
    assert ei.value.code == 403
    assert len(notif.unread(data_dir)) == 1


# ---------------- patrol wiring ----------------

def test_run_patrol_dispatches_notification(tmp_path, monkeypatch):
    """run_patrol hooks dispatch after storing the report."""
    from wrench import agent as agent_mod
    from wrench.store import Store

    class FakeClient:
        last_usage = {"total_tokens": 10}

        def __init__(self, *a, **k):
            pass

        def chat(self, messages, model=None, purpose=None):
            return json.dumps({"action": "final", "answer":
                               "STATUS: critical\nSUMMARY: disk on fire\nFINDINGS:\n"
                               "- [critical] /dev/sda gone (smart)"})

    monkeypatch.setattr(agent_mod.Agent, "gather_context",
                        lambda self: ("ctx", {}))
    cfg = Config(raw={"notify": {"desktop": False}})  # no real notify-send in tests
    monkeypatch.setattr(Config, "data_dir",
                        property(lambda self: tmp_path), raising=False)
    store = Store(tmp_path / "w.db")
    p = agent_mod.run_patrol(cfg, store, client=FakeClient())
    assert p["status"] == "critical"
    assert p["notification"] is not None
    assert p["notification"]["report_id"] == p["ts"]
    rows = notif.unread(tmp_path)
    assert len(rows) == 1 and rows[0]["severity"] == "critical"
    store.close()
