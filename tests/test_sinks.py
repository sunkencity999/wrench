"""Syslog (RFC 5424) + JSON-lines-over-HTTP sinks: address parsing, message
formatting, emission with mock sockets/openers, per-sink thresholds, and the
generic emit_event fan-out. No real network anywhere."""

from __future__ import annotations

import io
import json
import re
import urllib.request

import pytest

from wrench import notifications as notif
from wrench.config import Config


def _cfg(tmp_path, notify: dict) -> Config:
    c = Config(provider="meta", raw={"notify": notify})
    c.data_dir_override = tmp_path
    return c


# Config carries data_dir as a property off data_dir_override-less logic;
# easiest: build a tiny stand-in with the two attributes dispatch/emit use.
class FakeCfg:
    def __init__(self, data_dir, notify):
        self.data_dir = data_dir
        self.raw = {"notify": notify}


# ---------------- address parsing ----------------

@pytest.mark.parametrize("addr,expected", [
    ("/dev/log", ("unix", "/dev/log", 0)),
    ("udp://siem.example.com:514", ("udp", "siem.example.com", 514)),
    ("tcp://siem.example.com:601", ("tcp", "siem.example.com", 601)),
    ("siem.example.com:1514", ("udp", "siem.example.com", 1514)),
    ("udp://siem.example.com", ("udp", "siem.example.com", 514)),
])
def test_parse_syslog_address(addr, expected):
    assert notif.parse_syslog_address(addr) == expected


@pytest.mark.parametrize("bad", ["", "ftp://x:1", "udp://h:notaport"])
def test_parse_syslog_address_rejects(bad):
    with pytest.raises(ValueError):
        notif.parse_syslog_address(bad)


# ---------------- RFC 5424 formatting ----------------

def test_format_rfc5424_shape():
    rec = {"id": "abc123", "ts": 1700000000.0, "severity": "critical",
           "summary": "disk / at 97%", "kind": "patrol"}
    line = notif.format_rfc5424(rec, hostname="box1")
    # PRI: facility 1 (user) * 8 + severity 2 (critical) = 10
    assert line.startswith("<10>1 ")
    assert " box1 wrench " in line
    assert '[wrench@32473 severity="critical" kind="patrol" id="abc123"]' in line
    assert line.endswith("disk / at 97%")
    # RFC 5424 timestamp with timezone colon
    assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2} ", line)


@pytest.mark.parametrize("sev,pri", [
    ("info", 14), ("attention", 12), ("warning", 12), ("error", 11),
    ("critical", 10), ("garbage", 13),
])
def test_format_rfc5424_pri_mapping(sev, pri):
    line = notif.format_rfc5424({"severity": sev, "summary": "x", "ts": 1.0})
    assert line.startswith(f"<{pri}>1 ")


def test_format_rfc5424_escapes_sd_and_flattens_newlines():
    rec = {"severity": "error", "summary": "line1\nline2", "ts": 1.0,
           "kind": 'we"ird]'}
    line = notif.format_rfc5424(rec)
    assert "\n" not in line
    assert 'kind="we\\"ird\\]"' in line


# ---------------- syslog emission (mock sockets) ----------------

class FakeSock:
    def __init__(self):
        self.sent: list[bytes] = []
        self.connected_to = None
        self.closed = False

    def settimeout(self, t):
        self.timeout = t

    def connect(self, addr):
        self.connected_to = addr

    def send(self, data):
        self.sent.append(data)

    def sendto(self, data, addr):
        self.connected_to = addr
        self.sent.append(data)

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def test_send_syslog_unix(tmp_path):
    sock = FakeSock()
    rec = {"severity": "critical", "summary": "boom", "ts": 1.0, "id": "x"}
    ok = notif.send_syslog("/dev/log", rec, tmp_path, sock_factory=lambda s: sock)
    assert ok and sock.connected_to == "/dev/log" and sock.closed
    assert sock.sent and sock.sent[0].startswith(b"<10>1 ")


def test_send_syslog_udp(tmp_path):
    sock = FakeSock()
    ok = notif.send_syslog("udp://siem:514", {"severity": "error", "summary": "s",
                                              "ts": 1.0}, tmp_path,
                           sock_factory=lambda s: sock)
    assert ok and sock.connected_to == ("siem", 514)


def test_send_syslog_tcp_octet_counted(tmp_path):
    sock = FakeSock()
    ok = notif.send_syslog("tcp://siem:601", {"severity": "error", "summary": "s",
                                              "ts": 1.0}, tmp_path,
                           sock_factory=lambda s: sock)
    assert ok and sock.connected_to == ("siem", 601)
    frame = sock.sent[0]
    # RFC 6587 octet counting: "<len> <msg>"
    count, _, msg = frame.partition(b" ")
    assert int(count) == len(msg)


def test_send_syslog_failure_logged_not_raised(tmp_path):
    def boom(scheme):
        raise OSError("no route")
    ok = notif.send_syslog("udp://siem:514", {"severity": "error", "summary": "s"},
                           tmp_path, sock_factory=boom)
    assert ok is False
    assert "syslog sink failed" in (tmp_path / "notifications.log").read_text()


def test_send_syslog_empty_address(tmp_path):
    assert notif.send_syslog("", {}, tmp_path) is False


# ---------------- http jsonl sink (mock opener) ----------------

def test_send_http_jsonl(tmp_path):
    captured = {}

    class Resp(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req: urllib.request.Request, timeout):
        captured["url"] = req.full_url
        captured["body"] = req.data
        captured["ct"] = req.headers.get("Content-type")
        return Resp()

    rec = {"id": "n1", "ts": 2.0, "severity": "critical", "summary": "oh no",
           "kind": "blueprint.rollback", "report_id": None}
    ok = notif.send_http_jsonl("http://collector:8088/services/collector",
                               rec, tmp_path, opener=opener)
    assert ok
    assert captured["ct"] == "application/x-ndjson"
    assert captured["body"].endswith(b"\n")
    evt = json.loads(captured["body"])
    assert evt["sourcetype"] == "wrench:notification"
    assert evt["event"]["severity"] == "critical"
    assert evt["event"]["kind"] == "blueprint.rollback"
    assert evt["time"] == 2.0


def test_send_http_jsonl_failure_logged(tmp_path):
    def opener(req, timeout):
        raise urllib.error.URLError("refused")
    import urllib.error
    ok = notif.send_http_jsonl("http://x/y", {"severity": "error"}, tmp_path,
                               opener=opener)
    assert ok is False
    assert "http_jsonl sink failed" in (tmp_path / "notifications.log").read_text()


# ---------------- settings + fan-out thresholds ----------------

def test_settings_from_reads_sink_config(tmp_path):
    cfg = FakeCfg(tmp_path, {"syslog_address": "udp://s:514",
                             "syslog_min_severity": "ERROR",
                             "http_jsonl_url": "http://c/h",
                             "http_jsonl_min_severity": "critical"})
    st = notif.settings_from(cfg)
    assert st.syslog_address == "udp://s:514"
    assert st.syslog_min_severity == "error"
    assert st.http_jsonl_url == "http://c/h"
    assert st.http_jsonl_min_severity == "critical"


def test_fan_out_honors_per_sink_thresholds(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(notif, "send_desktop", lambda *a, **k: calls.append("desktop"))
    monkeypatch.setattr(notif, "send_webhook", lambda *a, **k: calls.append("webhook"))
    monkeypatch.setattr(notif, "send_syslog", lambda *a, **k: calls.append("syslog"))
    monkeypatch.setattr(notif, "send_http_jsonl", lambda *a, **k: calls.append("http"))
    st = notif.NotifySettings(desktop=True, webhook_url="http://w",
                              min_severity="critical",
                              syslog_address="udp://s:514",
                              syslog_min_severity="attention",
                              http_jsonl_url="http://c",
                              http_jsonl_min_severity="error")
    # attention: only syslog qualifies
    notif.fan_out(st, {"severity": "attention", "summary": "s"}, tmp_path)
    assert calls == ["syslog"]
    calls.clear()
    # critical: everything fires
    notif.fan_out(st, {"severity": "critical", "summary": "s"}, tmp_path)
    assert sorted(calls) == ["desktop", "http", "syslog", "webhook"]


def test_emit_event_records_and_fans_out(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(notif, "send_syslog",
                        lambda addr, rec, dd, **k: sent.append(rec) or True)
    cfg = FakeCfg(tmp_path, {"desktop": False,
                             "syslog_address": "udp://s:514"})
    rec = notif.emit_event(cfg, "blueprint.apply", "attention",
                           "applied /etc/nginx/nginx.conf")
    assert rec is not None and rec["kind"] == "blueprint.apply"
    assert sent and sent[0]["summary"].startswith("applied")
    rows = notif.read_all(tmp_path)
    assert len(rows) == 1 and rows[0]["severity"] == "attention"


def test_emit_event_below_all_thresholds_is_silent(tmp_path):
    cfg = FakeCfg(tmp_path, {"syslog_address": "udp://s:514"})
    assert notif.emit_event(cfg, "blueprint.apply", "info", "quiet") is None
    assert notif.read_all(tmp_path) == []


def test_emit_event_per_sink_threshold_below_global(tmp_path, monkeypatch):
    """Sink threshold below the global one still fires (attention floor holds)."""
    sent = []
    monkeypatch.setattr(notif, "send_http_jsonl",
                        lambda url, rec, dd, **k: sent.append(rec) or True)
    cfg = FakeCfg(tmp_path, {"desktop": False, "min_severity": "critical",
                             "http_jsonl_url": "http://c",
                             "http_jsonl_min_severity": "attention"})
    rec = notif.emit_event(cfg, "certs.renew", "attention", "cert expires in 14d")
    assert rec is not None and sent
    # info stays below the ladder floor everywhere — by design
    assert notif.emit_event(cfg, "certs.renew", "info", "quiet") is None


def test_emit_event_disabled(tmp_path):
    cfg = FakeCfg(tmp_path, {"enabled": False, "syslog_address": "udp://s:514"})
    assert notif.emit_event(cfg, "x", "critical", "y") is None


def test_dispatch_still_works_with_sinks(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(notif, "send_syslog",
                        lambda addr, rec, dd, **k: sent.append(rec) or True)
    cfg = FakeCfg(tmp_path, {"desktop": False, "syslog_address": "/dev/log"})
    rec = notif.dispatch(cfg, {"status": "critical", "summary": "disk full",
                               "findings": []}, report_id=1.0)
    assert rec is not None and sent and sent[0]["kind"] == "patrol"
