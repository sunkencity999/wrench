"""Prometheus exporter: exposition format correctness, metric coverage
(sensors / notifications / certs / patrols / blueprints / drift), label
escaping, the /metrics route on the dashboard, and the bare exporter server."""

from __future__ import annotations

import json
import re
import time
import urllib.request

import pytest

from wrench import metrics, notifications as notif
from wrench.store import Store

EXPO_LINE = re.compile(
    r"^(?:# (?:HELP|TYPE) [a-zA-Z_:][a-zA-Z0-9_:]* .+"
    r"|[a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})? -?\d+(?:\.\d+)?(?:e[+-]?\d+)?)$")


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "wrench.db")
    yield s
    s.close()


def _value(text: str, name: str, labels: str = "") -> float:
    pat = ("^" + re.escape(name) + (re.escape(labels) if labels else "")
           + r" (-?[\d.e+]+)$")
    m = re.search(pat, text, re.MULTILINE)
    assert m, f"{name}{labels} not found in:\n{text}"
    return float(m.group(1))


def test_every_line_is_valid_exposition(store, tmp_path):
    store.add_sample("os", {"cpu_pct": 10.0, "mem_pct": 20.0, "swap_pct": 0.0,
                            "disk_pct": {"/": 40.0}, "load_1m": 1.0,
                            "n_procs": 100, "uptime_s": 1000,
                            "net_recv_rate_kbs": 1.5, "net_sent_rate_kbs": 0.5})
    text = metrics.render(store, tmp_path)
    assert text.endswith("\n")
    for line in text.strip().splitlines():
        assert EXPO_LINE.match(line), f"bad exposition line: {line!r}"


def test_sensor_gauges(store, tmp_path):
    store.add_sample("os", {"cpu_pct": 12.5, "mem_pct": 43.2, "swap_pct": 7.0,
                            "disk_pct": {"/": 91.0, "/home": 50.0},
                            "load_1m": 2.25, "n_procs": 345, "uptime_s": 7200,
                            "net_recv_rate_kbs": 10.0, "net_sent_rate_kbs": 3.0})
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_cpu_percent") == 12.5
    assert _value(text, "wrench_mem_percent") == 43.2
    assert _value(text, "wrench_swap_percent") == 7.0
    assert _value(text, "wrench_disk_percent", '{mount="/"}') == 91.0
    assert _value(text, "wrench_disk_percent", '{mount="/home"}') == 50.0
    assert _value(text, "wrench_load_1m") == 2.25
    assert _value(text, "wrench_procs") == 345
    assert _value(text, "wrench_uptime_seconds") == 7200


def test_timestamp_full_precision(store, tmp_path):
    ts = 1793909627.5
    store.add_sample("os", {"cpu_pct": 1.0}, ts=ts)
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_sample_timestamp_seconds") == ts


def test_notification_counts_by_severity(store, tmp_path):
    notif.record(tmp_path, "critical", "a")
    notif.record(tmp_path, "critical", "b")
    notif.record(tmp_path, "attention", "c")
    notif.mark_read(tmp_path, None)
    notif.record(tmp_path, "error", "d")
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_notifications_total", '{severity="critical"}') == 2
    assert _value(text, "wrench_notifications_total", '{severity="attention"}') == 1
    assert _value(text, "wrench_notifications_total", '{severity="error"}') == 1
    assert _value(text, "wrench_notifications_unread") == 1


def test_cert_expiry_days_per_cert(store, tmp_path):
    store.upsert_cert({"path": "/etc/ssl/a.pem", "subject": "CN=a.example.com",
                       "days_left": 12, "not_after": 2000000000.0})
    store.upsert_cert({"path": "/etc/ssl/b.pem", "subject": "CN=b.example.com",
                       "days_left": -3, "not_after": 1000000.0})
    store.upsert_cert({"path": "/etc/ssl/broken.pem", "subject": "",
                       "error": "parse error"})
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_cert_expiry_days",
                  '{cn="a.example.com",path="/etc/ssl/a.pem"}') == 12
    assert _value(text, "wrench_cert_expiry_days",
                  '{cn="b.example.com",path="/etc/ssl/b.pem"}') == -3
    assert _value(text, "wrench_certs_tracked") == 2  # parse error excluded


def test_patrol_counters_and_last_success(store, tmp_path):
    store.add_patrol("m", "ok", "all clear", [], "#", 10)
    time.sleep(0.01)
    ok_ts = store.add_patrol("m", "ok", "still fine", [], "#", 10)
    time.sleep(0.01)
    last_ts = store.add_patrol("m", "attention", "disk warm", [], "#", 10)
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_patrols_total", '{status="ok"}') == 2
    assert _value(text, "wrench_patrols_total", '{status="attention"}') == 1
    assert _value(text, "wrench_patrol_last_run_timestamp_seconds") == pytest.approx(last_ts)
    assert _value(text, "wrench_patrol_last_ok_timestamp_seconds") == pytest.approx(ok_ts)


def test_blueprint_counters_from_audit_log(store, tmp_path):
    audit = tmp_path / "blueprint_audit.jsonl"
    rows = [{"ts": 1, "ok": True, "rolled_back": False, "intent": "a", "files": []},
            {"ts": 2, "ok": True, "rolled_back": False, "intent": "b", "files": []},
            {"ts": 3, "ok": False, "rolled_back": True, "intent": "c", "files": []},
            {"ts": 4, "ok": False, "rolled_back": False, "intent": "d", "files": []}]
    audit.write_text("".join(json.dumps(r) + "\n" for r in rows))
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_blueprint_applies_total") == 2
    assert _value(text, "wrench_blueprint_rollbacks_total") == 1
    assert _value(text, "wrench_blueprint_failures_total") == 1


def test_drift_change_count(store, tmp_path):
    store.add_diff("ports", "new listener :9999", ["+ :9999"])
    store.add_diff("packages", "2 upgraded", ["a", "b"])
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_drift_changes_7d") == 2
    assert "wrench_drift_last_change_timestamp_seconds" in text


def test_label_escaping(store, tmp_path):
    store.upsert_cert({"path": '/tmp/we"ird\\x.pem', "subject": 'CN=we"ird',
                       "days_left": 5, "not_after": 1.0})
    text = metrics.render(store, tmp_path)
    assert 'cn="we\\"ird"' in text
    assert '\\\\x.pem' in text


def test_empty_store_still_renders(store, tmp_path):
    text = metrics.render(store, tmp_path)
    assert "wrench_info" in text
    assert _value(text, "wrench_blueprint_applies_total") == 0
    assert "wrench_scrape_timestamp_seconds" in text


# ---------------- HTTP: dashboard /metrics + bare exporter ----------------

def _get(url: str) -> tuple[int, str, str]:
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.headers.get("Content-Type", ""), r.read().decode()


def test_webapp_metrics_route(tmp_path):
    from wrench.webapp import serve
    db = tmp_path / "wrench.db"
    s = Store(db)
    s.add_sample("os", {"cpu_pct": 5.0})
    s.close()
    httpd = serve(db, port=0, sample_thread=False)
    import threading
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = httpd.server_address[1]
        code, ctype, body = _get(f"http://127.0.0.1:{port}/metrics")
        assert code == 200
        assert ctype.startswith("text/plain")
        assert "wrench_cpu_percent 5" in body
    finally:
        httpd.shutdown()


def test_bare_exporter_server(tmp_path):
    db = tmp_path / "wrench.db"
    s = Store(db)
    s.add_sample("os", {"cpu_pct": 7.0})
    s.close()
    httpd = metrics.serve(db, port=0)
    import threading
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = httpd.server_address[1]
        code, ctype, body = _get(f"http://127.0.0.1:{port}/metrics")
        assert code == 200 and "wrench_cpu_percent 7" in body
        # anything else 404s
        with pytest.raises(urllib.error.HTTPError):
            _get(f"http://127.0.0.1:{port}/api/summary")
    finally:
        httpd.shutdown()


import urllib.error  # noqa: E402  (used in the test above)


def test_audit_and_approval_gauges(store, tmp_path):
    from wrench import audit, approvals
    # seal a couple of audit events + create/approve one approval token
    store.add_action("repair", "fixxer:disk-clean", "rm -rf /x", True, "ok")
    audit.append(tmp_path, "consent.grant", {"subsystem": "fixxer"})
    token, _ = approvals.create_pending(store, "fixxer apply", "d")
    approvals.approve(store, token)
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_audit_intact") == 1.0
    assert _value(text, "wrench_audit_entries") >= 3.0
    assert _value(text, "wrench_approvals", '{state="approved"}') == 1.0
    for line in text.strip().splitlines():
        assert EXPO_LINE.match(line), f"bad exposition line: {line!r}"


def test_audit_intact_gauge_flips_on_tamper(store, tmp_path):
    from wrench import audit
    for i in range(3):
        audit.append(tmp_path, f"e{i}", {"n": i})
    p = audit.audit_path(tmp_path)
    lines = p.read_text().splitlines()
    import json as _j
    victim = _j.loads(lines[1]); victim["detail"] = {"n": 999}
    lines[1] = _j.dumps(victim)
    p.write_text("\n".join(lines) + "\n")
    text = metrics.render(store, tmp_path)
    assert _value(text, "wrench_audit_intact") == 0.0
