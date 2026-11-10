"""wrench fleet — hub/node reporting, HMAC auth, dead-man's switch.

Pure crypto (sign/verify + forgery rejection), compact report building from
cached scans, authenticated ingest + store history/prune, the dead-man switch
with an injected clock, silent↔live transitions (notification + audit + flag
persistence), node push with outbox queue+retry, and the CLI status JSON schema.
No real host scans, no network — a mock opener stands in for the hub.
"""

from __future__ import annotations

import json
import time
from pathlib import Path


from wrench import fleet
from wrench.store import Store


# ---------------- fixtures ----------------

class _Cfg:
    """Minimal stand-in for a loaded Config (what fleet reads)."""
    def __init__(self, data_dir: Path, fleet_cfg: dict | None = None,
                 patrol_interval_min: int = 15):
        self.raw = {"fleet": fleet_cfg} if fleet_cfg is not None else {}
        self._data_dir = Path(data_dir)
        self.patrol_interval_min = patrol_interval_min

    @property
    def data_dir(self) -> Path:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        return self._data_dir


def _store(tmp_path) -> Store:
    return Store(tmp_path / "wrench.db")


_ts_counter = iter(range(100, 10_000_000))


def _report(node_id="web-01", status="attention", worst="warning",
            cadence=600, findings=None, gauges=None, ts=None):
    # every report is newer than the last: the hub rejects replays
    ts = float(next(_ts_counter)) if ts is None else ts
    return {
        "node_id": node_id, "hostname": node_id, "wrench_version": "2.0.0",
        "ts": ts, "status": status, "worst_severity": worst, "cadence_s": cadence,
        "summary": "disk /mnt at 94%", "findings": findings or [],
        "gauges": gauges or {},
    }


# ---------------- crypto (pure) ----------------

def test_token_generation_is_unique_and_hex():
    toks = {fleet.generate_token() for _ in range(50)}
    assert len(toks) == 50               # no collisions
    t = toks.pop()
    assert len(t) == 64 and int(t, 16) >= 0   # 32 bytes hex


def test_sign_verify_roundtrip():
    tok = fleet.generate_token()
    body = fleet.report_bytes({"node_id": "n1", "x": 1})
    sig = fleet.sign_body(tok, body)
    assert fleet.verify_body(tok, body, sig)


def test_verify_rejects_tampered_body():
    tok = fleet.generate_token()
    sig = fleet.sign_body(tok, fleet.report_bytes({"node_id": "n1", "x": 1}))
    assert not fleet.verify_body(tok, fleet.report_bytes({"node_id": "n1", "x": 2}), sig)


def test_verify_rejects_wrong_token_and_bad_signature():
    tok = fleet.generate_token()
    body = fleet.report_bytes({"node_id": "n1"})
    sig = fleet.sign_body(tok, body)
    assert not fleet.verify_body(fleet.generate_token(), body, sig)
    assert not fleet.verify_body(tok, body, "")
    assert not fleet.verify_body(tok, body, "deadbeef")


def test_report_bytes_is_deterministic_regardless_of_key_order():
    a = fleet.report_bytes({"node_id": "n", "b": 2, "a": 1})
    b = fleet.report_bytes({"a": 1, "node_id": "n", "b": 2})
    assert a == b


def test_token_fingerprint_is_stable_and_not_the_token():
    tok = fleet.generate_token()
    fp = fleet.token_fingerprint(tok)
    assert fp == fleet.token_fingerprint(tok) and fp != tok and len(fp) == 64


# ---------------- settings ----------------

def test_settings_node_and_hub_enabled(tmp_path):
    node = fleet.settings_from(_Cfg(tmp_path, {"hub_url": "http://h:8788",
                                               "token": "abc", "node_id": "web-01"}))
    assert node.node_enabled and not node.hub_enabled
    assert node.node_id == "web-01"

    hub = fleet.settings_from(_Cfg(tmp_path, {"authorized_tokens": ["t1", "t2"]}))
    assert hub.hub_enabled and not hub.node_enabled
    assert hub.authorized_tokens == ["t1", "t2"]


def test_settings_authorized_tokens_accepts_single_string(tmp_path):
    hub = fleet.settings_from(_Cfg(tmp_path, {"authorized_tokens": "solo"}))
    assert hub.authorized_tokens == ["solo"] and hub.hub_enabled


def test_settings_disabled_without_fleet_section(tmp_path):
    s = fleet.settings_from(_Cfg(tmp_path, None))
    assert not s.node_enabled and not s.hub_enabled


def test_cadence_defaults_to_patrol_interval(tmp_path):
    s = fleet.settings_from(_Cfg(tmp_path, {"authorized_tokens": ["t"]},
                                 patrol_interval_min=10))
    assert s.cadence_s == 600


# ---------------- report builder (reuses CACHED scans only) ----------------

def test_build_report_from_cached_patrol_and_sample(tmp_path):
    st = _store(tmp_path)
    st.add_sample("os", {"mem_pct": 20.0, "swap_pct": 49.5,
                         "disk_pct": {"/": 61.0, "/mnt": 94.0}, "load_1m": 1.2})
    st.add_patrol("m", "attention", "disk pressure on /mnt",
                  [{"severity": "warning", "text": "/mnt at 94%"},
                   {"severity": "recommendation", "text": "clean up"}],
                  "ans", 5)
    cfg = _Cfg(tmp_path, {"hub_url": "http://h", "token": "t", "node_id": "web-01"})
    rep = fleet.build_report(cfg, st, now=1000.0)
    assert rep["node_id"] == "web-01"
    assert rep["status"] == "attention" and rep["worst_severity"] == "warning"
    assert rep["gauges"]["disk_pct"]["/mnt"] == 94.0
    # recommendations are not pushed as findings
    assert all(f["severity"] != "recommendation" for f in rep["findings"])
    assert rep["wrench_version"]
    st.close()


def test_build_report_empty_store_is_ok(tmp_path):
    st = _store(tmp_path)
    rep = fleet.build_report(_Cfg(tmp_path, {}), st, now=1.0)
    assert rep["status"] == "ok" and rep["worst_severity"] == "ok"
    assert rep["summary"] == "no patrol yet"
    st.close()


def test_build_report_folds_cert_worst(tmp_path):
    st = _store(tmp_path)
    st.upsert_cert({"path": "/c.pem", "subject": "CN=soon", "days_left": 5,
                    "not_after": 9e9, "sans": ["soon"]})
    rep = fleet.build_report(_Cfg(tmp_path, {}), st, now=1.0)
    assert rep["gauges"]["cert_worst_days"] == 5
    assert rep["worst_severity"] in ("warning", "critical")
    assert rep["status"] in ("attention", "critical")
    st.close()


# ---------------- hub ingest + store ----------------

def test_ingest_upserts_and_counts(tmp_path):
    st = _store(tmp_path)
    s = fleet.FleetSettings(authorized_tokens=["tok"], max_skew_s=0)
    row1 = fleet.ingest(st, s, _report(), "tok", now=1000.0)
    assert row1["report_count"] == 1 and row1["status"] == "attention"
    assert row1["token_hash"] == fleet.token_fingerprint("tok")
    row2 = fleet.ingest(st, s, _report(status="critical", worst="critical"),
                        "tok", now=1100.0)
    assert row2["report_count"] == 2 and row2["status"] == "critical"
    assert row2["first_seen"] == 1000.0 and row2["last_seen"] == 1100.0
    st.close()


def test_ingest_prunes_report_history(tmp_path):
    st = _store(tmp_path)
    s = fleet.FleetSettings(authorized_tokens=["tok"], report_retention=5, max_skew_s=0)
    for i in range(12):
        fleet.ingest(st, s, _report(ts=float(i + 1)), "tok", now=1000.0 + i)
    hist = st.fleet_report_history("web-01", limit=100)
    assert len(hist) == 5           # capped
    st.close()


def test_identify_token_matches_and_rejects(tmp_path):
    good, other = fleet.generate_token(), fleet.generate_token()
    s = fleet.FleetSettings(authorized_tokens=[other, good])
    body = fleet.report_bytes(_report())
    sig = fleet.sign_body(good, body)
    assert fleet.identify_token(s, body, sig) == good
    # forged signature matches nothing
    assert fleet.identify_token(s, body, "00" * 32) is None
    assert fleet.identify_token(s, body, fleet.sign_body("nope", body)) is None


def test_parse_report_rejects_malformed():
    assert fleet.parse_report(b"not json") is None
    assert fleet.parse_report(b'{"no":"node_id"}') is None
    assert fleet.parse_report(fleet.report_bytes(_report()))["node_id"] == "web-01"


# ---------------- dead-man's switch (injected clock) ----------------

def test_is_silent_with_injected_clock(tmp_path):
    s = fleet.FleetSettings(authorized_tokens=["t"], silent_factor=2.0, max_skew_s=0)
    node = {"last_seen": 1000.0, "cadence_s": 600}
    assert not fleet.is_silent(node, now=1000.0 + 1100, settings=s)   # < 1200
    assert fleet.is_silent(node, now=1000.0 + 1300, settings=s)       # > 1200


def test_node_color_ladder(tmp_path):
    s = fleet.FleetSettings(authorized_tokens=["t"], max_skew_s=0)
    base = {"last_seen": 1000.0, "cadence_s": 600}
    fresh = 1000.0 + 10
    assert fleet.node_color({**base, "status": "ok"}, fresh, s) == "green"
    assert fleet.node_color({**base, "status": "attention"}, fresh, s) == "yellow"
    assert fleet.node_color({**base, "status": "critical"}, fresh, s) == "red"
    assert fleet.node_color({**base, "status": "ok"}, 1000.0 + 5000, s) == "silent"


def test_node_states_and_summary(tmp_path):
    st = _store(tmp_path)
    s = fleet.FleetSettings(authorized_tokens=["t"], silent_factor=2.0, max_skew_s=0)
    fleet.ingest(st, s, _report(node_id="a", status="ok", worst="ok"), "t", now=1000.0)
    fleet.ingest(st, s, _report(node_id="b", status="critical", worst="critical"),
                 "t", now=1000.0)
    states = fleet.node_states(st, s, now=1000.0 + 10)
    summ = fleet.fleet_summary(states)
    assert summ["total"] == 2 and summ["green"] == 1 and summ["red"] == 1
    # far in the future → both silent
    summ2 = fleet.fleet_summary(fleet.node_states(st, s, now=1000.0 + 999999))
    assert summ2["silent"] == 2
    st.close()


# ---------------- silent transitions (notify + audit + persist) ----------------

def test_check_silent_nodes_transition_and_idempotent(tmp_path, monkeypatch):
    st = _store(tmp_path)
    cfg = _Cfg(tmp_path, {"authorized_tokens": ["t"], "max_skew_s": 0})
    s = fleet.settings_from(cfg)
    fleet.ingest(st, s, _report(node_id="n1"), "t", now=1000.0)

    emitted, sealed = [], []
    monkeypatch.setattr("wrench.notifications.emit_event",
                        lambda c, kind, sev, msg, **k: emitted.append((kind, sev)))
    monkeypatch.setattr("wrench.audit.log_event",
                        lambda c, kind, detail, **k: sealed.append(kind))

    # not yet silent
    assert fleet.check_silent_nodes(cfg, st, s, now=1001.0) == []
    # crosses into silent (cadence 600 × factor 2 = 1200)
    t1 = fleet.check_silent_nodes(cfg, st, s, now=1000.0 + 1300)
    assert len(t1) == 1 and t1[0]["to"] == "silent"
    assert fleet.store_silent_flag(st, "n1") is True
    assert ("fleet.silent", "critical") in emitted and "fleet.silent" in sealed
    # second sweep while still silent → no duplicate transition
    assert fleet.check_silent_nodes(cfg, st, s, now=1000.0 + 1400) == []
    st.close()


def test_silent_then_recovered_transition(tmp_path, monkeypatch):
    st = _store(tmp_path)
    cfg = _Cfg(tmp_path, {"authorized_tokens": ["t"], "max_skew_s": 0})
    s = fleet.settings_from(cfg)
    monkeypatch.setattr("wrench.notifications.emit_event", lambda *a, **k: None)
    monkeypatch.setattr("wrench.audit.log_event", lambda *a, **k: None)
    fleet.ingest(st, s, _report(node_id="n1"), "t", now=1000.0)
    fleet.check_silent_nodes(cfg, st, s, now=1000.0 + 1300)      # → silent
    assert fleet.store_silent_flag(st, "n1") is True
    # a fresh report arrives, then a sweep sees it live again
    fleet.ingest(st, s, _report(node_id="n1"), "t", now=5000.0)
    tr = fleet.check_silent_nodes(cfg, st, s, now=5001.0)
    assert tr and tr[0]["to"] == "live"
    assert fleet.store_silent_flag(st, "n1") is False
    st.close()


def test_audit_registration_only_on_first_report(tmp_path, monkeypatch):
    st = _store(tmp_path)
    cfg = _Cfg(tmp_path, {"authorized_tokens": ["t"], "max_skew_s": 0})
    s = fleet.settings_from(cfg)
    monkeypatch.setattr("wrench.notifications.emit_event", lambda *a, **k: None)
    sealed = []
    monkeypatch.setattr("wrench.audit.log_event",
                        lambda c, kind, detail, **k: sealed.append(kind))
    row1 = fleet.ingest(st, s, _report(node_id="n1"), "t", now=1000.0)
    assert fleet.audit_registration(cfg, st, row1) is True
    row2 = fleet.ingest(st, s, _report(node_id="n1"), "t", now=1100.0)
    assert fleet.audit_registration(cfg, st, row2) is False
    assert sealed == ["fleet.register"]
    st.close()


# ---------------- node push (mock opener, outbox queue + retry) ----------------

class _Resp:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_push_once_signs_and_posts(tmp_path):
    tok = fleet.generate_token()
    s = fleet.FleetSettings(hub_url="http://hub:8788", token=tok)
    rep = _report()
    captured = {}

    def opener(req, timeout=0):
        captured["url"] = req.full_url
        captured["sig"] = req.get_header(fleet.SIG_HEADER.capitalize()) \
            or req.get_header(fleet.SIG_HEADER)
        captured["body"] = req.data
        return _Resp(200)

    ok, detail = fleet.push_once(s, rep, opener=opener)
    assert ok and captured["url"].endswith(fleet.REPORT_PATH)
    assert fleet.verify_body(tok, captured["body"], captured["sig"])


def test_node_push_queues_on_failure_then_clears(tmp_path):
    st = _store(tmp_path)
    tok = fleet.generate_token()
    cfg = _Cfg(tmp_path, {"hub_url": "http://hub", "token": tok, "node_id": "n1"})
    s = fleet.settings_from(cfg)
    st.add_patrol("m", "ok", "all quiet", [], "ans", 1)

    def boom(req, timeout=0):
        raise OSError("connection refused")

    res = fleet.node_push(cfg, st, s, now=1000.0, opener=boom)
    assert not res["ok"] and res["queued"]
    assert fleet._outbox_path(cfg.data_dir).exists()

    res2 = fleet.node_push(cfg, st, s, now=1001.0, opener=lambda r, timeout=0: _Resp(200))
    assert res2["ok"] and not fleet._outbox_path(cfg.data_dir).exists()
    st.close()


def test_node_push_noop_when_unconfigured(tmp_path):
    st = _store(tmp_path)
    cfg = _Cfg(tmp_path, {})
    res = fleet.node_push(cfg, st, fleet.settings_from(cfg))
    assert res["ok"] is False and res["queued"] is False
    st.close()


# ---------------- CLI status JSON schema ----------------

def _isolate_config(monkeypatch, tmp_path):
    """Point the CLI's config/data dirs at tmp_path regardless of import timing."""
    import wrench.config as wc
    monkeypatch.setattr(wc, "DATA_DIR", tmp_path)
    monkeypatch.setattr(wc, "CONFIG_DIR", tmp_path / "cfg")
    monkeypatch.setattr(wc, "CONFIG_PATH", tmp_path / "cfg" / "config.toml")


def test_cli_status_json_schema(tmp_path, monkeypatch):
    _isolate_config(monkeypatch, tmp_path)
    # seed a node into the data-dir db the CLI will open
    st = Store(tmp_path / "wrench.db")
    s = fleet.FleetSettings(authorized_tokens=["t"], max_skew_s=0)
    fleet.ingest(st, s, _report(node_id="web-01"), "t", now=time.time())
    st.close()

    from typer.testing import CliRunner
    from wrench.cli import app
    res = CliRunner().invoke(app, ["fleet", "status", "--json"])
    assert res.exit_code in (0, 1)
    payload = json.loads(res.stdout)
    assert payload["schema"] == "wrench.fleet.v1"
    assert payload["summary"]["total"] == 1
    assert payload["nodes"][0]["node_id"] == "web-01"
    assert "worst_severity" in payload["nodes"][0]


def test_cli_token_generates_and_registers(tmp_path, monkeypatch):
    _isolate_config(monkeypatch, tmp_path)
    from typer.testing import CliRunner
    from wrench.cli import app
    res = CliRunner().invoke(app, ["fleet", "token", "--label", "web-01"])
    assert res.exit_code == 0
    # the fingerprint was registered in the db; the raw token is never persisted
    st = Store(tmp_path / "wrench.db")
    toks = st.fleet_tokens()
    st.close()
    assert len(toks) == 1 and toks[0]["label"] == "web-01"
    assert toks[0]["token_hash"] not in res.stdout   # only the raw token is shown
