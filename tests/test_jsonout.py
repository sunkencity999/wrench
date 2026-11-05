"""--json output: envelope stability, per-command schemas, exit codes.

Every command runs through typer's CliRunner against an isolated
WRENCH_CONFIG_DIR / WRENCH_DATA_DIR so nothing touches the real box state.
The config module computes paths at import time, so these tests reload the
wrench modules under the temp env (one reload for the whole module).
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from wrench import jsonout
from wrench.cli import app

runner = CliRunner()


@pytest.fixture()
def tmp_env(tmp_path, monkeypatch):
    """Isolate config + data dirs (config computes them at import time)."""
    from wrench import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.toml")
    return tmp_path


def _parse(result, expect_exit=0):
    assert result.exit_code == expect_exit, result.output
    doc = json.loads(result.output)
    assert doc["schema"].startswith("wrench.") and doc["schema"].endswith(".v1")
    assert isinstance(doc["generated_at"], float)
    assert doc["host"] and doc["version"]
    return doc


# ---------------- envelope helpers ----------------

def test_envelope_shape_and_cleaning(tmp_path):
    from dataclasses import dataclass

    @dataclass
    class D:
        x: int
        p: object

    doc = jsonout.envelope("unit", {"d": D(1, tmp_path), "s": {1, 2}})
    assert doc["schema"] == "wrench.unit.v1"
    assert doc["d"] == {"x": 1, "p": str(tmp_path)}
    assert sorted(doc["s"]) == ["1", "2"] or sorted(doc["s"]) == [1, 2]
    # round-trips through json
    json.dumps(doc)


def test_emit_prints_single_document(capsys):
    jsonout.emit("unit", {"k": "v"})
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["k"] == "v"


# ---------------- per-command schemas ----------------

def test_version_json():
    doc = _parse(runner.invoke(app, ["version", "--json"]))
    assert doc["schema"] == "wrench.version.v1"


def test_status_json(tmp_env):
    doc = _parse(runner.invoke(app, ["status", "--json"]))
    assert doc["schema"] == "wrench.status.v1"
    os_ = doc["os"]
    for key in ("cpu_pct", "mem_pct", "swap_pct", "disk_pct", "n_procs"):
        assert key in os_
    assert isinstance(doc["anomalies_24h"], list)
    assert isinstance(doc["unread_notifications"], int)


def test_report_json_empty_and_populated(tmp_env):
    doc = _parse(runner.invoke(app, ["report", "--json"]))
    assert doc["schema"] == "wrench.report.v1"
    assert doc["count"] == 0 and doc["patrols"] == []

    # seed one patrol directly in the store
    from wrench.config import load_config
    from wrench.store import Store
    cfg = load_config()
    s = Store(cfg.db_path)
    s.add_patrol("test-model", "attention", "disk trending up",
                 [{"severity": "warning", "text": "disk 91%"}], "# report", 123)
    s.close()
    doc = _parse(runner.invoke(app, ["report", "--json", "-n", "5"]))
    assert doc["count"] == 1
    p = doc["patrols"][0]
    assert p["status"] == "attention" and p["summary"] == "disk trending up"
    assert p["findings"][0]["severity"] == "warning"
    assert p["tokens"] == 123


def test_report_json_does_not_mark_notifications_read(tmp_env):
    from wrench import notifications as notif
    from wrench.config import load_config
    cfg = load_config()
    notif.record(cfg.data_dir, "critical", "boom")
    _parse(runner.invoke(app, ["report", "--json"]))
    assert len(notif.unread(cfg.data_dir)) == 1  # --json is read-only


def test_drift_json(tmp_env):
    doc = _parse(runner.invoke(app, ["drift", "--json"]))
    assert doc["schema"] == "wrench.drift.v1"
    assert doc["baseline_recorded"] is True
    assert doc["change_count"] == 0 and doc["changes"] == []
    # second run: baseline exists now
    doc = _parse(runner.invoke(app, ["drift", "--json"]))
    assert doc["baseline_recorded"] is False
    assert isinstance(doc["changes"], list)


def test_certs_json(tmp_env, monkeypatch):
    from wrench import certs as cmod
    c = cmod.CertInfo(path="/tmp/x.pem", source="wellknown:/tmp", subject="CN=unit.test",
                      days_left=10, key_type="RSA", key_bits=2048,
                      not_before=1.0, not_after=2.0)
    monkeypatch.setattr(cmod, "inventory", lambda **k: ([c], []))
    doc = _parse(runner.invoke(app, ["certs", "--json", "--no-verify-chain"]))
    assert doc["schema"] == "wrench.certs.v1"
    assert doc["count"] == 1 and doc["needing_attention"] == 1
    row = doc["certs"][0]
    assert row["common_name"] == "unit.test"
    assert row["days_left"] == 10 and row["expiry_severity"] == "warning"
    assert row["weak_key"] is False


def test_certs_audit_json(tmp_env, monkeypatch):
    from wrench import certs as cmod
    monkeypatch.setattr(cmod, "audit_report", lambda **k: {
        "certs": [], "weaknesses": [
            cmod.ConfigWeakness(kind="tls_version", severity="warning",
                                detail="TLSv1 enabled", source="/etc/nginx/a.conf")],
        "probes": [{"port": 443, "ok": True, "protocol": "TLSv1.3"}]})
    doc = _parse(runner.invoke(app, ["certs", "audit", "--json", "--no-probe"]))
    assert doc["schema"] == "wrench.certs.audit.v1"
    assert doc["weaknesses"][0]["kind"] == "tls_version"
    assert doc["probes"][0]["port"] == 443


def test_blueprint_history_json(tmp_env):
    res = runner.invoke(app, ["blueprint", "--history", "--json"])
    doc = _parse(res)
    assert doc["schema"] == "wrench.blueprint.history.v1"
    assert doc["count"] == 0 and doc["history"] == []


def test_notifications_json_and_mark_read(tmp_env):
    from wrench import notifications as notif
    from wrench.config import load_config
    cfg = load_config()
    notif.record(cfg.data_dir, "critical", "service down")
    notif.record(cfg.data_dir, "attention", "disk 91%")
    doc = _parse(runner.invoke(app, ["notifications", "--json"]))
    assert doc["schema"] == "wrench.notifications.v1"
    assert doc["count"] == 2 and doc["unread_count"] == 2
    assert doc["notifications"][0]["severity"] == "critical"
    # mark-read mutates only when asked
    _parse(runner.invoke(app, ["notifications", "--json", "--mark-read"]))
    doc = _parse(runner.invoke(app, ["notifications", "--json"]))
    assert doc["unread_count"] == 0 and doc["count"] == 0
    doc = _parse(runner.invoke(app, ["notifications", "--json", "--all"]))
    assert doc["count"] == 2


def test_doctor_json_exit_codes(tmp_env, monkeypatch):
    from wrench import providers

    monkeypatch.setattr(providers.LLMClient, "ping",
                        lambda self: (True, "200 in 12ms"))
    doc = _parse(runner.invoke(app, ["doctor", "--json"]))
    assert doc["schema"] == "wrench.doctor.v1"
    assert doc["healthy"] is True
    assert doc["checks"]["provider_ping"]["ok"] is True
    assert doc["checks"]["sensor_os"]["ok"] is True
    assert "policy_tier" in doc["checks"]

    monkeypatch.setattr(providers.LLMClient, "ping",
                        lambda self: (False, "connection refused"))
    res = runner.invoke(app, ["doctor", "--json"])
    doc = _parse(res, expect_exit=1)
    assert doc["healthy"] is False


# ---------------- output purity: stdout is exactly one JSON doc ----------------

@pytest.mark.parametrize("argv", [
    ["status", "--json"],
    ["report", "--json"],
    ["drift", "--json"],
    ["notifications", "--json"],
    ["blueprint", "--history", "--json"],
    ["version", "--json"],
])
def test_json_stdout_is_pure(tmp_env, argv):
    res = runner.invoke(app, argv)
    assert res.exit_code == 0, res.output
    json.loads(res.output)  # raises if any rich noise leaked into stdout
