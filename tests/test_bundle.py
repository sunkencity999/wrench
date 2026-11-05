"""wrench bundle — portable evidence archive.

Collection contents, secret redaction, writer determinism, SUMMARY.md, and the
CLI command (both pretty + --json) plus the doctor offline section. Offline mode
is forced throughout so no collector reaches the network.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from typer.testing import CliRunner

from wrench import bundle
from wrench.cli import app
from wrench.store import Store

runner = CliRunner()


@dataclass
class FakeCfg:
    raw: dict = field(default_factory=dict)
    offline: bool = True
    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434/v1"
    api_key: str = "sk-LIVE-SECRET-should-never-appear"
    model: str = "qwen2.5:3b"
    deep_model: str = "qwen2.5:7b"
    policy_tier: str = "suggest"
    _data_dir: Path = None

    @property
    def data_dir(self) -> Path:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        return self._data_dir

    @property
    def db_path(self) -> Path:
        return self.data_dir / "wrench.db"


def _cfg(tmp_path) -> FakeCfg:
    return FakeCfg(
        _data_dir=tmp_path / "data",
        raw={
            "provider": {"name": "ollama"},
            "ollama": {"base_url": "http://127.0.0.1:11434/v1",
                       "api_key": "sk-TOML-SECRET-123"},
            "notify": {"webhook_url": "https://ntfy.sh/topic",
                       "token": "SECRET-TOKEN-xyz"},
            "fleet": {"authorized_tokens": ["NODE-SECRET-1", "NODE-SECRET-2"]},
            "general": {"offline": True},
        },
    )


# ---------------- redaction ----------------

def test_redact_walks_nested_keys():
    src = {
        "api_key": "s1", "base_url": "http://x", "token": "s2",
        "nested": {"password": "s3", "fine": "keep", "secret": "s4"},
        "list": [{"credential": "s5"}, {"ok": "keep2"}],
        "authorized_tokens": ["s6", "s7"],
        "webhook_url": "https://hooks.slack.com/services/T/B/XXXX",
        "hub_url": "http://10.0.0.9:8788",
    }
    out = bundle.redact(src)
    assert out["api_key"] == "<redacted>"
    assert out["base_url"] == "http://x"          # not a secret field
    assert out["hub_url"] == "http://10.0.0.9:8788"  # endpoint, not a secret
    assert out["webhook_url"] == "<redacted>"     # webhook URLs are bearer creds
    assert out["token"] == "<redacted>"
    assert out["nested"]["password"] == "<redacted>"
    assert out["nested"]["fine"] == "keep"
    assert out["nested"]["secret"] == "<redacted>"
    assert out["list"][0]["credential"] == "<redacted>"
    assert out["list"][1]["ok"] == "keep2"
    assert out["authorized_tokens"] == "<redacted>"   # key name matches 'token'


# ---------------- collect ----------------

EXPECTED_FILES = {
    bundle.VERSIONS_FILE, bundle.OFFLINE_FILE, bundle.CONFIG_FILE,
    bundle.STATUS_FILE, bundle.PATROL_FILE, bundle.DRIFT_FILE,
    bundle.SECURITY_FILE, bundle.COMPLY_FILE, bundle.BACKUPS_FILE,
    bundle.FORECAST_FILE, bundle.AUDIT_FILE, bundle.NOTIFICATIONS_FILE,
}


def test_collect_has_all_sections(tmp_path):
    cfg = _cfg(tmp_path)
    store = Store(cfg.db_path)
    sections = bundle.collect(cfg, store, now=1_800_000_000)
    assert set(sections) == EXPECTED_FILES
    # offline section reflects the mode
    assert sections[bundle.OFFLINE_FILE]["offline"] is True
    # config is redacted
    cfgj = sections[bundle.CONFIG_FILE]
    assert cfgj["ollama"]["api_key"] == "<redacted>"
    assert cfgj["notify"]["token"] == "<redacted>"
    # versions present, no key
    assert sections[bundle.VERSIONS_FILE]["wrench"]
    store.close()


def test_collect_is_resilient_to_broken_collector(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    store = Store(cfg.db_path)
    from wrench import sensors
    monkeypatch.setattr(sensors, "status_snapshot",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    sections = bundle.collect(cfg, store, now=1_800_000_000)
    assert "error" in sections[bundle.STATUS_FILE]
    assert "boom" in sections[bundle.STATUS_FILE]["error"]
    # the rest still built
    assert bundle.VERSIONS_FILE in sections
    store.close()


# ---------------- writer + determinism ----------------

def test_write_bundle_contents_and_summary(tmp_path):
    sections = {
        bundle.VERSIONS_FILE: {"wrench": "9.9.9", "python": "3.12",
                               "provider": "ollama"},
        bundle.OFFLINE_FILE: {"offline": True, "disabled": ["x"]},
        bundle.STATUS_FILE: {"os": {"cpu_pct": 3, "mem_pct": 10},
                             "anomalies_24h": []},
    }
    out = tmp_path / "b.tar.gz"
    bundle.write_bundle(sections, out, now=1_800_000_000)
    with tarfile.open(out) as t:
        names = t.getnames()
        assert "SUMMARY.md" in names
        assert names == sorted(names)         # deterministic sorted order
        summary = t.extractfile("SUMMARY.md").read().decode()
        assert "wrench evidence bundle" in summary
        assert "offline mode: ON" in summary
        vj = json.loads(t.extractfile(bundle.VERSIONS_FILE).read())
        assert vj["wrench"] == "9.9.9"


def test_write_bundle_deterministic_bytes(tmp_path):
    sections = {bundle.VERSIONS_FILE: {"wrench": "1.2.3"},
                bundle.OFFLINE_FILE: {"offline": False}}
    a = tmp_path / "a.tar.gz"
    b = tmp_path / "b.tar.gz"
    bundle.write_bundle(sections, a, now=1_800_000_000)
    bundle.write_bundle(sections, b, now=1_800_000_000)
    assert hashlib.sha256(a.read_bytes()).digest() == \
           hashlib.sha256(b.read_bytes()).digest()
    # gzip header mtime is zeroed (stable)
    assert a.read_bytes()[4:8] == b"\x00\x00\x00\x00"


def test_build_default_path_and_no_secrets(tmp_path):
    cfg = _cfg(tmp_path)
    store = Store(cfg.db_path)
    out = tmp_path / "evidence.tar.gz"
    path, sections = bundle.build(cfg, store, out_path=out, now=1_800_000_000)
    assert path == out and out.exists()
    raw = out.read_bytes()
    # decompress and scan every byte for the known secrets
    with gzip.open(io.BytesIO(raw)) as g:
        blob = g.read().decode("utf-8", "replace")
    for secret in ("sk-LIVE-SECRET", "sk-TOML-SECRET-123", "SECRET-TOKEN-xyz",
                   "NODE-SECRET-1", "NODE-SECRET-2"):
        assert secret not in blob, f"secret leaked: {secret}"
    store.close()


# ---------------- CLI ----------------

@pytest.fixture()
def tmp_env(tmp_path, monkeypatch):
    from wrench import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.toml")
    # write an offline config so no collector reaches the network
    (tmp_path / "config.toml").write_text(
        '[provider]\nname = "ollama"\n[ollama]\n'
        'base_url = "http://127.0.0.1:11434/v1"\napi_key = "sk-CLI-SECRET-999"\n'
        '[general]\noffline = true\n'
    )
    return tmp_path


def test_cli_bundle_json(tmp_env):
    out = tmp_env / "cli-bundle.tar.gz"
    res = runner.invoke(app, ["bundle", "--out", str(out), "--json"])
    assert res.exit_code == 0, res.output
    doc = json.loads(res.output)
    assert doc["schema"] == "wrench.bundle.v1"
    assert doc["offline"] is True
    assert "SUMMARY.md" in doc["files"]
    assert Path(doc["path"]).exists()
    assert doc["bytes"] > 0
    # no secret in the archive
    with gzip.open(out) as g:
        assert "sk-CLI-SECRET-999" not in g.read().decode("utf-8", "replace")


def test_cli_bundle_pretty(tmp_env):
    out = tmp_env / "pretty.tar.gz"
    res = runner.invoke(app, ["bundle", "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert "wrench bundle" in res.output
    assert out.exists()


def test_cli_doctor_offline_section_json(tmp_env, monkeypatch):
    # stub the provider ping so the local-brain check doesn't need a live ollama
    from wrench.providers import LLMClient
    monkeypatch.setattr(LLMClient, "ping", lambda self: (True, "pong"))
    res = runner.invoke(app, ["doctor", "--json"])
    assert res.exit_code == 0, res.output
    doc = json.loads(res.output)
    off = doc["checks"]["offline"]
    assert off["offline"] is True
    assert off["brain_is_local"] is True        # 127.0.0.1 brain
    assert "OSV/CVE lookups" in off["disabled"]
