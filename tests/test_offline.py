"""wrench offline — the zero-egress guarantee.

Private/public URL matrix (10./192.168./172.16/127./::1/CGNAT/localhost/
hostname-less), config detection ([general]/top-level/attr/env), and that every
wired subsystem skips politely when offline is on — all with mocks, never a real
network call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from wrench import offline
from wrench.store import Store


@dataclass
class FakeCfg:
    raw: dict = field(default_factory=dict)
    offline: bool | None = None
    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434/v1"
    api_key: str = ""
    model: str = "qwen2.5:3b"
    deep_model: str = "qwen2.5:7b"
    max_tokens: int = 256
    policy_tier: str = "suggest"
    _data_dir: Path = field(default=None)

    @property
    def data_dir(self) -> Path:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        return self._data_dir

    @property
    def db_path(self) -> Path:
        return self.data_dir / "wrench.db"


def _cfg(tmp_path, **kw) -> FakeCfg:
    kw.setdefault("_data_dir", tmp_path / "data")
    return FakeCfg(**kw)


# ---------------- is_offline detection ----------------

def test_is_offline_default_false():
    assert offline.is_offline(FakeCfg(raw={})) is False


def test_is_offline_general_section():
    assert offline.is_offline(FakeCfg(raw={"general": {"offline": True}})) is True


def test_is_offline_top_level_key():
    assert offline.is_offline(FakeCfg(raw={"offline": True})) is True


def test_is_offline_attr_wins():
    # explicit cfg.offline attribute takes precedence over raw
    assert offline.is_offline(FakeCfg(offline=True, raw={})) is True
    assert offline.is_offline(FakeCfg(offline=False, raw={"general": {"offline": True}})) is False


def test_is_offline_via_loaded_config(tmp_path, monkeypatch):
    # end-to-end through config.load_config with env + toml
    import importlib
    from wrench import config as cfgmod
    monkeypatch.setenv("WRENCH_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("WRENCH_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WRENCH_OFFLINE", "1")
    importlib.reload(cfgmod)
    try:
        c = cfgmod.load_config()
        assert c.offline is True
        assert offline.is_offline(c) is True
    finally:
        monkeypatch.delenv("WRENCH_OFFLINE", raising=False)
        importlib.reload(cfgmod)


# ---------------- private vs public host matrix ----------------

PRIVATE = [
    "http://127.0.0.1:11434/v1",
    "http://127.5.5.5:8109",
    "http://10.0.0.51:8103/v1",
    "http://192.168.1.9:8000",
    "http://172.16.3.4",
    "http://172.31.255.1/x",
    "http://[::1]:8103/v1",
    "http://[fc00::1]:9000",          # IPv6 ULA
    "http://[fe80::1%eth0]:9000",     # IPv6 link-local with zone
    "http://100.100.42.1:443",        # CGNAT / Tailscale
    "http://localhost:8109/v1",
    "http://api.localhost/v1",        # *.localhost convention
    "http://169.254.1.1",             # link-local
]

PUBLIC = [
    "https://api.osv.dev/v1/querybatch",
    "https://endoflife.date/api/python.json",
    "https://api.openai.com/v1",
    "https://api.anthropic.com/v1",
    "http://8.8.8.8",
    "https://example.com/hook",
    "http://notlocal.example:8000",   # bare hostname, not localhost
    "http://1.1.1.1",
]


@pytest.mark.parametrize("url", PRIVATE)
def test_private_urls_allowed_offline(url):
    assert offline.url_is_private(url) is True
    off = FakeCfg(raw={"general": {"offline": True}})
    assert offline.egress_allowed(off, url) is True
    assert offline.guard(off, url, "x").allowed is True


@pytest.mark.parametrize("url", PUBLIC)
def test_public_urls_refused_offline(url):
    assert offline.url_is_private(url) is False
    off = FakeCfg(raw={"general": {"offline": True}})
    assert offline.egress_allowed(off, url) is False
    g = offline.guard(off, url, "CVE scan")
    assert g.allowed is False
    assert "offline mode" in g.reason
    assert "CVE scan" in g.reason


def test_hostnameless_and_malformed():
    assert offline.url_is_private("") is False
    assert offline.url_is_private("not a url") is False
    assert offline.host_is_private("") is False
    # a bare host (no scheme) still parses
    assert offline.host_is_private("10.0.0.5") is True
    assert offline.host_is_private("evil.example") is False


def test_online_allows_everything():
    on = FakeCfg(raw={})          # offline unset → online
    for url in PUBLIC + PRIVATE:
        assert offline.egress_allowed(on, url) is True
        assert offline.guard(on, url, "x").allowed is True


def test_guardresult_is_truthy():
    assert bool(offline.guard(FakeCfg(raw={}), "https://x.com", "f")) is True
    assert bool(offline.guard(FakeCfg(raw={"general": {"offline": True}}),
                              "https://x.com", "f")) is False


def test_status_summary():
    on = offline.status_summary(FakeCfg(raw={}))
    assert on["offline"] is False and on["disabled"] == []
    off = offline.status_summary(FakeCfg(raw={"offline": True}))
    assert off["offline"] is True and "OSV/CVE lookups" in off["disabled"]


# ---------------- wired subsystems skip politely (mocks, no network) ----------------

def _boom(*a, **k):
    raise AssertionError("network was attempted in offline mode!")


def test_webintel_scan_skips_offline(tmp_path, monkeypatch):
    from wrench import webintel
    # any real HTTP would blow up the test
    monkeypatch.setattr(webintel.requests, "post", _boom)
    monkeypatch.setattr(webintel.requests, "get", _boom)
    store = Store(tmp_path / "w.db")
    cfg = _cfg(tmp_path, raw={"general": {"offline": True}})
    res = webintel.scan(cfg, store, force=True)
    assert res["online"] is False
    assert res["offline_mode"] is True
    assert res["vulns"] == []
    store.close()


def test_security_cve_scan_skips_offline(tmp_path, monkeypatch):
    from wrench import security, webintel
    monkeypatch.setattr(webintel, "osv_querybatch", _boom)
    store = Store(tmp_path / "s.db")
    cfg = _cfg(tmp_path, raw={"general": {"offline": True}})
    res = security.cve_scan(cfg, store, force=True)
    assert res["available"] is False
    assert res.get("offline_mode") is True
    assert "offline mode" in res["error"]
    store.close()


def test_provider_chat_refuses_public_offline(tmp_path, monkeypatch):
    from wrench import providers
    monkeypatch.setattr(providers.requests, "post", _boom)
    cfg = _cfg(tmp_path, raw={"general": {"offline": True}},
               provider="openai", base_url="https://api.openai.com/v1")
    client = providers.LLMClient(cfg)
    with pytest.raises(providers.ProviderError) as ei:
        client.chat([{"role": "user", "content": "hi"}])
    assert "offline mode" in str(ei.value)


def test_provider_chat_allows_local_offline(tmp_path, monkeypatch):
    from wrench import providers
    # local brain: the guard must NOT block; stub the HTTP to a canned reply
    def fake_post(url, headers=None, json=None, timeout=None, **k):
        class R:
            status_code = 200
            def json(self):
                return {"choices": [{"message": {"content": "pong"}}],
                        "usage": {"total_tokens": 1}}
        return R()
    monkeypatch.setattr(providers.requests, "post", fake_post)
    cfg = _cfg(tmp_path, raw={"general": {"offline": True}},
               provider="ollama", base_url="http://127.0.0.1:11434/v1")
    client = providers.LLMClient(cfg)
    assert client.chat([{"role": "user", "content": "hi"}]) == "pong"


def test_fleet_push_refuses_public_hub_offline(tmp_path):
    from wrench import fleet
    cfg = _cfg(tmp_path, raw={
        "general": {"offline": True},
        "fleet": {"hub_url": "https://hub.public.example", "token": "t" * 40},
    })
    store = Store(tmp_path / "f.db")
    res = fleet.node_push(cfg, store, opener=_boom)   # opener must never be called
    assert res["ok"] is False and res["queued"] is False
    assert "offline mode" in res["detail"]
    store.close()


def test_fleet_push_allows_private_hub_offline(tmp_path):
    from wrench import fleet
    captured = {}

    def opener(req, timeout=None):
        captured["url"] = req.full_url

        class R:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return R()

    cfg = _cfg(tmp_path, raw={
        "general": {"offline": True},
        "fleet": {"hub_url": "http://10.0.0.9:8788", "token": "t" * 40},
    })
    store = Store(tmp_path / "f.db")
    res = fleet.node_push(cfg, store, opener=opener)
    assert res["ok"] is True                 # private hub reached
    assert captured["url"].startswith("http://10.0.0.9:8788")
    store.close()


def test_notifications_fanout_blocks_public_webhook(tmp_path, monkeypatch):
    from wrench import notifications as notif
    monkeypatch.setattr(notif, "send_webhook", _boom)
    st = notif.NotifySettings(enabled=True, min_severity="info", desktop=False,
                              webhook_url="https://ntfy.sh/secret-topic")
    rec = {"severity": "critical", "summary": "x", "kind": "patrol"}
    out = notif.fan_out(st, rec, tmp_path, block_public=True)
    assert out["webhook"] is False           # skipped, send_webhook never called


def test_notifications_fanout_allows_private_webhook(tmp_path, monkeypatch):
    from wrench import notifications as notif
    called = {}
    monkeypatch.setattr(notif, "send_webhook",
                        lambda *a, **k: called.setdefault("hit", True) or True)
    st = notif.NotifySettings(enabled=True, min_severity="info", desktop=False,
                              webhook_url="http://192.168.1.5/hook")
    rec = {"severity": "critical", "summary": "x", "kind": "patrol"}
    out = notif.fan_out(st, rec, tmp_path, block_public=True)
    assert out["webhook"] is True and called.get("hit") is True


def test_approvals_skips_public_webhook_offline(tmp_path, monkeypatch):
    from wrench import approvals
    monkeypatch.setattr(approvals, "post_webhook", _boom)
    cfg = _cfg(tmp_path, raw={
        "general": {"offline": True},
        "approvals": {"approval_webhook_url": "https://hooks.example.com/w"},
    })
    store = Store(tmp_path / "a.db")
    token, posted = approvals.create_and_notify(cfg, store, "fixxer:apply", "detail")
    assert token and posted is False         # token minted, webhook skipped
    store.close()
