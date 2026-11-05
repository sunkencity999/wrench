"""`custom` provider tests — any OpenAI-compatible endpoint.

All HTTP is mocked; no live server needed. Covers: the PROVIDER_DEFAULTS entry,
that custom routes through the shared _openai_compat path, that a missing/empty
API key is allowed (keyless internal endpoints), the non-TTY init path that
never hangs, and a config.toml base_url override.
"""

from __future__ import annotations

import requests

from wrench.config import Config, load_config, write_default_config
from wrench.providers import LLMClient, ProviderError


# ---------------- helpers (mirror test_azure.py) ----------------

def _ok_response(text="pong"):
    return FakeResponse(200, {
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
    })


class FakeResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text or "err"

    def json(self):
        return self._payload


class Recorder:
    """Stands in for requests.post; records every call."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers=None, params=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers or {},
                           "params": params or {}, "json": json or {}})
        return self.responses.pop(0) if self.responses else _ok_response()


def _custom_cfg(**kw):
    base = dict(provider="custom", base_url="http://127.0.0.1:8000/v1",
                model="my-local-model", deep_model="my-local-model",
                api_key="", max_tokens=512,
                azure_api_version="", azure_auth="auto")
    base.update(kw)
    return Config(**base)


def _client(monkeypatch, cfg, responses):
    rec = Recorder(responses)
    monkeypatch.setattr(requests, "post", rec)
    return LLMClient(cfg), rec


# ---------------- 1. defaults entry sanity ----------------

def test_custom_in_provider_defaults():
    from wrench.config import PROVIDER_DEFAULTS
    assert "custom" in PROVIDER_DEFAULTS
    d = PROVIDER_DEFAULTS["custom"]
    # no sane default endpoint — must be empty so init demands one
    assert d["base_url"] == ""
    assert d["model"] == ""
    assert d["key_env"] == "CUSTOM_API_KEY"
    assert d["max_tokens"] == 4096


# ---------------- 2. custom routes through the openai-compat path ----------------

def test_custom_routes_openai_compat(monkeypatch):
    client, rec = _client(monkeypatch, _custom_cfg(), [_ok_response()])
    out = client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert out == "pong"
    call = rec.calls[0]
    # openai-compat path: <base>/chat/completions, model carried in the body
    assert call["url"] == "http://127.0.0.1:8000/v1/chat/completions"
    assert call["json"]["model"] == "my-local-model"
    # NOT the azure deployment-path dialect
    assert "/openai/deployments/" not in call["url"]
    assert call["params"] == {}


# ---------------- 3. keyless request allowed ----------------

def test_custom_keyless_request_allowed(monkeypatch):
    # empty key: no Authorization header, request still goes through
    client, rec = _client(monkeypatch, _custom_cfg(api_key=""), [_ok_response()])
    out = client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert out == "pong"
    assert "Authorization" not in rec.calls[0]["headers"]


def test_custom_with_key_sends_bearer(monkeypatch):
    # when a key IS provided, it rides as a bearer token (same as other compat)
    client, rec = _client(monkeypatch, _custom_cfg(api_key="sk-internal"),
                          [_ok_response()])
    client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert rec.calls[0]["headers"]["Authorization"] == "Bearer sk-internal"


def test_custom_http_error_is_clear(monkeypatch):
    client, _ = _client(monkeypatch, _custom_cfg(),
                        [FakeResponse(500, text="boom")])
    try:
        client.chat([{"role": "user", "content": "hi"}], retries=0)
        raise AssertionError("should have raised")
    except ProviderError as e:
        assert "custom HTTP 500" in str(e)


# ---------------- 4. init non-TTY path (never hangs) ----------------

def test_custom_guided_setup_non_tty_no_url(monkeypatch):
    """Non-TTY + no WRENCH_BASE_URL → incomplete, no prompt, no hang."""
    from wrench import cli
    monkeypatch.delenv("WRENCH_BASE_URL", raising=False)
    base_url, model, complete = cli._custom_guided_setup(interactive=False, model=None)
    assert complete is False
    assert base_url is None


def test_custom_guided_setup_non_tty_with_live_url(monkeypatch):
    """Non-TTY + WRENCH_BASE_URL pointing at a live endpoint → picks a model."""
    from wrench import cli, localsetup
    monkeypatch.setenv("WRENCH_BASE_URL", "http://127.0.0.1:8000/v1")
    monkeypatch.setattr(localsetup, "openai_server_alive", lambda url: True)
    monkeypatch.setattr(localsetup, "openai_models",
                        lambda url: ["model-a", "model-b"])
    base_url, model, complete = cli._custom_guided_setup(interactive=False, model=None)
    assert complete is True
    assert base_url == "http://127.0.0.1:8000/v1"
    assert model == "model-a"  # first served model in non-interactive mode


def test_custom_guided_setup_url_unreachable(monkeypatch):
    """A URL that doesn't answer /models → incomplete, URL preserved for the hint."""
    from wrench import cli, localsetup
    monkeypatch.setenv("WRENCH_BASE_URL", "http://127.0.0.1:9999/v1")
    monkeypatch.setattr(localsetup, "openai_server_alive", lambda url: False)
    base_url, model, complete = cli._custom_guided_setup(interactive=False, model=None)
    assert complete is False
    assert base_url == "http://127.0.0.1:9999/v1"


# ---------------- 5. config.toml base_url override for custom ----------------

def test_custom_config_toml_base_url_override(monkeypatch, tmp_path):
    import wrench.config as cfgmod
    monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "config.toml")
    for var in ("WRENCH_BASE_URL", "WRENCH_MODEL", "WRENCH_API_KEY", "CUSTOM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    write_default_config("custom", model="internal-vllm-model",
                         base_url="http://10.0.0.9:8000/v1")
    cfg = load_config(provider_override="custom")
    assert cfg.provider == "custom"
    assert cfg.base_url == "http://10.0.0.9:8000/v1"
    assert cfg.model == "internal-vllm-model"
    # keyless by default — no CUSTOM_API_KEY set
    assert cfg.api_key == ""


def test_custom_env_base_url_override(monkeypatch, tmp_path):
    import wrench.config as cfgmod
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "nope.toml")
    monkeypatch.setenv("WRENCH_BASE_URL", "http://envhost:8000/v1/")
    monkeypatch.delenv("CUSTOM_API_KEY", raising=False)
    monkeypatch.delenv("WRENCH_API_KEY", raising=False)
    cfg = load_config(provider_override="custom")
    assert cfg.base_url == "http://envhost:8000/v1"  # trailing slash stripped
    assert cfg.api_key == ""
