"""Azure OpenAI / AI Foundry adapter tests — all HTTP mocked, no live key needed."""

from __future__ import annotations

import requests

from wrench.config import Config, load_config, write_default_config
from wrench.providers import LLMClient, ProviderError


# ---------------- helpers ----------------

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


def _azure_cfg(**kw):
    base = dict(provider="azure", base_url="https://myres.openai.azure.com",
                model="my-deployment", deep_model="my-deployment",
                api_key="sk-azure-test", max_tokens=512,
                azure_api_version="2024-10-21", azure_auth="auto")
    base.update(kw)
    return Config(**base)


def _client(monkeypatch, cfg, responses):
    rec = Recorder(responses)
    monkeypatch.setattr(requests, "post", rec)
    return LLMClient(cfg), rec


# ---------------- URL construction ----------------

def test_azure_openai_deployment_url(monkeypatch):
    client, rec = _client(monkeypatch, _azure_cfg(), [_ok_response()])
    out = client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert out == "pong"
    call = rec.calls[0]
    assert call["url"] == ("https://myres.openai.azure.com/openai/deployments/"
                           "my-deployment/chat/completions")
    assert call["params"] == {"api-version": "2024-10-21"}
    # deployment-path style: no "model" in body
    assert "model" not in call["json"]


def test_azure_cognitiveservices_host_also_gets_deployment_path(monkeypatch):
    cfg = _azure_cfg(base_url="https://myres.cognitiveservices.azure.com")
    client, rec = _client(monkeypatch, cfg, [_ok_response()])
    client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert "/openai/deployments/my-deployment/chat/completions" in rec.calls[0]["url"]


def test_azure_explicit_deployment_path_used_as_is(monkeypatch):
    cfg = _azure_cfg(
        base_url="https://myres.openai.azure.com/openai/deployments/other-dep")
    client, rec = _client(monkeypatch, cfg, [_ok_response()])
    client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert rec.calls[0]["url"] == ("https://myres.openai.azure.com/openai/deployments/"
                                   "other-dep/chat/completions")


def test_foundry_serverless_url_and_model_in_body(monkeypatch):
    cfg = _azure_cfg(base_url="https://mymodel.eastus2.models.ai.azure.com",
                     model="Mistral-large")
    client, rec = _client(monkeypatch, cfg, [_ok_response()])
    client.chat([{"role": "user", "content": "hi"}], retries=0)
    call = rec.calls[0]
    assert call["url"] == "https://mymodel.eastus2.models.ai.azure.com/chat/completions"
    assert call["json"]["model"] == "Mistral-large"
    assert call["params"] == {"api-version": "2024-10-21"}


def test_custom_api_version(monkeypatch):
    cfg = _azure_cfg(azure_api_version="2025-01-01-preview")
    client, rec = _client(monkeypatch, cfg, [_ok_response()])
    client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert rec.calls[0]["params"] == {"api-version": "2025-01-01-preview"}


def test_missing_endpoint_is_a_clear_error(monkeypatch):
    client, _ = _client(monkeypatch, _azure_cfg(base_url=""), [])
    try:
        client.chat([{"role": "user", "content": "hi"}], retries=0)
        raise AssertionError("should have raised")
    except ProviderError as e:
        assert "AZURE_OPENAI_ENDPOINT" in str(e)


# ---------------- auth headers ----------------

def test_api_key_header_not_bearer(monkeypatch):
    client, rec = _client(monkeypatch, _azure_cfg(azure_auth="api-key"), [_ok_response()])
    client.chat([{"role": "user", "content": "hi"}], retries=0)
    h = rec.calls[0]["headers"]
    assert h["api-key"] == "sk-azure-test"
    assert "Authorization" not in h


def test_bearer_mode(monkeypatch):
    client, rec = _client(monkeypatch, _azure_cfg(azure_auth="bearer"), [_ok_response()])
    client.chat([{"role": "user", "content": "hi"}], retries=0)
    h = rec.calls[0]["headers"]
    assert h["Authorization"] == "Bearer sk-azure-test"
    assert "api-key" not in h


def test_auto_retries_bearer_on_401(monkeypatch):
    responses = [FakeResponse(401, text="key not valid here"), _ok_response("hello")]
    client, rec = _client(monkeypatch, _azure_cfg(azure_auth="auto"), responses)
    out = client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert out == "hello"
    assert len(rec.calls) == 2
    assert "api-key" in rec.calls[0]["headers"]
    assert rec.calls[1]["headers"]["Authorization"] == "Bearer sk-azure-test"


def test_explicit_api_key_mode_does_not_fall_back(monkeypatch):
    responses = [FakeResponse(401, text="nope")]
    client, rec = _client(monkeypatch, _azure_cfg(azure_auth="api-key"), responses)
    try:
        client.chat([{"role": "user", "content": "hi"}], retries=0)
        raise AssertionError("should have raised")
    except ProviderError as e:
        assert "401" in str(e)
    assert len(rec.calls) == 1


# ---------------- tools passthrough + errors ----------------

def test_tools_passthrough(monkeypatch):
    tools = [{"type": "function",
              "function": {"name": "get_disk", "parameters": {"type": "object"}}}]
    client, rec = _client(monkeypatch, _azure_cfg(), [_ok_response()])
    client.chat([{"role": "user", "content": "hi"}], retries=0, tools=tools)
    assert rec.calls[0]["json"]["tools"] == tools


def test_429_raises_provider_error_with_redacted_key(monkeypatch):
    responses = [FakeResponse(429, text="rate limited sk-azure-test please slow down")]
    client, _ = _client(monkeypatch, _azure_cfg(azure_auth="api-key"), responses)
    try:
        client.chat([{"role": "user", "content": "hi"}], retries=0)
        raise AssertionError("should have raised")
    except ProviderError as e:
        msg = str(e)
        assert "429" in msg
        assert "sk-azure-test" not in msg  # key never leaks into errors
        assert "<redacted>" in msg


def test_usage_logged_to_store(monkeypatch):
    class FakeStore:
        rows = []

        def add_tokens(self, *a):
            self.rows.append(a)

    rec = Recorder([_ok_response()])
    monkeypatch.setattr(requests, "post", rec)
    store = FakeStore()
    client = LLMClient(_azure_cfg(), store)
    client.chat([{"role": "user", "content": "hi"}], retries=0)
    assert store.rows and store.rows[0][0] == "azure"
    assert store.rows[0][4] == 7  # total_tokens


# ---------------- config loading ----------------

def test_config_env_vars(monkeypatch, tmp_path):
    import wrench.config as cfgmod
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "nope.toml")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://envres.openai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "sk-from-env")
    monkeypatch.delenv("WRENCH_BASE_URL", raising=False)
    monkeypatch.delenv("WRENCH_API_KEY", raising=False)
    cfg = load_config(provider_override="azure")
    assert cfg.provider == "azure"
    assert cfg.base_url == "https://envres.openai.azure.com"  # trailing slash stripped
    assert cfg.api_key == "sk-from-env"
    assert cfg.azure_api_version == "2024-10-21"  # sensible default
    assert cfg.azure_auth == "auto"


def test_config_toml_azure_section(monkeypatch, tmp_path):
    import wrench.config as cfgmod
    monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "config.toml")
    for var in ("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_API_KEY",
                "AZURE_OPENAI_API_VERSION", "WRENCH_BASE_URL", "WRENCH_MODEL"):
        monkeypatch.delenv(var, raising=False)
    write_default_config("azure", model="my-dep",
                         azure_endpoint="https://tomlres.openai.azure.com",
                         azure_api_version="2024-06-01")
    cfg = load_config(provider_override="azure")
    assert cfg.base_url == "https://tomlres.openai.azure.com"
    assert cfg.model == "my-dep"
    assert cfg.azure_api_version == "2024-06-01"
    text = (tmp_path / "config.toml").read_text()
    assert "api_key =" not in text.replace("# api_key_file", "")  # no key written


def test_write_config_with_key_is_owner_only(monkeypatch, tmp_path):
    import wrench.config as cfgmod
    monkeypatch.setattr(cfgmod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(cfgmod, "CONFIG_PATH", tmp_path / "config.toml")
    p = write_default_config("azure", model="dep",
                             azure_endpoint="https://x.openai.azure.com",
                             api_key="sk-secret")
    assert (p.stat().st_mode & 0o777) == 0o600
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("WRENCH_API_KEY", raising=False)
    cfg = load_config(provider_override="azure")
    assert cfg.api_key == "sk-secret"
