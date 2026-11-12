"""Model enrollment: live model listing, key handling, the `wrench model`
commands, and the client's adaptation to newer models' request parameters.

No test here talks to a real provider.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from wrench import audit, enroll, providers

KEY = "sk-ant-test-0123456789abcdefghij"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    import wrench.cli as cli
    import wrench.config as wc
    me = tmp_path / "me"
    (me / "cfg").mkdir(parents=True)
    monkeypatch.setattr(wc, "DATA_DIR", me)
    monkeypatch.setattr(wc, "CONFIG_DIR", me / "cfg")
    monkeypatch.setattr(wc, "CONFIG_PATH", me / "cfg" / "config.toml")
    monkeypatch.setattr(cli, "CONFIG_PATH", me / "cfg" / "config.toml")
    for v in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
              "WRENCH_API_KEY", "WRENCH_PROVIDER", "WRENCH_MODEL", "WRENCH_DEEP_MODEL",
              "WRENCH_BASE_URL", "WRENCH_API_KEY_FILE", "WRENCH_OFFLINE"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(enroll.requests, "get",
                        lambda *a, **k: pytest.fail("a test reached for the network"))
    monkeypatch.setattr(providers, "_QUIRKS", {})
    return me


def _cfg():
    from wrench.config import load_config
    return load_config()


class Resp:
    def __init__(self, status=200, body=None, text=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


class Http:
    """Answers GET /models from a script and records what was sent."""

    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers or {}, "params": params or {}})
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


# ------------------------------------------------------------ listing
def test_anthropic_listing_headers_paging_and_order():
    http = Http(
        Resp(body={"data": [
            {"id": "claude-haiku-9", "display_name": "Claude Haiku 9", "created_at": "2031-03-01T00:00:00Z"},
            {"id": "claude-opus-9", "display_name": "Claude Opus 9", "created_at": "2031-05-01T00:00:00Z"}],
            "has_more": True, "last_id": "claude-opus-9"}),
        Resp(body={"data": [
            {"id": "claude-sonnet-8", "display_name": "Claude Sonnet 8", "created_at": "2030-01-01T00:00:00Z"},
            {"id": "claude-opus-9"}], "has_more": False}))
    models = enroll.list_models("anthropic", "https://api.anthropic.com/v1/", KEY, http=http)
    assert [m.id for m in models] == ["claude-opus-9", "claude-haiku-9", "claude-sonnet-8"]
    assert models[0].name == "Claude Opus 9"
    first, second = http.calls
    assert first["url"] == "https://api.anthropic.com/v1/models"
    assert first["headers"]["x-api-key"] == KEY and "Authorization" not in first["headers"]
    assert first["headers"]["anthropic-version"] == "2023-06-01"
    assert second["params"]["after_id"] == "claude-opus-9"
    assert enroll.suggest(models) == ("claude-haiku-9", "claude-opus-9")


def test_openai_listing_keeps_only_chat_models():
    http = Http(Resp(body={"data": [
        {"id": "gpt-9-mini", "created": 300}, {"id": "gpt-9", "created": 310},
        {"id": "o7", "created": 290}, {"id": "text-embedding-9", "created": 400},
        {"id": "whisper-2", "created": 400}, {"id": "gpt-image-3", "created": 400},
        {"id": "gpt-9-realtime", "created": 400}, {"id": "tts-2-hd", "created": 400},
        {"id": "omni-moderation-latest", "created": 400}, {"id": "dall-e-4", "created": 400},
        {"id": "gpt-9-audio-preview", "created": 400}, {"id": "ft:something", "created": 1}]}))
    models = enroll.list_models("openai", "https://api.openai.com/v1", "sk-" + "x" * 30, http=http)
    assert [m.id for m in models] == ["gpt-9", "gpt-9-mini", "o7"]
    assert http.calls[0]["headers"]["Authorization"].startswith("Bearer sk-")
    assert enroll.suggest(models) == ("gpt-9-mini", "gpt-9")


def test_google_listing_strips_prefix_and_orders_by_version():
    http = Http(Resp(body={"data": [
        {"id": "models/gemini-8.5-flash"}, {"id": "models/gemini-9.0-pro"},
        {"id": "models/gemini-9.0-flash-lite"}, {"id": "models/text-embedding-004"},
        {"id": "models/imagen-9"}, {"id": "models/gemini-9.0-flash-image"},
        {"id": "models/gemini-9.0-flash-live"}, {"id": "models/aqa"}]}))
    base = "https://generativelanguage.googleapis.com/v1beta/openai"
    models = enroll.list_models("google", base, "AIza" + "y" * 30, http=http)
    assert [m.id for m in models] == ["gemini-9.0-pro", "gemini-9.0-flash-lite", "gemini-8.5-flash"]
    assert http.calls[0]["url"] == base + "/models"
    assert enroll.suggest(models) == ("gemini-9.0-flash-lite", "gemini-9.0-pro")


@pytest.mark.parametrize("resp,kind,needle", [
    (Resp(401, {"error": "bad"}), "auth", "did not accept that key"),
    (Resp(403, {"error": "no"}), "auth", "did not accept that key"),
    (Resp(500, None, text="upstream exploded " + KEY), "http", "HTTP 500"),
    (Resp(200, None, text="<html>"), "http", "not JSON"),
    (enroll.requests.ConnectionError("dns"), "network", "could not reach"),
])
def test_listing_failures_are_actionable_and_never_echo_the_key(resp, kind, needle):
    with pytest.raises(enroll.EnrollError) as e:
        enroll.list_models("anthropic", "https://api.anthropic.com/v1", KEY, http=Http(resp))
    assert e.value.kind == kind and needle in e.value.message and KEY not in e.value.message


def test_name_heuristics_match_whole_words():
    M = enroll.Model
    assert not M("gemini-9.0-pro").fast and M("gemini-9.0-flash").fast   # "mini" in "gemini"
    assert M("gpt-9-mini").fast and M("claude-haiku-9").fast and not M("claude-opus-9").fast
    assert enroll.is_chat_model("openai", "gpt-9-deliverable")           # "live" in "deliver"
    assert not enroll.is_chat_model("google", "gemini-9.0-flash-live")
    assert not enroll.is_chat_model("openai", "gpt-9-search-preview")
    assert not enroll.is_chat_model("openai", "text-embedding-9-large")


def test_suggestions_with_thin_lists():
    M = enroll.Model
    assert enroll.suggest([]) == ("", "")
    assert enroll.suggest([M("only-one")]) == ("only-one", "only-one")
    assert enroll.suggest([M("a-mini"), M("b-nano")]) == ("a-mini", "a-mini")
    assert enroll.suggest([M("big-1"), M("big-2")]) == ("big-1", "big-1")


# ------------------------------------------------------------ keys
@pytest.mark.parametrize("raw,clean", [
    ("  sk-abc  \n", "sk-abc"), ('"sk-abc"', "sk-abc"), ("Bearer sk-abc", "sk-abc"),
    ("'sk-abc'", "sk-abc")])
def test_pasted_keys_are_cleaned(raw, clean):
    assert enroll.clean_key(raw) == clean


@pytest.mark.parametrize("key,ok", [
    (KEY, True), ("", False), ("short", False), ("has a space in the middle of it", False),
    ("x" * 600, False), ("sk-ünïcode-0123456789abcdef", False)])
def test_key_shape(key, ok):
    assert (enroll.key_problem(key) is None) is ok


def test_key_is_stored_owner_only_and_removed(_env):
    path = enroll.save_key("anthropic", KEY)
    assert path == _env / "cfg" / "anthropic.key" and path.read_text().strip() == KEY
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list((_env / "cfg").glob("*.new"))
    assert enroll.key_source("anthropic") == ("file", KEY)
    assert enroll.remove_key("anthropic") and not enroll.remove_key("anthropic")
    assert enroll.key_source("anthropic") == ("", "")


def test_key_source_precedence(_env, monkeypatch):
    enroll.save_key("google", "file-key-0123456789abcdef")
    assert enroll.key_source("google")[0] == "file"
    monkeypatch.setenv("GOOGLE_API_KEY", "alt-env-key-0123456789")
    assert enroll.key_source("google") == ("env:GOOGLE_API_KEY", "alt-env-key-0123456789")
    monkeypatch.setenv("GEMINI_API_KEY", "main-env-key-0123456789")
    assert enroll.key_source("google")[0] == "env:GEMINI_API_KEY"
    assert _cfg_for("google").api_key == "main-env-key-0123456789"
    monkeypatch.delenv("GEMINI_API_KEY")
    assert _cfg_for("google").api_key == "alt-env-key-0123456789"


def _cfg_for(provider):
    from wrench.config import load_config
    return load_config(provider_override=provider)


def test_google_is_a_first_class_provider():
    cfg = _cfg_for("google")
    assert cfg.base_url == "https://generativelanguage.googleapis.com/v1beta/openai"
    assert "google" in enroll.CLOUD and set(enroll.CLOUD) == {"anthropic", "openai", "google"}
    for info in enroll.CLOUD.values():
        assert info["key_url"].startswith("https://")


# ------------------------------------------------------------ apply
def test_apply_writes_a_config_then_edits_it_in_place(_env):
    kf = enroll.save_key("anthropic", KEY)
    enroll.apply("anthropic", "claude-haiku-9", "claude-opus-9", kf)
    cfg = _cfg()
    assert (cfg.provider, cfg.model, cfg.deep_model, cfg.api_key) == \
        ("anthropic", "claude-haiku-9", "claude-opus-9", KEY)
    text = (_env / "cfg" / "config.toml").read_text()
    assert KEY not in text and "[policy]" in text          # key by reference; comments kept
    # switching provider keeps the old section and everything else
    enroll.save_key("openai", "sk-" + "o" * 30)
    enroll.apply("openai", "gpt-9-mini", "gpt-9", enroll.key_path("openai"))
    cfg = _cfg()
    assert (cfg.provider, cfg.model, cfg.api_key) == ("openai", "gpt-9-mini", "sk-" + "o" * 30)
    assert "claude-haiku-9" in (_env / "cfg" / "config.toml").read_text()
    st = enroll.status(cfg)
    assert st["key"] == {"present": True, "source": "file"} and st["hosted"] is True


# ------------------------------------------------------------ the CLI
MODELS = [enroll.Model("claude-opus-9", "Claude Opus 9", 30), enroll.Model("claude-haiku-9", "", 20),
          enroll.Model("claude-sonnet-8", "", 10)]


def _cli(args, input=None):
    from typer.testing import CliRunner

    from wrench.cli import app
    return CliRunner().invoke(app, args, input=input)


@pytest.fixture
def listed(monkeypatch):
    seen = []

    def fake(provider, base_url, key, **k):
        seen.append((provider, base_url, key))
        if key != KEY:
            raise enroll.EnrollError("auth", f"{provider} did not accept that key (HTTP 401).")
        return list(MODELS)
    monkeypatch.setattr(enroll, "list_models", fake)
    return seen


def test_setup_unattended_from_stdin(listed, _env):
    res = _cli(["model", "setup", "anthropic", "--key-stdin", "--no-test"], input=KEY + "\n")
    assert res.exit_code == 0, res.output
    assert "key accepted" in res.output and "3 model(s)" in res.output and KEY not in res.output
    cfg = _cfg()
    assert (cfg.provider, cfg.model, cfg.deep_model) == ("anthropic", "claude-haiku-9", "claude-opus-9")
    assert cfg.api_key == KEY and (_env / "cfg" / "anthropic.key").exists()
    recs = audit.read_records(_env)
    assert any(r["kind"] == "model.enroll" for r in recs) and KEY not in json.dumps(recs)


def test_setup_rejected_key_changes_nothing(listed, _env):
    res = _cli(["model", "setup", "anthropic", "--key-stdin", "--no-test"],
               input="sk-ant-wrong-0123456789abcdef\n")
    assert res.exit_code == 1 and "did not accept" in res.output and "nothing was changed" in res.output
    assert not (_env / "cfg" / "config.toml").exists()
    assert not (_env / "cfg" / "anthropic.key").exists()
    assert "sk-ant-wrong" not in res.output
    assert any(r["kind"] == "model.enroll.failed" for r in audit.read_records(_env))


def test_setup_refuses_a_model_the_key_cannot_use(listed, _env):
    res = _cli(["model", "setup", "anthropic", "--key-stdin", "--no-test", "--model", "claude-zeus"],
               input=KEY + "\n")
    assert res.exit_code == 1 and "not available to this key" in res.output
    assert not (_env / "cfg" / "anthropic.key").exists()
    res = _cli(["model", "setup", "anthropic", "--key-stdin", "--no-test",
                "--model", "claude-sonnet-8", "--deep-model", "claude-opus-9"], input=KEY + "\n")
    assert res.exit_code == 0 and _cfg().model == "claude-sonnet-8"


def test_setup_interactive_walkthrough(listed, _env, monkeypatch):
    import webbrowser

    import wrench.cli as cli
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(url))
    answers = "\n".join([
        "1",          # provider: anthropic
        "y",          # open the key page
        "not a key",  # a bad paste first
        KEY,          # the key (hidden)
        "3",          # everyday: number 3 = claude-sonnet-8
        "",           # deep: enter = suggestion
    ]) + "\n"
    res = _cli(["model", "setup", "--no-test"], input=answers)
    assert res.exit_code == 0, res.output
    assert opened == ["https://console.anthropic.com/settings/keys"]
    assert "does not look like an API key" in res.output and KEY not in res.output
    assert "subscription" in res.output                   # says what kind of account
    cfg = _cfg()
    assert (cfg.model, cfg.deep_model) == ("claude-sonnet-8", "claude-opus-9")
    assert "stored owner-only" in res.output


def test_setup_offers_a_key_from_the_environment(listed, _env, monkeypatch):
    import wrench.cli as cli
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    monkeypatch.setenv("ANTHROPIC_API_KEY", KEY)
    # use it: yes · store it for scheduled patrols: yes · two enters for the models
    res = _cli(["model", "setup", "anthropic", "--no-test"], input="y\ny\n\n\n")
    assert res.exit_code == 0, res.output
    assert "$ANTHROPIC_API_KEY" in res.output and "scheduled patrols" in res.output
    assert (_env / "cfg" / "anthropic.key").read_text().strip() == KEY
    # unattended with only the environment: works, and stores nothing
    (_env / "cfg" / "anthropic.key").unlink()
    res = _cli(["model", "setup", "anthropic", "--yes", "--no-test"])
    assert res.exit_code == 0 and "read from your environment" in res.output
    assert not (_env / "cfg" / "anthropic.key").exists()


def test_setup_edges(listed, _env, monkeypatch):
    assert _cli(["model", "setup"]).exit_code == 2                    # no terminal, no provider
    assert _cli(["model", "setup", "skynet"]).exit_code == 2
    assert _cli(["model", "setup", "azure"]).exit_code == 2
    assert _cli(["model", "setup", "anthropic", "--key-stdin"], input="").exit_code == 2
    res = _cli(["model", "setup", "anthropic", "--yes"])              # no key anywhere
    assert res.exit_code == 1 and "no key" in res.output
    monkeypatch.setenv("WRENCH_OFFLINE", "1")
    res = _cli(["model", "setup", "anthropic", "--key-stdin"], input=KEY + "\n")
    assert res.exit_code == 1 and "offline mode" in res.output and listed == []


def test_smoke_test_result_is_reported(listed, _env, monkeypatch):
    from wrench import localsetup
    monkeypatch.setattr(localsetup, "smoke_test", lambda cfg, store: (False, "no tool call"))
    res = _cli(["model", "setup", "anthropic", "--key-stdin"], input=KEY + "\n")
    assert res.exit_code == 0 and "smoke test failed" in res.output and "wrench model use" in res.output
    monkeypatch.setattr(localsetup, "smoke_test", lambda cfg, store: (True, "1 tool call"))
    res = _cli(["model", "setup", "anthropic", "--key-stdin"], input=KEY + "\n")
    assert "smoke test passed" in res.output


def test_list_use_show_logout(listed, _env):
    res = _cli(["model", "list", "anthropic"])
    assert res.exit_code == 1 and "wrench model setup anthropic" in res.output and listed == []
    _cli(["model", "setup", "anthropic", "--key-stdin", "--no-test"], input=KEY + "\n")

    res = _cli(["model", "list"])
    assert res.exit_code == 0 and "claude-opus-9" in res.output and "in use" in res.output
    d = json.loads(_cli(["model", "list", "--json"]).stdout)
    assert d["schema"] == "wrench.model.list.v1" and d["current"] == "claude-haiku-9"
    assert d["suggested"] == {"everyday": "claude-haiku-9", "deep": "claude-opus-9"}
    assert [m["id"] for m in d["models"]][0] == "claude-opus-9" and KEY not in json.dumps(d)

    assert _cli(["model", "use", "claude-sonnet-8"]).exit_code == 0
    assert _cli(["model", "use", "claude-opus-9", "--deep"]).exit_code == 0
    res = _cli(["model", "use", "opus"])
    assert res.exit_code == 1 and "did you mean: claude-opus-9" in res.output
    cfg = _cfg()
    assert (cfg.model, cfg.deep_model) == ("claude-sonnet-8", "claude-opus-9")
    assert _cli(["model", "use", "claude-not-listed-yet", "--force"]).exit_code == 0

    d = json.loads(_cli(["model", "--json"]).stdout)
    assert d["provider"] == "anthropic" and d["key"] == {"present": True, "source": "file"}
    out = _cli(["model"]).output
    assert "anthropic" in out and "stored on this machine" in out and KEY not in out

    res = _cli(["model", "logout"])
    assert res.exit_code == 0 and "removed the stored anthropic key" in res.output
    assert "revoke it" in res.output and not (_env / "cfg" / "anthropic.key").exists()
    assert "no key for anthropic" in _cli(["model", "logout"]).output
    assert "missing" in _cli(["model"]).output


def test_init_runs_enrollment_for_a_hosted_provider(listed, _env, monkeypatch):
    import wrench.cli as cli
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    monkeypatch.setattr(cli.sensors, "sample_all", lambda store: None)
    monkeypatch.setattr(cli.driftscan, "scan", lambda store: None)
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda url: None)
    answers = "\n".join(["n",   # do not open the browser
                         KEY,   # the key
                         "", "",  # take both suggestions
                         "n"]) + "\n"   # no dashboard password
    res = _cli(["init", "-p", "anthropic"], input=answers)
    assert res.exit_code == 0, res.output
    assert "key accepted" in res.output and "api key: configured" in res.output
    cfg = _cfg()
    assert (cfg.provider, cfg.model, cfg.api_key) == ("anthropic", "claude-haiku-9", KEY)
    assert "google" in [n for n, _ in cli.PROVIDER_MENU]


# ------------------------------------------------------------ newer models' parameters
class Post:
    def __init__(self, *responses):
        self.responses, self.bodies = list(responses), []

    def __call__(self, url, headers=None, json=None, timeout=None):
        self.bodies.append(json)
        return self.responses.pop(0)


OK_OPENAI = Resp(200, {"choices": [{"message": {"content": "pong"}}], "usage": {"total_tokens": 3}})
OK_ANTHROPIC = Resp(200, {"content": [{"text": "pong"}], "usage": {"input_tokens": 1, "output_tokens": 1}})


def test_openai_style_client_learns_max_completion_tokens_and_temperature(monkeypatch):
    post = Post(
        Resp(400, None, text="Unsupported parameter: 'max_tokens' is not supported with this "
                             "model. Use 'max_completion_tokens' instead."),
        Resp(400, None, text="Unsupported value: 'temperature' does not support 0.4 with this "
                             "model. Only the default (1) value is supported."),
        OK_OPENAI, OK_OPENAI)
    monkeypatch.setattr(providers.requests, "post", post)
    client = providers.LLMClient(_cfg_for("openai"))
    client.cfg.api_key = "sk-" + "x" * 30
    assert client.chat([{"role": "user", "content": "ping"}], model="gpt-9", retries=0) == "pong"
    first, second, third = post.bodies
    assert "max_tokens" in first and "temperature" in first
    assert "max_completion_tokens" in second and "max_tokens" not in second
    assert "temperature" not in third and "max_completion_tokens" in third
    # learned: the next call is right first time
    assert client.chat([{"role": "user", "content": "ping"}], model="gpt-9", retries=0) == "pong"
    assert "temperature" not in post.bodies[3] and len(post.bodies) == 4


def test_a_different_400_is_reported_not_retried_forever(monkeypatch):
    post = Post(Resp(400, None, text="context length exceeded"))
    monkeypatch.setattr(providers.requests, "post", post)
    client = providers.LLMClient(_cfg_for("openai"))
    with pytest.raises(providers.ProviderError, match="HTTP 400"):
        client.chat([{"role": "user", "content": "x"}], retries=0)
    assert len(post.bodies) == 1


def test_anthropic_client_drops_temperature_when_told(monkeypatch):
    post = Post(Resp(400, None, text="temperature: this model does not accept a custom value"),
                OK_ANTHROPIC)
    monkeypatch.setattr(providers.requests, "post", post)
    client = providers.LLMClient(_cfg_for("anthropic"))
    assert client.chat([{"role": "user", "content": "ping"}], retries=0) == "pong"
    assert "temperature" in post.bodies[0] and "temperature" not in post.bodies[1]
