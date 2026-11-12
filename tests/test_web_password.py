"""The dashboard password: hashing, the sign-in gate, live changes, the CLI.

A password set with `wrench password` (or during `wrench init`) gates every web
surface on every bind. Only a salted hash is stored.
"""

from __future__ import annotations

import json
import os
import stat

import pytest
from test_web_security import Cfg, _req, _serve

from wrench import audit, webauth

PW = "correct horse battery"
JSON_H = {"Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _cheap_hash(monkeypatch):
    """Real cost is 64 MiB per guess; the tests only need the mechanics."""
    monkeypatch.setattr(webauth, "_SCRYPT_N", 2 ** 12)


def _isolate(monkeypatch, tmp_path):
    import wrench.config as wc
    monkeypatch.setattr(wc, "DATA_DIR", tmp_path)
    monkeypatch.setattr(wc, "CONFIG_DIR", tmp_path / "cfg")
    monkeypatch.setattr(wc, "CONFIG_PATH", tmp_path / "cfg" / "config.toml")
    monkeypatch.delenv("WRENCH_WEB_PASSWORD", raising=False)
    monkeypatch.delenv("WRENCH_WEB_TOKEN", raising=False)


def _login(url, secret, field="password"):
    return _req(url + "/login", "POST", json.dumps({field: secret}).encode(), JSON_H)


@pytest.fixture
def served(tmp_path):
    """A loopback server resolved from config, as `wrench web` builds it."""
    httpd, url = _serve(tmp_path)
    yield tmp_path, url, httpd
    httpd.shutdown()


# ------------------------------------------------------------------ hashing
def test_hash_is_salted_and_verifies():
    a, b = webauth.hash_password(PW), webauth.hash_password(PW)
    assert a != b and PW not in a                       # salted; never the password
    assert a.startswith("scrypt$")
    assert webauth.verify_password(PW, a) and webauth.verify_password(PW, b)
    assert not webauth.verify_password(PW + "x", a)
    assert not webauth.verify_password("", a)


def test_real_cost_parameters_are_strong(monkeypatch):
    monkeypatch.undo()
    assert (webauth._SCRYPT_N, webauth._SCRYPT_R, webauth._SCRYPT_P) == (2 ** 16, 8, 1)
    h = webauth.hash_password(PW)
    assert h.startswith("scrypt$65536,8,1$") and webauth.verify_password(PW, h)


def test_pbkdf2_fallback_hashes_verify():
    import base64
    import hashlib
    salt = b"0123456789abcdef"
    dk = hashlib.pbkdf2_hmac("sha256", PW.encode(), salt, 20_000, dklen=32)
    stored = f"pbkdf2-sha256$20000${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
    assert webauth.verify_password(PW, stored)
    assert not webauth.verify_password("nope-nope", stored)


@pytest.mark.parametrize("stored", [
    "", "garbage", "scrypt$1,2$x$y", "plain$1$AAAA$AAAA", "scrypt$abc,8,1$AAAA$AAAA",
    "scrypt$1073741824,8,1$AAAA$AAAA",       # a tampered file must not eat the machine's memory
    "scrypt$4096,8,1$!!!$AAAA", "pbkdf2-sha256$1$AAAA$AAAA", PW,
])
def test_malformed_hashes_never_match(stored):
    assert webauth.verify_password(PW, stored) is False


@pytest.mark.parametrize("pw,ok", [
    ("short", False), ("1234567", False), ("12345678", True), ("x" * 256, True),
    ("x" * 257, False), ("with\nnewline!", False), ("pässwörd-ünïcode", True),
    ("only spaces are fine too", True),
])
def test_password_rules_are_length_only(pw, ok):
    assert (webauth.password_problem(pw) is None) is ok


def test_stored_owner_only_and_never_in_clear(tmp_path):
    path = webauth.set_password(tmp_path, PW)
    assert path == tmp_path / "web_password"
    assert PW not in path.read_text()
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob("*.new"))
    assert webauth.password_is_set(tmp_path)
    with pytest.raises(ValueError):
        webauth.set_password(tmp_path, "short")
    assert webauth.verify_password(PW, path.read_text())     # a refused change keeps the old one
    assert webauth.clear_password(tmp_path) and not webauth.clear_password(tmp_path)
    assert not webauth.password_is_set(tmp_path)


# ------------------------------------------------------------------ the gate
def test_password_gates_loopback(served):
    dd, url, _ = served
    assert _req(url + "/api/overview")[0] == 200            # no password: open on loopback
    webauth.set_password(dd, PW)
    assert _req(url + "/api/overview")[0] == 401            # live, no restart
    code, h, _ = _req(url + "/")
    assert code in (302, 303) and h["Location"].startswith("/login")
    assert _req(url + "/healthz")[0] == 200
    assert _login(url, "wrong password")[0] == 401
    code, h, body = _login(url, PW)
    assert code == 200 and json.loads(body)["role"] == "admin"
    cookie = h["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and PW not in cookie
    session = cookie.split(";")[0]
    code, _, body = _req(url + "/api/overview", headers={"Cookie": session})
    assert code == 200 and json.loads(body)["auth_required"] is True


def test_the_password_is_not_a_bearer_token(served):
    """Scripts use tokens. A password in a header would make every API call a
    64 MiB guess and invite it into shell history."""
    dd, url, _ = served
    webauth.set_password(dd, PW)
    assert _req(url + "/api/overview", headers={"Authorization": f"Bearer {PW}"})[0] == 401


def test_changing_the_password_signs_everyone_out(served):
    dd, url, _ = served
    webauth.set_password(dd, PW)
    session = _login(url, PW)[1]["Set-Cookie"].split(";")[0]
    assert _req(url + "/api/overview", headers={"Cookie": session})[0] == 200
    webauth.set_password(dd, "a different passphrase")
    assert _req(url + "/api/overview", headers={"Cookie": session})[0] == 401
    assert _login(url, PW)[0] == 401
    assert _login(url, "a different passphrase")[0] == 200


def test_clearing_reopens_loopback_but_never_a_network_bind(served, tmp_path):
    dd, url, _ = served
    webauth.set_password(dd, PW)
    webauth.clear_password(dd)
    assert _req(url + "/api/overview")[0] == 200

    wide = webauth.resolve(Cfg(dd), "0.0.0.0", dd)
    assert wide.required and wide.generated            # no password: a token is minted
    other = tmp_path / "other"
    other.mkdir()
    webauth.set_password(other, PW)
    wide = webauth.resolve(Cfg(other), "0.0.0.0", other)
    assert wide.required and not wide.generated and not wide.admin_token
    assert not (other / webauth.TOKEN_FILE).exists()   # the password is enough
    assert wide.role_for_secret(PW) == "admin"
    webauth.clear_password(other)                      # credentials vanish while serving…
    assert wide.required                               # …it locks, it does not open
    assert wide.role_for_request({}) is None and wide.role_for_secret(PW) is None


def test_tokens_still_work_beside_a_password(tmp_path):
    webauth.set_password(tmp_path, PW)
    httpd, url = _serve(tmp_path, raw={"web": {"auth_token": "admin-secret-token",
                                               "viewer_token": "viewer-secret-token"}})
    try:
        assert _req(url + "/api/overview",
                    headers={"Authorization": "Bearer admin-secret-token"})[0] == 200
        code, _, body = _login(url, "viewer-secret-token", field="token")   # the old field name
        assert code == 200 and json.loads(body)["role"] == "viewer"
        assert json.loads(_login(url, PW)[2])["role"] == "admin"
    finally:
        httpd.shutdown()


def test_password_guessing_is_rate_limited_and_audited(served):
    dd, url, _ = served
    webauth.set_password(dd, PW)
    codes = [_login(url, f"guess number {i}")[0] for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[-1] == 429
    assert _login(url, PW)[0] == 429                    # locked out even with the right one
    kinds = [r["kind"] for r in audit.read_records(dd)]
    assert kinds.count("web.login.failed") == 10
    assert PW not in json.dumps(audit.read_records(dd))


def test_oversized_secret_is_refused_without_hashing(tmp_path, monkeypatch):
    webauth.set_password(tmp_path, PW)
    ac = webauth.resolve(Cfg(tmp_path), "127.0.0.1", tmp_path)
    monkeypatch.setattr(webauth, "verify_password",
                        lambda *a: pytest.fail("hashed an oversized secret"))
    assert ac.role_for_secret("x" * 5000) is None and ac.role_for_secret("") is None


def test_login_page_asks_for_a_password():
    from wrench import webapp
    html = webapp._PAGES["login"] if hasattr(webapp, "_PAGES") else \
        (webapp.Path(webapp.__file__).parent / "web" / "login.html").read_text()
    assert "password" in html and "wrench password" in html
    assert 'autocomplete="current-password"' in html


# ------------------------------------------------------------------ the CLI
def _cli(args, input=None):
    from typer.testing import CliRunner

    from wrench.cli import app
    return CliRunner().invoke(app, args, input=input)


def test_cli_set_change_status_clear(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    assert _cli(["password", "--status"]).exit_code == 1
    res = _cli(["password", "--stdin"], input=PW + "\n")
    assert res.exit_code == 0 and "password set" in res.output and PW not in res.output
    assert webauth.verify_password(PW, (tmp_path / "web_password").read_text())
    assert _cli(["password", "--status"]).exit_code == 0

    res = _cli(["password", "--stdin"], input="a brand new one\n")
    assert res.exit_code == 0 and "changed" in res.output
    assert webauth.verify_password("a brand new one", (tmp_path / "web_password").read_text())

    res = _cli(["password", "--stdin"], input="short\n")
    assert res.exit_code == 1 and "at least 8" in res.output
    assert webauth.verify_password("a brand new one", (tmp_path / "web_password").read_text())

    res = _cli(["password", "--clear"])
    assert res.exit_code == 0 and "removed" in res.output
    assert not (tmp_path / "web_password").exists()
    assert _cli(["password", "--clear", "--stdin"]).exit_code == 2

    records = audit.read_records(tmp_path)
    kinds = [r["kind"] for r in records]
    assert [k for k in kinds if k.startswith("web.password")] == [
        "web.password.set", "web.password.changed", "web.password.cleared"]
    assert PW not in json.dumps(records) and "a brand new one" not in json.dumps(records)


def test_cli_json_and_no_terminal(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    res = _cli(["password"])                           # no TTY, no --stdin: never hangs
    assert res.exit_code == 2 and "--stdin" in res.output
    res = _cli(["password", "--stdin", "--json"], input=PW + "\n")
    out = json.loads(res.stdout)
    assert out["set"] is True and out["changed"] is True and PW not in res.stdout
    out = json.loads(_cli(["password", "--status", "--json"]).stdout)
    assert out["set"] is True and out["changed"] is False


def test_cli_interactive_asks_twice(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    import wrench.cli as cli
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    # too short, then a mismatch, then right
    res = _cli(["password"], input=f"short\n{PW}\nnot the same\n{PW}\n{PW}\n")
    assert res.exit_code == 0, res.output
    assert "at least 8" in res.output and "did not match" in res.output
    assert PW not in res.output
    assert webauth.verify_password(PW, (tmp_path / "web_password").read_text())
    res = _cli(["password"], input="a\nb\nc\n")       # three bad tries: give up, keep the old
    assert res.exit_code == 1
    assert webauth.verify_password(PW, (tmp_path / "web_password").read_text())


def test_init_step_env_prompt_and_skip(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    import wrench.cli as cli
    cfg = Cfg(tmp_path)
    # unattended, nothing provided: no password, and it says how to set one
    assert "wrench password" in cli._init_web_password(cfg, interactive=False)
    assert not webauth.password_is_set(tmp_path)
    # unattended install: from the environment
    monkeypatch.setenv("WRENCH_WEB_PASSWORD", PW)
    assert "password set" in cli._init_web_password(cfg, interactive=False)
    assert webauth.verify_password(PW, (tmp_path / "web_password").read_text())
    # already set: never asked again, never overwritten by a stale variable
    monkeypatch.setenv("WRENCH_WEB_PASSWORD", "something else entirely")
    assert "password set" in cli._init_web_password(cfg, interactive=True)
    assert webauth.verify_password(PW, (tmp_path / "web_password").read_text())
    # an unusable one is reported, not silently dropped
    webauth.clear_password(tmp_path)
    monkeypatch.setenv("WRENCH_WEB_PASSWORD", "short")
    assert "not usable" in cli._init_web_password(cfg, interactive=False)
    assert not webauth.password_is_set(tmp_path)


def test_init_prompts_in_a_terminal(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    import wrench.cli as cli
    cfg = Cfg(tmp_path)
    answers = iter([PW, PW])
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: True)
    monkeypatch.setattr(cli.typer, "prompt", lambda *a, **k: next(answers))
    assert "password set" in cli._init_web_password(cfg, interactive=True)
    assert webauth.verify_password(PW, (tmp_path / "web_password").read_text())
    webauth.clear_password(tmp_path)
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **k: False)
    assert "no password" in cli._init_web_password(cfg, interactive=True)
    assert not webauth.password_is_set(tmp_path)


def test_banner_says_how_to_get_in(tmp_path, monkeypatch):
    import io

    import wrench.cli as cli
    from rich.console import Console
    webauth.set_password(tmp_path, PW)
    httpd, _ = _serve(tmp_path)
    try:
        buf = io.StringIO()
        monkeypatch.setattr(cli, "console", Console(file=buf, width=200))
        cli._serve_banner(httpd, "127.0.0.1", 8787, "t", ["{url}"])
        assert "dashboard password" in buf.getvalue() and PW not in buf.getvalue()
    finally:
        httpd.shutdown()
