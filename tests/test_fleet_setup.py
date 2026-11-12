"""Guided fleet setup: the engine, the agent's two tools, and the wizard.

The rules under test: every change needs the operator's yes, passwords never
reach the model, and each step is a few validated values — not a command.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import stat
import sys

import pytest
from test_web_security import _serve

from wrench import agent as agent_mod
from wrench import audit, fleet, tools, webauth
from wrench import fleetsetup as fs
from wrench.store import Store

PW = "hub dashboard passphrase"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    """An isolated install at tmp_path/me, for this process and any child."""
    import wrench.cli as cli
    import wrench.config as wc
    me = tmp_path / "me"
    (me / "cfg").mkdir(parents=True)
    monkeypatch.setattr(wc, "DATA_DIR", me)
    monkeypatch.setattr(wc, "CONFIG_DIR", me / "cfg")
    monkeypatch.setattr(wc, "CONFIG_PATH", me / "cfg" / "config.toml")
    monkeypatch.setattr(cli, "CONFIG_PATH", me / "cfg" / "config.toml")
    monkeypatch.setenv("WRENCH_DATA_DIR", str(me))
    monkeypatch.setenv("WRENCH_CONFIG_DIR", str(me / "cfg"))
    for var in ("WRENCH_HUB_PASSWORD", "WRENCH_WEB_PASSWORD", "WRENCH_WEB_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(webauth, "_SCRYPT_N", 2 ** 12)
    monkeypatch.setattr(cli.sensors, "sample_all", lambda store: None)
    return me


def _cfg():
    from wrench.config import load_config
    return load_config()


@pytest.fixture
def store(_env):
    s = Store(_env / "wrench.db")
    yield s
    s.close()


class Operator:
    """Stands in for the person at the terminal."""

    def __init__(self, yes=True, secret=PW, with_secret=True):
        self.yes, self.secret = yes, secret
        self.asked: list[tuple[str, str]] = []
        self.secret_prompts: list[str] = []
        if with_secret:
            self.ask_secret = self._ask_secret

    def __call__(self, what, label):
        self.asked.append((what, label))
        return self.yes

    def _ask_secret(self, prompt, confirm=False, check=None):
        self.secret_prompts.append(prompt)
        return self.secret


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def hub(tmp_path):
    """Someone else's hub, with a password, on loopback."""
    dd = tmp_path / "hub"
    dd.mkdir()
    webauth.set_password(dd, PW)
    httpd, url = _serve(dd, fleet_hub=True)
    hs = Store(dd / "w.db")
    yield url, hs, dd
    hs.close()
    httpd.shutdown()


# ------------------------------------------------------------ the checklist
def test_fresh_machine_checklists(store):
    s = fs.state(_cfg(), store)
    assert not s["password_set"] and not s["hub"]["running"] and not s["node"]["connected"]
    hub_steps = fs.steps("hub", s)
    assert [x["key"] for x in hub_steps] == ["password", "listen", "tls", "start", "machines"]
    assert not any(x["done"] for x in hub_steps) and hub_steps[2]["optional"]
    node_steps = fs.steps("node", s)
    assert [x["key"] for x in node_steps] == ["connect", "schedule", "report"]
    with pytest.raises(ValueError):
        fs.steps("king", s)

    text = fs.tool_status(_cfg(), store, "hub")
    assert "as a HUB" in text and "[TO DO] Set the dashboard password" in text
    assert 'Next step: Set the dashboard password — fleet_setup(action="set_password")' in text
    assert "by hand: wrench password" in text
    text = fs.tool_status(_cfg(), store, "node")
    assert 'fleet_setup(action="node_connect")' in text and "typed privately" not in text
    over = fs.tool_status(_cfg(), store, "")
    assert "not a hub" in over and "not connected to a hub" in over and "HUB" in over


def test_checklist_follows_the_state(store):
    webauth.set_password(_cfg().data_dir, PW)
    assert fs.hub_listen(_cfg(), "0.0.0.0").ok
    s = fs.state(_cfg(), store)
    done = {x["key"]: x["done"] for x in fs.steps("hub", s)}
    assert done == {"password": True, "listen": True, "tls": False, "start": False,
                    "machines": False}
    assert 'Next step: Start the hub' in fs.describe("hub", s)
    assert "wrench fleet connect" in fs.steps("hub", s)[-1]["command"]


# ------------------------------------------------------------ every change needs a yes
MUTATING = ["set_password", "hub_listen", "hub_tls", "hub_start", "hub_stop", "schedule"]


@pytest.mark.parametrize("action", MUTATING)
def test_nobody_to_ask_means_nothing_changes(action, store, _env, monkeypatch):
    monkeypatch.setattr(fs, "hub_start", lambda *a, **k: pytest.fail("started a hub"))
    monkeypatch.setattr(fs, "schedule", lambda *a, **k: pytest.fail("installed a timer"))
    webauth.set_password(_cfg().data_dir, PW)
    before = sorted(p.name for p in _env.rglob("*"))
    out = fs.tool_action(_cfg(), store, action, {}, confirm_fn=None)
    assert out.startswith("DENIED") and "wrench" in out
    assert sorted(p.name for p in _env.rglob("*")) == before
    assert not (_env / "cfg" / "config.toml").exists()


@pytest.mark.parametrize("action", MUTATING)
def test_a_no_means_nothing_changes(action, store, _env, monkeypatch):
    monkeypatch.setattr(fs, "hub_start", lambda *a, **k: pytest.fail("started a hub"))
    monkeypatch.setattr(fs, "schedule", lambda *a, **k: pytest.fail("installed a timer"))
    webauth.set_password(_cfg().data_dir, PW)
    op = Operator(yes=False)
    out = fs.tool_action(_cfg(), store, action, {}, op)
    assert "declined" in out and len(op.asked) == 1 and op.asked[0][1].startswith("setup: ")
    assert op.secret_prompts == []                       # never even asked for a password
    assert not (_env / "cfg" / "config.toml").exists()
    assert webauth.verify_password(PW, (_env / "web_password").read_text())


def test_unknown_action_lists_the_real_ones(store):
    out = fs.tool_action(_cfg(), store, "format_disk", {}, Operator())
    assert "unknown action" in out and "node_connect" in out


# ------------------------------------------------------------ passwords stay private
def test_set_password_is_typed_privately(store, _env):
    op = Operator(secret="a fresh dashboard secret")
    out = fs.tool_action(_cfg(), store, "set_password", {"password": "from the model"}, op)
    assert "password set" in out and "a fresh dashboard secret" not in out
    assert op.secret_prompts == ["new dashboard password"]
    stored = (_env / "web_password").read_text()
    assert webauth.verify_password("a fresh dashboard secret", stored)
    assert not webauth.verify_password("from the model", stored)   # an argument is ignored
    assert "a fresh dashboard secret" not in json.dumps(audit.read_records(_env))
    assert "not shown to the model" in op.asked[0][0]


def test_no_private_channel_no_password_step(store, _env):
    op = Operator(with_secret=False)                      # e.g. a plain confirm callback
    out = fs.tool_action(_cfg(), store, "set_password", {}, op)
    assert out.startswith("DENIED") and op.asked == []
    assert not (_env / "web_password").exists()
    out = fs.tool_action(_cfg(), store, "set_password", {}, Operator(secret=""))
    assert "no password was entered" in out


# ------------------------------------------------------------ hub steps
@pytest.mark.parametrize("host", ["0.0.0.0; rm -rf /", "hub.example", "$(id)", "0.0.0.0\nhub = false",
                                  "999.1.1.1", ""])
def test_listen_address_is_validated(host, store, _env):
    res = fs.hub_listen(_cfg(), host) if host else None
    if host:
        assert not res.ok and "not an address" in res["message"]
        out = fs.tool_action(_cfg(), store, "hub_listen", {"host": host}, Operator())
        assert "not an address" in out
        assert not (_env / "cfg" / "config.toml").exists()
    else:                                                 # empty → the default, 0.0.0.0
        assert fs.tool_action(_cfg(), store, "hub_listen", {"host": ""}, Operator()).startswith("saved")


def test_hub_listen_saves_and_opts_in(store, _env):
    op = Operator()
    out = fs.tool_action(_cfg(), store, "hub_listen", {"port": "9443"}, op)
    assert "0.0.0.0:9443" in out and "every network interface" in op.asked[0][0]
    st = fleet.settings_from(_cfg())
    assert (st.listen_host, st.listen_port, st.hub) == ("0.0.0.0", 9443, True)
    assert "port must be" in fs.tool_action(_cfg(), store, "hub_listen", {"port": "http"}, op)
    assert not fs.hub_listen(_cfg(), "0.0.0.0", 70000).ok
    assert any(r["kind"] == "fleet.setup.listen" for r in audit.read_records(_env))


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs the openssl binary")
def test_hub_tls_makes_a_certificate_the_hub_can_serve(store, _env):
    res = fs.hub_tls(_cfg(), names=["hub.lan", "192.168.7.7", "bad name,DNS:evil", "x/../y"])
    assert res.ok, res["message"]
    cert, key = _env / "cfg" / "tls" / "hub-cert.pem", _env / "cfg" / "tls" / "hub-key.pem"
    assert cert.read_text().startswith("-----BEGIN CERTIFICATE-----")
    if os.name == "posix":
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert "hub.lan" in res["message"] and "192.168.7.7" in res["message"]
    assert "evil" not in res["message"] and "never copy" in res["message"]
    st = fleet.settings_from(_cfg())
    assert st.tls_cert == str(cert) and st.tls_key == str(key)
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))             # a usable pair
    again = fs.hub_tls(_cfg())
    assert again.ok and "existing certificate" in again["message"]


def test_hub_tls_without_openssl_says_so(store, monkeypatch):
    monkeypatch.setattr(fs.shutil, "which", lambda name: None)
    res = fs.hub_tls(_cfg())
    assert not res.ok and "openssl is not installed" in res["message"]
    assert "openssl is not installed" in fs.steps("hub", fs.state(_cfg(), store))[2]["detail"]


def test_hub_start_wants_a_password_first(store):
    op = Operator()
    out = fs.tool_action(_cfg(), store, "hub_start", {}, op)
    assert "set the dashboard password first" in out and op.asked == []


def test_hub_start_and_stop_for_real(store, _env):
    """Starts an actual detached hub on loopback, connects to it, stops it."""
    port = _free_port()
    webauth.set_password(_cfg().data_dir, PW)
    assert fs.hub_listen(_cfg(), "127.0.0.1", port).ok
    argv = [sys.executable, "-m", "wrench", "fleet", "serve", "--no-sample"]
    res = fs.hub_start(_cfg(), wait_s=45, argv=argv)
    try:
        assert res.ok, res["message"]
        assert fs.hub_answers("127.0.0.1", port, tls=False)
        s = fs.state(_cfg(), store)
        assert s["hub"]["running"] and s["hub"]["pid"] == res["pid"]
        assert fs.hub_start(_cfg())["already"] is True     # never a second one
        assert fleet.probe_hub(f"http://127.0.0.1:{port}") == ("ok", "")
    finally:
        stopped = fs.hub_stop(_cfg())
    assert stopped.ok, stopped["message"]
    assert not fs.hub_answers("127.0.0.1", port, tls=False)
    assert not (_env / fs.PID_FILE).exists()
    assert not fs.hub_stop(_cfg()).ok                      # nothing left to stop
    kinds = [r["kind"] for r in audit.read_records(_env)]
    assert "fleet.setup.hub_start" in kinds and "fleet.setup.hub_stop" in kinds


def test_one_long_session_sees_what_its_own_steps_saved(store, _env, monkeypatch):
    """A chat keeps one config object for its whole life. Found live: the hub was
    moved to a new port, then looked for on the old one and reported dead."""
    cfg = _cfg()                                           # loaded once, like `wrench chat`
    port = _free_port()
    op = Operator()
    assert "saved" in fs.tool_action(cfg, store, "hub_listen", {"host": "127.0.0.1",
                                                              "port": port}, op)
    assert f"127.0.0.1:{port}" in fs.tool_status(cfg, store, "hub")
    assert fleet.settings_from(cfg).listen_port == port
    webauth.set_password(cfg.data_dir, PW)
    monkeypatch.setattr(fs, "START_WAIT_S", 45)
    real_start = fs.hub_start
    monkeypatch.setattr(fs, "hub_start", lambda c, **k: real_start(
        c, wait_s=45, argv=[sys.executable, "-m", "wrench", "fleet", "serve", "--no-sample"]))
    try:
        out = fs.tool_action(cfg, store, "hub_start", {}, op)
        assert "running in the background" in out and f"port {port}" in out, out
        assert "[done] Start the hub" in fs.tool_status(cfg, store, "hub")
    finally:
        fs.hub_stop(_cfg())
    assert not fs.hub_answers("127.0.0.1", port, tls=False)


@pytest.mark.skipif(os.name != "posix", reason="process inspection is POSIX-only")
def test_stop_never_signals_a_pid_that_is_not_a_hub(store, _env):
    (_env / fs.PID_FILE).write_text(f"{os.getpid()}\n")    # a reused pid: this test run
    res = fs.hub_stop(_cfg())
    assert not res.ok and "not touching it" in res["message"]


def test_hub_start_reports_a_hub_that_will_not_start(store, _env):
    webauth.set_password(_cfg().data_dir, PW)
    res = fs.hub_start(_cfg(), wait_s=20,
                       argv=[sys.executable, "-c", "import sys; print('boom'); sys.exit(3)"])
    assert not res.ok and "did not come up" in res["message"] and "boom" in res["message"]
    assert not (_env / fs.PID_FILE).exists()


# ------------------------------------------------------------ node steps
def test_node_connect_end_to_end(hub, store, _env):
    url, hs, _ = hub
    op = Operator()
    assert "need the hub's address" in fs.tool_action(_cfg(), store, "node_connect", {}, op)
    out = fs.tool_action(_cfg(), store, "node_connect",
                         {"hub": url, "node_id": "lab-07", "tags": "lab, linux",
                          "password": "the model must not supply this"}, op)
    assert out.startswith("connected to") and "lab-07" in out and PW not in out
    assert op.secret_prompts == [f"password for the hub at {url}"]
    what, label = op.asked[0]
    assert url in what and '"lab-07"' in what and "not stored here" in what
    assert label == "setup: connect to the hub"            # loopback: no plain-HTTP warning
    conf = (_env / "cfg" / "config.toml").read_text()
    assert f'hub_url = "{url}"' in conf and "wfl_" in conf and PW not in conf
    assert PW not in json.dumps(audit.read_records(_env))
    node = hs.get_fleet_node("lab-07")
    assert node and node["meta"]["tags"] == ["lab", "linux"]
    assert fs.steps("node", fs.state(_cfg(), store))[0]["done"]
    assert fs.tool_action(_cfg(), store, "report_now", {}, None).startswith("reported to")


def test_node_connect_failures_send_and_save_nothing(hub, store, _env, monkeypatch):
    url, hs, _ = hub
    op = Operator(secret="not the hub password")
    out = fs.tool_action(_cfg(), store, "node_connect", {"hub": url}, op)
    assert "not valid" in out and "ON THE HUB" in out
    assert not (_env / "cfg" / "config.toml").exists() and hs.fleet_nodes() == []

    op = Operator()
    out = fs.tool_action(_cfg(), store, "node_connect", {"hub": "127.0.0.1:9"}, op)
    assert "no wrench hub answered" in out and op.asked == [] and op.secret_prompts == []
    out = fs.tool_action(_cfg(), store, "node_connect", {"hub": "ftp://x"}, op)
    assert "not an address" in out
    out = fs.tool_action(_cfg(), store, "node_connect", {"hub": url, "ca_file": "/no/such.pem"}, op)
    assert "is not a file" in out and op.asked == []

    # an untrusted certificate: stop before anyone is asked for a password
    monkeypatch.setattr(fleet, "probe_hub", lambda u, *a, **k: ("cert", "self-signed certificate"))
    out = fs.tool_action(_cfg(), store, "node_connect", {"hub": "hub.lan"}, op)
    assert "certificate is not trusted" in out and "ca_file" in out
    assert op.asked == [] and op.secret_prompts == []

    # nobody to ask: the address is checked, then refused with the command
    monkeypatch.undo()
    out = fs.tool_action(_cfg(), store, "node_connect", {"hub": url}, None)
    assert out.startswith("DENIED") and "wrench fleet connect" in out


def test_plain_http_to_another_machine_is_spelled_out(hub, store, monkeypatch):
    url, _, _ = hub
    monkeypatch.setattr(fleet, "is_local_url", lambda u: False)
    op = Operator(yes=False)
    out = fs.tool_action(_cfg(), store, "node_connect", {"hub": url}, op)
    what, label = op.asked[0]
    assert "WARNING: this hub has no TLS" in what and "unencrypted" in what
    assert label == "setup: connect to the hub over plain HTTP"
    assert "declined" in out and op.secret_prompts == []


def test_schedule_uses_the_real_installer_only_on_a_yes(store, monkeypatch):
    from wrench import scheduler
    calls = []
    monkeypatch.setattr(scheduler, "plan_install",
                        lambda b, m: calls.append(("plan", b, m)) or _Plan())
    monkeypatch.setattr(scheduler, "apply_plan", lambda plan, **k: calls.append("apply") or [])
    out = fs.tool_action(_cfg(), store, "schedule", {}, Operator(), wrench_bin="/opt/w/wrench")
    assert "installed and started the heartbeat via testkind" in out and "apply" in calls
    assert fs.schedule(_cfg(), store, "").ok is False       # no executable: say so


class _Plan:
    kind = "testkind"


# ------------------------------------------------------------ the agent
def test_tools_are_offered_and_dispatched(store):
    names = {t["name"] for t in tools.TOOL_SPECS}
    assert {"fleet_setup_status", "fleet_setup"} <= names
    spec = next(t for t in tools.TOOL_SPECS if t["name"] == "fleet_setup")
    assert "password" not in spec["args"]                 # there is no such argument
    assert "never ask for a password" in spec["desc"].lower()
    out = tools.dispatch("fleet_setup_status", {"role": "hub"}, store, "suggest", None, cfg=_cfg())
    assert "as a HUB" in out
    out = tools.dispatch("fleet_setup", {"action": "hub_listen"}, store, "suggest", None, cfg=_cfg())
    assert out.startswith("DENIED")                       # the web chat has nobody to ask
    assert "fleet_setup_status" in agent_mod.SYSTEM_PERSONA
    assert "Never ask for" in agent_mod.SYSTEM_PERSONA


class ScriptedModel:
    """A model that follows a script, and records everything it was shown."""

    def __init__(self, replies):
        self.replies, self.seen, self.last_usage = list(replies), [], {}

    def chat(self, messages, model=None, purpose="chat", **kw):
        self.seen.append(json.dumps(messages))
        return self.replies.pop(0)


def test_agent_walks_a_hub_setup_and_never_sees_the_password(store, _env):
    model = ScriptedModel([
        '{"action": "tool", "tool": "fleet_setup_status", "args": {"role": "hub"}}',
        '{"action": "tool", "tool": "fleet_setup", "args": {"action": "set_password"}}',
        '{"action": "tool", "tool": "fleet_setup", "args": {"action": "hub_listen", "host": "127.0.0.1"}}',
        '{"action": "tool", "tool": "fleet_setup_status", "args": {"role": "hub"}}',
        '{"action": "final", "answer": "Password set and the hub is configured. Next: start it."}',
    ])
    op = Operator(secret="typed by the operator only")
    a = agent_mod.Agent(_cfg(), store, client=model, confirm_fn=op)
    res = a.run("set this machine up as the hub for my other servers")
    assert "Next: start it" in res["answer"]
    assert [s for _, s in op.asked] == ["setup: set the dashboard password",
                                        "setup: make the hub reachable"]
    assert webauth.verify_password("typed by the operator only",
                                   (_env / "web_password").read_text())
    shown = "\n".join(model.seen)
    assert "typed by the operator only" not in shown      # not in any prompt, ever
    assert "dashboard password set" in shown              # only the outcome
    assert "[done] Set the dashboard password" in shown   # the second status reflects it


def test_an_empty_model_reply_is_retried_then_falls_back_to_the_checklist(store):
    model = ScriptedModel([
        '{"action": "tool", "tool": "fleet_setup_status", "args": {"role": "hub"}}',
        "", '{"action": "final", "answer": "Step one is the password. Shall I?"}'])
    res = agent_mod.Agent(_cfg(), store, client=model, confirm_fn=Operator()).run("make this a hub")
    assert res["answer"] == "Step one is the password. Shall I?"
    assert "Your reply was empty" in model.seen[-1]

    model = ScriptedModel([
        '{"action": "tool", "tool": "fleet_setup_status", "args": {"role": "hub"}}',
        '{"action": "final", "answer": "  "}', ""])
    res = agent_mod.Agent(_cfg(), store, client=model, confirm_fn=Operator()).run("make this a hub")
    assert "empty answer" in res["answer"] and "Next step: Set the dashboard password" in res["answer"]


def test_agent_connects_a_node(hub, store, _env):
    url, hs, _ = hub
    model = ScriptedModel([
        '{"action": "tool", "tool": "fleet_setup_status", "args": {"role": "node"}}',
        json.dumps({"action": "tool", "tool": "fleet_setup",
                    "args": {"action": "node_connect", "hub": url, "tags": "prod,web"}}),
        '{"action": "final", "answer": "Connected. Shall I schedule patrols?"}',
    ])
    op = Operator()
    res = agent_mod.Agent(_cfg(), store, client=model, confirm_fn=op).run(
        f"connect this machine to the hub at {url}")
    assert "Connected" in res["answer"] and len(hs.fleet_nodes()) == 1
    shown = "\n".join(model.seen)
    assert PW not in shown and "wfl_" not in shown        # neither the password nor the key


# ------------------------------------------------------------ the CLI
def _cli(args, input=None):
    from typer.testing import CliRunner

    from wrench.cli import app
    return CliRunner().invoke(app, args, input=input)


def test_cli_setup_check_and_json(store):
    res = _cli(["fleet", "setup", "hub", "--check"])
    assert res.exit_code == 1 and "Set the dashboard password" in res.output
    res = _cli(["fleet", "setup"])                        # no terminal, no role: an overview
    assert res.exit_code == 0 and "wrench fleet setup hub" in res.output
    assert _cli(["fleet", "setup", "emperor"]).exit_code == 2
    d = json.loads(_cli(["fleet", "setup", "node", "--json"]).stdout)
    assert d["schema"] == "wrench.fleet.setup.v1" and d["role"] == "node"
    assert [s["key"] for s in d["steps"]["node"]] == ["connect", "schedule", "report"]
    res = _cli(["fleet", "setup", "node"])                # no terminal: shows, changes nothing
    assert res.exit_code == 1 and "nothing changed" in res.output


def test_cli_wizard_connects_a_node(hub, store, _env, monkeypatch):
    url, hs, _ = hub
    import wrench.cli as cli
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    monkeypatch.setattr(fs, "schedule", lambda *a, **k: pytest.fail("installed a timer"))
    answers = "\n".join([
        url.replace("http://", ""),   # the hub's address
        "lab,wizard",                 # tags
        "",                           # no certificate
        "y",                          # do it? (connect)
        PW,                           # the hub password, hidden
        "n",                          # do it? (install the schedule) — no
    ]) + "\n"
    res = _cli(["fleet", "setup", "node"], input=answers)
    assert res.exit_code == 0, res.output
    assert "connected to" in res.output and "reported to" in res.output
    assert PW not in res.output and "declined" in res.output
    node = hs.fleet_nodes()[0]
    assert node["meta"]["tags"] == ["lab", "wizard"]
    assert "still to do" in res.output and "wrench install-service" in res.output


def test_cli_secret_channel_needs_a_terminal(monkeypatch):
    import wrench.cli as cli
    assert cli._confirm.ask_secret is cli._ask_secret
    monkeypatch.setattr(cli, "_isatty", lambda: False)
    assert cli._ask_secret("password") == ""


def test_cli_fleet_stop_with_nothing_running(store):
    res = _cli(["fleet", "stop"])
    assert res.exit_code == 1 and "no hub started in the background" in res.output


def test_placeholders_in_an_answer_are_not_swallowed():
    import io

    from rich.console import Console

    from wrench import report
    buf = io.StringIO()
    report.render_answer(Console(file=buf, width=120), "Run wrench fleet connect <hub-address> "
                         "--port 8936, or `wrench fleet connect <hub>` — see <https://example.org>.")
    out = buf.getvalue()
    assert "connect <hub-address> --port 8936" in out and "connect <hub>" in out
    assert "https://example.org" in out and "\\<" not in out
