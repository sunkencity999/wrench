"""Notification channels: email, Telegram, Slack, Teams, Discord, webhook.

Every sender is exercised over a real socket against a local stand-in server
(HTTP for the chat services, a minimal SMTP server for email). Nothing here
talks to a real service.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from wrench import audit, channels
from wrench import notifications as notif

TOKEN = "123456789:AAExampleTokenExampleTokenExample0001"
REC = {"id": "abc123def456", "ts": 1_800_000_000, "severity": "critical", "kind": "patrol",
       "summary": "disk /var is 96% full"}


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
    for k in list(os.environ):
        if k.startswith("WRENCH_NOTIFY_") or k == "WRENCH_OFFLINE":
            monkeypatch.delenv(k)
    monkeypatch.setattr(channels, "host_label", lambda: "web-01")
    (me / "cfg" / "config.toml").write_text("[notify]\ndesktop = false\n")
    return me


def _cfg():
    from wrench.config import load_config
    return load_config()


# ------------------------------------------------------------ stand-in servers
class _Web(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.got: list[dict] = []
        self.reply: dict = {}
        self.status = 200
        super().__init__(("127.0.0.1", 0), _WebHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _WebHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.got.append({"path": self.path, "json": json.loads(body or b"{}")})
        method = self.path.rsplit("/", 1)[-1]
        reply = self.server.reply.get(method, self.server.reply.get("*", {"ok": True}))
        raw = json.dumps(reply).encode()
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture
def web():
    srv = _Web()
    yield srv
    srv.shutdown()


class _Smtp(socketserver.ThreadingTCPServer):
    """Just enough SMTP to accept one message from smtplib."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        self.messages: list[dict] = []
        super().__init__(("127.0.0.1", 0), _SmtpHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()


class _SmtpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda line: self.wfile.write(line.encode() + b"\r\n")  # noqa: E731
        w("220 test ESMTP")
        mail = {"from": "", "to": [], "data": ""}
        while True:
            line = self.rfile.readline().decode("utf-8", "replace")
            if not line:
                return
            cmd = line.strip().upper()
            if cmd.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250-test\r\n250 8BITMIME\r\n")
            elif cmd.startswith("MAIL FROM:"):
                mail["from"] = line.split(":", 1)[1].strip()
                w("250 ok")
            elif cmd.startswith("RCPT TO:"):
                mail["to"].append(line.split(":", 1)[1].strip())
                w("250 ok")
            elif cmd == "DATA":
                w("354 go")
                lines = []
                while True:
                    d = self.rfile.readline().decode("utf-8", "replace")
                    if d in (".\r\n", ".\n", ""):
                        break
                    lines.append(d)
                mail["data"] = "".join(lines)
                self.server.messages.append(mail)
                w("250 queued")
            elif cmd == "QUIT":
                w("221 bye")
                return
            else:
                w("250 ok")


@pytest.fixture
def smtp():
    srv = _Smtp()
    yield srv
    srv.shutdown()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------ config round trip
def test_save_load_remove_round_trip(_env):
    channels.save(channels.Channel("mail", "email", "critical", {
        "host": "smtp.example.com", "port": 587, "security": "starttls",
        "username": "alerts@example.com", "from": "wrench <alerts@example.com>",
        "to": ["a@example.com", "b@example.com"]}, "the-mail-password"))
    channels.save(channels.Channel("ops", "slack", "", {}, "https://hooks.slack.com/services/T/B/SECRETTAIL99"))
    text = (_env / "cfg" / "config.toml").read_text()
    assert "the-mail-password" not in text and "SECRETTAIL99" not in text   # secrets by reference
    assert "[notify.channels.mail]" in text and "desktop = false" in text
    for name in ("mail", "ops"):
        p = _env / "cfg" / "notify" / f"{name}.secret"
        assert p.is_file()
        if os.name == "posix":
            assert stat.S_IMODE(p.stat().st_mode) == 0o600
    got = {c.name: c for c in channels.load(_cfg())}
    assert got["mail"].min_severity == "critical" and got["mail"].secret == "the-mail-password"
    assert got["mail"].settings["to"] == ["a@example.com", "b@example.com"]
    assert got["mail"].destination == "a@example.com, b@example.com via smtp.example.com"
    assert got["ops"].destination == "hooks.slack.com"           # never the URL itself
    # saving again replaces; it does not duplicate the section
    channels.save(channels.Channel("ops", "discord", "", {}, "https://discord.com/api/webhooks/1/abcdefghij"))
    text = (_env / "cfg" / "config.toml").read_text()
    assert text.count("[notify.channels.ops]") == 1 and channels.load(_cfg())[1].type == "discord"
    assert channels.remove("mail") and [c.name for c in channels.load(_cfg())] == ["ops"]
    assert not (_env / "cfg" / "notify" / "mail.secret").exists()
    assert "desktop = false" in (_env / "cfg" / "config.toml").read_text()
    assert not channels.remove("mail")


@pytest.mark.parametrize("name,ok", [("ops", True), ("phone-2", True), ("Ops", False),
                                     ("a b", False), ("", False), ("x" * 40, False),
                                     ("../etc", False), ("ops]\n[web", False)])
def test_channel_names(name, ok):
    assert channels.valid_name(name) is ok
    if not ok:
        with pytest.raises(ValueError):
            channels.save(channels.Channel(name, "slack", "", {}, "https://hooks.slack.com/x"))


def test_secret_sources_and_malformed_entries(_env, monkeypatch):
    (_env / "cfg" / "config.toml").write_text(
        '[notify.channels.inline]\ntype = "webhook"\nurl = "https://ntfy.example/topic"\n\n'
        '[notify.channels.off]\ntype = "slack"\nenabled = false\nurl = "https://hooks.slack.com/x"\n\n'
        '[notify.channels.bogus]\ntype = "carrier-pigeon"\n\n'
        '[notify.channels.envy]\ntype = "telegram"\nchat_id = "42"\n')
    monkeypatch.setenv("WRENCH_NOTIFY_ENVY_SECRET", TOKEN)
    got = {c.name: c for c in channels.load(_cfg())}
    assert set(got) == {"inline", "envy"}
    assert got["inline"].secret == "https://ntfy.example/topic" and got["envy"].secret == TOKEN
    assert channels.load(SimpleNamespace(raw={"notify": {"channels": "nope"}})) == []
    assert channels.load(SimpleNamespace(raw={})) == []


# ------------------------------------------------------------ what gets sent
def test_link_only_when_the_dashboard_has_a_real_address(_env):
    assert channels.dashboard_link(_cfg(), REC) == ""        # localhost means nothing on a phone
    (_env / "cfg" / "config.toml").write_text('[notify]\ndashboard_url = "https://hub.example:8788/"\n')
    assert channels.dashboard_link(_cfg(), REC) == "https://hub.example:8788/#notification=abc123def456"
    assert channels.dashboard_link(_cfg(), {"id": "a/../<b>"}) == "https://hub.example:8788/#notification=ab"
    (_env / "cfg" / "config.toml").write_text('[notify]\ndashboard_url = "javascript:alert(1)"\n')
    assert channels.dashboard_link(_cfg(), REC) == ""


def test_slack_discord_teams_webhook_payloads(web):
    link = "https://hub.example:8788/#notification=abc123def456"
    rec = dict(REC, summary="load <high> & rising on *db*")
    channels.send(channels.Channel("s", "slack", "", {}, web.url + "/slack"), rec, link)
    channels.send(channels.Channel("d", "discord", "", {}, web.url + "/discord"), rec, link)
    channels.send(channels.Channel("t", "teams", "", {}, web.url + "/teams"), rec, link)
    channels.send(channels.Channel("w", "webhook", "", {}, web.url + "/hook"), rec, link)
    slack, discord, teams, hook = (g["json"] for g in web.got)
    assert "load &lt;high&gt; &amp; rising" in slack["text"]          # cannot forge a Slack link
    assert "wrench · web-01 · critical" in slack["text"]
    assert f"<{link}|Show in the dashboard>" in slack["text"]
    assert "load <high> & rising" in discord["content"] and link in discord["content"]
    assert discord["allowed_mentions"] == {"parse": []}               # a finding cannot @everyone
    card = teams["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["content"]["body"][1]["text"] == rec["summary"]
    assert card["content"]["actions"][0]["url"] == link
    assert hook["severity"] == "critical" and hook["host"] == "web-01" and hook["link"] == link
    assert hook["message"] == rec["summary"] and "text" in hook and "content" in hook


def test_http_failures_are_reported_without_the_secret(web):
    web.status, web.reply = 404, {"*": {"error": "no_service"}}
    url = web.url + "/services/T000/B000/SUPERSECRETTAIL"
    with pytest.raises(channels.ChannelError) as e:
        channels.send(channels.Channel("s", "slack", "", {}, url), REC)
    assert "HTTP 404" in str(e.value) and "SUPERSECRETTAIL" not in str(e.value)
    with pytest.raises(channels.ChannelError) as e:
        channels.send(channels.Channel("s", "slack", "", {}, f"http://127.0.0.1:{_free_port()}/SUPERSECRETTAIL"), REC)
    assert "SUPERSECRETTAIL" not in str(e.value)
    with pytest.raises(channels.ChannelError, match="no URL is stored"):
        channels.send(channels.Channel("s", "slack", "", {}, ""), REC)
    with pytest.raises(channels.ChannelError, match="http"):
        channels.send(channels.Channel("s", "webhook", "", {}, "file:///etc/passwd"), REC)


def test_telegram_token_check_chat_discovery_and_send(web):
    web.reply = {
        "getMe": {"ok": True, "result": {"username": "wrench_ops_bot"}},
        "getUpdates": {"ok": True, "result": [
            {"message": {"chat": {"id": 111, "first_name": "Ada", "last_name": "L"}}},
            {"message": {"chat": {"id": -222, "title": "Ops room"}}},
            {"message": {"chat": {"id": 111, "first_name": "Ada", "last_name": "L"}}},
            {"edited_message": {}}]},
        "sendMessage": {"ok": True, "result": {}}}
    assert channels.telegram_bot_name(TOKEN, web.url) == "wrench_ops_bot"
    chats = channels.telegram_find_chats(TOKEN, web.url)
    assert chats == [{"id": "111", "name": "Ada L"}, {"id": "-222", "name": "Ops room"}]
    ch = channels.Channel("phone", "telegram", "", {"chat_id": "-222", "api_base": web.url}, TOKEN)
    channels.send(ch, REC)
    sent = web.got[-1]
    assert sent["path"] == f"/bot{TOKEN}/sendMessage"
    assert sent["json"]["chat_id"] == "-222" and "disk /var is 96% full" in sent["json"]["text"]
    assert "wrench · web-01 · critical" in sent["json"]["text"]
    assert ch.destination == "chat -222"

    web.reply["sendMessage"] = {"ok": False, "description": f"chat not found for bot{TOKEN}"}
    with pytest.raises(channels.ChannelError) as e:
        channels.send(ch, REC)
    assert "chat not found" in str(e.value) and TOKEN not in str(e.value)
    with pytest.raises(channels.ChannelError, match="does not look like"):
        channels.telegram_bot_name("not-a-token", web.url)          # refused before any request
    with pytest.raises(channels.ChannelError, match="chat_id"):
        channels.send(channels.Channel("p", "telegram", "", {"api_base": web.url}, TOKEN), REC)
    assert all("not-a-token" not in g["path"] for g in web.got)


def test_email_over_a_real_smtp_conversation(smtp):
    ch = channels.Channel("mail", "email", "", {
        "host": "127.0.0.1", "port": smtp.server_address[1], "security": "none",
        "from": "wrench <alerts@example.com>", "to": ["a@example.com", "b@example.com"]}, "")
    rec = dict(REC, summary="disk full\nBcc: attacker@evil.example\n\ninjected body")
    channels.send(ch, rec, "https://hub.example:8788/#notification=abc123def456")
    (m,) = smtp.messages
    assert "alerts@example.com" in m["from"] and len(m["to"]) == 2
    headers, _, body = m["data"].replace("\r\n", "\n").partition("\n\n")
    assert "Subject: [wrench] critical on web-01: disk full Bcc: attacker@evil.example" in headers
    assert not any(line.lower().startswith("bcc:") for line in headers.splitlines())  # no new header
    assert "To: a@example.com, b@example.com" in headers and "Auto-Submitted: auto-generated" in headers
    assert "machine:  web-01" in body and "severity: critical" in body
    assert "https://hub.example:8788/#notification=abc123def456" in body


def test_email_refusals_and_errors(smtp):
    base = {"host": "127.0.0.1", "port": smtp.server_address[1], "security": "none",
            "from": "a@example.com", "to": ["b@example.com"]}
    with pytest.raises(channels.ChannelError, match="without TLS"):
        channels.send(channels.Channel("m", "email", "", base, "a-password"), REC)
    assert smtp.messages == []
    with pytest.raises(channels.ChannelError, match="needs host, from and to"):
        channels.send(channels.Channel("m", "email", "", {"host": "x"}, ""), REC)
    with pytest.raises(channels.ChannelError, match="security must be"):
        channels.send(channels.Channel("m", "email", "", dict(base, security="rot13"), ""), REC)
    with pytest.raises(channels.ChannelError) as e:
        channels.send(channels.Channel("m", "email", "", dict(base, port=_free_port()), ""), REC)
    assert "Error" in str(e.value) or "refused" in str(e.value).lower()

    import smtplib

    class Refusing:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): pass
        def login(self, u, p): raise smtplib.SMTPAuthenticationError(535, b"bad creds hunter2secret")
    with pytest.raises(channels.ChannelError) as e:
        channels.send(channels.Channel("m", "email", "", dict(base, security="starttls",
                                                               username="a@example.com"),
                                       "hunter2secret"), REC,
                      smtp_factory=lambda h, p, s: Refusing())
    assert "app password" in str(e.value) and "hunter2secret" not in str(e.value)


# ------------------------------------------------------------ fan-out
def _two_channels(web):
    channels.save(channels.Channel("ops", "webhook", "", {}, web.url + "/ops"))
    channels.save(channels.Channel("phone", "webhook", "critical", {}, web.url + "/phone"))


def test_each_channel_has_its_own_threshold(web, _env):
    _two_channels(web)
    res = channels.deliver(_cfg(), dict(REC, severity="attention"), _env)
    assert res == {"ops": (True, "sent")} and [g["path"] for g in web.got] == ["/ops"]
    res = channels.deliver(_cfg(), REC, _env)
    assert set(res) == {"ops", "phone"}
    web.got.clear()
    assert channels.deliver(_cfg(), dict(REC, severity="info"), _env) == {}      # below both
    assert set(channels.deliver(_cfg(), dict(REC, severity="info"), _env, force=True)) == {"ops", "phone"}
    assert set(channels.deliver(_cfg(), REC, _env, only="phone")) == {"phone"}


def test_one_broken_channel_does_not_stop_the_others_and_is_logged(web, _env):
    _two_channels(web)
    channels.save(channels.Channel("dead", "webhook", "", {}, f"http://127.0.0.1:{_free_port()}/SECRETPATH123"))
    res = channels.deliver(_cfg(), REC, _env)
    assert res["ops"][0] and res["phone"][0] and not res["dead"][0]
    log = (_env / notif.LOG_NAME).read_text()
    assert "channel dead (webhook) failed" in log and "SECRETPATH123" not in log


def test_offline_mode_skips_public_servers(web, _env, monkeypatch):
    channels.save(channels.Channel("local", "webhook", "", {}, web.url + "/lan"))
    channels.save(channels.Channel("cloud", "slack", "", {}, "https://hooks.slack.com/services/x"))
    channels.save(channels.Channel("tg", "telegram", "", {"chat_id": "1"}, TOKEN))
    sent = []
    real = channels.send
    monkeypatch.setattr(channels, "send", lambda ch, *a, **k: sent.append(ch.name) or real(ch, *a, **k))
    res = channels.deliver(_cfg(), REC, _env, block_public=True)
    assert res["local"][0] and sent == ["local"]
    assert "offline mode" in res["cloud"][1] and "offline mode" in res["tg"][1]


def test_alerts_and_asked_for_messages_reach_channels(web, _env):
    _two_channels(web)
    cfg = _cfg()
    notif.emit_event(cfg, "fleet", "attention", "node db-01 is SILENT", data_dir=_env)
    assert [g["path"] for g in web.got] == ["/ops"]
    notif.emit_event(cfg, "backups", "critical", "restic job failed", data_dir=_env)
    assert sorted(g["path"] for g in web.got[1:]) == ["/ops", "/phone"]
    web.got.clear()
    notif.deliver(cfg, "brief", "info", "morning brief: all quiet", data_dir=_env)   # asked for
    assert sorted(g["path"] for g in web.got) == ["/ops", "/phone"]
    web.got.clear()
    notif.dispatch(cfg, {"status": "critical", "summary": "disk 96%", "findings": []}, data_dir=_env)
    assert sorted(g["path"] for g in web.got) == ["/ops", "/phone"]
    assert web.got[0]["json"]["message"] == "disk 96%"


def test_a_critical_only_channel_alone_still_gets_its_alert(web, _env):
    """The global threshold must not swallow what a channel asked for."""
    (_env / "cfg" / "config.toml").write_text('[notify]\ndesktop = false\nmin_severity = "critical"\n')
    channels.save(channels.Channel("all", "webhook", "attention", {}, web.url + "/all"))
    notif.emit_event(_cfg(), "certs", "attention", "certificate expires in 9d", data_dir=_env)
    assert [g["path"] for g in web.got] == ["/all"]


# ------------------------------------------------------------ the CLI
def _cli(args, input=None):
    from typer.testing import CliRunner

    from wrench.cli import app
    return CliRunner().invoke(app, args, input=input)


def test_cli_unattended_setup_test_list_remove(web, _env):
    url = web.url + "/hook/TOPSECRETTOPIC"
    res = _cli(["notify", "setup", "webhook", "--name", "ops", "--secret-stdin"], input=url + "\n")
    assert res.exit_code == 0, res.output
    assert "test message sent" in res.output and "TOPSECRETTOPIC" not in res.output
    assert web.got[0]["json"]["kind"] == "test" and "this channel works" in web.got[0]["json"]["message"]
    d = json.loads(_cli(["notify", "--json"]).stdout)
    assert d["schema"] == "wrench.notify.v1"
    assert d["channels"] == [{"name": "ops", "type": "webhook", "destination": "127.0.0.1",
                              "min_severity": "attention", "ready": True}]
    out = _cli(["notify"]).output
    assert "ops" in out and "TOPSECRETTOPIC" not in out

    res = _cli(["notify", "test"])
    assert res.exit_code == 0 and "✔ ops" in res.output and len(web.got) == 2
    d = json.loads(_cli(["notify", "test", "ops", "--json"]).stdout)
    assert d["ok"] and d["results"] == [{"name": "ops", "ok": True, "detail": "sent"}]
    assert _cli(["notify", "test", "nobody"]).exit_code == 1

    recs = audit.read_records(_env)
    assert any(r["kind"] == "notify.channel.added" for r in recs)
    assert "TOPSECRETTOPIC" not in json.dumps(recs)
    assert _cli(["notify", "remove", "ops"]).exit_code == 0
    assert _cli(["notify", "remove", "ops"]).exit_code == 1
    assert _cli(["notify", "test"]).exit_code == 1 and channels.load(_cfg()) == []


def test_cli_a_channel_that_fails_its_test_is_not_saved(_env):
    dead = f"http://127.0.0.1:{_free_port()}/x"
    res = _cli(["notify", "setup", "webhook", "--secret-stdin"], input=dead + "\n")
    assert res.exit_code == 1 and "did not go through" in res.output and "nothing saved" in res.output
    assert channels.load(_cfg()) == [] and not (_env / "cfg" / "notify").exists()
    res = _cli(["notify", "setup", "webhook", "--secret-stdin", "--no-test"], input=dead + "\n")
    assert res.exit_code == 0 and len(channels.load(_cfg())) == 1
    res = _cli(["notify", "test"])
    assert res.exit_code == 1 and "✖ webhook" in res.output


def test_cli_validation(_env):
    assert _cli(["notify", "setup"]).exit_code == 2                            # no terminal
    assert _cli(["notify", "setup", "pigeon"]).exit_code == 2
    assert _cli(["notify", "setup", "slack", "--name", "Bad Name", "--secret-stdin"],
                input="https://hooks.slack.com/x\n").exit_code == 2
    res = _cli(["notify", "setup", "slack", "--secret-stdin"], input="http://hooks.slack.com/x\n")
    assert res.exit_code == 1 and "not a webhook address" in res.output       # https only
    assert _cli(["notify", "setup", "telegram", "--secret-stdin", "--chat-id", "1"],
                input="nonsense\n").exit_code == 1
    assert _cli(["notify", "setup", "email", "--secret-stdin"], input="\n").exit_code == 2
    assert _cli(["notify", "setup", "webhook", "--min-severity", "loud"]).exit_code == 2
    assert channels.load(_cfg()) == []


def test_cli_interactive_telegram_walkthrough(_env, monkeypatch):
    import wrench.cli as cli
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    calls = iter([[], [{"id": "111", "name": "Ada L"}, {"id": "-222", "name": "Ops room"}]])
    sent = []
    monkeypatch.setattr(channels, "telegram_bot_name", lambda tok, *a, **k: "wrench_ops_bot")
    monkeypatch.setattr(channels, "telegram_find_chats", lambda tok, *a, **k: next(calls))
    monkeypatch.setattr(channels, "send", lambda ch, rec, *a, **k: sent.append((ch, rec)))
    answers = "\n".join([
        "2",        # type: telegram
        TOKEN,      # the token (hidden)
        "",         # "I sent it" — nothing has arrived yet
        "",         # "I sent it" — now two chats
        "2",        # the Ops room
        "critical", # only what cannot wait
    ]) + "\n"
    res = _cli(["notify", "setup"], input=answers)
    assert res.exit_code == 0, res.output
    assert "@wrench_ops_bot" in res.output and "no message has reached the bot yet" in res.output
    assert "Ops room" in res.output and TOKEN not in res.output
    (ch,) = channels.load(_cfg())
    assert (ch.name, ch.type, ch.min_severity) == ("telegram", "telegram", "critical")
    assert ch.settings["chat_id"] == "-222" and ch.settings["chat_name"] == "Ops room"
    assert ch.secret == TOKEN and TOKEN not in (_env / "cfg" / "config.toml").read_text()
    assert sent[0][1]["kind"] == "test"


def test_cli_email_setup_by_flags(smtp, _env):
    res = _cli(["notify", "setup", "email", "--name", "mail", "--host", "127.0.0.1",
                "--port", str(smtp.server_address[1]), "--security", "none",
                "--from", "wrench <alerts@example.com>", "--to", "a@example.com",
                "--to", "b@example.com", "--min-severity", "critical", "--secret-stdin"], input="\n")
    assert res.exit_code == 0, res.output
    assert len(smtp.messages) == 1 and "this channel works" in smtp.messages[0]["data"]
    (ch,) = channels.load(_cfg())
    assert ch.settings["to"] == ["a@example.com", "b@example.com"] and ch.min_severity == "critical"
    # a second channel of the same type gets its own name
    res = _cli(["notify", "setup", "email", "--host", "127.0.0.1", "--port",
                str(smtp.server_address[1]), "--security", "none", "--from", "x@example.com",
                "--to", "c@example.com", "--secret-stdin"], input="\n")
    assert res.exit_code == 0 and [c.name for c in channels.load(_cfg())] == ["email", "mail"]
