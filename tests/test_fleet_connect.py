"""`wrench fleet connect`: a machine trades the hub's dashboard password, once,
for a key of its own — and the console lists every machine, the hub included.
"""

from __future__ import annotations

import json
import time

import pytest
from test_web_security import Cfg, _push, _report, _req, _serve

from wrench import audit, fleet, webauth
from wrench.store import Store

PW = "hub dashboard passphrase"
JSON_H = {"Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _cheap_hash(monkeypatch):
    monkeypatch.setattr(webauth, "_SCRYPT_N", 2 ** 12)
    monkeypatch.delenv("WRENCH_HUB_PASSWORD", raising=False)
    monkeypatch.delenv("WRENCH_WEB_TOKEN", raising=False)


@pytest.fixture
def hub(tmp_path):
    dd = tmp_path / "hub"
    dd.mkdir()
    webauth.set_password(dd, PW)
    httpd, url = _serve(dd, fleet_hub=True)
    store = Store(dd / "w.db")
    yield url, store, dd
    store.close()
    httpd.shutdown()


def _connect(url, password=PW, node_id="web-01", headers=None, **extra):
    body = json.dumps({"password": password, "node_id": node_id, **extra}).encode()
    code, _, raw = _req(url + "/api/fleet/connect", "POST", body, {**JSON_H, **(headers or {})})
    return code, json.loads(raw or b"{}")


# ------------------------------------------------------------ the address
@pytest.mark.parametrize("typed,port,want", [
    ("192.168.1.10", None, ["https://192.168.1.10:8788", "http://192.168.1.10:8788"]),
    ("hub.lan:9000", None, ["https://hub.lan:9000", "http://hub.lan:9000"]),
    ("hub.lan", 9443, ["https://hub.lan:9443", "http://hub.lan:9443"]),
    ("hub.lan:9000", 9443, ["https://hub.lan:9000", "http://hub.lan:9000"]),   # typed port wins
    ("https://hub.example:8788/", None, ["https://hub.example:8788"]),
    ("http://10.0.0.5:8788", None, ["http://10.0.0.5:8788"]),                # explicit: as written
    ("[fd00::5]:8788", None, ["https://[fd00::5]:8788", "http://[fd00::5]:8788"]),
    ("fd00::5", None, ["https://[fd00::5]:8788", "http://[fd00::5]:8788"]),
    ("", None, []), ("ftp://hub", None, []), ("hub/path", None, []), ("hub:port", None, []),
    ("hub:99999", None, []), ("two words", None, []),
])
def test_hub_candidates(typed, port, want):
    assert fleet.hub_candidates(typed, port) == want


def test_is_local_url():
    assert fleet.is_local_url("http://127.0.0.1:8788") and fleet.is_local_url("http://localhost:1")
    assert fleet.is_local_url("http://[::1]:8788")
    assert not fleet.is_local_url("http://10.0.0.5:8788")
    assert not fleet.is_local_url("http://hub.lan:8788")
    assert not fleet.is_local_url("http://localhost.evil.example:8788")


# ------------------------------------------------------------ the grant
def test_connect_hands_out_a_key_that_reports(hub):
    url, store, dd = hub
    code, d = _connect(url)
    assert code == 200 and d["ok"] and d["token"].startswith(fleet.TOKEN_PREFIX)
    assert d["reconnected"] is False and d["node_id"] == "web-01"
    ok, detail = _push(url, d["token"], _report())
    assert ok, detail
    key = store.get_fleet_key(d["key_id"])
    assert key["single_node"] and key["label"] == "connect: web-01"
    # that key belongs to web-01 alone
    ok, detail = _push(url, d["token"], _report(node_id="db-01"))
    assert not ok and "single-node" in detail
    # neither the password nor the key itself is kept on the hub
    blob = (dd / "w.db").read_bytes() + json.dumps(audit.read_records(dd)).encode()
    assert PW.encode() not in blob and d["token"].encode() not in blob
    kinds = [r["kind"] for r in audit.read_records(dd)]
    assert "fleet.connect" in kinds


def test_wrong_password_is_refused_limited_and_audited(hub):
    url, store, dd = hub
    code, d = _connect(url, password="not the password")
    assert code == 401 and "token" not in d
    assert store.fleet_keys() == []
    codes = [_connect(url, password=f"guess {i} guess")[0] for i in range(11)]
    assert codes[-1] == 429
    assert _connect(url)[0] == 429                       # even the right one, for a minute
    recs = audit.read_records(dd)
    assert sum(r["kind"] == "fleet.connect.failed" for r in recs) == 10
    assert "not the password" not in json.dumps(recs)


def test_connect_and_browser_sign_in_share_one_guess_budget(hub):
    url, _, _ = hub
    for i in range(5):
        _connect(url, password=f"guess {i} guess")
        _req(url + "/login", "POST", json.dumps({"password": f"g{i} guess it"}).encode(), JSON_H)
    assert _connect(url)[0] == 429


def test_reconnect_keeps_history_and_retires_the_old_key(hub):
    url, store, _ = hub
    first = _connect(url)[1]
    assert _push(url, first["token"], _report())[0]
    second = _connect(url)[1]
    assert second["reconnected"] is True and second["key_id"] != first["key_id"]
    ok, detail = _push(url, first["token"], _report(ts=time.time() + 1))
    assert not ok and "revoked" in detail                # the lost key is dead
    ok, detail = _push(url, second["token"], _report(ts=time.time() + 2))
    assert ok, detail
    node = store.get_fleet_node("web-01")
    assert node["report_count"] == 2 and node["key_id"] == second["key_id"]


def test_reconnect_does_not_revoke_a_shared_enrollment_key(hub):
    url, store, _ = hub
    shared = fleet.enroll(store, label="site")
    assert _push(url, shared["token"], _report("web-01"))[0]
    assert _push(url, shared["token"], _report("web-02"))[0]
    new = _connect(url, node_id="web-01")[1]
    assert new["reconnected"] is True
    assert not store.get_fleet_key(shared["key_id"])["revoked"]
    assert _push(url, shared["token"], _report("web-02", ts=time.time() + 1))[0]
    # web-01 now answers only to its own key
    ok, detail = _push(url, shared["token"], _report("web-01", ts=time.time() + 1))
    assert not ok and "different credential" in detail
    assert _push(url, new["token"], _report("web-01", ts=time.time() + 2))[0]


def test_connect_needs_a_hub_a_password_and_a_name(tmp_path, hub):
    url, _, dd = hub
    assert _connect(url, node_id="")[0] == 400
    assert _connect(url, node_id="\x00\n ")[0] == 400
    # a browser on another origin cannot drive it
    assert _connect(url, headers={"Origin": "https://evil.example"})[0] == 403
    # not a JSON object
    assert _req(url + "/api/fleet/connect", "POST", b"[1]", JSON_H)[0] == 400
    # GET is not a way in
    assert _req(url + "/api/fleet/connect")[0] in (401, 404, 405)

    plain = tmp_path / "plain"
    plain.mkdir()
    webauth.set_password(plain, PW)
    httpd, purl = _serve(plain)                           # a dashboard, not a hub
    try:
        code, d = _connect(purl)
        assert code == 503 and "fleet serve" in d["error"]
    finally:
        httpd.shutdown()

    nopw = tmp_path / "nopw"
    nopw.mkdir()
    httpd, nurl = _serve(nopw, fleet_hub=True)            # a hub with no password
    try:
        code, d = _connect(nurl, password="")
        assert code == 403 and "wrench password" in d["error"]
        assert _connect(nurl, password="anything at all")[0] == 403
    finally:
        httpd.shutdown()

    off = tmp_path / "off"
    off.mkdir()
    webauth.set_password(off, PW)
    httpd, ourl = _serve(off, raw={"fleet": {"connect": False}}, fleet_hub=True)
    try:
        code, d = _connect(ourl)
        assert code == 403 and "connect = false" in d["error"]
    finally:
        httpd.shutdown()


def test_viewer_token_cannot_connect_but_admin_token_can(tmp_path):
    httpd, url = _serve(tmp_path, raw={"web": {"auth_token": "admin-secret-token",
                                               "viewer_token": "viewer-secret-token"}},
                        fleet_hub=True)
    try:
        assert _connect(url, password="viewer-secret-token")[0] == 401
        assert _connect(url, password="admin-secret-token")[0] == 200
    finally:
        httpd.shutdown()


def test_node_names_are_cleaned():
    assert fleet.clean_node_id("  web-01\n") == "web-01"
    assert fleet.clean_node_id("a\x00b\x1b[31m") == "ab[31m"
    assert len(fleet.clean_node_id("x" * 500)) == 120
    assert fleet.clean_node_id(None) == ""


# ------------------------------------------------------------ node-side helpers
def test_probe_and_connect_request_against_a_real_hub(hub):
    url, _, _ = hub
    assert fleet.probe_hub(url) == ("ok", "")
    verdict, detail = fleet.probe_hub("http://127.0.0.1:9", timeout=2)
    assert verdict == "unreachable" and detail
    # plain http answering where https was tried is "unreachable", never "cert"
    assert fleet.probe_hub(url.replace("http://", "https://"), timeout=3)[0] == "unreachable"
    res = fleet.connect_request(url, PW, "web-09")
    assert res["ok"] and res["token"].startswith(fleet.TOKEN_PREFIX)
    bad = fleet.connect_request(url, "wrong wrong wrong", "web-09")
    assert bad == {"ok": False, "code": 401, "detail": "that password is not valid"}
    gone = fleet.connect_request("http://127.0.0.1:9", PW, "web-09", timeout=2)
    assert gone["ok"] is False and gone["code"] == 0


def test_probe_reports_an_untrusted_certificate_as_such():
    import ssl
    import urllib.error

    def opener(req, timeout=None):
        raise urllib.error.URLError(ssl.SSLCertVerificationError("self-signed certificate"))
    assert fleet.probe_hub("https://hub.lan:8788", opener=opener)[0] == "cert"


# ------------------------------------------------------------ the console
def test_console_lists_the_hub_itself_once(hub):
    url, store, _ = hub
    session = _req(url + "/login", "POST", json.dumps({"password": PW}).encode(),
                   JSON_H)[1]["Set-Cookie"].split(";")[0]
    d = json.loads(_req(url + "/api/fleet/nodes", headers={"Cookie": session})[2])
    assert [n.get("local") for n in d["nodes"]] == [True] and d["summary"]["total"] == 1
    me = d["nodes"][0]["node_id"]
    # the hub joins itself: its stored row replaces the synthetic one
    key = fleet.enroll(store)
    assert _push(url, key["token"], _report(node_id=me))[0]
    d = json.loads(_req(url + "/api/fleet/nodes", headers={"Cookie": session})[2])
    assert len(d["nodes"]) == 1 and not d["nodes"][0].get("local")
    assert _req(url + "/api/fleet/nodes")[0] == 401      # the console is behind the password


def test_pages_carry_the_machine_picker():
    from pathlib import Path

    import wrench
    web = Path(wrench.__file__).parent / "web"
    dash, fl, js = ((web / n).read_text() for n in ("dashboard.html", "fleet.html", "base.js"))
    for page in (dash, fl):
        assert 'id="machine"' in page and "fillMachines(" in page
    assert "function fillMachines" in js and "All machines" in js and "This machine" in js
    assert "wrench fleet connect" in fl and "?node=" in fl


# ------------------------------------------------------------ the CLI
def _node_env(monkeypatch, tmp_path):
    import wrench.cli as cli
    import wrench.config as wc
    nd = tmp_path / "node"
    monkeypatch.setattr(wc, "DATA_DIR", nd)
    monkeypatch.setattr(wc, "CONFIG_DIR", nd / "cfg")
    monkeypatch.setattr(wc, "CONFIG_PATH", nd / "cfg" / "config.toml")
    monkeypatch.setattr(cli, "CONFIG_PATH", nd / "cfg" / "config.toml")
    monkeypatch.setattr(cli.sensors, "sample_all", lambda store: None)
    return nd


def _cli(args, input=None):
    from typer.testing import CliRunner

    from wrench.cli import app
    return CliRunner().invoke(app, args, input=input)


def test_cli_connect_end_to_end(hub, tmp_path, monkeypatch):
    url, store, _ = hub
    nd = _node_env(monkeypatch, tmp_path)
    addr = url.replace("http://", "")                    # a bare address, as an operator types it
    res = _cli(["fleet", "connect", addr, "--node-id", "lab-07", "--tags", "lab,linux",
                "--password-stdin"], input=PW + "\n")
    assert res.exit_code == 0, res.output
    assert "connected to" in res.output and "lab-07" in res.output and PW not in res.output
    conf = (nd / "cfg" / "config.toml").read_text()
    assert f'hub_url = "{url}"' in conf and 'node_id = "lab-07"' in conf and "wfl_" in conf
    assert PW not in conf                                # the password is kept nowhere on the node
    assert PW not in json.dumps(audit.read_records(nd))
    node = store.get_fleet_node("lab-07")
    assert node and node["report_count"] == 1 and node["meta"]["tags"] == ["lab", "linux"]


def test_cli_connect_wrong_password_saves_nothing(hub, tmp_path, monkeypatch):
    url, store, _ = hub
    nd = _node_env(monkeypatch, tmp_path)
    res = _cli(["fleet", "connect", url, "--password-stdin"], input="not the password\n")
    assert res.exit_code == 1 and "not valid" in res.output
    assert not (nd / "cfg" / "config.toml").exists() and store.fleet_nodes() == []
    monkeypatch.setenv("WRENCH_HUB_PASSWORD", PW)        # the unattended path
    assert _cli(["fleet", "connect", url, "--node-id", "lab-08"]).exit_code == 0
    assert store.get_fleet_node("lab-08")


def test_cli_connect_never_sends_the_password_over_plain_http_unasked(tmp_path, monkeypatch):
    _node_env(monkeypatch, tmp_path)
    sent = []
    monkeypatch.setattr(fleet, "probe_hub",
                        lambda url, *a, **k: ("ok", "") if url.startswith("http://")
                        else ("unreachable", "refused"))
    monkeypatch.setattr(fleet, "connect_request",
                        lambda *a, **k: sent.append(a) or {"ok": False, "code": 401, "detail": "x"})
    res = _cli(["fleet", "connect", "10.20.30.40", "--password-stdin"], input=PW + "\n")
    assert res.exit_code == 2 and "no TLS" in res.output and "--allow-http" in res.output
    assert sent == []
    res = _cli(["fleet", "connect", "10.20.30.40", "--password-stdin", "--allow-http"],
               input=PW + "\n")
    assert len(sent) == 1 and sent[0][0] == "http://10.20.30.40:8788"

    # in a terminal: asked, and the default answer is no
    import wrench.cli as cli
    sent.clear()
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    res = _cli(["fleet", "connect", "10.20.30.40"], input="\n")
    assert res.exit_code == 1 and "Send it anyway?" in res.output and sent == []


def test_cli_connect_does_not_step_down_from_an_untrusted_certificate(tmp_path, monkeypatch):
    _node_env(monkeypatch, tmp_path)
    tried, sent = [], []
    monkeypatch.setattr(fleet, "probe_hub",
                        lambda url, *a, **k: tried.append(url) or ("cert", "self-signed certificate"))
    monkeypatch.setattr(fleet, "connect_request", lambda *a, **k: sent.append(a))
    res = _cli(["fleet", "connect", "hub.lan", "--password-stdin", "--allow-http"], input=PW + "\n")
    assert res.exit_code == 1 and "--ca-file" in res.output
    assert tried == ["https://hub.lan:8788"] and sent == []


def test_cli_connect_bad_address_and_no_hub(tmp_path, monkeypatch):
    _node_env(monkeypatch, tmp_path)
    assert _cli(["fleet", "connect", "ftp://hub", "--password-stdin"], input="x\n").exit_code == 2
    monkeypatch.setattr(fleet, "PUSH_TIMEOUT_S", 2)
    res = _cli(["fleet", "connect", "127.0.0.1:9", "--password-stdin"], input=PW + "\n")
    assert res.exit_code == 1 and "no wrench hub answered" in res.output
    res = _cli(["fleet", "connect", "127.0.0.1:9"])     # no terminal, no password source
    assert res.exit_code in (1, 2)


def test_settings_connect_flag_defaults_on(tmp_path):
    assert fleet.settings_from(Cfg(tmp_path)).connect is True
    assert fleet.settings_from(Cfg(tmp_path, {"fleet": {"connect": False}})).connect is False
