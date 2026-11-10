"""Access control on the web surfaces: Host validation (DNS rebinding), token +
session auth, roles, CSRF, rate limiting, response headers — and the fleet v2
protocol end to end over real HTTP (enroll → signed report → replay / forgery /
revocation / node-binding rejections)."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from wrench import fleet, webapp, webauth
from wrench.store import Store


class Cfg:
    provider = "none"
    model = ""
    base_url = ""
    api_key = ""
    policy_tier = "suggest"
    offline = False
    patrol_interval_min = 15
    retention_days = 30

    def __init__(self, data_dir: Path, raw: dict | None = None):
        self._dd = Path(data_dir)
        self.raw = raw or {}

    @property
    def data_dir(self) -> Path:
        return self._dd


def _serve(tmp_path, auth=None, raw=None, fleet_hub=False):
    db = tmp_path / "w.db"
    Store(db).close()
    httpd = webapp.serve(db, port=0, bind="127.0.0.1", sample_thread=False,
                         cfg=Cfg(tmp_path, raw), auth=auth, fleet_hub=fleet_hub)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _req(url, method="GET", body=None, headers=None):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


@pytest.fixture
def open_server(tmp_path):
    httpd, url = _serve(tmp_path)
    yield url
    httpd.shutdown()


@pytest.fixture
def locked_server(tmp_path):
    auth = webauth.AuthConfig(bind="127.0.0.1", admin_token="admin-secret-token",
                              viewer_token="viewer-secret-token")
    httpd, url = _serve(tmp_path, auth=auth)
    yield url
    httpd.shutdown()


# ---------------- loopback: open, but not to a rebound hostname ----------------

def test_loopback_needs_no_login(open_server):
    code, _, body = _req(open_server + "/api/overview")
    assert code == 200
    d = json.loads(body)
    assert d["role"] == "admin" and d["auth_required"] is False
    assert "posture" in d and "pillars" in d["posture"]


def test_dns_rebinding_host_is_refused(open_server):
    # a hostile page whose hostname was re-pointed at 127.0.0.1 sends ITS name as Host
    code, _, _ = _req(open_server + "/api/overview", headers={"Host": "evil.example.com:8787"})
    assert code == 421
    code, _, _ = _req(open_server + "/", headers={"Host": "evil.example.com"})
    assert code == 421
    code, _, _ = _req(open_server + "/api/overview", headers={"Host": "localhost:9"})
    assert code == 200


def test_healthz_is_public_and_empty(locked_server):
    code, _, body = _req(locked_server + "/healthz")
    assert code == 200 and json.loads(body) == {"ok": True}


def test_security_headers_on_every_response(open_server):
    for path in ("/", "/api/overview", "/nope"):
        _, h, _ = _req(open_server + path)
        assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["X-Frame-Options"] == "DENY"
        assert h["Cache-Control"] == "no-store"
    _, h, body = _req(open_server + "/")
    nonce = h["Content-Security-Policy"].split("'nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"'.encode() in body       # the page's scripts carry it
    assert "unsafe-inline" not in h["Content-Security-Policy"].split("script-src")[1].split(";")[0]


# ---------------- token + session auth, roles ----------------

def test_api_requires_a_credential(locked_server):
    code, h, _ = _req(locked_server + "/api/overview")
    assert code == 401 and "Bearer" in h["WWW-Authenticate"]
    code, _, _ = _req(locked_server + "/api/patrols", headers={"Authorization": "Bearer nope"})
    assert code == 401
    code, h, _ = _req(locked_server + "/")                 # pages redirect to sign-in
    assert code == 303 and h["Location"].startswith("/login")
    code, _, _ = _req(locked_server + "/metrics")          # so does the exporter
    assert code == 401


def test_bearer_token_roles(locked_server):
    code, _, body = _req(locked_server + "/api/overview",
                         headers={"Authorization": "Bearer viewer-secret-token"})
    assert code == 200 and json.loads(body)["role"] == "viewer"
    # a viewer can read but not act
    code, _, _ = _req(locked_server + "/api/notifications/read", "POST", b"{}",
                      {"Authorization": "Bearer viewer-secret-token",
                       "Content-Type": "application/json"})
    assert code == 403
    code, _, _ = _req(locked_server + "/api/notifications/read", "POST", b"{}",
                      {"Authorization": "Bearer admin-secret-token",
                       "Content-Type": "application/json"})
    assert code == 200


def test_login_sets_a_hardened_session_cookie(locked_server):
    code, _, _ = _req(locked_server + "/login", "POST", json.dumps({"token": "wrong"}).encode(),
                      {"Content-Type": "application/json"})
    assert code == 401
    code, h, _ = _req(locked_server + "/login", "POST",
                      json.dumps({"token": "admin-secret-token"}).encode(),
                      {"Content-Type": "application/json"})
    assert code == 200
    cookie = h["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert "admin-secret-token" not in cookie          # the token never rides in the cookie
    session = cookie.split(";")[0]
    code, _, body = _req(locked_server + "/api/overview", headers={"Cookie": session})
    assert code == 200 and json.loads(body)["role"] == "admin"
    # a tampered cookie is rejected: a changed signature, and a changed role
    # under the original signature. (Always flip the last digit — overwriting
    # it with a constant left the cookie unchanged one run in 256.)
    forged = session[:-1] + ("0" if session[-1] != "0" else "1")
    code, _, _ = _req(locked_server + "/api/overview", headers={"Cookie": forged})
    assert code == 401
    code, _, _ = _req(locked_server + "/api/overview",
                      headers={"Cookie": session.replace("admin.", "viewer.", 1)})
    assert code == 401


def test_login_is_rate_limited(locked_server):
    codes = [_req(locked_server + "/login", "POST", json.dumps({"token": f"g{i}"}).encode(),
                  {"Content-Type": "application/json"})[0] for i in range(12)]
    assert codes[:10] == [401] * 10 and codes[-1] == 429


def test_cross_origin_post_is_refused(open_server):
    code, _, _ = _req(open_server + "/api/notifications/read", "POST", b"{}",
                      {"Origin": "https://evil.example.com", "Content-Type": "application/json"})
    assert code == 403
    code, _, _ = _req(open_server + "/api/notifications/read", "POST", b"{}",
                      {"Origin": "null", "Content-Type": "application/json"})
    assert code == 403


def test_session_helpers_are_pure():
    a = webauth.AuthConfig(admin_token="A" * 20, viewer_token="V" * 20)
    s = a.make_session("viewer", now=1000)
    assert a.role_for_session(s, now=1000) == "viewer"
    assert a.role_for_session(s, now=1000 + webauth.SESSION_TTL_S + 1) is None    # expired
    assert webauth.AuthConfig(admin_token="other").role_for_session(s, now=1000) is None
    assert a.role_for_token("A" * 20) == "admin" and a.role_for_token("") is None
    assert webauth.is_loopback_bind("127.0.0.1") and webauth.is_loopback_bind("::1")
    assert not webauth.is_loopback_bind("0.0.0.0") and not webauth.is_loopback_bind("10.0.0.5")


def test_non_loopback_bind_always_gets_a_token(tmp_path):
    ac = webauth.resolve(Cfg(tmp_path), "0.0.0.0", tmp_path)
    assert ac.required and ac.generated and len(ac.admin_token) >= 32
    assert (tmp_path / webauth.TOKEN_FILE).read_text().strip() == ac.admin_token
    again = webauth.resolve(Cfg(tmp_path), "0.0.0.0", tmp_path)          # stable across restarts
    assert again.admin_token == ac.admin_token
    assert not webauth.resolve(Cfg(tmp_path), "127.0.0.1", tmp_path).required


# ---------------- fleet v2 over real HTTP ----------------

def _report(node_id="web-01", ts=None):
    return {"node_id": node_id, "hostname": node_id, "wrench_version": "3.0.0",
            "ts": ts if ts is not None else time.time(), "status": "ok",
            "worst_severity": "ok", "cadence_s": 900, "summary": "all clear",
            "findings": [], "gauges": {"mem_pct": 41.0, "disk_pct": {"/": 55.0}},
            "meta": {"os": "linux", "os_label": "Ubuntu 24.04", "score": 91.0, "grade": "A",
                     "tags": ["prod"]}}


@pytest.fixture
def hub(tmp_path):
    httpd, url = _serve(tmp_path, fleet_hub=True)
    store = Store(tmp_path / "w.db")
    yield url, store
    store.close()
    httpd.shutdown()


def _push(url, token, report, now=None, node_id=None):
    st = fleet.FleetSettings(hub_url=url, token=token, node_id=node_id or report["node_id"])
    return fleet.push_once(st, report, now=now)


def test_fleet_enroll_join_report_roundtrip(hub):
    url, store = hub
    key = fleet.enroll(store, label="web tier")
    assert key["token"].startswith(fleet.TOKEN_PREFIX)
    ok, detail = _push(url, key["token"], _report())
    assert ok, detail
    code, _, body = _req(url + "/api/fleet/nodes")
    d = json.loads(body)
    assert d["summary"]["total"] == 1 and d["summary"]["avg_score"] == 91.0
    node = d["nodes"][0]
    assert node["node_id"] == "web-01" and node["meta"]["os_label"] == "Ubuntu 24.04"
    assert "token_hash" not in node and "key_id" not in node      # credentials stay on the hub
    # the hub never stored the token itself
    raw_db = (Path(store.path)).read_bytes()
    assert key["token"].encode() not in raw_db


def test_fleet_rejects_forged_and_unknown_keys(hub):
    url, store = hub
    fleet.enroll(store)
    ok, detail = _push(url, fleet.generate_enrollment_token(), _report())
    assert not ok and detail.startswith("HTTP 401")
    ok, detail = _push(url, "legacy-token-nobody-authorized", _report())
    assert not ok and detail.startswith("HTTP 401")


def test_fleet_rejects_replay_and_stale_clock(hub):
    url, store = hub
    key = fleet.enroll(store)
    st = fleet.FleetSettings(hub_url=url, token=key["token"], node_id="web-01")
    body = fleet.report_bytes(_report())
    headers = fleet.signed_headers(st, body, "web-01")
    code, _, _ = _req(url + fleet.REPORT_PATH, "POST", body, headers)
    assert code == 200
    # byte-for-byte replay of a captured request: refused
    code, _, out = _req(url + fleet.REPORT_PATH, "POST", body, headers)
    assert code == 409 and b"replay" in out
    # a validly signed report from a clock 2 hours off: refused
    ok, detail = _push(url, key["token"], _report(), now=time.time() - 7200)
    assert not ok and "HTTP 401" in detail and "clock" in detail
    # tampering with the signed timestamp breaks the signature
    bad = dict(headers)
    bad[fleet.TS_HEADER] = f"{time.time() + 5:.3f}"
    code, _, _ = _req(url + fleet.REPORT_PATH, "POST", body, bad)
    assert code == 401


def test_fleet_node_id_is_bound_to_its_key(hub):
    url, store = hub
    a, b = fleet.enroll(store, label="a"), fleet.enroll(store, label="b")
    assert _push(url, a["token"], _report("db-01"))[0]
    # a different (valid) key cannot overwrite db-01's row
    ok, detail = _push(url, b["token"], _report("db-01"))
    assert not ok and detail.startswith("HTTP 409")
    assert store.get_fleet_node("db-01")["key_id"] == a["key_id"]


def test_fleet_single_node_key_and_revocation(hub):
    url, store = hub
    key = fleet.enroll(store, single_node=True)
    assert _push(url, key["token"], _report("only-one"))[0]
    ok, detail = _push(url, key["token"], _report("second"))
    assert not ok and "HTTP 403" in detail
    assert store.revoke_fleet_key(key["key_id"], time.time())
    ok, detail = _push(url, key["token"], _report("only-one"))
    assert not ok and "HTTP 403" in detail and "revoked" in detail
    assert fleet.is_permanent_rejection(detail)        # the node will not queue + retry this


def test_fleet_csv_export_neutralizes_formulas(hub):
    url, store = hub
    key = fleet.enroll(store)
    r = _report("calc")
    r["findings"] = [{"severity": "critical", "text": "=HYPERLINK(\"http://evil\")"}]
    assert _push(url, key["token"], r)[0]
    code, h, body = _req(url + "/api/fleet/export.csv")
    assert code == 200 and "text/csv" in h["Content-Type"]
    assert b"'=HYPERLINK" in body and b",=HYPERLINK" not in body


def test_fleet_forget_and_oversize_report(hub):
    url, store = hub
    key = fleet.enroll(store)
    assert _push(url, key["token"], _report("gone"))[0]
    code, _, _ = _req(url + "/api/fleet/forget", "POST",
                      json.dumps({"node_id": "gone"}).encode(),
                      {"Content-Type": "application/json"})
    assert code == 200 and store.get_fleet_node("gone") is None
    code, _, _ = _req(url + fleet.REPORT_PATH, "POST", b"x" * (fleet.MAX_REPORT_BYTES + 1),
                      {"Content-Type": "application/json"})
    assert code == 413


def test_legacy_v1_token_still_reports(tmp_path):
    httpd, url = _serve(tmp_path, raw={"fleet": {"authorized_tokens": ["old-shared-token"]}})
    try:
        ok, detail = _push(url, "old-shared-token", _report("legacy-node"))
        assert ok, detail
        # …and gets the same replay protection from the ts inside the signed body
        st = fleet.FleetSettings(hub_url=url, token="old-shared-token")
        body = fleet.report_bytes(_report("legacy-2", ts=time.time()))
        hdrs = fleet.signed_headers(st, body, "legacy-2")
        assert _req(url + fleet.REPORT_PATH, "POST", body, hdrs)[0] == 200
        assert _req(url + fleet.REPORT_PATH, "POST", body, hdrs)[0] == 409
    finally:
        httpd.shutdown()


# ---------------- regressions from the independent review ----------------

def _raw(url, payload: bytes) -> bytes:
    import socket
    host, port = url.split("//")[1].split(":")
    with socket.create_connection((host, int(port)), timeout=10) as s:
        s.sendall(payload)
        s.settimeout(3)
        out = b""
        try:
            while chunk := s.recv(65536):
                out += chunk
        except OSError:
            pass
    return out


def test_unread_post_body_cannot_smuggle_a_second_request(open_server):
    smuggled = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
    req = (b"POST /nope HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
           b"Content-Length: " + str(len(smuggled)).encode() + b"\r\n\r\n" + smuggled)
    out = _raw(open_server, req)
    assert out.count(b"HTTP/1.1 ") == 1 and b"Connection: close" in out
    assert b'"ok": true' not in out


def test_chunked_bodies_are_refused(open_server):
    out = _raw(open_server, b"POST /api/chat HTTP/1.1\r\nHost: localhost\r\n"
                            b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 411") and out.count(b"HTTP/1.1 ") == 1


def test_malformed_credentials_are_a_clean_401(locked_server):
    out = _raw(locked_server, b"GET /api/overview HTTP/1.1\r\nHost: localhost\r\n"
                              b"Cookie: wrench_session=admin.999.\xe9\r\nConnection: close\r\n\r\n")
    assert out.startswith(b"HTTP/1.1 401")


def test_web_chat_is_pinned_to_suggest_even_when_autonomous(tmp_path, monkeypatch):
    seen = {}

    class FakeAgent:
        def __init__(self, cfg, store, **kw):
            seen["tier"] = cfg.policy_tier
            seen["confirm"] = kw.get("confirm_fn")

        def run(self, goal, **kw):
            return {"answer": "ok", "steps": [], "tokens": 1}

    import wrench.agent as agent_mod
    monkeypatch.setattr(agent_mod, "Agent", FakeAgent)

    class Auto(Cfg):
        provider = "ollama"
        model = "m"
        base_url = "http://127.0.0.1:11434/v1"
        policy_tier = "autonomous"

    db = tmp_path / "w.db"
    Store(db).close()
    cfg = Auto(tmp_path)
    httpd = webapp.serve(db, port=0, bind="127.0.0.1", sample_thread=False, cfg=cfg)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}"
        code, _, _ = _req(url + "/api/chat", "POST", json.dumps({"message": "hi"}).encode(),
                          {"Content-Type": "application/json"})
        assert code == 200 and seen["tier"] == "suggest"
        assert cfg.policy_tier == "autonomous"            # the real config is untouched
    finally:
        httpd.shutdown()


def test_login_page_redirect_is_same_origin_only():
    page = (webapp.WEB_DIR / "login.html").read_text()
    assert "u.origin === location.origin" in page and "startsWith('/')" not in page
