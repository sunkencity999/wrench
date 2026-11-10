"""The dashboard chat endpoint: same-origin gate, size cap, happy path with a
stubbed agent, and conversation memory."""

from __future__ import annotations

import json
import threading
import urllib.request

import pytest

from wrench import webapp
from wrench.store import Store


class FakeCfg:
    provider = "ollama"            # a keyless provider: the brain counts as configured
    model = "stub-model"
    base_url = "http://127.0.0.1:11434/v1"
    api_key = ""
    policy_tier = "suggest"
    offline = False
    patrol_interval_min = 15
    raw: dict = {}


@pytest.fixture
def server(tmp_path, monkeypatch):
    goals_seen = []

    class FakeAgent:
        def __init__(self, cfg, store, **kw):
            pass

        def run(self, goal, **kw):
            goals_seen.append(goal)
            return {"answer": f"echo: {goal[-30:]}", "steps": [{"tool": "run_diag"}],
                    "tokens": 42}

    import wrench.agent as agent_mod
    monkeypatch.setattr(agent_mod, "Agent", FakeAgent)

    db = tmp_path / "w.db"
    Store(db).close()
    httpd = webapp.serve(db, port=0, bind="127.0.0.1", sample_thread=False, cfg=FakeCfg())
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", goals_seen
    httpd.shutdown()


def _post(url, body: bytes, headers=None):
    req = urllib.request.Request(url + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def test_chat_happy_path_and_memory(server):
    url, goals = server
    code, d = _post(url, json.dumps({"message": "hello wrench"}).encode())
    assert code == 200
    assert d["reply"].startswith("echo:")
    assert d["tokens"] == 42 and d["steps"] == 1 and d["model"] == "stub-model"
    # second turn carries conversation history into the goal
    code, d2 = _post(url, json.dumps({"message": "and again"}).encode())
    assert code == 200
    assert "Conversation so far" in goals[1]
    assert "hello wrench" in goals[1]


def test_chat_rejects_foreign_origin(server):
    url, _ = server
    code, d = _post(url, json.dumps({"message": "hi"}).encode(),
                    headers={"Origin": "https://evil.example.com"})
    assert code == 403


def test_chat_allows_localhost_origin(server):
    url, _ = server
    code, _d = _post(url, json.dumps({"message": "hi"}).encode(),
                     headers={"Origin": url})
    assert code == 200


def test_chat_rejects_oversize_and_bad_json(server):
    url, _ = server
    code, _ = _post(url, b"x" * (webapp.MAX_CHAT_BODY + 1))
    assert code == 413
    code, _ = _post(url, b"{not json")
    assert code == 400
    code, _ = _post(url, json.dumps({"message": "   "}).encode())
    assert code == 400


def test_chat_disabled_without_cfg(tmp_path):
    db = tmp_path / "w.db"
    Store(db).close()
    httpd = webapp.serve(db, port=0, bind="127.0.0.1", sample_thread=False, cfg=None)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    code, d = _post(f"http://127.0.0.1:{port}", json.dumps({"message": "hi"}).encode())
    httpd.shutdown()
    assert code == 503


def test_is_local_origin():
    assert webapp._is_local_origin(None)
    assert webapp._is_local_origin("http://127.0.0.1:8787")
    assert webapp._is_local_origin("http://localhost:1234")
    assert not webapp._is_local_origin("https://evil.example.com")
    assert not webapp._is_local_origin("http://192.168.1.10:8787")


def test_dashboard_serves_chat_ui(server):
    url, _ = server
    with urllib.request.urlopen(url + "/", timeout=10) as r:
        html = r.read().decode()
    assert 'id="chat"' in html and 'id="chat-form"' in html
    assert "Keyboard shortcuts" in html
    assert "I'm wrench" in html
    assert "/api/webintel" in html and "/api/overview" in html
    # templates are fully rendered: no placeholder survives, scripts carry a nonce
    assert "__NONCE__" not in html and "__BASE_" not in html
    assert 'script nonce="' in html
