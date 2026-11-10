"""wrench approvals — async out-of-band approval token lifecycle.

create \u2192 approve \u2192 claim, plus expiry and single-use reuse-rejection, plus the
webhook payload shape and the fail-soft POST. Clock injected; no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from wrench import approvals as ap
from wrench.store import Store


@dataclass
class FakeCfg:
    raw: dict = field(default_factory=dict)
    data_dir: object = None


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "wrench.db")
    yield s
    s.close()


def test_settings_default_off():
    st = ap.settings_from(FakeCfg())
    assert not st.enabled and st.ttl_s >= 60


def test_settings_enabled_when_url_set():
    st = ap.settings_from(FakeCfg(raw={"approvals": {
        "approval_webhook_url": "https://h/x", "ttl_minutes": 5}}))
    assert st.enabled and st.ttl_s == 300


def test_create_pending_stores_hash_not_plaintext(store):
    token, rec = ap.create_pending(store, "fixxer apply", "3 findings",
                                   ttl_s=100, now=1000.0)
    assert rec["action"] == "fixxer apply"
    row = store.get_approval(ap.hash_token(token))
    assert row is not None
    assert row["approved"] is False and row["claimed"] is False
    # plaintext token must not appear anywhere in the stored row
    assert token not in str(row)


def test_approve_then_claim(store):
    token, _ = ap.create_pending(store, "blueprint --execute", "d", ttl_s=100, now=1000.0)
    assert not ap.is_approved(store, "blueprint --execute", now=1001.0)
    res = ap.approve(store, token, now=1001.0)
    assert res["status"] == "approved" and res["action"] == "blueprint --execute"
    assert ap.is_approved(store, "blueprint --execute", now=1002.0)
    # claim consumes it (single execution)
    assert ap.claim_approval(store, "blueprint --execute", now=1003.0)
    assert not ap.is_approved(store, "blueprint --execute", now=1004.0)
    assert not ap.claim_approval(store, "blueprint --execute", now=1005.0)


def test_approve_unknown_token(store):
    res = ap.approve(store, "nope-not-real", now=1000.0)
    assert res["status"] == "not_found"


def test_approve_expired(store):
    token, _ = ap.create_pending(store, "certs renew --execute", "d",
                                 ttl_s=10, now=1000.0)
    res = ap.approve(store, token, now=2000.0)  # well past expiry
    assert res["status"] == "expired"
    assert not ap.is_approved(store, "certs renew --execute", now=2001.0)


def test_reuse_rejected(store):
    token, _ = ap.create_pending(store, "fixxer apply", "d", ttl_s=1000, now=1000.0)
    assert ap.approve(store, token, now=1001.0)["status"] == "approved"
    # second approve of the same token is rejected (single-use)
    assert ap.approve(store, token, now=1002.0)["status"] == "already_used"


def test_claim_requires_prior_approval(store):
    ap.create_pending(store, "fixxer apply", "d", ttl_s=1000, now=1000.0)
    # never approved → cannot claim
    assert not ap.claim_approval(store, "fixxer apply", now=1001.0)


def test_webhook_payload_shape():
    pay = ap.webhook_payload("blueprint --execute", "harden sshd", "tok123", 1234.0)
    assert pay["type"] == "wrench.approval.request"
    assert pay["action"] == "blueprint --execute"
    assert pay["token"] == "tok123"
    assert pay["expiry"] == 1234.0
    assert "wrench approve tok123" in pay["instructions"]


def test_post_webhook_failsoft():
    def boom(*a, **k):
        raise OSError("network down")
    assert ap.post_webhook("https://h/x", {"a": 1}, opener=boom) is False
    assert ap.post_webhook("", {"a": 1}) is False  # no url → False, no raise


def test_create_and_notify_uses_settings(store):
    captured = {}

    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def opener(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = req.data
        return Resp()

    cfg = FakeCfg(raw={"approvals": {"approval_webhook_url": "https://h/approve",
                                     "ttl_minutes": 30}})
    token, posted = ap.create_and_notify(cfg, store, "fixxer apply", "2 findings",
                                         now=1000.0, opener=opener)
    assert posted is True
    assert captured["url"] == "https://h/approve"
    assert token.encode() in captured["body"]
    # a pending row exists, TTL honored (30 min)
    row = store.get_approval(ap.hash_token(token))
    assert row["expires"] == pytest.approx(1000.0 + 1800.0)


# ---------------- CLI gate wiring ----------------

def test_approval_gate_noop_when_disabled(tmp_path, store):
    from wrench import cli
    cfg = FakeCfg(raw={}, data_dir=tmp_path)
    # approvals off → returns without raising, even if stdin is non-tty
    cli._approval_gate(cfg, store, "fixxer apply", "d")


def test_approval_gate_creates_pending_and_exits(tmp_path, store, monkeypatch):
    import typer
    from wrench import cli, approvals, audit
    cfg = FakeCfg(raw={"approvals": {"approval_webhook_url": "https://h/x"}},
                  data_dir=tmp_path)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(approvals, "post_webhook", lambda *a, **k: True)
    with pytest.raises(typer.Exit) as ei:
        cli._approval_gate(cfg, store, "fixxer apply", "2 findings")
    assert ei.value.exit_code == 0
    # a pending approval was recorded + an audit event sealed
    assert len(store.recent_approvals(10)) == 1
    assert any(r["kind"] == "approval.requested" for r in audit.recent(tmp_path, 10))


def test_approval_gate_claims_when_approved(tmp_path, store, monkeypatch):
    from wrench import cli, approvals, audit
    cfg = FakeCfg(raw={"approvals": {"approval_webhook_url": "https://h/x"}},
                  data_dir=tmp_path)
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    key = approvals.bound_action("fixxer apply", "d")   # approvals bind to the request
    token, _ = approvals.create_pending(store, key, "d")  # real clock
    approvals.approve(store, token)
    # an approval for a DIFFERENT request detail must not be claimable
    assert approvals.bound_action("fixxer apply", "other") != key
    # already approved → gate claims and returns (no Exit)
    cli._approval_gate(cfg, store, "fixxer apply", "d")
    assert not approvals.is_approved(store, key)  # consumed
    assert any(r["kind"] == "approval.claimed" for r in audit.recent(tmp_path, 10))
