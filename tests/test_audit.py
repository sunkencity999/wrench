"""wrench audit — tamper-evident hash chain.

Pure-chain coverage plus on-disk append/verify: genesis seeding, chain growth,
and tamper detection (bit-flip a middle record → verify points at the exact
first broken link). No host state touched.
"""

from __future__ import annotations

import json


from wrench import audit


# ---------------- pure primitives ----------------

def test_canonical_ignores_hash_key_and_is_stable():
    rec = {"ts": 1.0, "actor": "me", "kind": "k", "detail": {"b": 2, "a": 1},
           "prev_hash": "x", "hash": "SHOULD-NOT-MATTER"}
    c1 = audit.canonical(rec)
    rec2 = dict(rec)
    rec2["hash"] = "totally-different"
    assert audit.canonical(rec2) == c1
    # sorted keys → deterministic regardless of detail insertion order
    assert '"a":1' in c1 and '"b":2' in c1


def test_record_hash_changes_with_any_field():
    base = audit.make_record(audit.GENESIS_PREV, "apply", {"x": 1}, actor="a", ts=1.0)
    other = audit.make_record(audit.GENESIS_PREV, "apply", {"x": 2}, actor="a", ts=1.0)
    assert base["hash"] != other["hash"]
    # same inputs → same hash (deterministic)
    again = audit.make_record(audit.GENESIS_PREV, "apply", {"x": 1}, actor="a", ts=1.0)
    assert again["hash"] == base["hash"]


def test_verify_records_empty_is_intact():
    out = audit.verify_records([])
    assert out["intact"] and out["count"] == 0 and out["broken_index"] is None


def test_verify_records_good_chain():
    recs = []
    prev = audit.GENESIS_PREV
    for i in range(5):
        r = audit.make_record(prev, f"k{i}", {"i": i}, actor="t", ts=float(i))
        recs.append(r)
        prev = r["hash"]
    out = audit.verify_records(recs)
    assert out["intact"] and out["count"] == 5


def test_verify_records_detects_altered_detail():
    recs = []
    prev = audit.GENESIS_PREV
    for i in range(4):
        r = audit.make_record(prev, f"k{i}", {"i": i}, actor="t", ts=float(i))
        recs.append(r)
        prev = r["hash"]
    # bit-flip the middle record's detail, leave its stored hash intact
    recs[2]["detail"] = {"i": 999}
    out = audit.verify_records(recs)
    assert not out["intact"]
    assert out["broken_index"] == 2
    assert "altered" in out["reason"]


def test_verify_records_detects_reorder_removal():
    recs = []
    prev = audit.GENESIS_PREV
    for i in range(4):
        r = audit.make_record(prev, f"k{i}", {"i": i}, actor="t", ts=float(i))
        recs.append(r)
        prev = r["hash"]
    # drop a middle record → the next record's prev_hash no longer matches
    del recs[1]
    out = audit.verify_records(recs)
    assert not out["intact"]
    assert out["broken_index"] == 1
    assert "prev_hash" in out["reason"]


# ---------------- on-disk chain ----------------

def test_first_append_seeds_genesis(tmp_path):
    rec = audit.append(tmp_path, "fixxer:apply", {"ok": True}, actor="tester")
    assert rec is not None and rec["kind"] == "fixxer:apply"
    recs = audit.read_records(tmp_path)
    assert len(recs) == 2  # genesis + the event
    assert recs[0]["kind"] == "genesis"
    assert recs[0]["prev_hash"] == audit.GENESIS_PREV
    assert recs[1]["prev_hash"] == recs[0]["hash"]
    assert audit.verify(tmp_path)["intact"]


def test_multiple_appends_single_genesis(tmp_path):
    for i in range(3):
        audit.append(tmp_path, f"event{i}", {"i": i})
    recs = audit.read_records(tmp_path)
    assert sum(1 for r in recs if r["kind"] == "genesis") == 1
    assert len(recs) == 4  # 1 genesis + 3 events
    assert audit.verify(tmp_path)["intact"]
    assert audit.last_hash(tmp_path) == recs[-1]["hash"]


def test_recent_returns_tail(tmp_path):
    for i in range(10):
        audit.append(tmp_path, f"e{i}", {"i": i})
    tail = audit.recent(tmp_path, limit=3)
    assert len(tail) == 3
    assert tail[-1]["kind"] == "e9"


def test_ondisk_tamper_detected_with_exact_index(tmp_path):
    for i in range(5):
        audit.append(tmp_path, f"e{i}", {"n": i})
    p = audit.audit_path(tmp_path)
    lines = p.read_text().splitlines()
    # tamper with a middle record (index 2 overall = genesis + e0 + [e1])
    victim = json.loads(lines[2])
    victim["detail"] = {"n": 4242}
    lines[2] = json.dumps(victim)
    p.write_text("\n".join(lines) + "\n")
    out = audit.verify(tmp_path)
    assert not out["intact"]
    assert out["broken_index"] == 2


def test_malformed_line_breaks_verify(tmp_path):
    audit.append(tmp_path, "e0", {})
    p = audit.audit_path(tmp_path)
    p.write_text(p.read_text() + "this is not json\n")
    out = audit.verify(tmp_path)
    assert not out["intact"]
    assert "malformed" in out["reason"]


def test_should_audit_action_skips_diag():
    assert audit.should_audit_action("fixxer:disk-clean")
    assert audit.should_audit_action("certs:renew:exec")
    assert audit.should_audit_action("blueprint:apply")
    assert not audit.should_audit_action("diag:journal")
    assert not audit.should_audit_action("diag:service")


def test_default_actor_env_override(monkeypatch):
    monkeypatch.setenv("WRENCH_ACTOR", "ci-bot")
    assert audit.default_actor() == "ci-bot"


# ---------------- store.add_action choke-point integration ----------------

def test_store_add_action_seals_consequential_events(tmp_path):
    from wrench.store import Store
    s = Store(tmp_path / "wrench.db")
    try:
        s.add_action("repair", "fixxer:disk-clean", "rm -rf /x", True, "ok")
        s.add_action("suggest", "certs:renew:exec", "certbot renew", True, "renewed")
        s.add_action("any", "diag:journal", "journalctl -u foo", True, "read")
    finally:
        s.close()
    recs = audit.read_records(tmp_path)
    kinds = [r["kind"] for r in recs]
    # genesis + 2 consequential; diag:* is skipped
    assert kinds == ["genesis", "fixxer:disk-clean", "certs:renew:exec"]
    assert audit.verify(tmp_path)["intact"]
    # the sealed detail carries the consent decision
    assert recs[1]["detail"]["approved"] is True


def test_store_add_action_records_denials(tmp_path):
    from wrench.store import Store
    s = Store(tmp_path / "wrench.db")
    try:
        s.add_action("repair", "fix-denied", "rm -rf /", False, "policy denied")
    finally:
        s.close()
    recs = audit.recent(tmp_path, 10)
    assert recs[-1]["kind"] == "fix-denied"
    assert recs[-1]["detail"]["approved"] is False
