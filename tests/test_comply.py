"""Compliance packs — engine primitives, pack loading, scoring, patrol, CLI."""

from __future__ import annotations

import json
import time

import pytest

from wrench import comply as cm
from wrench.comply import Rule


# ---- fixtures ----------------------------------------------------------------


def _rule(check: dict, sev: str = "medium", rid: str = "t.rule") -> Rule:
    return Rule(id=rid, title="t", severity=sev, rationale="r", check=check)


# ---- file_mode / file_owner ---------------------------------------------------


def test_file_mode_pass_and_fail(tmp_path):
    f = tmp_path / "f"
    f.write_text("x")
    f.chmod(0o640)
    assert cm.run_rule(_rule({"kind": "file_mode", "path": str(f),
                              "max_mode": "0644"})).status == "pass"
    f.chmod(0o666)
    r = cm.run_rule(_rule({"kind": "file_mode", "path": str(f),
                           "max_mode": "0644"}))
    assert r.status == "fail" and "0o666" in r.detail


def test_file_mode_missing_is_skip_or_ok(tmp_path):
    gone = str(tmp_path / "gone")
    assert cm.run_rule(_rule({"kind": "file_mode", "path": gone,
                              "max_mode": "0644"})).status == "skip"
    assert cm.run_rule(_rule({"kind": "file_mode", "path": gone,
                              "max_mode": "0644",
                              "missing_ok": True})).status == "pass"


def test_file_owner(tmp_path):
    import pwd
    me = pwd.getpwuid(__import__("os").getuid()).pw_name
    f = tmp_path / "f"
    f.write_text("x")
    assert cm.run_rule(_rule({"kind": "file_owner", "path": str(f),
                              "owner": me})).status == "pass"
    assert cm.run_rule(_rule({"kind": "file_owner", "path": str(f),
                              "owner": "root"})).status == "fail"


# ---- file_contains ------------------------------------------------------------


def test_file_contains_regex_and_comments(tmp_path):
    f = tmp_path / "conf"
    f.write_text("# MaxAuthTries 2\nMaxAuthTries 3\n")
    assert cm.run_rule(_rule({"kind": "file_contains", "path": str(f),
                              "regex": r"^MaxAuthTries\s+[1-4]$"})).status == "pass"
    f.write_text("# only a comment MaxAuthTries 3\n")
    assert cm.run_rule(_rule({"kind": "file_contains", "path": str(f),
                              "regex": r"^MaxAuthTries\s+[1-4]$"})).status == "fail"


def test_file_contains_absent(tmp_path):
    f = tmp_path / "conf"
    f.write_text("GoodKey yes\n")
    assert cm.run_rule(_rule({"kind": "file_contains", "path": str(f),
                              "regex": "BadKey", "absent": True})).status == "pass"
    f.write_text("BadKey on\n")
    assert cm.run_rule(_rule({"kind": "file_contains", "path": str(f),
                              "regex": "BadKey", "absent": True})).status == "fail"


def test_file_contains_unreadable_is_skip(tmp_path):
    assert cm.run_rule(_rule({"kind": "file_contains",
                              "path": str(tmp_path / "gone"),
                              "regex": "x"})).status == "skip"


# ---- sshd_config --------------------------------------------------------------


def test_sshd_first_wins_and_match_scope(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text("PermitRootLogin no\n"
                 "PermitRootLogin yes\n"       # first wins
                 "Match User git\n"
                 "PasswordAuthentication yes\n")  # inside Match: ignored
    r = cm.run_rule(_rule({"kind": "sshd_config", "path": str(f),
                           "key": "PermitRootLogin", "value": "no"}))
    assert r.status == "pass"
    # PasswordAuthentication only set inside Match => falls to default
    r2 = cm.run_rule(_rule({"kind": "sshd_config", "path": str(f),
                            "key": "PasswordAuthentication", "value": "no",
                            "default": "yes"}))
    assert r2.status == "fail" and "yes" in r2.detail


def test_sshd_default_when_unset(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text("Port 22\n")
    assert cm.run_rule(_rule({"kind": "sshd_config", "path": str(f),
                              "key": "PermitEmptyPasswords", "value": "no",
                              "default": "no"})).status == "pass"
    assert cm.run_rule(_rule({"kind": "sshd_config", "path": str(f),
                              "key": "PermitRootLogin",
                              "value": "no"})).status == "fail"  # no default


# ---- sysctl / login_defs ------------------------------------------------------


@pytest.fixture(autouse=True)
def _fake_sysctl_tree(monkeypatch, tmp_path_factory):
    """A tiny /proc/sys stand-in so sysctl rules behave the same on every OS."""
    root = tmp_path_factory.mktemp("procsys")
    (root / "kernel").mkdir()
    (root / "kernel" / "pid_max").write_text("4194304\n")
    monkeypatch.setattr(cm, "_SYSCTL_ROOT", str(root))


def test_sysctl_live_read():
    # kernel.pid_max exists everywhere; just prove the read path works
    r = cm.run_rule(_rule({"kind": "sysctl", "key": "kernel.pid_max",
                           "value": "definitely-not-this"}))
    assert r.status == "fail" and "kernel.pid_max" in r.detail
    missing = cm.run_rule(_rule({"kind": "sysctl",
                                 "key": "kernel.no_such_knob_xyz",
                                 "value": "1"}))
    assert missing.status == "skip"


def test_login_defs_ops(tmp_path):
    f = tmp_path / "login.defs"
    f.write_text("# comment\nPASS_MAX_DAYS 99999\nUMASK 022\n")
    assert cm.run_rule(_rule({"kind": "login_defs", "path": str(f),
                              "key": "PASS_MAX_DAYS", "op": "max",
                              "value": 365})).status == "fail"
    f.write_text("PASS_MAX_DAYS 180\nUMASK 027\n")
    assert cm.run_rule(_rule({"kind": "login_defs", "path": str(f),
                              "key": "PASS_MAX_DAYS", "op": "max",
                              "value": 365})).status == "pass"
    assert cm.run_rule(_rule({"kind": "login_defs", "path": str(f),
                              "key": "UMASK", "op": "min",
                              "value": "0o027"})).status == "pass"
    assert cm.run_rule(_rule({"kind": "login_defs", "path": str(f),
                              "key": "NOPE", "op": "max",
                              "value": 1})).status == "fail"


# ---- passwd/shadow checks ------------------------------------------------------


def test_single_uid0(monkeypatch, tmp_path):
    def fake_read(path):
        if path == "/etc/passwd":
            return ("root:x:0:0::/root:/bin/bash\n"
                    "evil:x:0:0::/root:/bin/bash\n"
                    "bob:x:1000:1000::/home/bob:/bin/bash\n"), ""
        return None, "nope"

    monkeypatch.setattr(cm, "_read", fake_read)
    r = cm.run_rule(_rule({"kind": "single_uid0"}))
    assert r.status == "fail" and "evil" in r.detail


def test_no_empty_passwords(monkeypatch):
    monkeypatch.setattr(cm, "_read",
                        lambda p: ("root:$6$x:19000::::::\nbad::19000::::::\n", ""))
    r = cm.run_rule(_rule({"kind": "no_empty_passwords"}))
    assert r.status == "fail" and "bad" in r.detail
    monkeypatch.setattr(cm, "_read", lambda p: (None, "unreadable without root"))
    assert cm.run_rule(_rule({"kind": "no_empty_passwords"})).status == "skip"


# ---- mount_option --------------------------------------------------------------


def test_mount_option(monkeypatch):
    monkeypatch.setattr(
        cm, "_read",
        lambda p: ("tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n", ""))
    assert cm.run_rule(_rule({"kind": "mount_option", "mountpoint": "/tmp",
                              "option": "nosuid"})).status == "pass"
    assert cm.run_rule(_rule({"kind": "mount_option", "mountpoint": "/tmp",
                              "option": "noexec"})).status == "fail"
    assert cm.run_rule(_rule({"kind": "mount_option", "mountpoint": "/xyz",
                              "option": "nodev"})).status == "skip"
    assert cm.run_rule(_rule({"kind": "mount_option", "mountpoint": "/xyz",
                              "option": "nodev",
                              "missing_ok": True})).status == "pass"


# ---- broken checks never crash --------------------------------------------------


def test_broken_check_is_skip():
    r = cm.run_rule(_rule({"kind": "file_mode"}))   # missing path key
    assert r.status == "skip" and "check error" in r.detail


# ---- pack loading ---------------------------------------------------------------


def test_shipped_packs_load_and_validate():
    packs = cm.list_packs()
    names = {p.name for p in packs}
    assert {"cis-ubuntu-essentials", "wrench-baseline"} <= names
    for p in packs:
        assert len(p.rules) > 0
        for r in p.rules:
            r.validate()   # raises on any bad rule


def test_load_pack_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(cm, "_PACK_DIR", tmp_path)
    with pytest.raises(ValueError, match="unknown pack"):
        cm.load_pack("nope")
    (tmp_path / "bad.json").write_text("{not json")
    with pytest.raises(ValueError, match="invalid JSON"):
        cm.load_pack("bad")
    (tmp_path / "nokey.json").write_text(json.dumps({"name": "nokey"}))
    with pytest.raises(ValueError, match="missing"):
        cm.load_pack("nokey")
    (tmp_path / "dup.json").write_text(json.dumps({
        "name": "dup", "title": "t", "rules": [
            {"id": "a", "title": "x", "severity": "low", "rationale": "",
             "check": {"kind": "single_uid0"}},
            {"id": "a", "title": "y", "severity": "low", "rationale": "",
             "check": {"kind": "single_uid0"}}]}))
    with pytest.raises(ValueError, match="duplicate"):
        cm.load_pack("dup")
    with pytest.raises(ValueError, match="bad pack name"):
        cm.load_pack("../etc/passwd")


def test_rule_validation_errors():
    with pytest.raises(ValueError, match="bad severity"):
        _rule({"kind": "single_uid0"}, sev="whatever").validate()
    with pytest.raises(ValueError, match="unknown check kind"):
        _rule({"kind": "rm -rf"}).validate()
    with pytest.raises(ValueError, match="bad rule id"):
        Rule(id="BAD ID!", title="t", severity="low", rationale="",
             check={"kind": "single_uid0"}).validate()


# ---- scoring / scan / baseline / patrol -----------------------------------------


class _FakeStore:
    def __init__(self):
        self.snaps = {}

    def add_snapshot(self, kind, payload):
        self.snaps[kind] = (time.time(), payload)

    def last_snapshot(self, kind):
        return self.snaps.get(kind)


def _mini_pack(monkeypatch, tmp_path, rules):
    monkeypatch.setattr(cm, "_PACK_DIR", tmp_path)
    (tmp_path / "mini.json").write_text(json.dumps(
        {"name": "mini", "title": "Mini",
         "platforms": ["linux", "macos", "windows"], "rules": rules}))


def test_scoring_ignores_skips(monkeypatch, tmp_path):
    _mini_pack(monkeypatch, tmp_path, [
        {"id": "p1", "title": "passes", "severity": "low", "rationale": "",
         "check": {"kind": "single_uid0"}},
        {"id": "f1", "title": "fails", "severity": "critical", "rationale": "",
         "check": {"kind": "sysctl", "key": "kernel.pid_max",
                   "value": "not-this"}},
        {"id": "s1", "title": "skips", "severity": "high", "rationale": "",
         "check": {"kind": "sysctl", "key": "kernel.nope_xyz", "value": "1"}},
    ])
    rep = cm.run_pack(cm.load_pack("mini"))
    assert rep["counts"] == {"pass": 1, "fail": 1, "skip": 1}
    assert rep["score"] == 50.0                 # skip excluded from grading
    assert rep["severity_fails"]["critical"] == 1


def test_scan_persists_slim_snapshot(monkeypatch, tmp_path):
    _mini_pack(monkeypatch, tmp_path, [
        {"id": "f1", "title": "fails", "severity": "high", "rationale": "",
         "check": {"kind": "sysctl", "key": "kernel.pid_max",
                   "value": "not-this"}}])
    store = _FakeStore()
    out = cm.scan(store, packs=["mini"])
    assert out["fail_ids"] == ["f1"]
    _, slim = store.snaps[cm.SCAN_KIND]
    assert slim["fails"][0]["id"] == "f1"
    assert "results" not in slim["packs"][0]    # slim, not full


def test_patrol_findings_respect_baseline(monkeypatch, tmp_path):
    store = _FakeStore()
    store.add_snapshot(cm.SCAN_KIND, {
        "packs": [{"pack": "mini", "score": 50.0,
                   "counts": {"pass": 1, "fail": 2, "skip": 0},
                   "severity_fails": {"critical": 1, "high": 1,
                                      "medium": 0, "low": 0}}],
        "fails": [{"id": "old", "title": "known debt", "severity": "high"},
                  {"id": "new", "title": "fresh failure",
                   "severity": "critical"}]})
    # no baseline: both are findings
    out = cm.patrol_findings(None, store)
    assert {f["summary"].split(":")[0] for f in out} == {"old", "new"}
    # baseline accepts "old": only "new" remains, mapped to critical
    store.add_snapshot(cm.BASELINE_KIND, {"fail_ids": ["old"]})
    out2 = cm.patrol_findings(None, store)
    assert len(out2) == 1
    assert out2[0]["severity"] == "critical" and "new" in out2[0]["summary"]
    assert out2[0]["area"] == "comply"


def test_patrol_never_raises():
    class Boom:
        def last_snapshot(self, k):
            raise RuntimeError("gone")

    assert cm.patrol_findings(None, Boom()) == []
    assert cm.patrol_summary_line(None, Boom()) == "comply: unavailable"


def test_patrol_summary_line(monkeypatch):
    store = _FakeStore()
    store.add_snapshot(cm.SCAN_KIND, {
        "packs": [{"pack": "mini", "score": 88.0,
                   "counts": {}, "severity_fails": {}}], "fails": []})
    line = cm.patrol_summary_line(None, store)
    assert "mini 88.0%" in line and "no baseline" in line
    store.add_snapshot(cm.BASELINE_KIND, {"fail_ids": ["a", "b"]})
    assert "baseline 2 accepted" in cm.patrol_summary_line(None, store)


def test_narration_context(monkeypatch, tmp_path):
    _mini_pack(monkeypatch, tmp_path, [
        {"id": "f1", "title": "fails", "severity": "high", "rationale": "",
         "check": {"kind": "sysctl", "key": "kernel.pid_max",
                   "value": "not-this"}}])
    report = cm.scan(None, packs=["mini"])
    txt = cm.narration_context(report)
    assert "FAIL [high] f1" in txt and "score" in txt


# ---- CLI ------------------------------------------------------------------------


def _cli(tmp_path, *args):
    import subprocess
    import sys
    import os
    env = dict(os.environ, WRENCH_DATA_DIR=str(tmp_path))
    return subprocess.run([sys.executable, "-m", "wrench.cli", *args],
                          capture_output=True, text=True, env=env, timeout=120)


def test_cli_comply_json_envelope(tmp_path):
    r = _cli(tmp_path, "comply", "--pack", "wrench-baseline", "--json")
    data = json.loads(r.stdout)
    assert data["schema"] == "wrench.comply.v1"
    assert data["packs"][0]["pack"] == "wrench-baseline"
    assert {"pass", "fail", "skip"} >= {x["status"] for x in data["results"]}
    # exit code: 0 unless a critical fails (this box has none as of authoring)
    assert r.returncode == (1 if data["critical_fails"] else 0)


def test_cli_comply_unknown_pack(tmp_path):
    r = _cli(tmp_path, "comply", "--pack", "nope")
    assert r.returncode == 2
    assert "unknown pack" in r.stdout + r.stderr


def test_cli_comply_show(tmp_path):
    r = _cli(tmp_path, "comply", "show", "wb.singleuid0")
    assert r.returncode == 0
    assert "UID-0" in r.stdout
    r2 = _cli(tmp_path, "comply", "show", "no.such.rule")
    assert r2.returncode == 2


def test_cli_comply_accept_and_metrics(tmp_path):
    r = _cli(tmp_path, "comply", "accept", "--yes")
    assert r.returncode == 0 and "baseline accepted" in r.stdout
    # audit chain sealed
    ra = _cli(tmp_path, "audit", "--json")
    audit = json.loads(ra.stdout)
    kinds = [e.get("kind") for e in audit["entries"]]
    assert "comply.baseline.accept" in kinds and audit["intact"]
    # metrics expose score + baseline flag
    from wrench.metrics import render
    from wrench.store import Store
    store = Store(tmp_path / "wrench.db")
    text = render(store, tmp_path)
    assert 'wrench_comply_score{pack="' in text    # whichever pack applies to this OS
    assert "wrench_comply_baseline_accepted 1" in text
    store.close()
