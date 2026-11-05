"""blueprints: diff parse/apply/rollback with fixture configs, safety rails,
checker dispatch, ceremony gates, drafting protocol, history."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wrench import blueprint as bp


# ---------------- fixtures ----------------

class FakeCfg:
    def __init__(self, root: Path, tier: str = "suggest"):
        self.raw = {"blueprint": {"allowed_roots": [str(root)]}}
        self.policy_tier = tier
        self.data_dir = root / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.model = "fake-model"


class FakeStore:
    def __init__(self):
        self.actions, self.snapshots, self.diffs = [], [], []

    def add_action(self, tier, kind, command, approved, result):
        self.actions.append((tier, kind, command, approved, result))

    def add_snapshot(self, kind, payload):
        self.snapshots.append((kind, payload))

    def add_diff(self, kind, summary, details=None):
        self.diffs.append((kind, summary, details))


class FakeClient:
    """Returns queued responses in order."""
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def chat(self, messages, **kw):
        self.calls.append((messages, kw))
        return self.responses.pop(0)


@pytest.fixture()
def root(tmp_path):
    return tmp_path


@pytest.fixture()
def cfg(root):
    return FakeCfg(root)


def _mkdiff(path: str, old: list[str], new: list[str], start: int = 1) -> str:
    """Tiny unified-diff builder for one contiguous hunk."""
    body = []
    for ln in old:
        body.append("-" + ln)
    for ln in new:
        body.append("+" + ln)
    return (f"--- a{path}\n+++ b{path}\n"
            f"@@ -{start},{len(old)} +{start},{len(new)} @@\n"
            + "\n".join(body) + "\n")


MODIFY_DIFF = """\
--- a{p}
+++ b{p}
@@ -1,3 +1,4 @@
 keep1
-change me
+changed
+added
 keep2
"""

NEW_FILE_DIFF = """\
--- /dev/null
+++ b{p}
@@ -0,0 +1,3 @@
+# managed by wrench blueprint
+daily
+rotate 4
"""


# ---------------- parse ----------------

def test_parse_modify():
    patches = bp.parse_unified_diff(MODIFY_DIFF.format(p="/etc/demo.conf"))
    assert len(patches) == 1
    assert patches[0].path == "/etc/demo.conf"
    assert not patches[0].is_new
    assert len(patches[0].hunks) == 1


def test_parse_new_file():
    patches = bp.parse_unified_diff(NEW_FILE_DIFF.format(p="/etc/logrotate.d/x"))
    assert patches[0].is_new


def test_parse_git_style_headers_and_fences_tolerated():
    text = ("diff --git a/etc/x.conf b/etc/x.conf\nindex 123..456 100644\n"
            + MODIFY_DIFF.format(p="/etc/x.conf"))
    assert bp.parse_unified_diff(text)[0].path == "/etc/x.conf"


def test_parse_refuses_deletion():
    text = "--- a/etc/x.conf\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-gone\n"
    with pytest.raises(bp.BlueprintError, match="deletion"):
        bp.parse_unified_diff(text)


def test_parse_refuses_binary():
    with pytest.raises(bp.BlueprintError, match="binary"):
        bp.parse_unified_diff("Binary files a/x and b/x differ\n")


def test_parse_refuses_oversize():
    big = MODIFY_DIFF.format(p="/etc/x.conf") + "# pad\n" * (bp.MAX_DIFF_BYTES // 6)
    with pytest.raises(bp.BlueprintError, match="size cap"):
        bp.parse_unified_diff(big)


def test_parse_refuses_too_many_files():
    text = "".join(NEW_FILE_DIFF.format(p=f"/etc/f{i}.conf")
                   for i in range(bp.MAX_TARGET_FILES + 1))
    with pytest.raises(bp.BlueprintError, match="cap"):
        bp.parse_unified_diff(text)


def test_parse_rejects_count_mismatch():
    bad = ("--- a/etc/x.conf\n+++ b/etc/x.conf\n@@ -1,5 +1,2 @@\n keep\n-x\n+y\n")
    with pytest.raises(bp.BlueprintError, match="counts"):
        bp.parse_unified_diff(bad)


def test_parse_no_hunks():
    with pytest.raises(bp.BlueprintError, match="no applicable hunks"):
        bp.parse_unified_diff("just some prose\n")


# ---------------- apply ----------------

def test_apply_modify():
    patch = bp.parse_unified_diff(MODIFY_DIFF.format(p="/etc/demo.conf"))[0]
    out = bp.apply_patch_text("keep1\nchange me\nkeep2\n", patch)
    assert out == "keep1\nchanged\nadded\nkeep2\n"


def test_apply_new_file():
    patch = bp.parse_unified_diff(NEW_FILE_DIFF.format(p="/etc/x"))[0]
    assert bp.apply_patch_text("", patch) == "# managed by wrench blueprint\ndaily\nrotate 4\n"


def test_apply_fuzz_offset():
    """Hunk claims line 1 but context actually lives at line 4 — fuzz finds it."""
    patch = bp.parse_unified_diff(MODIFY_DIFF.format(p="/etc/demo.conf"))[0]
    src = "pre1\npre2\npre3\nkeep1\nchange me\nkeep2\n"
    out = bp.apply_patch_text(src, patch)
    assert "changed\nadded" in out and out.startswith("pre1\n")


def test_apply_context_mismatch():
    patch = bp.parse_unified_diff(MODIFY_DIFF.format(p="/etc/demo.conf"))[0]
    with pytest.raises(bp.BlueprintError, match="drifted|context"):
        bp.apply_patch_text("totally\ndifferent\nfile\n", patch)


def test_apply_preserves_no_trailing_newline():
    d = _mkdiff("/etc/x", ["old"], ["new"])
    patch = bp.parse_unified_diff(d)[0]
    assert bp.apply_patch_text("old", patch) == "new"


# ---------------- safety rails ----------------

@pytest.mark.parametrize("path", [
    "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
    "/etc/fstab", "/etc/ssl/private/server.key", "/etc/ssh/ssh_host_ed25519_key",
    "/etc/nginx/tls.pem",
])
def test_denylist(path, cfg):
    cfg.raw = {"blueprint": {"allowed_roots": ["/etc"]}}
    ok, reason = bp.path_allowed(cfg, path)
    assert not ok and "denylist" in reason


def test_sudoers_dropin_allowed_but_direct_denied(cfg):
    cfg.raw = {"blueprint": {"allowed_roots": ["/etc"]}}
    assert bp.path_allowed(cfg, "/etc/sudoers.d/90-wrench")[0]
    assert not bp.path_allowed(cfg, "/etc/sudoers")[0]


def test_allowlist_roots(cfg, root):
    assert bp.path_allowed(cfg, str(root / "app.conf"))[0]
    ok, reason = bp.path_allowed(cfg, "/etc/other.conf")
    assert not ok and "outside allowed roots" in reason


def test_relative_and_traversal_paths_refused(cfg):
    assert not bp.path_allowed(cfg, "etc/x.conf")[0]
    assert not bp.path_allowed(cfg, "/etc/../etc/passwd")[0]


def test_validate_plan_refuses_binary_target(cfg, root):
    tgt = root / "blob.conf"
    tgt.write_bytes(b"abc\x00def")
    d = _mkdiff(str(tgt), ["abc"], ["xyz"])
    with pytest.raises(bp.BlueprintError, match="binary"):
        bp.validate_plan(cfg, "x", d)


def test_validate_plan_missing_file_with_old_side(cfg, root):
    d = _mkdiff(str(root / "ghost.conf"), ["old"], ["new"])
    with pytest.raises(bp.BlueprintError, match="does not exist"):
        bp.validate_plan(cfg, "x", d)


# ---------------- checker dispatch ----------------

@pytest.mark.parametrize("path,checker", [
    ("/etc/ssh/sshd_config", "sshd"),
    ("/etc/ssh/sshd_config.d/50-harden.conf", "sshd"),
    ("/etc/nginx/sites-available/site", "nginx"),
    ("/etc/sudoers.d/90-wrench", "sudoers"),
    ("/etc/sysctl.d/99-tuning.conf", "sysctl"),
    ("/etc/logrotate.d/myapp", "logrotate"),
    ("/etc/fail2ban/jail.d/sshd.local", "fail2ban"),
    ("/etc/systemd/system/foo.service", "systemd"),
    ("/etc/bind/named.conf.options", "named"),
])
def test_checker_dispatch(path, checker):
    spec = bp.checker_for(path)
    assert spec is not None and spec.id == checker


def test_checker_unknown():
    assert bp.checker_for("/etc/someapp/random.ini") is None


def test_sysctl_syntax():
    ok, _ = bp._sysctl_syntax("# c\nnet.ipv4.ip_forward = 1\n\nvm.swappiness=10\n")
    assert ok
    bad, note = bp._sysctl_syntax("this is not sysctl\n")
    assert not bad and "line 1" in note


def test_staged_argv_builders():
    assert bp._sshd_staged("/tmp/s")[:2] == ["sshd", "-t"]
    assert bp._visudo_staged("/tmp/s")[:2] == ["visudo", "-c"]
    assert bp._logrotate_staged("/tmp/s")[0] == "logrotate"


# ---------------- consent gate ----------------

def test_apply_permitted_tiers(cfg, monkeypatch, root):
    monkeypatch.setattr(bp, "consent_path", lambda c: root / "consent.json")
    cfg.policy_tier = "suggest"
    ok, reason = bp.apply_permitted(cfg)
    assert not ok and "consent" in reason
    cfg.policy_tier = "repair"
    assert bp.apply_permitted(cfg)[0]
    cfg.policy_tier = "autonomous"
    assert bp.apply_permitted(cfg)[0]
    cfg.policy_tier = "observe"
    assert not bp.apply_permitted(cfg)[0]


def test_consent_roundtrip(cfg, monkeypatch, root):
    monkeypatch.setattr(bp, "consent_path", lambda c: root / "consent.json")
    assert bp.load_consent(cfg) is None
    bp.write_consent(cfg)
    assert bp.load_consent(cfg)["granted"] is True
    cfg.policy_tier = "suggest"
    assert bp.apply_permitted(cfg)[0]  # consent on record
    assert bp.revoke_consent(cfg)
    assert bp.load_consent(cfg) is None


# ---------------- ceremony ----------------

def _plan_for(cfg, root, name="app.conf", content="keep1\nchange me\nkeep2\n"):
    tgt = root / name
    tgt.write_text(content)
    d = MODIFY_DIFF.format(p=str(tgt))
    return bp.validate_plan(cfg, "test intent", d), tgt


def _no_drift(monkeypatch):
    from wrench import driftscan
    monkeypatch.setattr(driftscan, "scan", lambda store: [])


def test_dry_run_touches_nothing(cfg, root, monkeypatch):
    plan, tgt = _plan_for(cfg, root)
    before = tgt.read_text()
    res = bp.apply_plan(cfg, FakeStore(), plan, execute=False,
                        run=lambda argv, timeout=60: (0, "ok"))
    assert res.ok and "dry-run" in res.message
    assert tgt.read_text() == before
    assert not (cfg.data_dir / bp.BACKUP_DIRNAME).exists()


def test_execute_happy_path(cfg, root, monkeypatch):
    _no_drift(monkeypatch)
    store = FakeStore()
    plan, tgt = _plan_for(cfg, root)
    calls = []

    def run(argv, timeout=60):
        calls.append(argv)
        return 0, "ok"

    res = bp.apply_plan(cfg, store, plan, execute=True, run=run)
    assert res.ok and not res.rolled_back
    assert tgt.read_text() == "keep1\nchanged\nadded\nkeep2\n"
    # backup exists and holds the ORIGINAL content
    bdir = Path(res.backup_dir)
    assert (bdir / "manifest.json").exists()
    backed = bdir / str(tgt).lstrip("/")
    assert backed.read_text() == "keep1\nchange me\nkeep2\n"
    # audit written + drift snapshot labeled
    rows = bp.history(cfg)
    assert rows and rows[-1]["ok"] and rows[-1]["intent"] == "test intent"
    assert store.snapshots and store.snapshots[0][0] == "blueprint"
    assert store.snapshots[0][1]["label"].startswith("blueprint:")
    assert store.actions and store.actions[0][1] == "blueprint:apply"


def test_execute_new_file_then_rollback_removes_it(cfg, root, monkeypatch):
    """live-checker failure on a created file → rollback deletes the file."""
    _no_drift(monkeypatch)
    tgt = root / "nginx" / "site.conf"
    cfg.raw["blueprint"]["allowed_roots"] = [str(root)]
    d = NEW_FILE_DIFF.format(p=str(tgt))
    plan = bp.validate_plan(cfg, "new vhost", d)
    # pretend this path is nginx-checked
    monkeypatch.setattr(bp, "checker_for",
                        lambda p: bp.CheckerSpec("nginx", (str(tgt),),
                                                 live_argv=("nginx", "-t"),
                                                 reload_units=("nginx",)))

    def run(argv, timeout=60):
        if argv[:2] == ["nginx", "-t"]:
            return 1, "nginx: configuration test failed"
        return 0, "ok"

    res = bp.apply_plan(cfg, FakeStore(), plan, execute=True, run=run)
    assert not res.ok and res.rolled_back
    assert not tgt.exists(), "created file must be removed on rollback"
    assert "rejected the applied config" in res.message


def test_execute_staged_check_failure_touches_nothing(cfg, root, monkeypatch):
    plan, tgt = _plan_for(cfg, root)
    before = tgt.read_text()
    monkeypatch.setattr(bp, "checker_for",
                        lambda p: bp.CheckerSpec("sshd", (str(tgt),),
                                                 staged_argv=bp._sshd_staged,
                                                 live_argv=("sshd", "-t")))

    def run(argv, timeout=60):
        if argv[0] == "sshd" and "-f" in argv:
            return 255, "bad config line 3"
        return 0, "ok"

    res = bp.apply_plan(cfg, FakeStore(), plan, execute=True, run=run)
    assert not res.ok and not res.rolled_back  # nothing was written
    assert tgt.read_text() == before
    assert "nothing touched" in res.message


def test_execute_reload_failure_rolls_back(cfg, root, monkeypatch):
    _no_drift(monkeypatch)
    cfg.policy_tier = "repair"
    plan, tgt = _plan_for(cfg, root)
    original = tgt.read_text()
    monkeypatch.setattr(bp, "checker_for",
                        lambda p: bp.CheckerSpec("nginx", (str(tgt),),
                                                 live_argv=("nginx", "-t"),
                                                 reload_units=("nginx",)))

    def run(argv, timeout=60):
        if argv[:2] == ["systemctl", "reload"]:
            return 1, "Job for nginx.service failed"
        return 0, "ok"

    res = bp.apply_plan(cfg, FakeStore(), plan, execute=True, run=run)
    assert not res.ok and res.rolled_back
    assert tgt.read_text() == original
    # a reload is re-attempted after rollback to restore the daemon
    assert any(s.name == "reload_after_rollback" for s in res.steps)


def test_execute_probe_failure_rolls_back(cfg, root, monkeypatch):
    _no_drift(monkeypatch)
    cfg.policy_tier = "repair"
    plan, tgt = _plan_for(cfg, root)
    original = tgt.read_text()
    monkeypatch.setattr(bp, "checker_for",
                        lambda p: bp.CheckerSpec("nginx", (str(tgt),),
                                                 live_argv=("nginx", "-t"),
                                                 reload_units=("nginx",)))
    state = {"reloads": 0}

    def run(argv, timeout=60):
        if argv[:2] == ["systemctl", "reload"]:
            state["reloads"] += 1
            return 0, ""
        if argv[:2] == ["systemctl", "is-active"] and "--quiet" not in argv:
            return 3, "failed"  # health probe fails
        return 0, "ok"

    res = bp.apply_plan(cfg, FakeStore(), plan, execute=True, run=run)
    assert not res.ok and res.rolled_back
    assert tgt.read_text() == original
    assert "unhealthy" in res.message


def test_execute_reload_requires_policy_allowlist(cfg, root, monkeypatch):
    """suggest tier may not reload → apply is rolled back, not half-done."""
    _no_drift(monkeypatch)
    cfg.policy_tier = "suggest"  # ceremony invoked directly (CLI normally gates)
    plan, tgt = _plan_for(cfg, root)
    original = tgt.read_text()
    monkeypatch.setattr(bp, "checker_for",
                        lambda p: bp.CheckerSpec("nginx", (str(tgt),),
                                                 reload_units=("nginx",)))
    res = bp.apply_plan(cfg, FakeStore(), plan, execute=True,
                        run=lambda argv, timeout=60: (0, "ok"))
    assert not res.ok and res.rolled_back
    assert "not permitted at tier" in res.message
    assert tgt.read_text() == original


def test_execute_inactive_unit_skips_reload(cfg, root, monkeypatch):
    _no_drift(monkeypatch)
    cfg.policy_tier = "repair"
    plan, tgt = _plan_for(cfg, root)
    monkeypatch.setattr(bp, "checker_for",
                        lambda p: bp.CheckerSpec("fail2ban", (str(tgt),),
                                                 reload_units=("fail2ban",)))

    def run(argv, timeout=60):
        if argv[:2] == ["systemctl", "is-active"]:
            return 3, "inactive"
        if argv[:2] == ["systemctl", "reload"]:
            raise AssertionError("must not reload an inactive unit")
        return 0, "ok"

    res = bp.apply_plan(cfg, FakeStore(), plan, execute=True, run=run)
    assert res.ok
    assert any("reload skipped" in s.detail for s in res.steps)


def test_drift_detected_between_draft_and_apply(cfg, root):
    plan, tgt = _plan_for(cfg, root)
    tgt.write_text("somebody\nedited\nthis\n")  # drift!
    res = bp.apply_plan(cfg, FakeStore(), plan, execute=True,
                        run=lambda argv, timeout=60: (0, "ok"))
    assert not res.ok and "nothing touched" in res.message


def test_rollback_from_backup_restores(cfg, root, monkeypatch):
    _no_drift(monkeypatch)
    plan, tgt = _plan_for(cfg, root)
    bdir = bp.make_backup(cfg, plan)
    tgt.write_text("clobbered\n")
    notes = bp.rollback_from_backup(bdir)
    assert any("restored" in n for n in notes)
    assert tgt.read_text() == "keep1\nchange me\nkeep2\n"


# ---------------- history ----------------

def test_history_empty(cfg):
    assert bp.history(cfg) == []


def test_history_lists_outcomes(cfg, root, monkeypatch):
    _no_drift(monkeypatch)
    plan, _ = _plan_for(cfg, root)
    bp.apply_plan(cfg, FakeStore(), plan, execute=True,
                  run=lambda argv, timeout=60: (0, "ok"))
    rows = bp.history(cfg)
    assert len(rows) == 1
    assert rows[0]["files"] and rows[0]["digest"] == plan.digest()
    assert isinstance(rows[0]["steps"], list)


def test_history_tolerates_corrupt_lines(cfg):
    p = bp.audit_path(cfg)
    p.write_text('not json\n{"intent": "x", "ok": true}\n')
    rows = bp.history(cfg)
    assert len(rows) == 1 and rows[0]["intent"] == "x"


# ---------------- drafting ----------------

def test_extract_diff_from_fence():
    raw = "Here you go:\n```diff\n--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-a\n+b\n```\nenjoy"
    out = bp._extract_diff(raw)
    assert out.startswith("--- a/x")


def test_extract_diff_rejects_prose():
    with pytest.raises(bp.BlueprintError, match="unified diff"):
        bp._extract_diff("I would suggest changing PermitRootLogin to no.")


def test_draft_happy(cfg, root):
    tgt = root / "sshd.conf"
    tgt.write_text("PermitRootLogin yes\nX11Forwarding yes\n")
    diff = _mkdiff(str(tgt), ["PermitRootLogin yes"], ["PermitRootLogin no"])
    client = FakeClient(f"```diff\n{diff}```")
    plan = bp.draft(cfg, None, "disable root login", targets=[str(tgt)], client=client)
    assert plan.new_contents[str(tgt)].startswith("PermitRootLogin no")
    assert plan.model == "fake-model"


def test_draft_retry_on_bad_context(cfg, root):
    tgt = root / "a.conf"
    tgt.write_text("real line\n")
    bad = _mkdiff(str(tgt), ["imaginary line"], ["new"])
    good = _mkdiff(str(tgt), ["real line"], ["new line"])
    client = FakeClient(bad, good)
    plan = bp.draft(cfg, None, "x", targets=[str(tgt)], client=client)
    assert len(client.calls) == 2
    assert "FAILED VALIDATION" in client.calls[1][0][0]["content"]
    assert plan.new_contents[str(tgt)] == "new line\n"


def test_draft_rejects_offtarget_files(cfg, root):
    tgt = root / "a.conf"
    tgt.write_text("x\n")
    other = root / "other.conf"
    other.write_text("y\n")
    sneaky = _mkdiff(str(other), ["y"], ["z"])
    client = FakeClient(sneaky, sneaky)
    with pytest.raises(bp.BlueprintError, match="non-target"):
        bp.draft(cfg, None, "x", targets=[str(tgt)], client=client)


def test_draft_exhausts_retries(cfg, root):
    tgt = root / "a.conf"
    tgt.write_text("x\n")
    client = FakeClient("no diff here", "still no diff")
    with pytest.raises(bp.BlueprintError, match="could not draft"):
        bp.draft(cfg, None, "x", targets=[str(tgt)], client=client)


def test_draft_refuses_denylisted_target(cfg):
    cfg.raw = {"blueprint": {"allowed_roots": ["/etc"]}}
    with pytest.raises(bp.BlueprintError, match="denylisted"):
        bp.draft(cfg, None, "x", targets=["/etc/shadow"], client=FakeClient())


def test_propose_targets_validates(cfg, root):
    good = str(root / "ok.conf")
    client = FakeClient(json.dumps({"targets": [good], "reason": "r"}))
    assert bp.propose_targets(cfg, None, "intent", client=client) == [good]
    client = FakeClient(json.dumps({"targets": ["/etc/passwd"]}))
    with pytest.raises(bp.BlueprintError, match="denylist"):
        bp.propose_targets(cfg, None, "intent", client=client)
    client = FakeClient("garbage, no json")
    with pytest.raises(bp.BlueprintError, match="no usable targets"):
        bp.propose_targets(cfg, None, "intent", client=client)
