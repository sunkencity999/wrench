"""fixxer: catalog detect/apply/verify, risk-tier gating, consent flow, audit."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from wrench import fixxer as fx
from wrench import scheduler


# ---------------- helpers ----------------

def make_cfg(tmp_path: Path, fixxer_cfg: dict | None = None) -> SimpleNamespace:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return SimpleNamespace(data_dir=data, raw={"fixxer": fixxer_cfg or {}})


class StubStore:
    def __init__(self):
        self.actions = []

    def add_action(self, tier, kind, command, approved, result):
        self.actions.append((tier, kind, command, approved, result))


APT_SIM_UPGRADE = """\
NOTE: This is only a simulation!
Inst libssl3 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])
Inst vim [2:9.1.0016-1ubuntu7.3] (2:9.1.0016-1ubuntu7.4 Ubuntu:24.04/noble-updates [amd64])
Conf libssl3 (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])
"""

APT_SIM_AUTOREMOVE = """\
NOTE: This is only a simulation!
Remv linux-image-6.8.0-45-generic [6.8.0-45.45]
Remv libold1 [1.2.3]
"""


# ---------------- detectors ----------------

def test_pkg_upgrade_apt_detects_and_plans(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, APT_SIM_UPGRADE))
    ctx = {"pkg_manager": "apt", "cfg_fixxer": {}}
    f = fx._detect_pkg_upgrade(ctx)
    assert f is not None
    assert f.risk == "moderate"
    assert f.commands == [["apt-get", "upgrade", "-y"]]
    assert f.needs_sudo
    assert f.env_extra.get("DEBIAN_FRONTEND") == "noninteractive"
    assert "2 packages upgradable (1 security)" in f.detail
    assert f.rollback_hint


def test_pkg_upgrade_apt_none_when_clean(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, "NOTE: simulation\nConf nothing"))
    assert fx._detect_pkg_upgrade({"pkg_manager": "apt", "cfg_fixxer": {}}) is None


def test_pkg_upgrade_verify_clean_after_apply(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, "nothing pending"))
    ok, note = fx._verify_pkg_upgrade({"pkg_manager": "apt"}, None)
    assert ok and "no pending" in note


def test_pkg_upgrade_verify_fails_when_still_pending(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, APT_SIM_UPGRADE))
    ok, note = fx._verify_pkg_upgrade({"pkg_manager": "apt"}, None)
    assert not ok and "still pending" in note


def test_pkg_autoremove_apt_detects_kernels(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, APT_SIM_AUTOREMOVE))
    f = fx._detect_pkg_autoremove({"pkg_manager": "apt", "cfg_fixxer": {}})
    assert f is not None
    assert f.commands == [["apt-get", "autoremove", "--purge", "-y"]]
    assert "old kernel" in f.detail
    assert "old kernels" in f.title


def test_pkg_autoremove_none_when_no_orphans(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, "NOTE: simulation"))
    assert fx._detect_pkg_autoremove({"pkg_manager": "apt", "cfg_fixxer": {}}) is None


def test_pkg_upgrade_dnf_uses_exit_100(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (100, "pkg1.x86_64  1.2  updates"))
    f = fx._detect_pkg_upgrade({"pkg_manager": "dnf", "cfg_fixxer": {}})
    assert f is not None and f.commands == [["dnf", "upgrade", "-y"]]
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, ""))
    assert fx._detect_pkg_upgrade({"pkg_manager": "dnf", "cfg_fixxer": {}}) is None


def test_pkg_upgrade_pacman_and_orphans(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, "linux 6.1-1 -> 6.2-1\nvim 1 -> 2"))
    f = fx._detect_pkg_upgrade({"pkg_manager": "pacman", "cfg_fixxer": {}})
    assert f is not None and f.commands == [["pacman", "-Syu", "--noconfirm"]]
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, "orphan1\norphan2"))
    g = fx._detect_pkg_autoremove({"pkg_manager": "pacman", "cfg_fixxer": {}})
    assert g is not None
    assert g.commands == [["pacman", "-Rns", "--noconfirm", "orphan1", "orphan2"]]


def test_pkg_upgrade_brew(monkeypatch):
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, "wget\njq"))
    f = fx._detect_pkg_upgrade({"pkg_manager": "brew", "cfg_fixxer": {}})
    assert f is not None and not f.needs_sudo and f.commands == [["brew", "upgrade"]]


def test_journal_vacuum_detects_above_threshold(monkeypatch):
    monkeypatch.setattr(fx.platforms, "is_linux", lambda: True)
    monkeypatch.setattr(fx.shutil, "which", lambda c: "/usr/bin/journalctl")
    monkeypatch.setattr(
        fx, "_run",
        lambda argv, **kw: (0, "Archived and active journals take up 2.1G in the file system."))
    ctx = {"cfg_fixxer": {"journal_max_mb": 1024, "journal_vacuum_to": "500M"}}
    f = fx._detect_journal_vacuum(ctx)
    assert f is not None
    assert f.risk == "safe"
    assert f.commands == [["journalctl", "--vacuum-size=500M"]]
    # under threshold → no finding
    monkeypatch.setattr(
        fx, "_run",
        lambda argv, **kw: (0, "Archived and active journals take up 300.0M in the file system."))
    assert fx._detect_journal_vacuum(ctx) is None


def test_journal_vacuum_verify(monkeypatch):
    monkeypatch.setattr(fx.shutil, "which", lambda c: "/usr/bin/journalctl")
    monkeypatch.setattr(
        fx, "_run",
        lambda argv, **kw: (0, "Archived and active journals take up 480.0M in the file system."))
    ok, note = fx._verify_journal_vacuum({"cfg_fixxer": {"journal_max_mb": 1024}}, None)
    assert ok and "480" in note


def test_cache_clean_apt(monkeypatch):
    monkeypatch.setattr(fx, "_dir_size_mb", lambda p: 800.0)
    f = fx._detect_cache_clean({"pkg_manager": "apt", "cfg_fixxer": {}})
    assert f is not None and f.commands == [["apt-get", "clean"]] and f.risk == "safe"
    monkeypatch.setattr(fx, "_dir_size_mb", lambda p: 10.0)
    assert fx._detect_cache_clean({"pkg_manager": "apt", "cfg_fixxer": {}}) is None
    ok, note = fx._verify_cache_clean({"pkg_manager": "apt"}, None)
    assert ok


def test_tmp_clean_detect_and_verify(monkeypatch):
    monkeypatch.setattr(fx.platforms, "is_windows", lambda: False)
    monkeypatch.setattr(fx, "_stale_tmp", lambda age: (7, 250.0))
    f = fx._detect_tmp_clean({"cfg_fixxer": {"tmp_age_days": 14}})
    assert f is not None and f.risk == "moderate"
    assert f.commands[0][:2] == ["find", "/tmp"]
    assert "-maxdepth" in f.commands[0] and "-delete" in f.commands[0]
    monkeypatch.setattr(fx, "_stale_tmp", lambda age: (0, 0.0))
    assert fx._detect_tmp_clean({"cfg_fixxer": {}}) is None
    ok, _ = fx._verify_tmp_clean({"cfg_fixxer": {}}, None)
    assert ok


def test_failed_units_detection(monkeypatch):
    monkeypatch.setattr(fx.platforms, "is_linux", lambda: True)
    monkeypatch.setattr(fx.shutil, "which", lambda c: "/usr/bin/systemctl")

    def fake_run(argv, **kw):
        if "--user" in argv:
            return 0, ""
        return 0, "● broken.service loaded failed failed Broken thing\n"

    monkeypatch.setattr(fx, "_run", fake_run)
    f = fx._detect_reset_failed({})
    assert f is not None and f.risk == "safe"
    assert ["systemctl", "reset-failed"] in f.commands
    g = fx._detect_restart_failed({})
    assert g is not None and g.commands == [["systemctl", "restart", "broken.service"]]
    assert g.needs_sudo and g.risk == "moderate"


def test_no_failed_units_means_no_findings(monkeypatch):
    monkeypatch.setattr(fx.platforms, "is_linux", lambda: True)
    monkeypatch.setattr(fx.shutil, "which", lambda c: "/usr/bin/systemctl")
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (0, ""))
    assert fx._detect_reset_failed({}) is None
    assert fx._detect_restart_failed({}) is None


# ---------------- scan ----------------

def test_scan_sorts_by_risk_and_survives_broken_detector(monkeypatch, tmp_path):
    cfg = make_cfg(tmp_path)

    def det_mod(ctx):
        return fx.Finding("pkg_upgrade", "t", "moderate", "d", [["true"]])

    def det_safe(ctx):
        return fx.Finding("journal_vacuum", "t", "safe", "d", [["true"]])

    def det_boom(ctx):
        raise RuntimeError("detector exploded")

    cat = [
        fx.ActionSpec("pkg_upgrade", "t", "moderate", det_mod, lambda c, f: (True, "")),
        fx.ActionSpec("x_boom", "t", "safe", det_boom, lambda c, f: (True, "")),
        fx.ActionSpec("journal_vacuum", "t", "safe", det_safe, lambda c, f: (True, "")),
    ]
    monkeypatch.setattr(fx, "CATALOG", cat)
    findings, ctx = fx.scan(cfg)
    assert [f.risk for f in findings] == ["safe", "moderate"]  # sorted, boom skipped


def test_scan_skips_wrong_platform(monkeypatch, tmp_path):
    cfg = make_cfg(tmp_path)
    called = []
    cat = [fx.ActionSpec("a", "t", "safe",
                         lambda ctx: called.append(1), lambda c, f: (True, ""),
                         platforms=("windows",))]
    monkeypatch.setattr(fx, "CATALOG", cat)
    monkeypatch.setattr(fx.platforms, "current_platform", lambda: "linux")
    findings, _ = fx.scan(cfg)
    assert findings == [] and called == []


# ---------------- apply + audit ----------------

def test_apply_finding_runs_verifies_and_audits(monkeypatch, tmp_path):
    cfg = make_cfg(tmp_path)
    store = StubStore()
    ran = []
    monkeypatch.setattr(fx, "_run", lambda argv, **kw: (ran.append(argv), (0, "done"))[1])
    monkeypatch.setattr(fx, "_sudo_prefix", lambda ni: ["sudo", "-n"] if ni else ["sudo"])
    spec = fx.ACTIONS_BY_ID["pkg_refresh"]
    monkeypatch.setattr(spec, "verify", lambda ctx, f: (True, "fresh"))

    f = fx.Finding("pkg_refresh", "Refresh", "safe", "stale",
                   commands=[["apt-get", "update"]], needs_sudo=True, rollback_hint="none")
    res = fx.apply_finding(cfg, store, {"pkg_manager": "apt"}, f, "auto", non_interactive=True)
    assert res.ok and res.verified and res.verify_note == "fresh"
    assert ran == [["sudo", "-n", "apt-get", "update"]]
    # audit log written
    rows = fx.audit_tail(cfg)
    assert len(rows) == 1
    assert rows[0]["action"] == "pkg_refresh" and rows[0]["mode"] == "auto"
    assert rows[0]["ok"] and rows[0]["verified"] and rows[0]["rollback_hint"] == "none"
    # store action logged
    assert store.actions and store.actions[0][0] == "auto"


def test_apply_finding_failure_short_circuits(monkeypatch, tmp_path):
    cfg = make_cfg(tmp_path)
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return 1, "boom"

    monkeypatch.setattr(fx, "_run", fake_run)
    f = fx.Finding("pkg_refresh", "Refresh", "safe", "d",
                   commands=[["cmd-one"], ["cmd-two"]], needs_sudo=False)
    res = fx.apply_finding(cfg, None, {}, f, "interactive")
    assert not res.ok and not res.verified
    assert len(calls) == 1  # second command never ran
    assert fx.audit_tail(cfg)[0]["ok"] is False


def test_sudo_prefix_modes(monkeypatch):
    monkeypatch.setattr(fx.platforms, "is_windows", lambda: False)
    monkeypatch.setattr(fx.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(fx.shutil, "which", lambda c: "/usr/bin/sudo")
    assert fx._sudo_prefix(non_interactive=True) == ["sudo", "-n"]
    assert fx._sudo_prefix(non_interactive=False) == ["sudo"]
    monkeypatch.setattr(fx.os, "geteuid", lambda: 0, raising=False)
    assert fx._sudo_prefix(True) == []


# ---------------- consent + tier gating ----------------

def test_consent_roundtrip_and_revoke(monkeypatch, tmp_path):
    monkeypatch.setattr("wrench.config.CONFIG_DIR", tmp_path)
    cfg = make_cfg(tmp_path)
    assert fx.load_consent(cfg) is None
    p = fx.write_consent(cfg, ["safe", "bogus", "moderate"])
    data = json.loads(p.read_text())
    assert data["tiers"] == ["safe", "moderate"]  # bogus filtered, canonical order
    assert fx.load_consent(cfg)["tiers"] == ["safe", "moderate"]
    assert fx.revoke_consent(cfg) is True
    assert fx.load_consent(cfg) is None
    assert fx.revoke_consent(cfg) is False


def test_corrupt_consent_is_treated_as_absent(monkeypatch, tmp_path):
    monkeypatch.setattr("wrench.config.CONFIG_DIR", tmp_path)
    (tmp_path / fx.CONSENT_FILENAME).write_text("{not json")
    assert fx.load_consent(make_cfg(tmp_path)) is None


def test_effective_auto_tiers_is_consent_intersect_config(monkeypatch, tmp_path):
    monkeypatch.setattr("wrench.config.CONFIG_DIR", tmp_path)
    # no consent → nothing, regardless of config
    cfg = make_cfg(tmp_path, {"auto_tiers": ["safe", "moderate", "risky"]})
    assert fx.effective_auto_tiers(cfg) == []
    # consent safe+moderate, default config (safe) → safe only
    fx.write_consent(cfg, ["safe", "moderate"])
    assert fx.effective_auto_tiers(make_cfg(tmp_path)) == ["safe"]
    # both widened → safe+moderate
    wide = make_cfg(tmp_path, {"auto_tiers": ["safe", "moderate"]})
    assert fx.effective_auto_tiers(wide) == ["safe", "moderate"]
    # config widened to risky but consent lacks it → still no risky
    risky_cfg = make_cfg(tmp_path, {"auto_tiers": ["safe", "moderate", "risky"]})
    assert "risky" not in fx.effective_auto_tiers(risky_cfg)


def test_auto_scope_filters_findings(monkeypatch, tmp_path):
    monkeypatch.setattr("wrench.config.CONFIG_DIR", tmp_path)
    cfg = make_cfg(tmp_path)
    fx.write_consent(cfg, ["safe"])
    findings = [
        fx.Finding("a", "safe thing", "safe", "d", [["true"]]),
        fx.Finding("b", "mod thing", "moderate", "d", [["true"]]),
    ]
    scoped = fx.auto_scope(cfg, findings)
    assert [f.action_id for f in scoped] == ["a"]


def test_auto_scope_empty_without_consent(monkeypatch, tmp_path):
    monkeypatch.setattr("wrench.config.CONFIG_DIR", tmp_path)
    cfg = make_cfg(tmp_path)
    findings = [fx.Finding("a", "safe thing", "safe", "d", [["true"]])]
    assert fx.auto_scope(cfg, findings) == []


# ---------------- catalog hygiene ----------------

def test_catalog_commands_are_handwritten_argv_lists():
    """The safety line: every catalog action yields list-of-argv commands,
    carries a valid risk tier, and has a verifier."""
    assert fx.CATALOG, "catalog must not be empty"
    ids = [a.id for a in fx.CATALOG]
    assert len(ids) == len(set(ids)), "duplicate action ids"
    for spec in fx.CATALOG:
        assert spec.risk in fx.RISK_TIERS
        assert callable(spec.detect) and callable(spec.verify)
        assert spec.id in fx.ACTIONS_BY_ID


def test_audit_tail_handles_missing_and_garbage(tmp_path):
    cfg = make_cfg(tmp_path)
    assert fx.audit_tail(cfg) == []
    fx.audit_path(cfg).write_text('{"ok": true}\nnot-json\n{"ok": false}\n')
    rows = fx.audit_tail(cfg)
    assert len(rows) == 2


# ---------------- scheduler integration ----------------

def test_fixxer_systemd_plan(monkeypatch, tmp_path):
    monkeypatch.setattr(scheduler.platforms, "service_manager", lambda: "systemd")
    plan = scheduler.plan_install_fixxer("/usr/bin/wrench", 4, home=tmp_path)
    assert plan.kind == "systemd"
    timer = plan.files[tmp_path / ".config" / "systemd" / "user" / "wrench-fixxer.timer"]
    assert "OnCalendar=*-*-* 04:00:00" in timer
    svc = plan.files[tmp_path / ".config" / "systemd" / "user" / "wrench-fixxer.service"]
    assert "fixxer --auto --no-llm" in svc
    assert ["systemctl", "--user", "enable", "--now", "wrench-fixxer.timer"] in plan.commands


def test_fixxer_launchd_plan(monkeypatch, tmp_path):
    monkeypatch.setattr(scheduler.platforms, "service_manager", lambda: "launchd")
    plan = scheduler.plan_install_fixxer("/usr/local/bin/wrench", 3, home=tmp_path)
    plist = next(iter(plan.files.values()))
    assert scheduler.FIXXER_LAUNCHD_LABEL in plist
    assert "<integer>3</integer>" in plist and "fixxer" in plist


def test_fixxer_schtasks_plan(monkeypatch, tmp_path):
    monkeypatch.setattr(scheduler.platforms, "service_manager", lambda: "schtasks")
    plan = scheduler.plan_install_fixxer("C:\\wrench.exe", 5, home=tmp_path)
    argv = plan.commands[0]
    assert "/SC" in argv and "DAILY" in argv and "05:00" in argv


def test_uninstall_plan_includes_fixxer_units(monkeypatch, tmp_path):
    monkeypatch.setattr(scheduler.platforms, "service_manager", lambda: "systemd")
    plan = scheduler.plan_uninstall(home=tmp_path)
    paths = [str(p) for p in plan.files]
    assert any("wrench-fixxer.timer" in p for p in paths)
    assert ["systemctl", "--user", "disable", "--now", "wrench-fixxer.timer"] in plan.commands


def test_pkg_manager_detection(monkeypatch):
    monkeypatch.setattr(fx.platforms, "current_platform", lambda: "linux")
    monkeypatch.setattr(fx.shutil, "which",
                        lambda c: "/usr/bin/apt-get" if c == "apt-get" else None)
    assert fx.pkg_manager() == "apt"
    monkeypatch.setattr(fx.shutil, "which", lambda c: None)
    assert fx.pkg_manager() is None
    monkeypatch.setattr(fx.platforms, "current_platform", lambda: "macos")
    monkeypatch.setattr(fx.shutil, "which", lambda c: "/opt/homebrew/bin/brew" if c == "brew" else None)
    assert fx.pkg_manager() == "brew"
