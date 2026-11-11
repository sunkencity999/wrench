"""install-service plans for all three OSes — pure planning, no real scheduler touched."""

from pathlib import Path

import pytest

from wrench import platforms, scheduler


HOME = Path("/tmp/fakehome")


def test_systemd_plan(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    monkeypatch.setattr(platforms, "has", lambda c: c == "systemctl")
    plan = scheduler.plan_install("/usr/bin/wrench", 15, home=HOME)
    assert plan.kind == "systemd"
    svc = plan.files[HOME / ".config" / "systemd" / "user" / "wrench-patrol.service"]
    assert 'ExecStart="/usr/bin/wrench" heartbeat --quiet' in svc   # quoted: paths with spaces
    assert 'Environment="PATH=' in svc
    timer = plan.files[HOME / ".config" / "systemd" / "user" / "wrench-patrol.timer"]
    assert "OnUnitActiveSec=15min" in timer
    assert ["systemctl", "--user", "daemon-reload"] in plan.commands


def test_launchd_plan(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "darwin")
    monkeypatch.setattr(platforms, "has", lambda c: c == "launchctl")
    plan = scheduler.plan_install("/opt/homebrew/bin/wrench", 30, home=HOME)
    assert plan.kind == "launchd"
    plist_path = HOME / "Library" / "LaunchAgents" / f"{scheduler.LAUNCHD_LABEL}.plist"
    plist = plan.files[plist_path]
    assert "<integer>1800</integer>" in plist           # 30 min -> seconds
    assert "<string>/opt/homebrew/bin/wrench</string>" in plist
    assert "<string>heartbeat</string>" in plist    # the timer beats; jobs decide what runs
    assert plan.commands[-1][:2] == ["launchctl", "bootstrap"]
    assert plan.commands[-1][-1] == str(plist_path)
    # scheduled runs get a real PATH and a log file (launchd's default has neither)
    assert "<key>EnvironmentVariables</key>" in plist and "StandardErrorPath" in plist


def test_schtasks_plan(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "win32")
    monkeypatch.setattr(platforms, "has", lambda c: c == "schtasks")
    plan = scheduler.plan_install(r"C:\Python\Scripts\wrench.exe", 15, home=HOME)
    assert plan.kind == "schtasks"
    assert plan.files == {}
    (cmd,) = plan.commands
    assert cmd[:3] == ["schtasks", "/Create", "/F"]
    assert "/MO" in cmd and "15" in cmd
    assert any("wrench.exe" in part for part in cmd)


def test_no_scheduler_raises(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    monkeypatch.setattr(platforms, "has", lambda c: False)
    with pytest.raises(scheduler.SchedulerError):
        scheduler.plan_install("/usr/bin/wrench", 15, home=HOME)


def test_apply_plan_writes_files_and_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    monkeypatch.setattr(platforms, "has", lambda c: c == "systemctl")
    plan = scheduler.plan_install("/usr/bin/wrench", 15, home=tmp_path)
    ran = []
    log = scheduler.apply_plan(plan, runner=ran.append)
    assert (tmp_path / ".config" / "systemd" / "user" / "wrench-patrol.timer").exists()
    assert ["systemctl", "--user", "enable", "--now", "wrench-patrol.timer"] in ran
    assert any("wrote:" in line for line in log)


def test_uninstall_plan_removes_files(tmp_path, monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    monkeypatch.setattr(platforms, "has", lambda c: c == "systemctl")
    plan = scheduler.plan_install("/usr/bin/wrench", 15, home=tmp_path)
    scheduler.apply_plan(plan, runner=lambda argv: None)
    un = scheduler.plan_uninstall(home=tmp_path)
    scheduler.apply_plan(un, uninstall=True, runner=lambda argv: None)
    assert not (tmp_path / ".config" / "systemd" / "user" / "wrench-patrol.timer").exists()


def test_apply_plan_raises_when_the_enable_step_fails(tmp_path):
    """"installed + started" must mean it started."""
    import types
    plan = scheduler.InstallPlan(kind="systemd", files={tmp_path / "u.timer": "x"},
                                 commands=[["systemctl", "--user", "enable", "--now", "u.timer"]])
    failing = lambda argv: types.SimpleNamespace(returncode=1, stderr="Failed to connect to bus")  # noqa: E731
    import pytest
    with pytest.raises(scheduler.SchedulerError) as e:
        scheduler.apply_plan(plan, runner=failing)
    assert "Failed to connect to bus" in str(e.value)
    # leading cleanup commands may fail without aborting the install
    plan2 = scheduler.InstallPlan(kind="launchd", files={}, optional_commands=1,
                                  commands=[["launchctl", "bootout", "x"], ["launchctl", "bootstrap", "y"]])
    seq = iter([1, 0])
    log = scheduler.apply_plan(plan2, runner=lambda argv: types.SimpleNamespace(returncode=next(seq), stderr=""))
    assert len(log) == 2
