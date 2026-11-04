"""install-service: schedule `wrench patrol` natively on each OS.

Linux   → user systemd service + timer (~/.config/systemd/user/)
macOS   → launchd user agent plist (~/Library/LaunchAgents/)
Windows → Scheduled Task via schtasks

Each installer is split into a pure "plan" step (files to write + commands to
run) and an "apply" step, so the plan is unit-testable on any OS without
touching the real scheduler.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import platforms

LAUNCHD_LABEL = "io.github.sunkencity999.wrench-patrol"
WINDOWS_TASK = "WrenchPatrol"


@dataclass
class InstallPlan:
    kind: str                                   # systemd | launchd | schtasks
    files: dict[Path, str] = field(default_factory=dict)   # path -> content
    commands: list[list[str]] = field(default_factory=list)
    check_hint: str = ""
    uninstall_hint: str = ""


class SchedulerError(RuntimeError):
    pass


# ---------------- plans ----------------

def _systemd_plan(wrench_bin: str, interval_min: int, home: Path) -> InstallPlan:
    unit_dir = home / ".config" / "systemd" / "user"
    service = f"""[Unit]
Description=wrench patrol — intentional sysadmin agent
After=network-online.target

[Service]
Type=oneshot
Nice=10
ExecStart={wrench_bin} patrol --quiet --no-html
"""
    timer = f"""[Unit]
Description=wrench patrol every {interval_min} minutes

[Timer]
OnBootSec=3min
OnUnitActiveSec={interval_min}min
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
"""
    return InstallPlan(
        kind="systemd",
        files={
            unit_dir / "wrench-patrol.service": service,
            unit_dir / "wrench-patrol.timer": timer,
        },
        commands=[
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "enable", "--now", "wrench-patrol.timer"],
        ],
        check_hint="systemctl --user list-timers wrench-patrol.timer",
        uninstall_hint="wrench install-service --uninstall  "
                       "(or: systemctl --user disable --now wrench-patrol.timer)",
    )


def _launchd_plan(wrench_bin: str, interval_min: int, home: Path) -> InstallPlan:
    plist_path = home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{wrench_bin}</string>
    <string>patrol</string>
    <string>--quiet</string>
    <string>--no-html</string>
  </array>
  <key>StartInterval</key><integer>{interval_min * 60}</integer>
  <key>RunAtLoad</key><false/>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>10</integer>
</dict>
</plist>
"""
    return InstallPlan(
        kind="launchd",
        files={plist_path: plist},
        commands=[
            # bootout is a no-op if not loaded; keeps re-installs idempotent
            ["launchctl", "unload", str(plist_path)],
            ["launchctl", "load", "-w", str(plist_path)],
        ],
        check_hint=f"launchctl list | grep {LAUNCHD_LABEL}",
        uninstall_hint=f"wrench install-service --uninstall  "
                       f"(or: launchctl unload -w {plist_path} && rm {plist_path})",
    )


def _schtasks_plan(wrench_bin: str, interval_min: int, home: Path) -> InstallPlan:  # noqa: ARG001
    tr = f'"{wrench_bin}" patrol --quiet --no-html'
    return InstallPlan(
        kind="schtasks",
        files={},
        commands=[
            ["schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", str(interval_min),
             "/TN", WINDOWS_TASK, "/TR", tr],
        ],
        check_hint=f"schtasks /Query /TN {WINDOWS_TASK}",
        uninstall_hint=f"wrench install-service --uninstall  "
                       f"(or: schtasks /Delete /F /TN {WINDOWS_TASK})",
    )


PLANNERS = {
    "systemd": _systemd_plan,
    "launchd": _launchd_plan,
    "schtasks": _schtasks_plan,
}


def plan_install(wrench_bin: str, interval_min: int, home: Path | None = None) -> InstallPlan:
    mgr = platforms.service_manager()
    if mgr is None:
        raise SchedulerError(
            f"no supported scheduler found on this {platforms.current_platform()} system "
            "(need systemd, launchd, or schtasks). Run `wrench watch` in a shell/tmux instead."
        )
    return PLANNERS[mgr](wrench_bin, interval_min, home or Path.home())


def plan_uninstall(home: Path | None = None) -> InstallPlan:
    home = home or Path.home()
    mgr = platforms.service_manager()
    if mgr == "systemd":
        unit_dir = home / ".config" / "systemd" / "user"
        return InstallPlan(
            kind="systemd",
            commands=[
                ["systemctl", "--user", "disable", "--now", "wrench-patrol.timer"],
                ["systemctl", "--user", "daemon-reload"],
            ],
            files={unit_dir / "wrench-patrol.service": "", unit_dir / "wrench-patrol.timer": ""},
        )
    if mgr == "launchd":
        plist = home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        return InstallPlan(kind="launchd",
                           commands=[["launchctl", "unload", "-w", str(plist)]],
                           files={plist: ""})
    if mgr == "schtasks":
        return InstallPlan(kind="schtasks",
                           commands=[["schtasks", "/Delete", "/F", "/TN", WINDOWS_TASK]])
    raise SchedulerError("no supported scheduler found on this system")


# ---------------- apply ----------------

def apply_plan(plan: InstallPlan, uninstall: bool = False, runner=None) -> list[str]:
    """Write/remove files and run the plan's commands. Returns human-readable log lines."""
    run = runner or (lambda argv: subprocess.run(argv, check=False, capture_output=True))
    log: list[str] = []
    if uninstall:
        for argv in plan.commands:
            run(argv)
            log.append("ran: " + " ".join(argv))
        for path in plan.files:
            try:
                path.unlink(missing_ok=True)
                log.append(f"removed: {path}")
            except OSError as e:
                log.append(f"could not remove {path}: {e}")
        return log
    for path, content in plan.files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        log.append(f"wrote: {path}")
    for argv in plan.commands:
        run(argv)
        log.append("ran: " + " ".join(argv))
    return log
