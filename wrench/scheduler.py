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
FIXXER_LAUNCHD_LABEL = "io.github.sunkencity999.wrench-fixxer"
FIXXER_WINDOWS_TASK = "WrenchFixxer"


@dataclass
class InstallPlan:
    kind: str                                   # systemd | launchd | schtasks
    files: dict[Path, str] = field(default_factory=dict)   # path -> content
    commands: list[list[str]] = field(default_factory=list)
    # how many LEADING commands are best-effort cleanup (allowed to fail)
    optional_commands: int = 0
    check_hint: str = ""
    uninstall_hint: str = ""


class SchedulerError(RuntimeError):
    pass


# ---------------- shared pieces ----------------

def _scheduler_path() -> str:
    """PATH for scheduled runs.

    launchd and cron hand a job `/usr/bin:/bin:/usr/sbin:/sbin`. Under that,
    Homebrew, docker, smartctl and nvm-installed node all "disappear", so a
    scheduled patrol sees a different machine than an interactive one. Bake in
    the PATH the operator installed with, plus the usual tool directories.
    """
    import os
    seen: list[str] = []
    for d in (os.environ.get("PATH", "").split(os.pathsep)
              + ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
                 "/usr/local/sbin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]):
        if d and d not in seen and not d.startswith("."):
            seen.append(d)
    return os.pathsep.join(seen)


def _log_dir() -> Path:
    from .config import DATA_DIR
    return Path(DATA_DIR) / "logs"


def _launchd_plist(label: str, wrench_bin: str, args: list[str], schedule_xml: str) -> str:
    from xml.sax.saxutils import escape
    log = _log_dir() / f"{label}.log"
    arg_xml = "\n".join(f"    <string>{escape(a)}</string>" for a in [wrench_bin, *args])
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{escape(label)}</string>
  <key>ProgramArguments</key>
  <array>
{arg_xml}
  </array>
{schedule_xml}
  <key>RunAtLoad</key><false/>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>10</integer>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>{escape(_scheduler_path())}</string></dict>
  <key>StandardOutPath</key><string>{escape(str(log))}</string>
  <key>StandardErrorPath</key><string>{escape(str(log))}</string>
</dict>
</plist>
"""


def _launchd_commands(label: str, plist_path: Path) -> list[list[str]]:
    """bootout (ignored if not loaded) then bootstrap into the user's GUI domain."""
    import os
    domain = f"gui/{os.getuid()}" if hasattr(os, "getuid") else "gui/501"
    return [
        ["launchctl", "bootout", f"{domain}/{label}"],
        ["launchctl", "bootstrap", domain, str(plist_path)],
    ]


# ---------------- plans ----------------

def _systemd_plan(wrench_bin: str, interval_min: int, home: Path) -> InstallPlan:
    unit_dir = home / ".config" / "systemd" / "user"
    service = f"""[Unit]
Description=wrench patrol — the sysadmin's right hand

[Service]
Type=oneshot
Nice=10
Environment="PATH={_scheduler_path()}"
ExecStart="{wrench_bin}" patrol --quiet --no-html
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
        check_hint="systemctl --user list-timers wrench-patrol.timer   "
                   "(servers: `loginctl enable-linger $USER` keeps it running after logout)",
        uninstall_hint="wrench install-service --uninstall  "
                       "(or: systemctl --user disable --now wrench-patrol.timer)",
    )


def _launchd_plan(wrench_bin: str, interval_min: int, home: Path) -> InstallPlan:
    plist_path = home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
    plist = _launchd_plist(
        LAUNCHD_LABEL, wrench_bin, ["patrol", "--quiet", "--no-html"],
        f"  <key>StartInterval</key><integer>{interval_min * 60}</integer>")
    return InstallPlan(
        kind="launchd",
        files={plist_path: plist},
        commands=_launchd_commands(LAUNCHD_LABEL, plist_path),
        optional_commands=1,
        check_hint=f"launchctl list | grep {LAUNCHD_LABEL}   (log: {_log_dir() / (LAUNCHD_LABEL + '.log')})",
        uninstall_hint="wrench install-service --uninstall",
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


# ---------------- auto-fixxer (opt-in, consent-gated at the CLI layer) ----------------

def _systemd_fixxer_plan(wrench_bin: str, hour: int, home: Path) -> InstallPlan:
    unit_dir = home / ".config" / "systemd" / "user"
    service = f"""[Unit]
Description=wrench auto-fixxer — consented autonomous fixes (audited)
After=network-online.target

[Service]
Type=oneshot
Nice=10
ExecStart={wrench_bin} fixxer --auto --no-llm
"""
    timer = f"""[Unit]
Description=wrench auto-fixxer daily at {hour:02d}:00

[Timer]
OnCalendar=*-*-* {hour:02d}:00:00
RandomizedDelaySec=600
Persistent=true

[Install]
WantedBy=timers.target
"""
    return InstallPlan(
        kind="systemd",
        files={
            unit_dir / "wrench-fixxer.service": service,
            unit_dir / "wrench-fixxer.timer": timer,
        },
        commands=[
            ["systemctl", "--user", "daemon-reload"],
            ["systemctl", "--user", "enable", "--now", "wrench-fixxer.timer"],
        ],
        check_hint="systemctl --user list-timers wrench-fixxer.timer",
        uninstall_hint="systemctl --user disable --now wrench-fixxer.timer",
    )


def _launchd_fixxer_plan(wrench_bin: str, hour: int, home: Path) -> InstallPlan:
    plist_path = home / "Library" / "LaunchAgents" / f"{FIXXER_LAUNCHD_LABEL}.plist"
    plist = _launchd_plist(
        FIXXER_LAUNCHD_LABEL, wrench_bin, ["fixxer", "--auto", "--no-llm"],
        "  <key>StartCalendarInterval</key>\n"
        f"  <dict><key>Hour</key><integer>{hour}</integer>"
        "<key>Minute</key><integer>0</integer></dict>")
    return InstallPlan(
        kind="launchd",
        files={plist_path: plist},
        commands=_launchd_commands(FIXXER_LAUNCHD_LABEL, plist_path),
        optional_commands=1,
        check_hint=f"launchctl list | grep {FIXXER_LAUNCHD_LABEL}",
        uninstall_hint="wrench install-service --uninstall",
    )


def _schtasks_fixxer_plan(wrench_bin: str, hour: int, home: Path) -> InstallPlan:  # noqa: ARG001
    tr = f'"{wrench_bin}" fixxer --auto --no-llm'
    return InstallPlan(
        kind="schtasks",
        commands=[
            ["schtasks", "/Create", "/F", "/SC", "DAILY", "/ST", f"{hour:02d}:00",
             "/TN", FIXXER_WINDOWS_TASK, "/TR", tr],
        ],
        check_hint=f"schtasks /Query /TN {FIXXER_WINDOWS_TASK}",
        uninstall_hint=f"schtasks /Delete /F /TN {FIXXER_WINDOWS_TASK}",
    )


FIXXER_PLANNERS = {
    "systemd": _systemd_fixxer_plan,
    "launchd": _launchd_fixxer_plan,
    "schtasks": _schtasks_fixxer_plan,
}


def plan_install_fixxer(wrench_bin: str, hour: int = 4, home: Path | None = None) -> InstallPlan:
    mgr = platforms.service_manager()
    if mgr is None:
        raise SchedulerError(
            "no supported scheduler found — run `wrench fixxer --auto` from your own cron instead."
        )
    return FIXXER_PLANNERS[mgr](wrench_bin, hour, home or Path.home())


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
                ["systemctl", "--user", "disable", "--now", "wrench-fixxer.timer"],
                ["systemctl", "--user", "daemon-reload"],
            ],
            files={unit_dir / "wrench-patrol.service": "", unit_dir / "wrench-patrol.timer": "",
                   unit_dir / "wrench-fixxer.service": "", unit_dir / "wrench-fixxer.timer": ""},
        )
    if mgr == "launchd":
        plist = home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
        fplist = home / "Library" / "LaunchAgents" / f"{FIXXER_LAUNCHD_LABEL}.plist"
        return InstallPlan(kind="launchd",
                           commands=[_launchd_commands(LAUNCHD_LABEL, plist)[0],
                                     _launchd_commands(FIXXER_LAUNCHD_LABEL, fplist)[0]],
                           files={plist: "", fplist: ""})
    if mgr == "schtasks":
        return InstallPlan(kind="schtasks",
                           commands=[["schtasks", "/Delete", "/F", "/TN", WINDOWS_TASK],
                                     ["schtasks", "/Delete", "/F", "/TN", FIXXER_WINDOWS_TASK]])
    raise SchedulerError("no supported scheduler found on this system")


# ---------------- apply ----------------

def _default_runner(argv: list[str]):
    return subprocess.run(argv, check=False, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=60)


def apply_plan(plan: InstallPlan, uninstall: bool = False, runner=None) -> list[str]:
    """Write/remove files and run the plan's commands. Returns human-readable log lines.

    On install, a failing (non-cleanup) command raises SchedulerError with the
    tool's own message — "installed + started" must mean it started.
    """
    run = runner or _default_runner
    log: list[str] = []
    if uninstall:
        for argv in plan.commands:
            try:
                run(argv)
            except Exception:  # noqa: BLE001 — removing something already gone is fine
                pass
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
        path.write_text(content, encoding="utf-8")
        log.append(f"wrote: {path}")
    if plan.kind == "launchd":
        try:
            _log_dir().mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    for i, argv in enumerate(plan.commands):
        try:
            res = run(argv)
        except subprocess.TimeoutExpired:
            raise SchedulerError(f"`{' '.join(argv)}` timed out") from None
        except OSError as e:
            raise SchedulerError(f"`{' '.join(argv)}` could not run: {e}") from None
        code = getattr(res, "returncode", 0)
        log.append("ran: " + " ".join(argv) + ("" if not code else f"  (exit {code})"))
        if code and i >= plan.optional_commands:
            err = (getattr(res, "stderr", "") or getattr(res, "stdout", "") or "")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
            raise SchedulerError(
                f"`{' '.join(argv)}` failed (exit {code}): {err.strip()[:300] or 'no output'}"
                + ("\nhint: over SSH with no user session, run "
                   "`loginctl enable-linger $USER` and retry" if plan.kind == "systemd" else ""))
    return log
