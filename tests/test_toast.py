"""Clickable desktop notifications on macOS, Windows and Linux, and `wrench show`.

The bug this guards against: a macOS toast sent through `osascript` belongs to
Script Editor, so clicking it opened Script Editor. A click must lead to the
alert, on every platform.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from wrench import notifications as notif
from wrench import toast


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    import wrench.cli as cli
    import wrench.config as wc
    me = tmp_path / "me"
    (me / "cfg").mkdir(parents=True)
    monkeypatch.setattr(wc, "DATA_DIR", me)
    monkeypatch.setattr(wc, "CONFIG_DIR", me / "cfg")
    monkeypatch.setattr(wc, "CONFIG_PATH", me / "cfg" / "config.toml")
    monkeypatch.setattr(cli, "CONFIG_PATH", me / "cfg" / "config.toml")
    monkeypatch.setenv("WRENCH_DATA_DIR", str(me))
    monkeypatch.setenv("WRENCH_CONFIG_DIR", str(me / "cfg"))
    return me


def _cfg():
    from wrench.config import load_config
    return load_config()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Runner:
    """Records every command instead of running it."""

    def __init__(self, rc=0, stdout="", make=None):
        self.calls, self.rc, self.stdout, self.make = [], rc, stdout, make

    def __call__(self, argv, *a, **k):
        self.calls.append(list(argv))
        if self.make and argv[0] == "osacompile":
            Path(argv[2]).mkdir(parents=True, exist_ok=True)
            (Path(argv[2]) / "Contents").mkdir(exist_ok=True)
        return SimpleNamespace(returncode=self.rc, stdout=self.stdout, stderr="")


# ------------------------------------------------------------ macOS: the helper app
def test_helper_source_carries_no_alert_text_and_escapes_paths(_env, monkeypatch):
    monkeypatch.setattr(toast, "show_command", lambda: 'run "the show" \\ now')
    src = toast.applet_source(_env / 'odd "dir"')
    assert 'odd \\"dir\\"/notifier' in src                 # a path cannot end the string
    assert 'run \\"the show\\" \\\\ now' in src
    assert "display notification b with title t" in src    # text comes from files, not source
    assert "on reopen" in src and "-mmin -1" in src        # stale requests are not re-posted
    assert "__STATE__" not in src and "__SHOW__" not in src


def test_show_command_points_at_this_install(monkeypatch, _env):
    cmd = toast.show_command()
    assert sys.executable in cmd and "-m wrench show --from-toast" in cmd
    assert f"WRENCH_DATA_DIR={_env}" in cmd.replace("'", "")
    monkeypatch.delenv("WRENCH_DATA_DIR")
    monkeypatch.delenv("WRENCH_CONFIG_DIR")
    assert not toast.show_command().startswith("/usr/bin/env")


def test_helper_is_built_once_then_reused(_env, monkeypatch):
    monkeypatch.setattr(toast.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(toast.shutil, "which", lambda name: f"/usr/bin/{name}")
    run = Runner(make=True)
    app = toast.ensure_applet(_env, runner=run)
    assert app == _env / "notifier" / "wrench.app"
    tools = [c[0] for c in run.calls]
    assert tools[0] == "osacompile" and tools.count("plutil") == 4 and tools[-1] == "codesign"
    plist_edits = {c[2]: c[4] for c in run.calls if c[0] == "plutil"}
    assert plist_edits["CFBundleIdentifier"] == toast.BUNDLE_ID
    assert plist_edits["CFBundleName"] == "wrench" and plist_edits["LSUIElement"] == "true"
    again = Runner(make=True)
    assert toast.ensure_applet(_env, runner=again) == app and again.calls == []
    # wrench changed what the helper should do: it is rebuilt
    monkeypatch.setattr(toast, "show_command", lambda: "something-new")
    assert toast.ensure_applet(_env, runner=again) == app and again.calls[0][0] == "osacompile"


def test_helper_unavailable_means_none_not_an_error(_env, monkeypatch):
    monkeypatch.setattr(toast.platform, "system", lambda: "Linux")
    assert toast.ensure_applet(_env, runner=Runner()) is None
    monkeypatch.setattr(toast.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(toast.shutil, "which", lambda name: None)
    assert toast.ensure_applet(_env, runner=Runner()) is None
    monkeypatch.setattr(toast.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert toast.ensure_applet(_env, runner=Runner(rc=1)) is None       # compile failed
    assert toast.post_macos("t", "b", _env, runner=Runner(rc=1)) is False


def test_posting_hands_the_text_over_in_files(_env, monkeypatch):
    monkeypatch.setattr(toast.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(toast.shutil, "which", lambda name: f"/usr/bin/{name}")
    run = Runner(make=True)
    title = 'disk "full"; do shell script "rm -rf ~"'
    assert toast.post_macos(title, "body\nline two", _env, notif_id="abc123", runner=run)
    nd = _env / "notifier"
    assert (nd / "pending.title").read_text() == title
    assert (nd / "pending.body").read_text() == "body\nline two"
    assert toast.last_clicked(_env) == "abc123"
    assert run.calls[-1] == ["open", "-g", str(nd / "wrench.app")]
    assert all(title not in " ".join(c) for c in run.calls)             # never on a command line
    assert "rm -rf" not in (nd / "notifier.applescript").read_text()


@pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("osacompile"),
                    reason="builds a real macOS applet")
def test_a_real_helper_builds_and_is_validly_signed(_env):
    app = toast.ensure_applet(_env)
    assert app and (app / "Contents" / "Info.plist").is_file()
    ident = subprocess.run(["plutil", "-extract", "CFBundleIdentifier", "raw",
                            str(app / "Contents" / "Info.plist")],
                           capture_output=True, text=True).stdout.strip()
    assert ident == toast.BUNDLE_ID
    if shutil.which("codesign"):
        assert subprocess.run(["codesign", "--verify", str(app)],
                              capture_output=True).returncode == 0


def test_the_test_suite_never_posts_a_real_toast(_env, monkeypatch):
    monkeypatch.setattr(toast, "post_macos", lambda *a, **k: pytest.fail("posted a real toast"))
    monkeypatch.setattr(toast, "post_linux", lambda *a, **k: pytest.fail("posted a real toast"))
    monkeypatch.setattr(notif.shutil, "which", lambda name: None)
    assert notif.send_desktop("t", "b", _env) is False


def test_macos_falls_back_to_the_plain_toast(_env, monkeypatch):
    """If the helper cannot be used, the alert still arrives the old way."""
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.setattr(notif.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(toast, "post_macos", lambda *a, **k: False)
    ran = []
    monkeypatch.setattr(notif.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(notif.subprocess, "run", lambda argv, **k: ran.append(argv))
    assert notif.send_desktop("title", "body", _env, notif_id="x") is True
    assert ran and ran[0][0] == "osascript"
    # and when it works, osascript is not used at all
    ran.clear()
    monkeypatch.setattr(toast, "post_macos", lambda *a, **k: True)
    assert notif.send_desktop("title", "body", _env, notif_id="x") is True and ran == []
    # desktop_click = false: the plain toast, by choice
    assert notif.send_desktop("title", "body", _env, click=False) is True and ran[0][0] == "osascript"
    assert notif.settings_from(SimpleNamespace(raw={})).desktop_click is True
    assert notif.settings_from(SimpleNamespace(raw={"notify": {"desktop_click": False}})).desktop_click is False


# ------------------------------------------------------------ Windows
def test_windows_toast_registers_itself_and_opens_the_alert():
    s = toast.windows_script('it\'s "quoted"', 'body with $dollar `tick "dq"',
                             url="http://localhost:8787/#notification=abc",
                             program=r"C:\Program Files\Py\pythonw.exe")
    assert '"' not in s                                    # it travels on a command line
    assert r"HKCU:\Software\Classes\AppUserModelId\wrench" in s and "'DisplayName'" in s
    assert r"HKCU:\Software\Classes\wrench-show" in s and "'URL Protocol'" in s
    assert "-m wrench show --from-toast" in s and r"C:\Program Files\Py\pythonw.exe" in s
    assert "'activationType','protocol'" in s and "'wrench-show:open'" in s
    assert "http://localhost:8787/#notification=abc" in s  # the fallback when registering fails
    assert "it''s " in s and "[char]34" in s
    assert "$ErrorActionPreference='Stop'" in s            # so a failed write is noticed
    assert s.rstrip().endswith("::new($t))")               # the toast itself comes last

    plain = toast.windows_script("t", "b", click=False)
    assert "HKCU" not in plain and "launch" not in plain and "CreateToastNotifier('wrench')" in plain
    argv = notif.desktop_plan("t't", "body", system="Windows", url="javascript:alert(1)")
    assert argv[0] == "powershell" and "t''t" in argv[-1] and "javascript" not in argv[-1]


@pytest.mark.parametrize("text", ["plain", "it's", 'say "hi"', "a'\"'b", "", "$(calc) `whoami`; rm"])
def test_ps_literal_round_trips_without_double_quotes(text):
    lit = toast.ps_literal(text)
    assert '"' not in lit and lit.startswith("(") and lit.endswith(")")
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell:
        out = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command",
                              f"[Console]::Out.Write({lit})"], capture_output=True, text=True,
                             timeout=60).stdout
        assert out == text


@pytest.mark.skipif(not (shutil.which("pwsh") or shutil.which("powershell")),
                    reason="needs PowerShell to parse the script")
def test_windows_script_is_valid_powershell(tmp_path):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    f = tmp_path / "toast.ps1"
    f.write_text(toast.windows_script('a "b" \'c\'', "body", url="http://localhost:8787/#x"),
                 encoding="utf-8")
    check = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::"
             f"ParseFile('{f}',[ref]$t,[ref]$e);[Console]::Out.Write($e.Count)")
    out = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-Command", check],
                         capture_output=True, text=True, timeout=60).stdout
    assert out.strip() == "0"


@pytest.mark.skipif(os.name != "nt", reason="writes to the Windows registry (HKCU)")
def test_windows_registration_really_lands_in_the_registry(monkeypatch):
    import winreg
    monkeypatch.setattr(toast, "WIN_APP_ID", "wrench-selftest")
    monkeypatch.setattr(toast, "WIN_PROTOCOL", "wrench-selftest-show")
    script = toast.windows_register_script(r"C:\Program Files\Py\pythonw.exe") \
        + "[Console]::Out.Write($ok)"
    base = r"Software\Classes"
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                             capture_output=True, text=True, timeout=120)
        assert out.stdout.strip() == "True", out.stderr
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base + r"\AppUserModelId\wrench-selftest") as k:
            assert winreg.QueryValueEx(k, "DisplayName")[0] == "wrench"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base + r"\wrench-selftest-show") as k:
            assert winreg.QueryValueEx(k, "")[0] == "URL:wrench-selftest-show"
            assert winreg.QueryValueEx(k, "URL Protocol")[0] == ""
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            base + r"\wrench-selftest-show\shell\open\command") as k:
            assert winreg.QueryValueEx(k, "")[0] == \
                r'"C:\Program Files\Py\pythonw.exe" -m wrench show --from-toast'
    finally:
        for sub in (r"\wrench-selftest-show\shell\open\command", r"\wrench-selftest-show\shell\open",
                    r"\wrench-selftest-show\shell", r"\wrench-selftest-show",
                    r"\AppUserModelId\wrench-selftest"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base + sub)
            except OSError:
                pass


# ------------------------------------------------------------ Linux
def test_linux_uses_an_action_only_where_notify_send_has_them():
    assert toast.linux_supports_actions(Runner(stdout="  -A, --action=[NAME=]Text...")) is True
    assert toast.linux_supports_actions(Runner(stdout="  -u, --urgency=LEVEL")) is False
    plain = notif.desktop_plan("t", "b", system="Linux")
    assert plain[0] == "notify-send" and not any("--action" in a for a in plain)


def test_linux_click_opens_the_alert_and_a_dismissal_does_not(_env, monkeypatch):
    shown = []
    monkeypatch.setattr(toast, "show", lambda cfg, nid, **k: shown.append(nid))
    run = Runner(stdout="default\n")
    assert toast.linux_wait_and_show(_cfg(), "title; $(x)", "body", "abc123", runner=run) == "clicked"
    argv = run.calls[0]
    assert argv[0] == "notify-send" and "--action=default=Show" in argv and "--action=show=Show" in argv
    assert argv[-2:] == ["title; $(x)", "body"] and shown == ["abc123"]   # an argv, never a shell
    assert toast.linux_wait_and_show(_cfg(), "t", "b", "x", runner=Runner(stdout="")) == "dismissed"
    assert toast.linux_wait_and_show(_cfg(), "t", "b", "x", runner=Runner(rc=1)) == "failed"
    assert shown == ["abc123"]


# ------------------------------------------------------------ wrench show
def test_alert_addresses(_env):
    (_env / "cfg" / "config.toml").write_text("[general]\nweb_port = 9123\n")
    cfg = _cfg()
    assert toast.dashboard_url(cfg, "abc123") == "http://localhost:9123/#notification=abc123"
    assert toast.dashboard_url(cfg, "") == "http://localhost:9123/#notifications"
    assert toast.dashboard_url(cfg, "a/../b?<script>") == "http://localhost:9123/#notification=abscript"
    (_env / "cfg" / "config.toml").write_text('[web]\ntls_cert = "/x.pem"\n')
    assert toast.dashboard_url(_cfg(), "a1").startswith("https://localhost:8787/")


def test_show_starts_the_dashboard_only_when_needed(_env, monkeypatch):
    opened, started = [], []
    monkeypatch.setattr(toast, "dashboard_running", lambda cfg: True)
    monkeypatch.setattr(toast, "start_dashboard", lambda cfg: started.append(1) or {"ok": True})
    res = toast.show(_cfg(), "abc", opener=opened.append)
    assert res["ok"] and not res["started"] and opened == [res["url"]] and started == []

    monkeypatch.setattr(toast, "dashboard_running", lambda cfg: False)
    monkeypatch.setattr(toast, "start_dashboard",
                        lambda cfg: started.append(1) or {"ok": True, "started": True})
    res = toast.show(_cfg(), "abc", opener=opened.append)
    assert res["ok"] and res["started"] and started == [1]
    assert toast.show(_cfg(), "abc", start=False)["ok"] is False
    monkeypatch.setattr(toast, "start_dashboard", lambda cfg: {"ok": False, "detail": "port in use"})
    res = toast.show(_cfg(), "abc", opener=opened.append)
    assert not res["ok"] and "port in use" in res["detail"] and len(opened) == 2


def test_dashboard_really_starts_in_the_background_and_stops(_env):
    port = _free_port()
    (_env / "cfg" / "config.toml").write_text(f"[general]\nweb_port = {port}\n")
    cfg = _cfg()
    assert not toast.dashboard_running(cfg)
    res = toast.start_dashboard(cfg, wait_s=45,
                                argv=[sys.executable, "-m", "wrench", "web", "--no-sample"])
    try:
        assert res["ok"] and res["started"], res["detail"]
        assert toast.dashboard_running(cfg)
        assert toast.start_dashboard(cfg)["started"] is False          # never a second one
        shown = toast.show(cfg, "abc123", open_browser=False)
        assert shown == {"ok": True, "url": f"http://localhost:{port}/#notification=abc123",
                         "started": False, "detail": "ready"}
    finally:
        stopped = toast.stop_dashboard(cfg)
    assert stopped["ok"], stopped["detail"]
    assert not toast.dashboard_running(cfg) and not toast.stop_dashboard(cfg)["ok"]


@pytest.mark.skipif(os.name != "posix", reason="process inspection is POSIX-only")
def test_stop_leaves_an_unrelated_process_alone(_env):
    (_env / toast.WEB_PID).write_text(f"{os.getpid()}\n")
    res = toast.stop_dashboard(_cfg())
    assert not res["ok"] and "not touching it" in res["detail"]


def _cli(args):
    from typer.testing import CliRunner

    from wrench.cli import app
    return CliRunner().invoke(app, args)


def test_cli_show(_env, monkeypatch):
    monkeypatch.setattr(toast, "dashboard_running", lambda cfg: True)
    a = notif.record(_env, "attention", "disk /var is at 88%", kind="patrol")
    b = notif.record(_env, "critical", "backup failed", kind="patrol")
    res = _cli(["show", "--no-browser"])
    assert res.exit_code == 0 and f"#notification={b['id']}" in res.output   # the newest unread
    d = json.loads(_cli(["show", a["id"], "--no-browser", "--json"]).stdout)
    assert d["schema"] == "wrench.show.v1" and d["notification"] == a["id"] and d["ok"]
    # a clicked toast: the one that was posted, not merely the newest
    (_env / "notifier").mkdir()
    (_env / "notifier" / "last").write_text(json.dumps({"id": a["id"]}))
    assert f"#notification={a['id']}" in _cli(["show", "--from-toast", "--no-browser"]).output
    monkeypatch.setattr(toast, "dashboard_running", lambda cfg: False)
    monkeypatch.setattr(toast, "start_dashboard", lambda cfg: {"ok": False, "detail": "nope"})
    assert _cli(["show", "--no-browser"]).exit_code == 1


def test_dashboard_can_land_on_one_alert():
    import wrench
    web = Path(wrench.__file__).parent / "web"
    dash, login, css = ((web / n).read_text() for n in ("dashboard.html", "login.html", "base.css"))
    assert "h.startsWith('notification=')" in dash and "data-nid=" in dash and "wantNotif" in dash
    assert "+ location.hash" in login                       # the link survives signing in
    assert ".item.hl" in css
