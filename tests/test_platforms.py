"""Platform abstraction tests — every OS branch, mocked where we can't run natively."""

from pathlib import Path

import pytest

from wrench import platforms


@pytest.mark.parametrize("sys_platform,expected", [
    ("linux", "linux"),
    ("linux2", "linux"),
    ("darwin", "macos"),
    ("win32", "windows"),
    ("cygwin", "windows"),
    ("sunos5", "unknown"),
])
def test_current_platform(monkeypatch, sys_platform, expected):
    monkeypatch.setattr(platforms.sys, "platform", sys_platform)
    assert platforms.current_platform() == expected


def test_linux_dirs_follow_xdg(monkeypatch, tmp_path):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    assert platforms.default_config_dir() == tmp_path / "cfg" / "wrench"
    assert platforms.default_data_dir() == tmp_path / "data" / "wrench"


def test_linux_dirs_default(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert platforms.default_config_dir() == Path.home() / ".config" / "wrench"
    assert platforms.default_data_dir() == Path.home() / ".local" / "share" / "wrench"


def test_macos_dirs(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "darwin")
    expected = Path.home() / "Library" / "Application Support" / "wrench"
    assert platforms.default_config_dir() == expected
    assert platforms.default_data_dir() == expected


def test_windows_dirs(monkeypatch, tmp_path):
    monkeypatch.setattr(platforms.sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert platforms.default_config_dir() == tmp_path / "Roaming" / "wrench"
    assert platforms.default_data_dir() == tmp_path / "Local" / "wrench"


def test_windows_dirs_fallback_without_env(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "win32")
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    assert "wrench" in str(platforms.default_config_dir())
    assert "wrench" in str(platforms.default_data_dir())


def test_primary_mount(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    assert platforms.primary_mount() == "/"
    monkeypatch.setattr(platforms.sys, "platform", "win32")
    monkeypatch.setenv("SystemDrive", "D:")
    assert platforms.primary_mount() == "D:\\"


def test_service_manager_per_platform(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    monkeypatch.setattr(platforms, "has", lambda c: c == "systemctl")
    assert platforms.service_manager() == "systemd"
    monkeypatch.setattr(platforms.sys, "platform", "darwin")
    monkeypatch.setattr(platforms, "has", lambda c: c == "launchctl")
    assert platforms.service_manager() == "launchd"
    monkeypatch.setattr(platforms.sys, "platform", "win32")
    monkeypatch.setattr(platforms, "has", lambda c: c == "schtasks")
    assert platforms.service_manager() == "schtasks"
    monkeypatch.setattr(platforms, "has", lambda c: False)
    assert platforms.service_manager() is None


def test_log_backend_per_platform(monkeypatch):
    monkeypatch.setattr(platforms.sys, "platform", "linux")
    monkeypatch.setattr(platforms, "has", lambda c: c == "journalctl")
    assert platforms.log_backend() == "journald"
    monkeypatch.setattr(platforms.sys, "platform", "darwin")
    monkeypatch.setattr(platforms, "has", lambda c: c == "log")
    assert platforms.log_backend() == "unified_log"
    monkeypatch.setattr(platforms.sys, "platform", "win32")
    monkeypatch.setattr(platforms, "has", lambda c: c == "wevtutil")
    assert platforms.log_backend() == "windows_event_log"
    monkeypatch.setattr(platforms, "has", lambda c: False)
    assert platforms.log_backend() is None


def test_capabilities_shape():
    caps = platforms.capabilities()
    assert caps["platform"] in ("linux", "macos", "windows", "unknown")
    for key in ("service_manager", "log_backend", "docker", "smartctl"):
        assert key in caps
