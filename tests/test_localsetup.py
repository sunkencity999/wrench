"""Tests for the guided local-Ollama setup: resource detection,
model recommendation table, and the interactive init menu."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

from wrench import localsetup
from wrench.localsetup import Resources, recommend


# ---------------- recommendation table ----------------

@pytest.mark.parametrize(
    "ram,vram,apple,expected",
    [
        (4, None, False, "qwen2.5:1.5b"),    # tiny box
        (8, None, False, "qwen2.5:3b"),      # 8 GB RAM → small
        (16, None, False, "qwen2.5:7b"),     # 16 GB RAM → mid
        (32, None, False, "qwen2.5:14b"),    # 32 GB RAM → large
        (64, None, False, "qwen2.5:14b"),    # lots of RAM, no GPU → still 14B
        (16, 12, False, "qwen2.5:14b"),      # 12 GB VRAM → 14B even on 16 GB RAM
        (64, 24, False, "qwen3:30b"),      # 24 GB VRAM → MoE flagship
        (128, 96, False, "qwen3:30b"),     # Blackwell-class
        (16, None, True, "qwen2.5:7b"),     # 16 GB Apple Silicon → RAM rule → 8B
    ],
)
def test_recommend_tiers(ram, vram, apple, expected):
    res = Resources(ram_gb=ram, vram_gb=vram, apple_silicon=apple)
    tag, gb, reason = recommend(res)
    assert tag == expected
    assert gb > 0 and reason


def test_recommend_apple_silicon_unified_counts_as_gpu():
    # 64 GB M-series: 60% of unified = 38.4 GB effective VRAM → 30B tier
    tag, _, _ = recommend(Resources(ram_gb=64, vram_gb=None, apple_silicon=True))
    assert tag == "qwen3:30b"
    # 32 GB M-series: 19.2 GB effective → 14B tier (not the 19 GB 30B — too tight)
    tag, _, _ = recommend(Resources(ram_gb=32, vram_gb=None, apple_silicon=True))
    assert tag == "qwen2.5:14b"


def test_all_tier_tags_are_verified_tools_families():
    # every recommended tag must come from a verified tools-capable family
    for tag, gb, blurb in localsetup.TIERS:
        assert tag.startswith(("qwen2.5:", "qwen3:"))
        assert gb > 0 and blurb


# ---------------- resource detection ----------------

def _fake_vm(gib):
    return SimpleNamespace(total=int(gib * 1024**3))


def test_detect_resources_ram_only():
    with mock.patch("psutil.virtual_memory", return_value=_fake_vm(15.6)), \
         mock.patch("wrench.localsetup.shutil.which", return_value=None), \
         mock.patch("wrench.localsetup.platform.system", return_value="Linux"):
        res = localsetup.detect_resources()
    assert res.ram_gb == 15.6
    assert res.vram_gb is None
    assert not res.apple_silicon
    assert res.effective_vram_gb == 0.0


def test_detect_resources_nvidia_vram():
    smi_out = SimpleNamespace(returncode=0, stdout="97887\n32607\n")
    with mock.patch("psutil.virtual_memory", return_value=_fake_vm(128)), \
         mock.patch("wrench.localsetup.shutil.which", return_value="/usr/bin/nvidia-smi"), \
         mock.patch("wrench.localsetup.subprocess.run", return_value=smi_out), \
         mock.patch("wrench.localsetup.platform.system", return_value="Linux"):
        res = localsetup.detect_resources()
    assert res.vram_gb == pytest.approx(97887 / 1024, rel=1e-3)  # takes the LARGEST GPU
    assert recommend(res)[0] == "qwen3:30b"


def test_detect_resources_nvidia_smi_broken_is_graceful():
    with mock.patch("psutil.virtual_memory", return_value=_fake_vm(16)), \
         mock.patch("wrench.localsetup.shutil.which", return_value="/usr/bin/nvidia-smi"), \
         mock.patch("wrench.localsetup.subprocess.run", side_effect=OSError("boom")), \
         mock.patch("wrench.localsetup.platform.system", return_value="Linux"):
        res = localsetup.detect_resources()
    assert res.vram_gb is None
    assert recommend(res)[0] == "qwen2.5:7b"


def test_detect_resources_apple_silicon():
    with mock.patch("psutil.virtual_memory", return_value=_fake_vm(36)), \
         mock.patch("wrench.localsetup.shutil.which", return_value=None), \
         mock.patch("wrench.localsetup.platform.system", return_value="Darwin"), \
         mock.patch("wrench.localsetup.platform.machine", return_value="arm64"):
        res = localsetup.detect_resources()
    assert res.apple_silicon
    assert res.effective_vram_gb == pytest.approx(36 * 0.6)


# ---------------- install commands per OS ----------------

@pytest.mark.parametrize("os_name,needle", [
    ("Linux", "ollama.com/install.sh"),
    ("Windows", "winget"),
])
def test_install_commands(os_name, needle):
    with mock.patch("wrench.localsetup.platform.system", return_value=os_name):
        cmds = localsetup.install_commands()
    assert any(needle in c for c in cmds)


def test_install_commands_macos_brew_vs_manual():
    with mock.patch("wrench.localsetup.platform.system", return_value="Darwin"):
        with mock.patch("wrench.localsetup.shutil.which", return_value="/opt/homebrew/bin/brew"):
            assert any("brew install ollama" in c for c in localsetup.install_commands())
        with mock.patch("wrench.localsetup.shutil.which", return_value=None):
            assert any("ollama.com/download" in c for c in localsetup.install_commands())


# ---------------- smoke test gate ----------------

def _smoke_with_agent_result(result):
    fake_agent = mock.MagicMock()
    fake_agent.run.return_value = result
    with mock.patch("wrench.agent.Agent", return_value=fake_agent):
        return localsetup.smoke_test(mock.MagicMock(), mock.MagicMock())


def test_smoke_test_requires_tool_call():
    ok, detail = _smoke_with_agent_result(
        {"answer": "Linux 7.0", "steps": [], "tokens": 10})
    assert not ok and "no tool call" in detail


def test_smoke_test_passes_with_tool_call_and_answer():
    ok, detail = _smoke_with_agent_result(
        {"answer": "Linux 7.0.0-38-generic", "steps": [{"tool": "run_diag"}], "tokens": 99})
    assert ok and "1 tool call" in detail


def test_smoke_test_fails_on_provider_error():
    ok, detail = _smoke_with_agent_result(
        {"answer": "(provider error: x)", "steps": [], "tokens": 0, "error": "x"})
    assert not ok and "provider error" in detail


# ---------------- init menu flow (mocked TTY) ----------------

def test_choose_provider_default_enter_is_ollama():
    """Enter = first row = ollama (local-first, no brand favoritism)."""
    from wrench import cli
    with mock.patch("typer.prompt", return_value="1"):
        assert cli._choose_provider() == "ollama"


@pytest.mark.parametrize("entry,expected", [
    ("1", "ollama"),
    ("ollama", "ollama"),
    ("2", "lmstudio"),
    ("3", "openai"),
    ("ANTHROPIC", "anthropic"),
    ("5", "meta"),
    ("meta", "meta"),
    ("6", "azure"),
    ("azure", "azure"),
    ("7", "litellm"),
    ("garbage", "ollama"),   # unknown input falls back to local with a warning
])
def test_choose_provider_entries(entry, expected):
    from wrench import cli
    with mock.patch("typer.prompt", return_value=entry):
        assert cli._choose_provider() == expected


def test_init_non_interactive_defaults_to_meta(tmp_path, monkeypatch, capsys):
    """No TTY → documented functional fallback (meta) + neutral note, no menu."""
    from typer.testing import CliRunner
    from wrench import cli
    monkeypatch.setenv("WRENCH_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("WRENCH_DATA_DIR", str(tmp_path / "data"))
    # the env var is read at import: without this, init opens the real data dir
    monkeypatch.setattr("wrench.config.DATA_DIR", tmp_path / "data")
    monkeypatch.delenv("WRENCH_WEB_PASSWORD", raising=False)
    # re-point module-level paths that were resolved at import time
    cfgdir = tmp_path / "cfg"
    monkeypatch.setattr("wrench.config.CONFIG_DIR", cfgdir)
    monkeypatch.setattr("wrench.config.CONFIG_PATH", cfgdir / "config.toml")
    monkeypatch.setattr("wrench.cli.CONFIG_PATH", cfgdir / "config.toml")
    monkeypatch.setattr(cli, "_isatty", lambda: False)
    with mock.patch.object(cli, "_choose_provider") as menu, \
         mock.patch.object(cli.sensors, "sample_all"), \
         mock.patch.object(cli.driftscan, "scan"):
        result = CliRunner().invoke(cli.app, ["init"])
    assert result.exit_code == 0, result.output
    menu.assert_not_called()
    assert "functional" in result.output and "fallback" in result.output
    assert (cfgdir / "config.toml").exists()
    assert 'name = "meta"' in (cfgdir / "config.toml").read_text()


def test_init_provider_flag_skips_menu(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from wrench import cli
    cfgdir = tmp_path / "cfg"
    monkeypatch.setenv("WRENCH_CONFIG_DIR", str(cfgdir))
    monkeypatch.setenv("WRENCH_DATA_DIR", str(tmp_path / "data"))
    # the env var is read at import: without this, init opens the real data dir
    monkeypatch.setattr("wrench.config.DATA_DIR", tmp_path / "data")
    monkeypatch.delenv("WRENCH_WEB_PASSWORD", raising=False)
    monkeypatch.setattr("wrench.config.CONFIG_DIR", cfgdir)
    monkeypatch.setattr("wrench.config.CONFIG_PATH", cfgdir / "config.toml")
    monkeypatch.setattr("wrench.cli.CONFIG_PATH", cfgdir / "config.toml")
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    with mock.patch.object(cli, "_choose_provider") as menu, \
         mock.patch.object(cli.sensors, "sample_all"), \
         mock.patch.object(cli.driftscan, "scan"):
        result = CliRunner().invoke(cli.app, ["init", "-p", "openai", "-m", "gpt-4.1-mini"],
                                    input="n\n")       # the dashboard-password question
    assert result.exit_code == 0, result.output
    assert "Put a password on the web dashboard?" in result.output
    assert "no password" in result.output
    assert not (tmp_path / "data" / "web_password").exists()
    menu.assert_not_called()
    text = (cfgdir / "config.toml").read_text()
    assert 'name = "openai"' in text and 'model = "gpt-4.1-mini"' in text


def test_init_rejects_unknown_provider(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from wrench import cli
    cfgdir = tmp_path / "cfg"
    monkeypatch.setattr("wrench.config.CONFIG_DIR", cfgdir)
    monkeypatch.setattr("wrench.config.CONFIG_PATH", cfgdir / "config.toml")
    monkeypatch.setattr("wrench.cli.CONFIG_PATH", cfgdir / "config.toml")
    result = CliRunner().invoke(cli.app, ["init", "-p", "skynet"])
    assert result.exit_code == 1
    assert "unknown provider" in result.output


def test_init_ollama_runs_guided_setup_and_smoke(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from wrench import cli
    cfgdir = tmp_path / "cfg"
    monkeypatch.setenv("WRENCH_CONFIG_DIR", str(cfgdir))
    monkeypatch.setenv("WRENCH_DATA_DIR", str(tmp_path / "data"))
    # the env var is read at import: without this, init opens the real data dir
    monkeypatch.setattr("wrench.config.DATA_DIR", tmp_path / "data")
    monkeypatch.delenv("WRENCH_WEB_PASSWORD", raising=False)
    monkeypatch.setattr("wrench.config.CONFIG_DIR", cfgdir)
    monkeypatch.setattr("wrench.config.CONFIG_PATH", cfgdir / "config.toml")
    monkeypatch.setattr("wrench.cli.CONFIG_PATH", cfgdir / "config.toml")
    monkeypatch.setattr(cli, "_isatty", lambda: True)
    with mock.patch.object(cli, "_ollama_guided_setup",
                           return_value="qwen2.5:7b") as guided, \
         mock.patch("wrench.localsetup.server_alive", return_value=True), \
         mock.patch("wrench.localsetup.smoke_test",
                    return_value=(True, "1 tool call(s)")) as smoke, \
         mock.patch.object(cli.sensors, "sample_all"), \
         mock.patch.object(cli.driftscan, "scan"):
        result = CliRunner().invoke(cli.app, ["init", "-p", "ollama", "--yes"])
    assert result.exit_code == 0, result.output
    guided.assert_called_once()
    smoke.assert_called_once()
    assert "smoke test passed" in result.output
    text = (cfgdir / "config.toml").read_text()
    assert 'name = "ollama"' in text and 'model = "qwen2.5:7b"' in text
