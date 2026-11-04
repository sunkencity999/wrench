"""Config loading for wrench.

Precedence: env vars > ~/.config/wrench/config.toml > defaults.
Never logs or prints API keys.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # py311+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

from . import platforms

# Per-OS defaults (Linux: XDG dirs; macOS: ~/Library/Application Support;
# Windows: %APPDATA% / %LOCALAPPDATA%), overridable via env.
_cfg_env = os.environ.get("WRENCH_CONFIG_DIR")
CONFIG_DIR = Path(_cfg_env).expanduser() if _cfg_env else platforms.default_config_dir()
CONFIG_PATH = CONFIG_DIR / "config.toml"
_data_env = os.environ.get("WRENCH_DATA_DIR")
DATA_DIR = Path(_data_env).expanduser() if _data_env else platforms.default_data_dir()

PROVIDER_DEFAULTS = {
    "meta": {
        "base_url": "https://api.meta.ai/v1",
        "model": "muse-spark-1.3",
        "deep_model": "muse-wonder-1.0",
        "key_env": "META_API_KEY",
        "max_tokens": 6144,  # muse models are reasoning models; they think before they speak
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "deep_model": "gpt-4o",
        "key_env": "OPENAI_API_KEY",
        "max_tokens": 4096,
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-3-5-haiku-latest",
        "deep_model": "claude-sonnet-4-20250514",
        "key_env": "ANTHROPIC_API_KEY",
        "max_tokens": 4096,
    },
    "ollama": {
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "qwen2.5:3b",    # tools-capable; guided setup picks a size for your hardware
        "deep_model": "qwen2.5:7b",
        "key_env": "OLLAMA_API_KEY",  # usually unset; ollama needs none
        "max_tokens": 4096,
    },
    "lmstudio": {
        "base_url": "http://127.0.0.1:1234/v1",
        "model": "local-model",
        "deep_model": "local-model",
        "key_env": "LMSTUDIO_API_KEY",
        "max_tokens": 4096,
    },
    "litellm": {
        "base_url": "http://127.0.0.1:4000/v1",
        "model": "gpt-4o-mini",
        "deep_model": "gpt-4o",
        "key_env": "LITELLM_API_KEY",
        "max_tokens": 4096,
    },
}


@dataclass
class Config:
    provider: str = "meta"
    base_url: str = ""
    model: str = ""
    deep_model: str = ""
    api_key: str = ""
    max_tokens: int = 6144
    policy_tier: str = "suggest"  # observe | suggest | repair | autonomous
    patrol_interval_min: int = 15
    retention_days: int = 30
    web_port: int = 8787
    raw: dict = field(default_factory=dict)

    @property
    def data_dir(self) -> Path:
        d = DATA_DIR
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def db_path(self) -> Path:
        return self.data_dir / "wrench.db"


def _read_toml() -> dict:
    if CONFIG_PATH.exists():
        try:
            return tomllib.loads(CONFIG_PATH.read_text())
        except Exception as e:  # noqa: BLE001
            print(f"wrench: warning: could not parse {CONFIG_PATH}: {e}", file=sys.stderr)
    return {}


def load_config(provider_override: str | None = None, model_override: str | None = None) -> Config:
    raw = _read_toml()
    provider = (
        provider_override
        or os.environ.get("WRENCH_PROVIDER")
        or raw.get("provider", {}).get("name")
        or raw.get("provider_name")
        or "meta"
    ).lower()
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["meta"])
    psec = raw.get(provider, {}) if isinstance(raw.get(provider), dict) else {}

    base_url = os.environ.get("WRENCH_BASE_URL") or psec.get("base_url") or defaults["base_url"]
    model = model_override or os.environ.get("WRENCH_MODEL") or psec.get("model") or defaults["model"]
    deep_model = os.environ.get("WRENCH_DEEP_MODEL") or psec.get("deep_model") or defaults["deep_model"]
    key = os.environ.get(defaults["key_env"], "") or os.environ.get("WRENCH_API_KEY", "") or psec.get("api_key", "")
    # Optional: key file path (keeps keys out of config/env entirely)
    key_file = os.environ.get("WRENCH_API_KEY_FILE") or psec.get("api_key_file")
    if not key and key_file:
        p = Path(key_file).expanduser()
        if p.exists():
            key = p.read_text().strip()

    gen = raw.get("general", {})
    pol = raw.get("policy", {})
    return Config(
        provider=provider,
        base_url=base_url.rstrip("/"),
        model=model,
        deep_model=deep_model,
        api_key=key,
        max_tokens=int(psec.get("max_tokens", defaults["max_tokens"])),
        policy_tier=os.environ.get("WRENCH_POLICY") or pol.get("tier", "suggest"),
        patrol_interval_min=int(gen.get("patrol_interval_min", 15)),
        retention_days=int(gen.get("retention_days", 30)),
        web_port=int(os.environ.get("WRENCH_WEB_PORT") or gen.get("web_port", 8787)),
        raw=raw,
    )


DEFAULT_CONFIG_TOML = """\
# wrench configuration — https://github.com/sunkencity999/wrench
# Env vars override this file. API keys are read from env first:
#   META_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY / ...
# or set api_key_file below to point at a file containing the key.

[provider]
name = "{provider}"  # meta | openai | anthropic | ollama | lmstudio | litellm

[{provider}]
# base_url = "{base_url}"
model = "{model}"
deep_model = "{deep_model}"
# api_key_file = "~/.config/wrench/{provider}.key"

[policy]
# observe   — look, never touch, never suggest commands
# suggest   — (default) diagnose and propose fixes; never executes mutations
# repair    — may run allowlisted fixes after interactive confirmation
# autonomous — may run allowlisted fixes unattended (logged, bounded)
tier = "suggest"

[general]
patrol_interval_min = {interval}
retention_days = 30
web_port = 8787

[webintel]
# Built-in web intelligence: OSV.dev CVE lookups for installed packages and
# endoflife.date EOL checks. Free APIs, no keys. Results cache in sqlite;
# patrols reuse the cache and NEVER fail if the internet is down.
enable = true
cadence_hours = 24
# distro_watchlist = ["openssl", "openssh", "sudo"]  # override the curated default
"""


def write_default_config(provider: str = "meta", interval: int = 15,
                         model: str | None = None,
                         deep_model: str | None = None) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    d = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["meta"])
    CONFIG_PATH.write_text(
        DEFAULT_CONFIG_TOML.format(
            provider=provider,
            base_url=d["base_url"],
            model=model or d["model"],
            deep_model=deep_model or model or d["deep_model"],
            interval=interval,
        )
    )
    return CONFIG_PATH
