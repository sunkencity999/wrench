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
    "azure": {
        # No sane default endpoint — every Azure resource has its own.
        # Set AZURE_OPENAI_ENDPOINT or [azure] endpoint in config.toml.
        "base_url": "",
        "model": "gpt-4o-mini",       # = your DEPLOYMENT name on Azure OpenAI
        "deep_model": "gpt-4o",
        "key_env": "AZURE_OPENAI_API_KEY",
        "max_tokens": 4096,
        "api_version": "2024-10-21",
    },
    "custom": {
        # Any OpenAI-compatible endpoint — vLLM, llama.cpp, TGI, a FastAPI
        # shim, your own server. No sane default base_url: every endpoint is
        # its own. Routes through the shared _openai_compat path. The API key
        # is OPTIONAL — many internal endpoints are keyless.
        "base_url": "",
        "model": "",
        "deep_model": "",
        "key_env": "CUSTOM_API_KEY",
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
    azure_api_version: str = "2024-10-21"
    azure_auth: str = "auto"  # api-key | bearer | auto (api-key first, bearer on 401)
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

    base_url = (
        os.environ.get("WRENCH_BASE_URL")
        or (os.environ.get("AZURE_OPENAI_ENDPOINT") if provider == "azure" else None)
        or psec.get("base_url")
        or psec.get("endpoint")  # [azure] section calls it "endpoint"
        or defaults["base_url"]
    )
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
        azure_api_version=(
            os.environ.get("AZURE_OPENAI_API_VERSION")
            or psec.get("api_version")
            or PROVIDER_DEFAULTS["azure"]["api_version"]
        ),
        azure_auth=str(psec.get("auth", "auto")).lower(),
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
name = "{provider}"  # ollama | lmstudio | openai | anthropic | meta | azure | litellm | custom

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

[notify]
# After each patrol, wrench taps you on the shoulder when findings meet the
# threshold: a JSONL inbox entry (CLI banner + dashboard toast), a desktop
# notification, and an optional generic JSON webhook (ntfy / Slack / Discord).
enabled = true
min_severity = "attention"   # attention | error | critical
desktop = true
# webhook_url = "https://ntfy.sh/your-topic"

[webintel]
# Built-in web intelligence: OSV.dev CVE lookups for installed packages and
# endoflife.date EOL checks. Free APIs, no keys. Results cache in sqlite;
# patrols reuse the cache and NEVER fail if the internet is down.
enable = true
cadence_hours = 24
# distro_watchlist = ["openssl", "openssh", "sudo"]  # override the curated default

[maintenance]
# Allowed change windows for EXECUTING state-changes (fixxer apply,
# blueprint --execute, certs renew --execute). Empty/missing = no windows =
# current behavior. Grammar: "<day> HH:MM-HH:MM" where day is Mon..Sun, a range
# like Mon-Fri, or * for every day; end <= start crosses midnight.
# windows  = ["Sat 02:00-06:00", "Sun 02:00-06:00"]
# timezone = "America/Los_Angeles"   # optional; local time if unset

[approvals]
# Async out-of-band approval for consent-gated changes (Slack/Teams-style),
# no server required. When a webhook URL is set, a non-interactive run mints a
# single-use token (stored HASHED in sqlite with a TTL), POSTs a pending
# approval (action, detail, token, expiry), and exits cleanly; a second channel
# runs `wrench approve <token>`. Empty/missing = off.
# approval_webhook_url = "https://hooks.example.com/wrench"
# ttl_minutes          = 60

[fleet]
# Fleet mode — many nodes, one view. Default OFF: no [fleet] = zero behavior
# change. A NODE pushes a compact signed snapshot to a HUB after each patrol;
# the HUB (`wrench fleet serve`) aggregates them into a dashboard + dead-man's
# switch. Auth is an HMAC-SHA256 shared token (generate one with
# `wrench fleet token`). Run the hub behind a TLS reverse proxy on the internet.
#
# --- node side (this box reports TO a hub) ---
# hub_url  = "http://hub.example:8788"
# token    = "<paste a `wrench fleet token` value>"
# node_id  = "web-01"            # optional; defaults to hostname
#
# --- hub side (this box RECEIVES reports) ---
# listen_host       = "127.0.0.1"
# listen_port       = 8788
# authorized_tokens = ["<node token>", "<another node token>"]
# silent_factor     = 2.0        # SILENT when last_seen > factor × cadence
# report_retention  = 200        # per-node report history cap
"""

AZURE_SECTION_TOML = """\
[azure]
# Azure OpenAI resource:   https://<resource>.openai.azure.com
# AI Foundry serverless:   https://<name>.<region>.models.ai.azure.com
endpoint = "{endpoint}"
model = "{model}"        # your DEPLOYMENT name (Azure OpenAI) / model name (Foundry)
deep_model = "{deep_model}"
api_version = "{api_version}"
auth = "auto"            # api-key | bearer | auto (api-key first, bearer on 401)
{key_line}
"""


def write_default_config(provider: str = "meta", interval: int = 15,
                         model: str | None = None,
                         deep_model: str | None = None,
                         azure_endpoint: str | None = None,
                         azure_api_version: str | None = None,
                         api_key: str | None = None,
                         base_url: str | None = None) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    d = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["meta"])
    text = DEFAULT_CONFIG_TOML.format(
        provider=provider,
        base_url=base_url or d["base_url"],
        model=model or d["model"],
        deep_model=deep_model or model or d["deep_model"],
        interval=interval,
    )
    if base_url:
        # a guided setup chose/confirmed this base URL — write it uncommented
        text = text.replace(f'# base_url = "{base_url}"', f'base_url = "{base_url}"')
    if provider == "azure":
        key_line = f'api_key = "{api_key}"' if api_key \
            else '# api_key_file = "~/.config/wrench/azure.key"  # or export AZURE_OPENAI_API_KEY'
        section = AZURE_SECTION_TOML.format(
            endpoint=(azure_endpoint or "").rstrip("/"),
            model=model or d["model"],
            deep_model=deep_model or model or d["deep_model"],
            api_version=azure_api_version or d["api_version"],
            key_line=key_line,
        )
        # replace the generic provider section with the azure-specific one
        head, _, tail = text.partition(f"[{provider}]")
        tail = tail.split("\n\n", 1)[1] if "\n\n" in tail else ""
        text = head + section + "\n" + tail
    CONFIG_PATH.write_text(text)
    if provider == "azure" and api_key:
        CONFIG_PATH.chmod(0o600)  # key inside — owner-only
    return CONFIG_PATH
