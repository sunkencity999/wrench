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
        # fallbacks only — `wrench model setup` picks from the account's live list
        "model": "claude-haiku-5-5",
        "deep_model": "claude-opus-5-5",
        "key_env": "ANTHROPIC_API_KEY",
        "max_tokens": 4096,
    },
    "google": {
        # Gemini through Google's OpenAI-compatible endpoint (key from AI Studio)
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash",
        "deep_model": "gemini-2.5-pro",
        "key_env": "GEMINI_API_KEY",
        "key_env_alt": ["GOOGLE_API_KEY"],
        "max_tokens": 6144,
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
    offline: bool = False  # declared zero-egress mode (see wrench/offline.py)
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
            return tomllib.loads(CONFIG_PATH.read_text(encoding="utf-8"))
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
    key = (os.environ.get(defaults["key_env"], "")
           or next((os.environ[n] for n in defaults.get("key_env_alt", []) if os.environ.get(n)), "")
           or os.environ.get("WRENCH_API_KEY", "") or psec.get("api_key", ""))
    # Optional: key file path (keeps keys out of config/env entirely)
    key_file = os.environ.get("WRENCH_API_KEY_FILE") or psec.get("api_key_file")
    if not key and key_file:
        p = Path(key_file).expanduser()
        if p.exists():
            key = p.read_text().strip()

    gen = raw.get("general", {})
    pol = raw.get("policy", {})
    # offline mode: [general] offline, or a top-level offline, or WRENCH_OFFLINE
    _off_env = os.environ.get("WRENCH_OFFLINE")
    offline = (
        (_off_env.strip().lower() in ("1", "true", "yes", "on"))
        if _off_env is not None
        else bool(gen.get("offline", raw.get("offline", False)))
    )
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
        offline=offline,
        raw=raw,
    )


DEFAULT_CONFIG_TOML = """\
# wrench configuration — https://github.com/sunkencity999/wrench
# Env vars override this file. API keys are read from env first:
#   META_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY / ...
# or set api_key_file below to point at a file containing the key.

[provider]
name = "{provider}"  # ollama | lmstudio | openai | anthropic | google | meta | azure | litellm | custom
# hosted provider? `wrench model setup` takes the key, lists the models your
# account can use, and fills in the section below.

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
# What it may run is a fixed catalog: `wrench commands`. To shape it:
# sudo = true                       # accept a `sudo -n ` prefix (never prompts)
# disabled_packs = ["net-probe"]    # switch whole packs off
# allow_diag = ["zpool status -v"]  # your own read-only commands, exact text
# allow_fix = ["systemctl restart myapp"]   # your own fixes, exact text

[general]
patrol_interval_min = {interval}
retention_days = 30
web_port = 8787
# Air-gap / offline-first: when true, wrench NEVER reaches a public host.
# OSV/CVE, endoflife.date, webintel, update checks, and provider calls to
# non-private base_urls are refused with a clear message; the local brain
# (loopback/LAN), fleet push to a private hub, and every local check still
# work. Default false = zero behavior change. (env: WRENCH_OFFLINE=1)
# offline = false

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

[memory]
# What wrench remembers (`wrench remember`, `wrench memory`). Notes the agent
# writes while nobody is present wait for `wrench memory review`.
# enabled      = true
# agent_writes = "review"   # or "off": refuse unattended notes outright
# learn_habits = true       # learn from your approvals and your routines

[heartbeat]
# Scheduled work (`wrench jobs`, started by `wrench install-service`).
# enabled          = true
# max_tier         = "suggest"   # the most a scheduled `ask` job may do
# job_timeout_s    = 900
# propose_routines = true        # offer to schedule what you do by hand each day

[web]
# The dashboard (`wrench web`). Put a password on it with `wrench password`
# (it is not a config key: only a salted hash is kept, in the data dir). With
# no password, 127.0.0.1 needs no sign-in, and any other bind address needs a
# token on every page and API call — if you set none, one is generated and
# stored owner-only in the data dir.
# bind         = "127.0.0.1"
# auth_token   = "<long random string>"   # full access (or env WRENCH_WEB_TOKEN)
# viewer_token = "<another>"              # read-only: no chat, no changes
# allowed_hosts = ["wrench.example.com"]  # extra Host names to answer to
# tls_cert = "/etc/wrench/tls/fullchain.pem"
# tls_key  = "/etc/wrench/tls/privkey.pem"
# allow_tier_raise = false   # true: admins may raise the policy tier from the
#                            # dashboard (otherwise: `wrench policy <tier>`)

[fleet]
# Fleet mode — many machines, one console. Default OFF.
#
#   guided:       wrench fleet setup           (or ask in `wrench chat`)
#   on the hub:   wrench password              (the dashboard password)
#                 wrench fleet serve --host 0.0.0.0
#   on each node: wrench fleet connect <hub-address>    (asks for that password
#                 once, gets this machine its own key, writes the lines below)
#   or with keys: wrench fleet enroll → wrench fleet join <hub-url> <key>
#
# Every report is HMAC-signed with a timestamp; the hub rejects replays, stale
# clocks, revoked keys, and a node id claimed by a different key.
#
# --- node side (written by `wrench fleet connect` / `join`) ---
# hub_url  = "https://hub.example:8788"
# token    = "wfl_…"
# node_id  = "web-01"            # optional; defaults to hostname
# tags     = ["prod", "web"]     # optional; searchable in the fleet console
# ca_file  = "/etc/ssl/corp-ca.pem"   # optional; for a hub with a private cert
#
# --- hub side ---
# listen_host       = "127.0.0.1"
# listen_port       = 8788
# tls_cert          = "/etc/wrench/tls/fullchain.pem"
# tls_key           = "/etc/wrench/tls/privkey.pem"
# silent_factor     = 2.0        # SILENT when last report > factor × cadence
# max_skew_s        = 300        # accepted clock difference between node and hub
# report_retention  = 200        # per-node report history cap
# connect           = true       # false: refuse `wrench fleet connect` (keys only)
# authorized_tokens = ["…"]      # legacy 2.x shared tokens (still accepted)
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
    CONFIG_PATH.write_text(text, encoding="utf-8")
    if os.name == "posix":
        CONFIG_PATH.chmod(0o600)  # may hold an API key or a fleet key — owner-only
    return CONFIG_PATH


def _toml_value(v) -> str:
    """A scalar/list as TOML (strings are JSON-escaped, which is valid TOML)."""
    import json as _json
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    # JSON string escaping is valid TOML, except that JSON writes astral
    # characters as surrogate pairs — keep non-ASCII literal instead
    return _json.dumps(str(v), ensure_ascii=False)


def set_policy_tier(tier: str, path: Path | None = None) -> Path:
    """Persist ``[policy] tier``. Raises ValueError for an unknown tier."""
    from .policy import TIERS
    tier = str(tier or "").strip().lower()
    if tier not in TIERS:
        raise ValueError(f"unknown tier '{tier}' — one of: {', '.join(TIERS)}")
    return set_section_values("policy", {"tier": tier}, path)


def policy_env_override() -> str:
    """The tier forced by the WRENCH_POLICY environment variable, or ''. While
    it is set, the config file's tier is ignored."""
    return (os.environ.get("WRENCH_POLICY") or "").strip().lower()


def set_section_values(section: str, values: dict, path: Path | None = None) -> Path:
    """Set keys in one ``[section]`` of config.toml, preserving everything else.

    A line-level edit rather than a parse-and-rewrite, so the comments that
    document the file survive. Existing (uncommented) keys are replaced in
    place; new keys are inserted right under the section header; a missing
    section (or file) is created. The file is made owner-only, because this is
    how secrets such as a fleet enrollment key get written.
    """
    import os as _os
    import re as _re
    path = Path(path) if path is not None else CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    header = _re.compile(r"^\s*\[([^\[\]]+)\]\s*(#.*)?$")
    # any table header ends a section — including [[array.of.tables]]
    boundary = _re.compile(r"^\s*\[")
    start = next((i for i, ln in enumerate(lines)
                  if (m := header.match(ln)) and m.group(1).strip() == section), None)
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"[{section}]")
        start = len(lines) - 1
    def _is_boundary(i: int) -> bool:
        # a "[" line is a table header unless it is the continuation of a
        # multi-line array value (those are indented or follow an open bracket)
        return bool(boundary.match(lines[i])) and not _in_multiline(lines, start + 1, i)

    end = next((i for i in range(start + 1, len(lines)) if _is_boundary(i)), len(lines))
    pending = dict(values)
    i = start + 1
    while i < end:
        m = _re.match(r"^\s*([A-Za-z0-9_\-]+)\s*=", lines[i])
        if m and m.group(1) in pending and not _in_multiline(lines, start + 1, i):
            # replace the whole value, including any continuation lines of a
            # multi-line array it used to span
            span = 1
            while i + span < end and _open_brackets("\n".join(lines[i:i + span])) > 0:
                span += 1
            lines[i:i + span] = [f"{m.group(1)} = {_toml_value(pending.pop(m.group(1)))}"]
            end -= span - 1
        i += 1
    insert = [f"{k} = {_toml_value(v)}" for k, v in pending.items()]
    lines[start + 1:start + 1] = insert
    text = "\n".join(lines) + "\n"
    try:
        tomllib.loads(text)                   # never write a config we cannot read back
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"could not update [{section}] in {path} without breaking it "
                         f"({e}) — edit the file by hand") from None
    tmp = path.with_suffix(".toml.tmp")
    # created owner-only from the first byte: this file may carry a secret
    fd = _os.open(tmp, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
    with _os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    if _os.name == "posix":
        _os.chmod(tmp, 0o600)
    _os.replace(tmp, path)
    return path


def _open_brackets(text: str) -> int:
    """Net unclosed '[' in TOML text, ignoring brackets inside strings/comments."""
    depth, quote = 0, ""
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 1
            elif ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            nl = text.find("\n", i)
            i = len(text) if nl < 0 else nl
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        i += 1
    return depth


def _in_multiline(lines: list[str], first: int, i: int) -> bool:
    """Is line ``i`` inside a multi-line array value that began at/after ``first``?"""
    depth = 0
    for j in range(first, i):
        ln = lines[j]
        if depth == 0 and "=" not in ln.split("#", 1)[0]:
            continue                      # header / comment / blank: not a value
        depth = max(0, depth + _open_brackets(ln))
    return depth > 0
