"""Model enrollment — connect a hosted model provider and pick a model from
what the account can actually use.

    wrench model setup            choose a provider, paste a key, pick a model
    wrench model list             what this key can use, newest first
    wrench model use <model>      switch model
    wrench model logout           forget the stored key

What "sign in" means here. Anthropic and Google do not let a third-party
tool use a consumer subscription login, and OpenAI's "Sign in with ChatGPT"
needs a client id issued to the project. The credential every provider
supports for a tool like this is an API key from the provider's console, so
enrollment opens that page, takes the key at a hidden prompt, proves it works
by listing the account's models, and stores it owner-only.

Nothing is hard-coded about which models exist: the list always comes from
the provider, live. The suggestions (a fast model for patrols, a strong one
for `--deep`) are name heuristics over that list and are only suggestions.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import requests

from .providers import _redact

# The hosted providers enrollment knows how to walk someone through.
CLOUD = {
    "anthropic": {
        "label": "Anthropic — Claude",
        "key_url": "https://console.anthropic.com/settings/keys",
        "key_hint": "starts with sk-ant-",
        "account": "an Anthropic Console account with billing (a Claude.ai subscription "
                   "is separate and cannot be used by other tools)",
    },
    "openai": {
        "label": "OpenAI — GPT",
        "key_url": "https://platform.openai.com/api-keys",
        "key_hint": "starts with sk-",
        "account": "an OpenAI Platform account with billing (a ChatGPT subscription is "
                   "separate)",
    },
    "google": {
        "label": "Google — Gemini",
        "key_url": "https://aistudio.google.com/apikey",
        "key_hint": "from Google AI Studio",
        "account": "a Google account; AI Studio issues the key",
    },
}

# ids that are not chat models, by provider family
_NOT_CHAT = re.compile(
    # stems (match as a prefix of a word) …
    r"embed|whisper|dall-e|moderation|realtime|transcri|imagen|"
    # … and whole words, so "live" does not hit "deliver" or "mini" hit "gemini"
    r"(?<![a-z])(?:tts|audio|image|veo|speech|search|aqa|live|sora|guard|rerank|instruct|"
    r"babbage|davinci|computer-use|vision-preview)(?![a-z])", re.I)
_FAST = re.compile(r"(?<![a-z])(?:haiku|mini|nano|flash|lite|small|instant|spark)(?![a-z])", re.I)


class EnrollError(Exception):
    """A failure the operator can act on. ``kind``: auth | network | http |
    offline | config."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class Model:
    id: str
    name: str = ""
    created: float = 0.0

    @property
    def fast(self) -> bool:
        return bool(_FAST.search(self.id))


# ---------------------------------------------------------------- listing
def _created(v) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and v:
        try:
            from datetime import datetime
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def _version_key(model_id: str) -> tuple:
    """Order ids by the numbers in them when the provider gives no dates."""
    return tuple(float(n) for n in re.findall(r"\d+(?:\.\d+)?", model_id)[:4])


def is_chat_model(provider: str, model_id: str) -> bool:
    if _NOT_CHAT.search(model_id):
        return False
    if provider == "google":
        return "gemini" in model_id.lower() or "gemma" in model_id.lower()
    if provider == "openai":
        return bool(re.match(r"(gpt-|o\d|chatgpt-)", model_id))
    return True


def list_models(provider: str, base_url: str, api_key: str, timeout: float = 20,
                http=requests) -> list[Model]:
    """Ask the provider which models this key can use: chat models only,
    newest first. Raises EnrollError."""
    base = (base_url or "").rstrip("/")
    if not base:
        raise EnrollError("config", f"no base URL is set for {provider}")
    headers = {"User-Agent": "wrench"}
    params: dict = {}
    if provider == "anthropic":
        headers.update({"x-api-key": api_key, "anthropic-version": "2023-06-01"})
        params = {"limit": 100}
    elif api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    out: list[Model] = []
    seen: set[str] = set()
    for _page in range(10):
        try:
            r = http.get(f"{base}/models", headers=headers, params=params, timeout=timeout)
        except requests.RequestException as e:
            raise EnrollError("network", f"could not reach {provider} at {base} "
                                         f"({e.__class__.__name__})") from e
        if r.status_code in (401, 403):
            raise EnrollError("auth", f"{provider} did not accept that key (HTTP "
                                      f"{r.status_code}). Check it was copied whole and "
                                      "that the account has API access.")
        if r.status_code != 200:
            raise EnrollError("http", f"{provider} answered HTTP {r.status_code}: "
                                      + _redact(str(r.text)[:200], api_key))
        try:
            d = r.json()
        except ValueError as e:
            raise EnrollError("http", f"{provider} sent something that is not JSON") from e
        rows = d.get("data") if isinstance(d, dict) else d
        if not isinstance(rows, list):
            rows = (d.get("models") if isinstance(d, dict) else None) or []
        for m in rows:
            if not isinstance(m, dict):
                continue
            mid = str(m.get("id") or m.get("name") or "")
            if mid.startswith("models/"):          # Gemini lists "models/gemini-…"
                mid = mid[len("models/"):]
            if not mid or mid in seen or not is_chat_model(provider, mid):
                continue
            seen.add(mid)
            out.append(Model(id=mid, name=str(m.get("display_name") or m.get("displayName") or ""),
                             created=_created(m.get("created_at", m.get("created")))))
        if provider == "anthropic" and isinstance(d, dict) and d.get("has_more") \
                and d.get("last_id"):
            params = {"limit": 100, "after_id": d["last_id"]}
            continue
        break
    out.sort(key=lambda m: (m.created, _version_key(m.id), m.id), reverse=True)
    return out


def suggest(models: list[Model]) -> tuple[str, str]:
    """(everyday model, deep model) from a newest-first list. Patrols run every
    few minutes, so the everyday pick is the newest *fast* model when there is
    one; the deep pick is the newest model that is not a fast variant."""
    if not models:
        return "", ""
    fast = next((m.id for m in models if m.fast), "")
    strong = next((m.id for m in models if not m.fast), "")
    return (fast or strong or models[0].id), (strong or fast or models[0].id)


# ---------------------------------------------------------------- key storage
def key_path(provider: str) -> Path:
    from . import config
    return Path(config.CONFIG_DIR) / f"{provider}.key"


def clean_key(raw: str) -> str:
    """What was pasted, minus the wrapping people paste along with it."""
    k = (raw or "").strip().strip("\"'").strip()
    if k.lower().startswith("bearer "):
        k = k[7:].strip()
    return k


def key_problem(key: str) -> str | None:
    if not key:
        return "no key was entered"
    if any(c.isspace() for c in key) or len(key) < 16 or len(key) > 512:
        return "that does not look like an API key (it should be one long string, no spaces)"
    if not key.isascii():
        return "that key contains characters an API key cannot have"
    return None


def save_key(provider: str, key: str) -> Path:
    """Store the key owner-only, written whole (never half a key on disk)."""
    path = key_path(provider)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(key + "\n")
    if os.name == "posix":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def remove_key(provider: str) -> bool:
    try:
        key_path(provider).unlink()
        return True
    except FileNotFoundError:
        return False


def key_source(provider: str, raw: dict | None = None) -> tuple[str, str]:
    """Where this provider's key would come from: (source, key). source is
    'env:<NAME>' | 'file' | 'config' | ''."""
    from . import config
    d = config.PROVIDER_DEFAULTS.get(provider, {})
    for name in [d.get("key_env", "")] + list(d.get("key_env_alt", [])) + ["WRENCH_API_KEY"]:
        if name and os.environ.get(name):
            return f"env:{name}", os.environ[name].strip()
    sec = (raw or {}).get(provider, {})
    sec = sec if isinstance(sec, dict) else {}
    if sec.get("api_key"):
        return "config", str(sec["api_key"]).strip()
    kf = sec.get("api_key_file")
    for p in ([Path(str(kf)).expanduser()] if kf else []) + [key_path(provider)]:
        try:
            k = p.read_text(encoding="utf-8").strip()
            if k:
                return "file", k
        except OSError:
            continue
    return "", ""


# ---------------------------------------------------------------- applying
def apply(provider: str, model: str, deep_model: str = "", key_file: Path | None = None) -> Path:
    """Make ``provider``/``model`` the configured brain. Keeps the rest of the
    config, comments included."""
    from . import config
    if not config.CONFIG_PATH.exists():
        config.write_default_config(provider, model=model, deep_model=deep_model or model)
    config.set_section_values("provider", {"name": provider})
    values: dict = {"model": model, "deep_model": deep_model or model}
    if key_file is not None:
        values["api_key_file"] = str(key_file)
    return config.set_section_values(provider, values)


def status(cfg) -> dict:
    src, key = key_source(cfg.provider, getattr(cfg, "raw", None))
    return {
        "provider": cfg.provider, "model": cfg.model, "deep_model": cfg.deep_model,
        "base_url": cfg.base_url, "hosted": cfg.provider in CLOUD,
        "key": {"present": bool(key or cfg.api_key), "source": src or
                ("config" if cfg.api_key else "")},
    }
