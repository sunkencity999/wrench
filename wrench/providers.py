"""Unified LLM client for wrench.

One client, seven doors: meta (default), openai, ollama, lmstudio, litellm speak
OpenAI-compatible chat completions; anthropic gets a native adapter; azure gets
an Azure OpenAI / AI Foundry adapter (deployment URLs, api-version query,
api-key header). Every call logs token usage to the store (if given one) so
`wrench web` can show spend.

Keys are never logged, never printed, never included in errors.
"""

from __future__ import annotations

import json
import time

import requests

from .config import Config


class ProviderError(RuntimeError):
    pass


def _redact(text: str, key: str) -> str:
    return text.replace(key, "<redacted>") if key else text


class LLMClient:
    def __init__(self, cfg: Config, store=None):
        self.cfg = cfg
        self.store = store
        self.last_usage: dict = {}
        # Local backends run on whatever hardware is present — a CPU-only box
        # can legitimately take minutes per reply. Don't kill it at 3 minutes.
        self.timeout = 600 if cfg.provider in ("ollama", "lmstudio") else 180

    # ---------------- public API ----------------
    def chat(
        self,
        messages: list[dict],
        model: str | None = None,
        max_tokens: int | None = None,
        temperature: float = 0.4,
        purpose: str = "chat",
        retries: int = 2,
        tools: list[dict] | None = None,
    ) -> str:
        """Send a chat; return assistant text. Raises ProviderError on failure."""
        model = model or self.cfg.model
        max_tokens = max_tokens or self.cfg.max_tokens
        last_err: Exception | None = None
        for attempt in range(retries + 1):
            try:
                if self.cfg.provider == "anthropic":
                    text, usage = self._anthropic(messages, model, max_tokens, temperature)
                elif self.cfg.provider == "azure":
                    text, usage = self._azure(messages, model, max_tokens, temperature, tools)
                elif self.cfg.provider == "ollama" and self._wants_native_nothink(model):
                    text, usage = self._ollama_native(messages, model, max_tokens, temperature)
                else:
                    text, usage = self._openai_compat(messages, model, max_tokens, temperature, tools)
                self.last_usage = usage
                if self.store is not None and usage:
                    self.store.add_tokens(
                        self.cfg.provider,
                        model,
                        usage.get("prompt_tokens", 0),
                        usage.get("completion_tokens", 0),
                        usage.get("total_tokens", 0),
                        purpose,
                    )
                return text
            except ProviderError as e:
                last_err = e
                if attempt < retries:
                    time.sleep(1.5 * (attempt + 1))
        raise ProviderError(str(last_err))

    def ping(self) -> tuple[bool, str]:
        """Cheap liveness check. Returns (ok, detail)."""
        try:
            text = self.chat(
                [{"role": "user", "content": "Reply with exactly: pong"}],
                max_tokens=2048,
                purpose="doctor-ping",
            )
            return True, text.strip()[:60]
        except Exception as e:  # noqa: BLE001
            return False, _redact(str(e), self.cfg.api_key)[:300]

    # ---------------- adapters ----------------
    def _parse_chat_response(self, d: dict):
        """Shared parser for OpenAI-shaped chat-completions responses."""
        try:
            choice = d["choices"][0]
            content = choice["message"].get("content")
            if content is None and choice.get("finish_reason") == "length":
                raise ProviderError(
                    "model spent its whole budget thinking (reasoning model) — raise max_tokens"
                )
            usage = d.get("usage") or {}
            return (content or "").strip(), usage
        except (KeyError, IndexError) as e:
            raise ProviderError(f"unexpected response shape: {list(d.keys())}") from e

    def _openai_compat(self, messages, model, max_tokens, temperature, tools=None):
        url = f"{self.cfg.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        body = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            body["tools"] = tools
        try:
            r = requests.post(url, headers=headers, json=body, timeout=self.timeout)
        except requests.RequestException as e:
            raise ProviderError(
                f"{self.cfg.provider} unreachable at {self.cfg.base_url}: {e.__class__.__name__}"
            ) from e
        if r.status_code != 200:
            raise ProviderError(
                f"{self.cfg.provider} HTTP {r.status_code}: {_redact(r.text[:300], self.cfg.api_key)}"
            )
        return self._parse_chat_response(r.json())

    # ---------------- azure (Azure OpenAI + AI Foundry serverless) ----------------
    def _azure_url_and_body_style(self, model: str) -> tuple[str, bool]:
        """Return (url, include_model_in_body).

        Two Azure endpoint families:
        - Azure OpenAI resource: https://<res>.openai.azure.com — the deployment
          name lives in the URL path and the body carries no "model".
        - AI Foundry serverless: https://<name>.<region>.models.ai.azure.com —
          plain /chat/completions with "model" in the body.
        A base_url that already contains /openai/deployments/... is used as-is.
        """
        base = self.cfg.base_url.rstrip("/")
        if "/openai/deployments/" in base:
            return f"{base}/chat/completions", False
        if ".openai.azure.com" in base or ".cognitiveservices.azure.com" in base:
            return f"{base}/openai/deployments/{model}/chat/completions", False
        # Foundry serverless (models.ai.azure.com) or anything else OpenAI-shaped
        return f"{base}/chat/completions", True

    @staticmethod
    def _azure_headers(api_key: str, mode: str) -> dict:
        h = {"Content-Type": "application/json"}
        if mode == "bearer":
            h["Authorization"] = f"Bearer {api_key}"
        else:  # api-key (Azure OpenAI's native header)
            h["api-key"] = api_key
        return h

    def _azure(self, messages, model, max_tokens, temperature, tools=None):
        if not self.cfg.base_url:
            raise ProviderError(
                "azure endpoint not configured — set AZURE_OPENAI_ENDPOINT or "
                "[azure] endpoint in config.toml"
            )
        url, model_in_body = self._azure_url_and_body_style(model)
        params = {"api-version": self.cfg.azure_api_version or "2024-10-21"}
        body = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if model_in_body:
            body["model"] = model
        if tools:
            body["tools"] = tools

        auth = (self.cfg.azure_auth or "auto").lower()
        modes = {"api-key": ["api-key"], "bearer": ["bearer"]}.get(auth, ["api-key", "bearer"])
        r = None
        for i, mode in enumerate(modes):
            headers = self._azure_headers(self.cfg.api_key, mode)
            try:
                r = requests.post(url, headers=headers, params=params, json=body,
                                  timeout=self.timeout)
            except requests.RequestException as e:
                raise ProviderError(
                    f"azure unreachable at {self.cfg.base_url}: {e.__class__.__name__}"
                ) from e
            # auto mode: a 401 on api-key may just mean this endpoint wants Bearer
            # (Foundry serverless accepts either, depending on how it was provisioned)
            if r.status_code == 401 and i + 1 < len(modes):
                continue
            break
        if r.status_code != 200:
            raise ProviderError(
                f"azure HTTP {r.status_code}: {_redact(r.text[:300], self.cfg.api_key)}"
            )
        return self._parse_chat_response(r.json())

    # ---------------- ollama native (thinking disabled) ----------------
    @staticmethod
    def _wants_native_nothink(model: str) -> bool:
        """Thinking-family local models burn their whole token budget (and, on a
        CPU box, many minutes) reasoning before one JSON line. Ollama's native
        /api/chat supports `think: false`; the OpenAI-compat endpoint doesn't."""
        return any(fam in model.lower() for fam in ("qwen3", "deepseek-r1", "magistral"))

    def _ollama_native(self, messages, model, max_tokens, temperature):
        base = self.cfg.base_url
        base = base[:-3] if base.endswith("/v1") else base
        body = {
            "model": model,
            "messages": messages,
            "stream": False,
            "think": False,
            "options": {"num_predict": max_tokens, "temperature": temperature},
        }
        try:
            r = requests.post(f"{base}/api/chat", json=body, timeout=self.timeout)
        except requests.RequestException as e:
            raise ProviderError(
                f"ollama unreachable at {base}: {e.__class__.__name__}") from e
        if r.status_code != 200:
            raise ProviderError(f"ollama HTTP {r.status_code}: {r.text[:300]}")
        d = r.json()
        text = (d.get("message", {}).get("content") or "").strip()
        pt, ct = d.get("prompt_eval_count", 0), d.get("eval_count", 0)
        return text, {"prompt_tokens": pt, "completion_tokens": ct,
                      "total_tokens": pt + ct}

    def _anthropic(self, messages, model, max_tokens, temperature):
        url = f"{self.cfg.base_url}/messages"
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.cfg.api_key,
            "anthropic-version": "2023-06-01",
        }
        system = "\n".join(m["content"] for m in messages if m["role"] == "system") or None
        convo = [m for m in messages if m["role"] != "system"]
        body = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": convo,
        }
        if system:
            body["system"] = system
        try:
            r = requests.post(url, headers=headers, json=body, timeout=180)
        except requests.RequestException as e:
            raise ProviderError(f"anthropic unreachable: {e.__class__.__name__}") from e
        if r.status_code != 200:
            raise ProviderError(
                f"anthropic HTTP {r.status_code}: {_redact(r.text[:300], self.cfg.api_key)}"
            )
        d = r.json()
        text = "".join(b.get("text", "") for b in d.get("content", []))
        u = d.get("usage", {})
        usage = {
            "prompt_tokens": u.get("input_tokens", 0),
            "completion_tokens": u.get("output_tokens", 0),
            "total_tokens": u.get("input_tokens", 0) + u.get("output_tokens", 0),
        }
        return text.strip(), usage


def extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of model text (handles ```json fences)."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()
    # fast path
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # scan for first balanced object
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            c = text[i]
            if esc:
                esc = False
                continue
            if c == "\\":
                esc = True
            elif c == '"' and not esc:
                in_str = not in_str
            elif not in_str:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start : i + 1])
                        except json.JSONDecodeError:
                            break
        start = text.find("{", start + 1)
    return None
