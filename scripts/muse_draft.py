#!/usr/bin/env python3
"""Hackathon helper: ask muse models for copy drafts. Reads key from credentials
file into env; never prints it. Logs token usage to the workspace burn log."""
import json
import os
import sys
import time
from pathlib import Path

import requests

KEY_FILE = Path.home() / ".openclaw/credentials/meta_llama_api_key.txt"
LOG = Path.home() / ".openclaw/workspace/reports/state/wrench_hackathon_tokens.md"

os.environ.setdefault("META_API_KEY", KEY_FILE.read_text().strip())


def ask(prompt: str, model: str = "muse-wonder-1.0", max_tokens: int = 8000, temp: float = 0.8) -> str:
    r = requests.post(
        "https://api.meta.ai/v1/chat/completions",
        headers={"Authorization": f"Bearer {os.environ['META_API_KEY']}"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}],
              "max_tokens": max_tokens, "temperature": temp},
        timeout=600,
    )
    d = r.json()
    if "choices" not in d:
        raise SystemExit(f"API error: {json.dumps(d)[:200]}")
    u = d.get("usage", {})
    with LOG.open("a") as f:
        f.write(f"| {time.strftime('%Y-%m-%d %H:%M')} | {model} | {u.get('prompt_tokens',0)} | "
                f"{u.get('completion_tokens',0)} | {u.get('total_tokens',0)} | copy-draft |\n")
    return d["choices"][0]["message"]["content"] or ""


if __name__ == "__main__":
    prompt = sys.stdin.read()
    model = sys.argv[1] if len(sys.argv) > 1 else "muse-wonder-1.0"
    print(ask(prompt, model=model))
