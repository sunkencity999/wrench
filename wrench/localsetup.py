"""Guided local-model setup (Ollama).

Detects machine resources (RAM, NVIDIA VRAM, Apple Silicon unified memory),
recommends a tool-calling-capable model tier, installs Ollama (with explicit
consent — never silently), pulls the model, and runs a real tool-calling
smoke test through the wrench agent loop before declaring success.

Model tiers: the CPU-feasible tiers use the qwen2.5 family — tools-capable
and NON-thinking, which matters: thinking-family models (qwen3 hybrids) burn
thousands of reasoning tokens per reply, i.e. many minutes per turn on a
CPU-only box (measured live: qwen3:4b spent 4k tokens / ~7 min on one tool
call at ~10 tok/s). The 24 GB+ GPU tier uses the qwen3:30b MoE, which is fast
on real GPU hardware. All tags + `tools` capability verified against
ollama.com/library (qwen2.5, qwen3, llama3.2) on 2026-11-04; llama3.2:3b is a
documented tool-use alternative for the small tier.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass

import requests

OLLAMA_URL = "http://127.0.0.1:11434"

# (tag, approx download GiB, blurb) — ordered small → large.
# Tags + tools capability verified on ollama.com/library (2026-11-04).
TIERS = [
    ("qwen2.5:1.5b", 1.0, "tiny — fits anywhere, fine for short diagnostics"),
    ("qwen2.5:3b", 1.9, "small — good tool use, comfortable on 8 GB RAM"),
    ("qwen2.5:7b", 4.7, "mid — solid reasoning, wants 16 GB RAM"),
    ("qwen2.5:14b", 9.0, "large — strong, wants 32 GB RAM or a 12 GB+ GPU"),
    ("qwen3:30b", 19.0, "MoE flagship — fast on a 24 GB+ GPU"),
]


@dataclass
class Resources:
    ram_gb: float
    vram_gb: float | None  # NVIDIA dedicated VRAM (largest GPU), if any
    apple_silicon: bool = False

    @property
    def effective_vram_gb(self) -> float:
        """GPU-addressable memory. Apple Silicon shares RAM with the GPU;
        count ~60% of unified memory as safely usable for a model."""
        if self.vram_gb:
            return self.vram_gb
        if self.apple_silicon:
            return self.ram_gb * 0.6
        return 0.0


def detect_resources() -> Resources:
    import psutil

    ram_gb = psutil.virtual_memory().total / (1024**3)
    vram_gb: float | None = None
    apple = platform.system() == "Darwin" and platform.machine() == "arm64"

    smi = shutil.which("nvidia-smi")
    if smi:
        try:
            out = subprocess.run(
                [smi, "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
            )
            if out.returncode == 0:
                vals = [float(x) for x in out.stdout.split() if x.strip().replace(".", "").isdigit()]
                if vals:
                    vram_gb = max(vals) / 1024  # MiB → GiB
        except (OSError, subprocess.SubprocessError, ValueError):
            pass

    if apple and ram_gb <= 0:  # pragma: no cover - paranoia
        try:
            out = subprocess.run(["sysctl", "-n", "hw.memsize"],
                                 capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
            ram_gb = int(out.stdout.strip()) / (1024**3)
        except (OSError, subprocess.SubprocessError, ValueError):
            pass

    return Resources(ram_gb=round(ram_gb, 1), vram_gb=vram_gb, apple_silicon=apple)


def recommend(res: Resources) -> tuple[str, float, str]:
    """Return (model_tag, approx_gb, reason)."""
    vram = res.effective_vram_gb
    if vram >= 24:
        tag, gb, blurb = TIERS[4]
        reason = f"{vram:.0f} GB GPU memory — the 30B MoE will fly"
    elif vram >= 12 or res.ram_gb >= 32:
        tag, gb, blurb = TIERS[3]
        reason = (f"{vram:.0f} GB GPU memory" if vram >= 12
                  else f"{res.ram_gb:.0f} GB RAM") + " — 14B class fits well"
    elif res.ram_gb >= 16:
        tag, gb, blurb = TIERS[2]
        reason = f"{res.ram_gb:.0f} GB RAM — 8B class is the sweet spot"
    elif res.ram_gb >= 8:
        tag, gb, blurb = TIERS[1]
        reason = f"{res.ram_gb:.0f} GB RAM — 4B class keeps headroom"
    else:
        tag, gb, blurb = TIERS[0]
        reason = f"{res.ram_gb:.0f} GB RAM — stay tiny"
    return tag, gb, f"{reason} ({blurb})"


# ---------------- ollama presence ----------------

def ollama_binary() -> str | None:
    return shutil.which("ollama")


def server_alive(base: str = OLLAMA_URL) -> bool:
    try:
        return requests.get(f"{base}/api/version", timeout=3).status_code == 200
    except requests.RequestException:
        return False


def installed_models(base: str = OLLAMA_URL) -> list[str]:
    try:
        r = requests.get(f"{base}/api/tags", timeout=5)
        r.raise_for_status()
        return [m.get("name", "") for m in r.json().get("models", [])]
    except (requests.RequestException, ValueError):
        return []


def install_commands() -> list[str]:
    """The official installer command(s) for this OS (shown to the user first)."""
    os_name = platform.system()
    if os_name == "Linux":
        return ["curl -fsSL https://ollama.com/install.sh | sh"]
    if os_name == "Darwin":
        if shutil.which("brew"):
            return ["brew install ollama", "brew services start ollama"]
        return ["open https://ollama.com/download/mac  (download + drag to Applications)"]
    if os_name == "Windows":
        return ["winget install -e --id Ollama.Ollama"]
    return []


def run_install() -> bool:
    """Run the official installer. Returns True on success."""
    os_name = platform.system()
    try:
        if os_name == "Linux":
            return subprocess.run(
                "curl -fsSL https://ollama.com/install.sh | sh",
                shell=True, timeout=900).returncode == 0
        if os_name == "Darwin":
            if shutil.which("brew"):
                ok = subprocess.run(["brew", "install", "ollama"], timeout=900).returncode == 0
                if ok:
                    subprocess.run(["brew", "services", "start", "ollama"], timeout=120)
                return ok
            subprocess.run(["open", "https://ollama.com/download/mac"], timeout=30)
            return False  # manual step; caller re-checks
        if os_name == "Windows":
            return subprocess.run(
                ["winget", "install", "-e", "--id", "Ollama.Ollama"],
                timeout=900).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    return False


def pull_model(tag: str) -> bool:
    """`ollama pull <tag>` streaming progress to the terminal."""
    try:
        return subprocess.run(["ollama", "pull", tag], stdout=sys.stderr,
                              timeout=3600).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ------- OpenAI-compatible local servers (LM Studio, LiteLLM) -------

def openai_server_alive(base_url: str) -> bool:
    """True if an OpenAI-compatible server answers GET <base>/models."""
    try:
        return requests.get(f"{base_url.rstrip('/')}/models",
                            timeout=3).status_code == 200
    except requests.RequestException:
        return False


def openai_models(base_url: str) -> list[str]:
    """Model ids from an OpenAI-compatible /models endpoint
    ({"data": [{"id": ...}, ...]}). Empty list on any failure."""
    try:
        r = requests.get(f"{base_url.rstrip('/')}/models", timeout=5)
        r.raise_for_status()
        data = r.json().get("data", [])
        return [m.get("id", "") for m in data if isinstance(m, dict) and m.get("id")]
    except (requests.RequestException, ValueError, AttributeError):
        return []


# ---------------- smoke test ----------------

def smoke_test(cfg, store) -> tuple[bool, str]:
    """One real tool-calling round-trip through the wrench agent loop.

    Passes only if the agent made ≥1 tool call AND produced a non-error answer.
    """
    from . import agent as agent_mod

    a = agent_mod.Agent(cfg, store)
    # The probe must be unanswerable from context alone, or small models will
    # skip the tool call (the system prompt already names the OS/host).
    probe = ("Setup smoke test: use the run_diag tool to execute exactly "
             "`date +%s` (on Windows: `echo %RANDOM%`), then reply with a final "
             "answer of one sentence that quotes the exact number it printed.")
    try:
        res = a.run(probe, purpose="local-setup-smoke", max_steps=3)
    except Exception as e:  # noqa: BLE001
        return False, f"agent loop crashed: {e}"
    if res.get("error"):
        return False, f"provider error: {res['error']}"
    if not res.get("steps"):
        return False, "model answered but made no tool call — tool protocol not followed"
    answer = (res.get("answer") or "").strip()
    if not answer:
        return False, "empty final answer"
    return True, f"{len(res['steps'])} tool call(s), answer: {answer[:120]}"
