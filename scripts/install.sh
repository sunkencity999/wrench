#!/usr/bin/env bash
# wrench installer — Linux & macOS
#   curl -fsSL https://raw.githubusercontent.com/sunkencity999/wrench/main/scripts/install.sh | bash
set -euo pipefail

REPO="git+https://github.com/sunkencity999/wrench"

say()  { printf '\033[1;34m[wrench]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[wrench]\033[0m %s\n' "$*" >&2; exit 1; }

# 1. find a python >= 3.10
PY=""
for cand in python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then
    if "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
      PY="$cand"; break
    fi
  fi
done
[ -n "$PY" ] || fail "python 3.10+ not found. Install it (apt/brew/pyenv) and re-run."
say "using $("$PY" --version 2>&1)"

# 2. prefer pipx, fall back to pip --user
if command -v pipx >/dev/null 2>&1; then
  say "installing with pipx..."
  pipx install --force "$REPO"
elif "$PY" -m pipx --version >/dev/null 2>&1; then
  say "installing with $PY -m pipx..."
  "$PY" -m pipx install --force "$REPO"
else
  say "pipx not found — installing with pip --user (consider 'pip install pipx' for cleaner installs)"
  "$PY" -m pip install --user --upgrade "$REPO"
fi

# 3. verify + optional interactive setup
if command -v wrench >/dev/null 2>&1; then
  say "installed: $(wrench version)"
  # curl|bash pipes stdin, so talk to the real terminal when one exists
  if [ -t 1 ] && [ -r /dev/tty ] && [ -z "${CI:-}" ]; then
    printf '\033[1;34m[wrench]\033[0m set up now? Bring your own mind — fully local via Ollama, or any API provider. [Y/n] '
    read -r reply < /dev/tty || reply="n"
    case "$reply" in
      [Nn]*) say "later, then: wrench init && wrench doctor && wrench patrol" ;;
      *) wrench init < /dev/tty || true ;;
    esac
  else
    say "next: wrench init && wrench doctor && wrench patrol"
    say "(wrench init shows an interactive provider menu — local + private via Ollama/LM Studio, or any API brain: OpenAI, Anthropic, Meta, Azure, LiteLLM)"
  fi
else
  say "installed, but 'wrench' is not on PATH yet."
  say "add your user bin dir to PATH (usually ~/.local/bin) and run: wrench init"
fi
