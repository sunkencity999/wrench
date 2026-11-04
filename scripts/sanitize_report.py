#!/usr/bin/env python3
"""Sanitize patrol reports for public demo artifacts.

Replaces the real hostname with 'devbox', home paths with /home/user, masks any
non-loopback IPs, and scrubs a wordlist of private names. Then VERIFIES nothing
on the blocklist survived; exits 1 if anything leaks.
"""
import re
import sys
from pathlib import Path

REPLACEMENTS = [
    (re.compile(r"Devbox2", re.I), "devbox"),
    (re.compile(r"/home/sunkencity999"), "/home/user"),
    (re.compile(r"sunkencity999(?!\.github|/wrench)"), "user"),
    (re.compile(r"\b(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2,3}\b"), "x.x.x.x"),
    (re.compile(r"workspace-\w+"), "workspace"),
    (re.compile(r"cherubesque[\w-]*", re.I), "wiki-app"),
    (re.compile(r"stackchan[\w-]*", re.I), "robot-app"),
    (re.compile(r"openclaw", re.I), "agent-host"),
    (re.compile(r"(?:aibox|colibri|esmeralda|antonia|christopher)", re.I), "redacted"),
]
BLOCKLIST = ["Devbox2", "sunkencity999.github.io/wrench-NOPE", "christopher", "antonia",
             "esmeralda", "10.0.0.", "192.168.", "LLM|", "api_key", "Bearer "]


def sanitize(text: str) -> str:
    for pat, rep in REPLACEMENTS:
        text = pat.sub(rep, text)
    return text


def main() -> int:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    out = sanitize(src.read_text())
    leaks = [b for b in BLOCKLIST if b.lower() in out.lower() and "NOPE" not in b]
    if leaks:
        print(f"LEAK after sanitize: {leaks}", file=sys.stderr)
        return 1
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(out)
    print(f"wrote {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
