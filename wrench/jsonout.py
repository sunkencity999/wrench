"""Machine-readable JSON output for the read/report commands.

Every ``--json`` command prints exactly one JSON object to stdout — no rich
formatting, no banners, no progress spinners — so output can be piped straight
into jq, CI assertions, or a collector. The envelope is stable:

    {
      "schema": "wrench.<command>.v1",   # bump the suffix on breaking change
      "generated_at": <epoch seconds>,
      "host": "<hostname>",
      "version": "<wrench version>",
      ...command-specific fields...
    }

Exit codes keep their interactive meaning (e.g. ``doctor --json`` exits 1 when
the provider is unreachable). See docs/json-output.md for per-command schemas.
"""

from __future__ import annotations

import dataclasses
import json
import platform
import time
from typing import Any

from . import __version__

SCHEMA_VERSION = "v1"


def _clean(obj: Any) -> Any:
    """Recursively convert to plain JSON types (dataclasses, Paths, sets)."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return _clean(dataclasses.asdict(obj))
    if isinstance(obj, dict):
        return {str(k): _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_clean(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def envelope(command: str, data: dict) -> dict:
    """Wrap command data in the stable envelope."""
    return {
        "schema": f"wrench.{command}.{SCHEMA_VERSION}",
        "generated_at": round(time.time(), 3),
        "host": platform.node() or "localhost",
        "version": __version__,
        **_clean(data),
    }


def emit(command: str, data: dict) -> None:
    """Print one envelope as a single JSON document to stdout."""
    print(json.dumps(envelope(command, data), ensure_ascii=False, indent=2))
