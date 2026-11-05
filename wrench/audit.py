"""wrench audit — a tamper-evident, hash-chained event log.

Every *consequential* thing wrench does — a consent grant or denial, a fixxer
apply, a blueprint apply or rollback, a certificate renewal, a security
baseline accept, a policy-tier change, a maintenance-window override — is
appended to an append-only JSONL log in the data dir.  Each record carries the
hash of the record before it:

    {ts, actor, kind, detail, prev_hash, hash}

    hash = sha256(prev_hash + canonical(ts, actor, kind, detail, prev_hash))

The first write seeds a ``genesis`` record whose ``prev_hash`` is 64 zeros.
``verify()`` re-walks the whole chain and reports INTACT, or the exact index of
the first broken link — a single altered byte anywhere breaks every hash from
that point on, which is the whole point.

House rules (same as certs/security/backups):
  - stdlib only, no new dependencies;
  - pure helpers (``canonical``/``record_hash``/``verify_records``) take plain
    data so tests feed synthetic chains with no host state;
  - auditing must *never* break its caller — ``append``/``log_event`` swallow
    their own I/O errors and return best-effort.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import time
from pathlib import Path

from . import __version__

AUDIT_NAME = "audit.jsonl"
GENESIS_PREV = "0" * 64
# fields that participate in the hash, in a fixed vocabulary (order is
# irrelevant — canonicalization sorts keys — but this documents the schema)
HASHED_FIELDS = ("ts", "actor", "kind", "detail", "prev_hash")

# kinds routed through store.add_action that are pure read-only diagnostics and
# must NOT flood the consequential-event chain.
_SKIP_PREFIXES = ("diag",)


def audit_path(data_dir: Path | str) -> Path:
    return Path(data_dir) / AUDIT_NAME


def default_actor() -> str:
    """Who performed this action: WRENCH_ACTOR, else the OS user, else unknown."""
    actor = os.environ.get("WRENCH_ACTOR")
    if actor:
        return actor[:120]
    try:
        return (getpass.getuser() or "unknown")[:120]
    except Exception:  # noqa: BLE001 — getuser can raise with no passwd entry
        return os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"


# ---------------- pure chain primitives (fixture-friendly) ----------------

def canonical(record: dict) -> str:
    """Deterministic JSON of the hashed fields only (never the ``hash`` key)."""
    payload = {k: record.get(k) for k in HASHED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def record_hash(prev_hash: str, record: dict) -> str:
    """sha256(prev_hash + canonical(record)) as hex."""
    h = hashlib.sha256()
    h.update((prev_hash + canonical(record)).encode("utf-8"))
    return h.hexdigest()


def make_record(prev_hash: str, kind: str, detail, actor: str | None = None,
                ts: float | None = None) -> dict:
    """Build a fully-sealed record (with its ``hash``) chained to ``prev_hash``."""
    rec = {
        "ts": round(ts if ts is not None else time.time(), 6),
        "actor": actor or default_actor(),
        "kind": str(kind),
        "detail": detail,
        "prev_hash": prev_hash,
    }
    rec["hash"] = record_hash(prev_hash, rec)
    return rec


def verify_records(records: list[dict]) -> dict:
    """Re-walk an in-memory chain. Pure.

    Returns {intact, count, broken_index, reason}. An empty chain is trivially
    intact. ``broken_index`` is the 0-based index of the first bad record.
    """
    prev = GENESIS_PREV
    for i, rec in enumerate(records):
        if not isinstance(rec, dict) or "hash" not in rec or "prev_hash" not in rec:
            return {"intact": False, "count": len(records), "broken_index": i,
                    "reason": "malformed record (not a sealed audit entry)"}
        if rec.get("prev_hash") != prev:
            return {"intact": False, "count": len(records), "broken_index": i,
                    "reason": ("chain broken: prev_hash does not match the "
                               "previous record's hash (a record was inserted, "
                               "removed, or reordered)")}
        expect = record_hash(rec["prev_hash"], rec)
        if expect != rec.get("hash"):
            return {"intact": False, "count": len(records), "broken_index": i,
                    "reason": "record altered: stored hash does not match its contents"}
        prev = rec["hash"]
    return {"intact": True, "count": len(records), "broken_index": None,
            "reason": "chain intact"}


# ---------------- on-disk chain ----------------

def read_records(data_dir: Path | str) -> list[dict]:
    """All sealed records in order. Malformed lines are kept as sentinels so
    ``verify`` can point at them; callers that only want good rows filter."""
    p = audit_path(data_dir)
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"__malformed__": line[:200]})
    return out


def last_hash(data_dir: Path | str) -> str | None:
    recs = read_records(data_dir)
    for rec in reversed(recs):
        if isinstance(rec, dict) and rec.get("hash"):
            return rec["hash"]
    return None


def _write_record(path: Path, rec: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


def ensure_genesis(data_dir: Path | str) -> dict | None:
    """Seed the genesis record if the chain is empty. Returns it, or None if
    the chain already exists. Never raises."""
    try:
        p = audit_path(data_dir)
        if p.exists() and any(line.strip() for line in p.read_text().splitlines()):
            return None
        gen = make_record(GENESIS_PREV, "genesis",
                          {"msg": "audit chain initialized", "version": __version__},
                          actor="wrench")
        _write_record(p, gen)
        return gen
    except OSError:
        return None


def append(data_dir: Path | str, kind: str, detail, actor: str | None = None,
           ts: float | None = None) -> dict | None:
    """Seal one event onto the chain. Seeds genesis on first write.

    Returns the written record, or None on I/O failure (auditing never breaks
    its caller)."""
    try:
        p = audit_path(data_dir)
        ensure_genesis(data_dir)
        prev = last_hash(data_dir) or GENESIS_PREV
        rec = make_record(prev, kind, detail, actor=actor, ts=ts)
        _write_record(p, rec)
        return rec
    except Exception:  # noqa: BLE001 — a broken audit must not break the action
        return None


def verify(data_dir: Path | str) -> dict:
    """Re-walk the on-disk chain. See ``verify_records``."""
    return verify_records(read_records(data_dir))


def recent(data_dir: Path | str, limit: int = 20) -> list[dict]:
    """The most recent sealed records (newest last), malformed rows skipped."""
    good = [r for r in read_records(data_dir) if isinstance(r, dict) and r.get("hash")]
    return good[-limit:] if limit and limit > 0 else good


# ---------------- convenience for subsystem callers ----------------

def should_audit_action(kind: str) -> bool:
    """True when a store.add_action kind is a consequential (non-diag) event."""
    k = (kind or "").lower()
    return not any(k.startswith(pre) for pre in _SKIP_PREFIXES)


def log_event(cfg, kind: str, detail, actor: str | None = None,
              data_dir: Path | None = None) -> dict | None:
    """Append an event using a loaded Config for the data dir. Never raises."""
    try:
        dd = Path(data_dir) if data_dir is not None else cfg.data_dir
    except Exception:  # noqa: BLE001
        return None
    return append(dd, kind, detail, actor=actor)
