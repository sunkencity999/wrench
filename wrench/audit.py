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
import hmac
import json
import os
import time
from pathlib import Path

from . import __version__
from .filelock import FileLock

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
    # A record must fit comfortably inside the tail window read on append;
    # an oversized detail is replaced by a bounded preview rather than written.
    try:
        encoded = json.dumps(detail, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        encoded = repr(detail)
    if len(encoded) > MAX_DETAIL_CHARS:
        detail = {"truncated": True, "chars": len(encoded),
                  "preview": encoded[:MAX_DETAIL_CHARS // 2]}
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
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
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


MAX_DETAIL_CHARS = 16000
HEAD_NAME = "audit.head"
KEY_ENV = "WRENCH_AUDIT_KEY_FILE"


def head_path(data_dir: Path | str) -> Path:
    return Path(data_dir) / HEAD_NAME


def _mac_key() -> bytes | None:
    """Optional HMAC key for the chain, read from a file OUTSIDE the data dir.

    A bare hash chain proves internal consistency; anyone who can write the log
    can also recompute every hash. With a key the log's writer does not hold at
    verify time (root-owned file, a secrets mount), each record carries a MAC
    that a rewrite cannot reproduce. Set WRENCH_AUDIT_KEY_FILE to enable.
    """
    path = os.environ.get(KEY_ENV)
    if not path:
        return None
    try:
        key = Path(path).expanduser().read_bytes().strip()
        return key or None
    except OSError:
        return None


def record_mac(key: bytes, rec: dict) -> str:
    return hmac.new(key, str(rec.get("hash", "")).encode("ascii", "replace"),
                    hashlib.sha256).hexdigest()


def _head_mac(key: bytes, count, last: str) -> str:
    return hmac.new(key, f"head|{count}|{last}".encode("utf-8", "replace"),
                    hashlib.sha256).hexdigest()


def _read_head(data_dir: Path | str) -> dict | None:
    try:
        obj = json.loads(head_path(data_dir).read_text(encoding="utf-8"))
        return obj if isinstance(obj, dict) and "hash" in obj and "count" in obj else None
    except (OSError, ValueError):
        return None


def _write_head(data_dir: Path | str, count: int, last: str) -> None:
    p = head_path(data_dir)
    tmp = p.with_suffix(".head.tmp")
    head = {"count": count, "hash": last, "ts": time.time()}
    key = _mac_key()
    if key:
        head["mac"] = _head_mac(key, count, last)
    tmp.write_text(json.dumps(head), encoding="utf-8")
    os.replace(tmp, p)
    _owner_only(p)


def _owner_only(p: Path) -> None:
    if os.name == "posix":
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


def _tail_hash(path: Path) -> str | None:
    """Hash of the last sealed record, reading only the file's tail."""
    try:
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 65536))
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        try:
            rec = json.loads(line)
            if isinstance(rec, dict) and rec.get("hash"):
                return rec["hash"]
        except ValueError:
            continue
    return None


def _write_record(path: Path, rec: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    if new:
        _owner_only(path)


def _seal(data_dir: Path | str, kind: str, detail, actor: str | None,
          ts: float | None) -> dict:
    """Append one record. Caller holds the lock."""
    p = audit_path(data_dir)
    prev = _tail_hash(p) if p.exists() else None
    head = _read_head(data_dir)
    if prev is None:
        gen = make_record(GENESIS_PREV, "genesis",
                          {"msg": "audit chain initialized", "version": __version__},
                          actor="wrench")
        key = _mac_key()
        if key:
            gen["mac"] = record_mac(key, gen)
        _write_record(p, gen)
        prev, count = gen["hash"], 1
        if head and int(head.get("count") or 0) > 0:
            # the head says events were sealed, yet the log is gone: someone
            # deleted or emptied it. Starting a clean chain silently would
            # erase that — the new chain opens by recording it.
            gap = make_record(prev, "audit.discontinuity", {
                "sealed_count": head.get("count"), "sealed_hash": head.get("hash"),
                "found_count": 0, "found_hash": None,
                "msg": "audit log was missing or empty although events had been sealed",
            }, actor="wrench")
            if key:
                gap["mac"] = record_mac(key, gap)
            _write_record(p, gap)
            prev, count = gap["hash"], 2
        if kind == "genesis":
            _write_head(data_dir, count, prev)
            return gen
    elif head and head.get("hash") == prev:
        count = int(head["count"])
    else:
        # no head yet (pre-3.0 log) or it disagrees with the file — recount
        count = sum(1 for r in read_records(data_dir)
                    if isinstance(r, dict) and r.get("hash"))
        if head:
            # The file is not what was sealed (truncated, replaced, restored
            # from an older copy). Appending would otherwise re-seal the head
            # and erase that fact, so the discontinuity itself goes on record.
            gap = make_record(prev, "audit.discontinuity", {
                "sealed_count": head.get("count"), "sealed_hash": head.get("hash"),
                "found_count": count, "found_hash": prev,
                "msg": "audit log did not match its sealed head when this event was written",
            }, actor="wrench")
            key = _mac_key()
            if key:
                gap["mac"] = record_mac(key, gap)
            _write_record(p, gap)
            prev, count = gap["hash"], count + 1
    rec = make_record(prev, kind, detail, actor=actor, ts=ts)
    key = _mac_key()
    if key:
        rec["mac"] = record_mac(key, rec)
    _write_record(p, rec)
    _write_head(data_dir, count + 1, rec["hash"])
    return rec


def ensure_genesis(data_dir: Path | str) -> dict | None:
    """Seed the genesis record if the chain is empty. Returns it, or None if
    the chain already exists. Never raises."""
    try:
        p = audit_path(data_dir)
        with FileLock(p):
            if p.exists() and _tail_hash(p):
                return None
            return _seal(data_dir, "genesis", None, None, None)
    except OSError:
        return None


def append(data_dir: Path | str, kind: str, detail, actor: str | None = None,
           ts: float | None = None) -> dict | None:
    """Seal one event onto the chain. Seeds genesis on first write.

    The read-last-hash → write step runs under a cross-process lock: two
    writers that both chained onto the same record would fork the chain and
    leave a permanent false "tamper" verdict.

    Returns the written record, or None on I/O failure (auditing never breaks
    its caller)."""
    try:
        with FileLock(audit_path(data_dir)):
            return _seal(data_dir, kind, detail, actor, ts)
    except Exception:  # noqa: BLE001 — a broken audit must not break the action
        return None


def verify(data_dir: Path | str) -> dict:
    """Re-walk the on-disk chain, then check it against the sealed head.

    The chain alone cannot see its own tail being cut off — every remaining
    link still verifies. The head file records how many events were sealed and
    the last hash, so a truncated (or wholesale replaced) log is caught; a log
    written by 3.x with no head at all has had its head removed. With a MAC key
    configured, every record from the first MAC'd one onward — and the head —
    must carry a valid MAC, so a rewrite without the key cannot pass.

    Never raises: a log that cannot be verified is reported as not intact.
    """
    try:
        with FileLock(audit_path(data_dir)):      # a consistent log + head pair
            return _verify_locked(data_dir)
    except Exception as e:  # noqa: BLE001
        return {"intact": False, "count": 0, "broken_index": None, "head": None,
                "mac_checked": False, "discontinuities": 0,
                "reason": f"audit log could not be verified ({e.__class__.__name__}: {e})"}


def _sealed_by_3x(records: list[dict]) -> bool:
    """Was this chain started by a version that always writes a head?"""
    if not records or not isinstance(records[0], dict):
        return False
    ver = str((records[0].get("detail") or {}).get("version", "")) \
        if isinstance(records[0].get("detail"), dict) else ""
    return ver.split(".")[0].isdigit() and int(ver.split(".")[0]) >= 3


def _verify_locked(data_dir: Path | str) -> dict:
    head = _read_head(data_dir)
    records = read_records(data_dir)
    res = verify_records(records)
    res["head"] = None
    res["mac_checked"] = False
    res["discontinuities"] = sum(1 for r in records
                                 if isinstance(r, dict) and r.get("kind") == "audit.discontinuity")
    if not res["intact"]:
        return res
    key = _mac_key()
    if head:
        res["head"] = {"count": head["count"]}
        try:
            n = int(head["count"])
        except (TypeError, ValueError):
            return {**res, "intact": False, "reason": "sealed head is malformed"}
        if len(records) < n:
            return {**res, "intact": False, "broken_index": len(records),
                    "reason": (f"log truncated: {n} event(s) were sealed but only "
                               f"{len(records)} remain")}
        if n >= 1 and records[n - 1].get("hash") != head["hash"]:
            return {**res, "intact": False, "broken_index": n - 1,
                    "reason": "log does not match the sealed head (it was replaced or rewritten)"}
        if key and head.get("mac") is not None and not hmac.compare_digest(
                str(head["mac"]).encode("utf-8", "replace"),
                _head_mac(key, head["count"], head["hash"]).encode()):
            return {**res, "intact": False,
                    "reason": "sealed head MAC does not verify (rewritten without the audit key)"}
    elif _sealed_by_3x(records):
        return {**res, "intact": False,
                "reason": "the sealed head file is missing — it was removed, so truncation "
                          "can no longer be ruled out"}
    if key:
        res["mac_checked"] = True
        seen_mac = False
        for i, rec in enumerate(records):
            mac = rec.get("mac")
            if mac is None:
                if seen_mac:
                    # once records are MAC'd, an un-MAC'd one was written (or
                    # rewritten) by someone without the key
                    return {**res, "intact": False, "broken_index": i,
                            "reason": "record has no MAC although earlier records do "
                                      "(rewritten without the audit key)"}
                continue     # sealed before a key was configured
            seen_mac = True
            if not hmac.compare_digest(str(mac).encode("utf-8", "replace"),
                                       record_mac(key, rec).encode()):
                return {**res, "intact": False, "broken_index": i,
                        "reason": "record MAC does not verify (rewritten without the audit key)"}
        if seen_mac and head and head.get("mac") is None:
            return {**res, "intact": False,
                    "reason": "sealed head has no MAC although records do "
                              "(rewritten without the audit key)"}
    return res


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
