"""sqlite store for wrench: samples, snapshots, diffs, patrols, actions, token spend."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

# Bump when a migration is added to ``_MIGRATIONS``. The value is persisted in
# sqlite's ``PRAGMA user_version`` so an old database upgrades in place.
SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts REAL NOT NULL,
    sensor TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples (sensor, ts);

CREATE TABLE IF NOT EXISTS baselines (
    sensor TEXT NOT NULL,
    metric TEXT NOT NULL,
    ewma REAL NOT NULL,
    ewvar REAL NOT NULL,
    n INTEGER NOT NULL,
    updated REAL NOT NULL,
    PRIMARY KEY (sensor, metric)
);

CREATE TABLE IF NOT EXISTS anomalies (
    ts REAL NOT NULL,
    sensor TEXT NOT NULL,
    metric TEXT NOT NULL,
    value REAL NOT NULL,
    zscore REAL NOT NULL,
    note TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots ON snapshots (kind, ts);

CREATE TABLE IF NOT EXISTS diffs (
    ts REAL NOT NULL,
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    details TEXT
);

CREATE TABLE IF NOT EXISTS patrols (
    ts REAL NOT NULL,
    model TEXT,
    status TEXT,
    summary TEXT,
    findings TEXT,
    report_md TEXT,
    tokens INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS actions (
    ts REAL NOT NULL,
    tier TEXT NOT NULL,
    kind TEXT NOT NULL,
    command TEXT NOT NULL,
    approved INTEGER NOT NULL,
    result TEXT
);

CREATE TABLE IF NOT EXISTS webintel_cache (
    key TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certs (
    path TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    source TEXT,
    subject TEXT,
    issuer TEXT,
    serial TEXT,
    not_before REAL,
    not_after REAL,
    days_left INTEGER,
    sans TEXT,
    key_type TEXT,
    key_bits INTEGER,
    sig_algo TEXT,
    is_ca INTEGER,
    self_signed INTEGER,
    chain_complete INTEGER,
    fingerprint TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    token_hash TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    detail TEXT,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    claimed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_approvals_action ON approvals (action);

CREATE TABLE IF NOT EXISTS fleet_nodes (
    node_id TEXT PRIMARY KEY,
    hostname TEXT,
    token_hash TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    status TEXT,
    worst_severity TEXT,
    summary TEXT,
    cadence_s REAL,
    wrench_version TEXT,
    findings TEXT,
    gauges TEXT,
    report_count INTEGER NOT NULL DEFAULT 0,
    silent INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fleet_reports (
    node_id TEXT NOT NULL,
    ts REAL NOT NULL,
    status TEXT,
    worst_severity TEXT,
    summary TEXT,
    payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_fleet_reports ON fleet_reports (node_id, ts);

CREATE TABLE IF NOT EXISTS fleet_tokens (
    token_hash TEXT PRIMARY KEY,
    label TEXT,
    created REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS fleet_keys (
    key_id TEXT PRIMARY KEY,
    label TEXT,
    hmac_key TEXT NOT NULL,
    created REAL NOT NULL,
    revoked REAL,
    single_node INTEGER NOT NULL DEFAULT 0,
    last_used REAL
);

CREATE TABLE IF NOT EXISTS tokens_spent (
    ts REAL NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL,
    completion_tokens INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL,
    purpose TEXT
);
"""


# Additive, idempotent migrations keyed by the version they produce. Each entry
# is a list of (table, column, ddl) — applied only when the column is missing,
# so a half-applied upgrade simply resumes.
_MIGRATIONS: dict[int, list[tuple[str, str, str]]] = {
    2: [
        ("fleet_nodes", "meta", "ALTER TABLE fleet_nodes ADD COLUMN meta TEXT"),
        ("fleet_nodes", "report_ts", "ALTER TABLE fleet_nodes ADD COLUMN report_ts REAL"),
        ("fleet_nodes", "key_id", "ALTER TABLE fleet_nodes ADD COLUMN key_id TEXT"),
    ],
}

# Rows that record what the box *did* (patrol reports, the action log, token
# spend, approvals) outlive raw telemetry: they are the operational history.
HISTORY_RETENTION_FLOOR_DAYS = 365


def _max_number(mapping) -> float | None:
    """Largest numeric value of a mapping; None for anything else (old rows may
    hold whatever a node sent before reports were sanitized)."""
    if not isinstance(mapping, dict):
        return None
    nums = [v for v in mapping.values() if isinstance(v, (int, float)) and not isinstance(v, bool)]
    return max(nums, default=None)


def _harden_permissions(path: Path) -> None:
    """Owner-only data dir + database on POSIX. Best-effort, never fatal.

    The store holds telemetry, the action log and fleet signing keys; nothing
    else on a shared host has any business reading it. (No-op on Windows, where
    the per-user profile ACL already scopes %LOCALAPPDATA%.)
    """
    if os.name != "posix":
        return
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    for suffix in ("", "-wal", "-shm"):
        try:
            os.chmod(str(path) + suffix, 0o600)
        except OSError:
            pass


class _Immediate:
    """BEGIN IMMEDIATE … COMMIT/ROLLBACK around a block of Store calls.

    Store methods call ``self.db.commit()`` as they go; inside this block those
    are deferred to the single commit at exit, so the block is atomic.
    """

    def __init__(self, store: "Store"):
        self.store = store

    def __enter__(self):
        self.real = self.store.db
        self.real.commit()
        self.real.execute("BEGIN IMMEDIATE")
        self.store.db = _NoCommit(self.real)
        return self.store

    def __exit__(self, exc_type, exc, tb):
        self.store.db = self.real
        if exc_type is None:
            self.real.commit()
        else:
            self.real.rollback()
        return False


class _NoCommit:
    """A connection proxy whose commit() is a no-op (see _Immediate)."""

    def __init__(self, db):
        self._db = db

    def commit(self):
        pass

    def __getattr__(self, name):
        return getattr(self._db, name)


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # timeout = how long a writer waits on another process's lock. The
        # dashboard sampler, a scheduled patrol and an interactive command all
        # share this file, so "database is locked" must be a wait, not a crash.
        self.db = sqlite3.connect(str(self.path), timeout=30)
        try:
            # WAL: readers never block the writer (and vice versa).
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError:
            pass  # read-only media / network filesystems: stay on the default journal
        self.db.executescript(SCHEMA)
        self._migrate()
        self.db.commit()
        _harden_permissions(self.path)

    def _columns(self, table: str) -> set[str]:
        return {r[1] for r in self.db.execute(f"PRAGMA table_info({table})").fetchall()}

    def _migrate(self) -> None:
        current = self.db.execute("PRAGMA user_version").fetchone()[0]
        if current >= SCHEMA_VERSION:
            return
        for version in sorted(_MIGRATIONS):
            if version <= current:
                continue
            for table, column, ddl in _MIGRATIONS[version]:
                if column not in self._columns(table):
                    self.db.execute(ddl)
        self.db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    def immediate(self):
        """``with store.immediate():`` — run a read-check-write as ONE transaction
        holding the write lock from the start (BEGIN IMMEDIATE)."""
        return _Immediate(self)

    @property
    def schema_version(self) -> int:
        return self.db.execute("PRAGMA user_version").fetchone()[0]

    # ---- samples / baselines ----
    def add_sample(self, sensor: str, payload: dict, ts: float | None = None) -> None:
        self.db.execute(
            "INSERT INTO samples (ts, sensor, payload) VALUES (?,?,?)",
            (ts or time.time(), sensor, json.dumps(payload)),
        )
        self.db.commit()

    def recent_samples(self, sensor: str, since_s: float = 3600 * 24) -> list[tuple[float, dict]]:
        cur = self.db.execute(
            "SELECT ts, payload FROM samples WHERE sensor=? AND ts>=? ORDER BY ts",
            (sensor, time.time() - since_s),
        )
        return [(ts, json.loads(p)) for ts, p in cur.fetchall()]

    def last_sample(self, sensor: str) -> tuple[float, dict] | None:
        cur = self.db.execute(
            "SELECT ts, payload FROM samples WHERE sensor=? ORDER BY ts DESC LIMIT 1", (sensor,)
        )
        row = cur.fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def update_baseline(self, sensor: str, metric: str, value: float, alpha: float = 0.08) -> float:
        """EWMA baseline update; returns z-score of value vs prior baseline (0.0 while warming up)."""
        cur = self.db.execute(
            "SELECT ewma, ewvar, n FROM baselines WHERE sensor=? AND metric=?", (sensor, metric)
        )
        row = cur.fetchone()
        z = 0.0
        if row is None:
            ewma, ewvar, n = value, 0.0, 1
        else:
            ewma, ewvar, n = row
            # Floor the deviation. A metric that sat perfectly still has ~zero
            # variance: without a floor a real jump scores z=0 (never flagged)
            # or a 0.1-point tick scores z=60 (always flagged). The floor is
            # 2% of the level, at least 1.0 — "normal jitter" for a percentage.
            sd = max(ewvar**0.5, abs(ewma) * 0.02, 1.0)
            if n >= 20:
                z = (value - ewma) / sd
            delta = value - ewma
            ewma += alpha * delta
            ewvar = (1 - alpha) * (ewvar + alpha * delta * delta)
            n += 1
        self.db.execute(
            "INSERT INTO baselines (sensor, metric, ewma, ewvar, n, updated) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(sensor, metric) DO UPDATE SET ewma=?, ewvar=?, n=?, updated=?",
            (sensor, metric, ewma, ewvar, n, time.time(), ewma, ewvar, n, time.time()),
        )
        self.db.commit()
        return z

    def add_anomaly(self, sensor: str, metric: str, value: float, z: float, note: str = "") -> None:
        self.db.execute(
            "INSERT INTO anomalies (ts, sensor, metric, value, zscore, note) VALUES (?,?,?,?,?,?)",
            (time.time(), sensor, metric, value, z, note),
        )
        self.db.commit()

    def recent_anomalies(self, since_s: float = 3600 * 24) -> list[dict]:
        cur = self.db.execute(
            "SELECT ts, sensor, metric, value, zscore, note FROM anomalies WHERE ts>=? ORDER BY ts DESC",
            (time.time() - since_s,),
        )
        return [
            dict(ts=r[0], sensor=r[1], metric=r[2], value=r[3], zscore=r[4], note=r[5])
            for r in cur.fetchall()
        ]

    # ---- snapshots / diffs ----
    def add_snapshot(self, kind: str, payload: dict) -> None:
        self.db.execute(
            "INSERT INTO snapshots (ts, kind, payload) VALUES (?,?,?)",
            (time.time(), kind, json.dumps(payload, sort_keys=True)),
        )
        self.db.commit()

    def last_snapshot(self, kind: str) -> tuple[float, dict] | None:
        cur = self.db.execute(
            "SELECT ts, payload FROM snapshots WHERE kind=? ORDER BY ts DESC LIMIT 1", (kind,)
        )
        row = cur.fetchone()
        return (row[0], json.loads(row[1])) if row else None

    def add_diff(self, kind: str, summary: str, details: dict | list | None = None) -> None:
        self.db.execute(
            "INSERT INTO diffs (ts, kind, summary, details) VALUES (?,?,?,?)",
            (time.time(), kind, summary, json.dumps(details or {})),
        )
        self.db.commit()

    def recent_diffs(self, since_s: float = 3600 * 24 * 7) -> list[dict]:
        cur = self.db.execute(
            "SELECT ts, kind, summary, details FROM diffs WHERE ts>=? ORDER BY ts DESC",
            (time.time() - since_s,),
        )
        return [
            dict(ts=r[0], kind=r[1], summary=r[2], details=json.loads(r[3] or "{}"))
            for r in cur.fetchall()
        ]

    # ---- patrols ----
    def add_patrol(
        self, model: str, status: str, summary: str, findings: list, report_md: str, tokens: int
    ) -> float:
        """Insert a patrol row; returns its timestamp (the patrol's report id)."""
        ts = time.time()
        self.db.execute(
            "INSERT INTO patrols (ts, model, status, summary, findings, report_md, tokens) VALUES (?,?,?,?,?,?,?)",
            (ts, model, status, summary, json.dumps(findings), report_md, tokens),
        )
        self.db.commit()
        return ts

    def recent_patrols(self, limit: int = 50) -> list[dict]:
        cur = self.db.execute(
            "SELECT ts, model, status, summary, findings, report_md, tokens FROM patrols ORDER BY ts DESC LIMIT ?",
            (limit,),
        )
        return [
            dict(
                ts=r[0], model=r[1], status=r[2], summary=r[3],
                findings=json.loads(r[4] or "[]"), report_md=r[5], tokens=r[6],
            )
            for r in cur.fetchall()
        ]

    # ---- actions ----
    def add_action(self, tier: str, kind: str, command: str, approved: bool, result: str) -> None:
        self.db.execute(
            "INSERT INTO actions (ts, tier, kind, command, approved, result) VALUES (?,?,?,?,?,?)",
            (time.time(), tier, kind, command, int(approved), result[:4000]),
        )
        self.db.commit()
        # Seal consequential actions onto the tamper-evident audit chain. This is
        # the narrowest choke point: fixxer applies, blueprint applies, cert
        # renewals and backups restore-tests all route through here. Read-only
        # diagnostics (diag:*) are skipped. Never fatal.
        try:
            from . import audit
            if audit.should_audit_action(kind):
                audit.append(
                    self.path.parent, kind,
                    {"tier": tier, "command": command[:300],
                     "approved": bool(approved), "result": result[:300]},
                )
        except Exception:  # noqa: BLE001 — auditing must never break an action
            pass

    def recent_actions(self, limit: int = 100) -> list[dict]:
        cur = self.db.execute(
            "SELECT ts, tier, kind, command, approved, result FROM actions ORDER BY ts DESC LIMIT ?",
            (limit,),
        )
        return [
            dict(ts=r[0], tier=r[1], kind=r[2], command=r[3], approved=bool(r[4]), result=r[5])
            for r in cur.fetchall()
        ]

    # ---- approvals (webhook approval tokens) ----
    def add_approval(self, token_hash: str, action: str, detail: str,
                     created: float, expires: float) -> None:
        self.db.execute(
            "INSERT INTO approvals (token_hash, action, detail, created, expires, "
            "approved, claimed) VALUES (?,?,?,?,?,0,0) "
            "ON CONFLICT(token_hash) DO UPDATE SET action=excluded.action, "
            "detail=excluded.detail, created=excluded.created, expires=excluded.expires, "
            "approved=0, claimed=0",
            (token_hash, action, detail, created, expires),
        )
        self.db.commit()

    def get_approval(self, token_hash: str) -> dict | None:
        cur = self.db.execute(
            "SELECT token_hash, action, detail, created, expires, approved, claimed "
            "FROM approvals WHERE token_hash=?", (token_hash,))
        r = cur.fetchone()
        if not r:
            return None
        return dict(token_hash=r[0], action=r[1], detail=r[2], created=r[3],
                    expires=r[4], approved=bool(r[5]), claimed=bool(r[6]))

    def set_approval_flags(self, token_hash: str, approved: bool | None = None,
                           claimed: bool | None = None) -> None:
        sets, args = [], []
        if approved is not None:
            sets.append("approved=?")
            args.append(int(approved))
        if claimed is not None:
            sets.append("claimed=?")
            args.append(int(claimed))
        if not sets:
            return
        args.append(token_hash)
        self.db.execute(f"UPDATE approvals SET {', '.join(sets)} WHERE token_hash=?", args)
        self.db.commit()

    def approve_once(self, token_hash: str, now: float) -> bool:
        """Atomically flip pending→approved. False if it was not pending+live."""
        cur = self.db.execute(
            "UPDATE approvals SET approved=1 WHERE token_hash=? AND approved=0 "
            "AND claimed=0 AND expires>?", (token_hash, now))
        self.db.commit()
        return cur.rowcount == 1

    def claim_once(self, action: str, now: float) -> bool:
        """Atomically consume ONE approved, live approval for ``action``.

        A single UPDATE — two runs racing for the same approval cannot both
        win, so one approval is one execution.
        """
        cur = self.db.execute(
            "UPDATE approvals SET claimed=1 WHERE token_hash = ("
            " SELECT token_hash FROM approvals WHERE action=? AND approved=1 "
            " AND claimed=0 AND expires>? ORDER BY created LIMIT 1) "
            "AND approved=1 AND claimed=0", (action, now))
        self.db.commit()
        return cur.rowcount == 1

    def approved_unclaimed_for(self, action: str, now: float) -> dict | None:
        """Oldest approved, unclaimed, unexpired approval for an action, if any."""
        cur = self.db.execute(
            "SELECT token_hash, action, detail, created, expires, approved, claimed "
            "FROM approvals WHERE action=? AND approved=1 AND claimed=0 AND expires>? "
            "ORDER BY created LIMIT 1", (action, now))
        r = cur.fetchone()
        if not r:
            return None
        return dict(token_hash=r[0], action=r[1], detail=r[2], created=r[3],
                    expires=r[4], approved=bool(r[5]), claimed=bool(r[6]))

    def recent_approvals(self, limit: int = 50) -> list[dict]:
        cur = self.db.execute(
            "SELECT token_hash, action, detail, created, expires, approved, claimed "
            "FROM approvals ORDER BY created DESC LIMIT ?", (limit,))
        return [dict(token_hash=r[0], action=r[1], detail=r[2], created=r[3],
                     expires=r[4], approved=bool(r[5]), claimed=bool(r[6]))
                for r in cur.fetchall()]

    # ---- tokens ----
    def add_tokens(
        self, provider: str, model: str, prompt: int, completion: int, total: int, purpose: str
    ) -> None:
        self.db.execute(
            "INSERT INTO tokens_spent (ts, provider, model, prompt_tokens, completion_tokens, total_tokens, purpose) "
            "VALUES (?,?,?,?,?,?,?)",
            (time.time(), provider, model, prompt, completion, total, purpose),
        )
        self.db.commit()

    def token_totals(self) -> list[dict]:
        cur = self.db.execute(
            "SELECT provider, model, SUM(prompt_tokens), SUM(completion_tokens), SUM(total_tokens), COUNT(*) "
            "FROM tokens_spent GROUP BY provider, model ORDER BY SUM(total_tokens) DESC"
        )
        return [
            dict(provider=r[0], model=r[1], prompt=r[2], completion=r[3], total=r[4], calls=r[5])
            for r in cur.fetchall()
        ]

    # ---- certs ----
    def upsert_cert(self, row: dict, ts: float | None = None) -> None:
        """Insert/update one cert inventory row keyed by resolved path."""
        self.db.execute(
            "INSERT INTO certs (path, ts, source, subject, issuer, serial, not_before, "
            "not_after, days_left, sans, key_type, key_bits, sig_algo, is_ca, self_signed, "
            "chain_complete, fingerprint, error) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET ts=excluded.ts, source=excluded.source, "
            "subject=excluded.subject, issuer=excluded.issuer, serial=excluded.serial, "
            "not_before=excluded.not_before, not_after=excluded.not_after, "
            "days_left=excluded.days_left, sans=excluded.sans, key_type=excluded.key_type, "
            "key_bits=excluded.key_bits, sig_algo=excluded.sig_algo, is_ca=excluded.is_ca, "
            "self_signed=excluded.self_signed, chain_complete=excluded.chain_complete, "
            "fingerprint=excluded.fingerprint, error=excluded.error",
            (
                row["path"], ts or time.time(), row.get("source"), row.get("subject"),
                row.get("issuer"), row.get("serial"), row.get("not_before"),
                row.get("not_after"), row.get("days_left"),
                json.dumps(row.get("sans") or []), row.get("key_type"),
                row.get("key_bits"), row.get("sig_algo"),
                int(bool(row.get("is_ca"))), int(bool(row.get("self_signed"))),
                (None if row.get("chain_complete") is None else int(bool(row.get("chain_complete")))),
                row.get("fingerprint_sha256") or row.get("fingerprint"), row.get("error"),
            ),
        )
        self.db.commit()

    def recent_certs(self) -> list[dict]:
        cur = self.db.execute(
            "SELECT path, ts, source, subject, issuer, serial, not_before, not_after, "
            "days_left, sans, key_type, key_bits, sig_algo, is_ca, self_signed, "
            "chain_complete, fingerprint, error FROM certs ORDER BY "
            "(days_left IS NULL), days_left"
        )
        out = []
        for r in cur.fetchall():
            out.append(dict(
                path=r[0], ts=r[1], source=r[2], subject=r[3], issuer=r[4], serial=r[5],
                not_before=r[6], not_after=r[7], days_left=r[8],
                sans=json.loads(r[9] or "[]"), key_type=r[10], key_bits=r[11],
                sig_algo=r[12], is_ca=bool(r[13]), self_signed=bool(r[14]),
                chain_complete=(None if r[15] is None else bool(r[15])),
                fingerprint=r[16], error=r[17],
            ))
        return out

    # ---- web-intel cache (TTL key-value) ----
    def cache_get(self, key: str, max_age_s: float) -> dict | list | None:
        cur = self.db.execute("SELECT ts, payload FROM webintel_cache WHERE key=?", (key,))
        row = cur.fetchone()
        if row is None or (time.time() - row[0]) > max_age_s:
            return None
        try:
            return json.loads(row[1])
        except json.JSONDecodeError:
            return None

    def cache_put(self, key: str, payload: dict | list) -> None:
        self.db.execute(
            "INSERT INTO webintel_cache (key, ts, payload) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET ts=excluded.ts, payload=excluded.payload",
            (key, time.time(), json.dumps(payload)),
        )
        self.db.commit()

    # ---- fleet (hub side) ----
    def upsert_fleet_node(self, node_id: str, hostname: str, token_hash: str,
                          status: str, worst_severity: str, summary: str,
                          cadence_s: float | None, wrench_version: str,
                          findings: list | None, gauges: dict | None,
                          now: float, silent: int = 0, meta: dict | None = None,
                          report_ts: float | None = None,
                          key_id: str | None = None) -> dict:
        """Insert/update a node row from an ingested report. Returns the row.

        ``first_seen`` and ``report_count`` accumulate across reports; ``silent``
        is preserved on update (the dead-man transition logic owns that flag).
        """
        cur = self.db.execute(
            "SELECT first_seen, report_count, silent FROM fleet_nodes WHERE node_id=?",
            (node_id,))
        row = cur.fetchone()
        first_seen = row[0] if row else now
        count = (row[1] if row else 0) + 1
        keep_silent = silent if row is None else row[2]
        self.db.execute(
            "INSERT INTO fleet_nodes (node_id, hostname, token_hash, first_seen, "
            "last_seen, status, worst_severity, summary, cadence_s, wrench_version, "
            "findings, gauges, report_count, silent, meta, report_ts, key_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(node_id) DO UPDATE SET hostname=excluded.hostname, "
            "token_hash=excluded.token_hash, last_seen=excluded.last_seen, "
            "status=excluded.status, worst_severity=excluded.worst_severity, "
            "summary=excluded.summary, cadence_s=excluded.cadence_s, "
            "wrench_version=excluded.wrench_version, findings=excluded.findings, "
            "gauges=excluded.gauges, report_count=excluded.report_count, "
            "meta=excluded.meta, report_ts=excluded.report_ts, key_id=excluded.key_id",
            (node_id, hostname, token_hash, first_seen, now, status, worst_severity,
             summary, cadence_s, wrench_version, json.dumps(findings or []),
             json.dumps(gauges or {}), count, keep_silent,
             json.dumps(meta or {}), report_ts, key_id),
        )
        self.db.execute(
            "INSERT INTO fleet_reports (node_id, ts, status, worst_severity, summary, payload) "
            "VALUES (?,?,?,?,?,?)",
            (node_id, now, status, worst_severity, summary,
             json.dumps({"findings": findings or [], "gauges": gauges or {},
                         "score": (meta or {}).get("score")})),
        )
        self.db.commit()
        return self.get_fleet_node(node_id)

    def prune_fleet_reports(self, node_id: str, keep: int = 200) -> int:
        """Cap a node's report history to the newest ``keep`` rows. Returns deleted."""
        cur = self.db.execute(
            "SELECT COUNT(*) FROM fleet_reports WHERE node_id=?", (node_id,))
        total = cur.fetchone()[0]
        if total <= keep:
            return 0
        self.db.execute(
            "DELETE FROM fleet_reports WHERE node_id=? AND ts NOT IN "
            "(SELECT ts FROM fleet_reports WHERE node_id=? ORDER BY ts DESC LIMIT ?)",
            (node_id, node_id, keep),
        )
        self.db.commit()
        return total - keep

    def _fleet_row(self, r) -> dict:
        return dict(
            node_id=r[0], hostname=r[1], token_hash=r[2], first_seen=r[3],
            last_seen=r[4], status=r[5], worst_severity=r[6], summary=r[7],
            cadence_s=r[8], wrench_version=r[9],
            findings=json.loads(r[10] or "[]"), gauges=json.loads(r[11] or "{}"),
            report_count=r[12], silent=bool(r[13]),
            meta=json.loads(r[14] or "{}"), report_ts=r[15], key_id=r[16],
        )

    _FLEET_COLS = ("node_id, hostname, token_hash, first_seen, last_seen, status, "
                   "worst_severity, summary, cadence_s, wrench_version, findings, "
                   "gauges, report_count, silent, meta, report_ts, key_id")

    def get_fleet_node(self, node_id: str) -> dict | None:
        cur = self.db.execute(
            f"SELECT {self._FLEET_COLS} FROM fleet_nodes WHERE node_id=?", (node_id,))
        r = cur.fetchone()
        return self._fleet_row(r) if r else None

    def fleet_nodes(self) -> list[dict]:
        cur = self.db.execute(
            f"SELECT {self._FLEET_COLS} FROM fleet_nodes ORDER BY last_seen DESC")
        return [self._fleet_row(r) for r in cur.fetchall()]

    def set_fleet_silent(self, node_id: str, silent: bool) -> None:
        self.db.execute("UPDATE fleet_nodes SET silent=? WHERE node_id=?",
                        (int(silent), node_id))
        self.db.commit()

    def fleet_report_history(self, node_id: str, limit: int = 50) -> list[dict]:
        cur = self.db.execute(
            "SELECT ts, status, worst_severity, summary, payload FROM fleet_reports "
            "WHERE node_id=? ORDER BY ts DESC LIMIT ?", (node_id, limit))
        out = []
        for r in cur.fetchall():
            try:
                payload = json.loads(r[4] or "{}")
            except json.JSONDecodeError:
                payload = {}
            gauges = payload.get("gauges") or {}
            out.append(dict(ts=r[0], status=r[1], worst_severity=r[2], summary=r[3],
                            score=payload.get("score"),
                            mem_pct=gauges.get("mem_pct"),
                            cpu_pct=gauges.get("cpu_pct"),
                            disk_max_pct=_max_number(gauges.get("disk_pct"))))
        return out

    def delete_fleet_node(self, node_id: str) -> bool:
        """Forget a node (decommissioned box): its row and its report history."""
        cur = self.db.execute("DELETE FROM fleet_nodes WHERE node_id=?", (node_id,))
        self.db.execute("DELETE FROM fleet_reports WHERE node_id=?", (node_id,))
        self.db.commit()
        return cur.rowcount > 0

    # ---- fleet enrollment keys (hub side) ----
    _KEY_COLS = "key_id, label, hmac_key, created, revoked, single_node, last_used"

    @staticmethod
    def _key_row(r) -> dict:
        return dict(key_id=r[0], label=r[1], hmac_key=r[2], created=r[3],
                    revoked=r[4], single_node=bool(r[5]), last_used=r[6])

    def add_fleet_key(self, key_id: str, label: str, hmac_key: str,
                      created: float, single_node: bool = False) -> None:
        self.db.execute(
            "INSERT INTO fleet_keys (key_id, label, hmac_key, created, single_node) "
            "VALUES (?,?,?,?,?)", (key_id, label, hmac_key, created, int(single_node)))
        self.db.commit()

    def get_fleet_key(self, key_id: str) -> dict | None:
        r = self.db.execute(
            f"SELECT {self._KEY_COLS} FROM fleet_keys WHERE key_id=?", (key_id,)).fetchone()
        return self._key_row(r) if r else None

    def fleet_keys(self) -> list[dict]:
        cur = self.db.execute(
            f"SELECT {self._KEY_COLS} FROM fleet_keys ORDER BY created DESC")
        return [self._key_row(r) for r in cur.fetchall()]

    def revoke_fleet_key(self, key_id: str, now: float) -> bool:
        cur = self.db.execute(
            "UPDATE fleet_keys SET revoked=? WHERE key_id=? AND revoked IS NULL",
            (now, key_id))
        self.db.commit()
        return cur.rowcount > 0

    def touch_fleet_key(self, key_id: str, now: float) -> None:
        self.db.execute("UPDATE fleet_keys SET last_used=? WHERE key_id=?", (now, key_id))
        self.db.commit()

    def fleet_nodes_for_key(self, key_id: str) -> list[str]:
        cur = self.db.execute("SELECT node_id FROM fleet_nodes WHERE key_id=?", (key_id,))
        return [r[0] for r in cur.fetchall()]

    def add_fleet_token(self, token_hash: str, label: str, created: float) -> None:
        self.db.execute(
            "INSERT INTO fleet_tokens (token_hash, label, created) VALUES (?,?,?) "
            "ON CONFLICT(token_hash) DO UPDATE SET label=excluded.label",
            (token_hash, label, created))
        self.db.commit()

    def fleet_tokens(self) -> list[dict]:
        cur = self.db.execute(
            "SELECT token_hash, label, created FROM fleet_tokens ORDER BY created DESC")
        return [dict(token_hash=r[0], label=r[1], created=r[2]) for r in cur.fetchall()]

    # ---- housekeeping ----
    def prune(self, retention_days: int = 30) -> dict:
        """Apply retention. Returns {table: rows_deleted}.

        - raw telemetry (samples, anomalies, diffs) ages out at ``retention_days``;
        - snapshots age out too, EXCEPT the newest row of each kind — that row is
          the live drift baseline / accepted security or compliance baseline, and
          deleting it would silently un-bless the box;
        - operational history (patrols, actions, token spend, spent approvals)
          is kept for at least a year.
        """
        now = time.time()
        retention_days = max(1, int(retention_days))
        cutoff = now - retention_days * 86400
        history_cutoff = now - max(retention_days, HISTORY_RETENTION_FLOOR_DAYS) * 86400
        deleted: dict[str, int] = {}
        for table in ("samples", "anomalies", "diffs"):
            cur = self.db.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
            deleted[table] = cur.rowcount
        # the health-score history is a trend line, kept as long as other history
        cur = self.db.execute(
            "DELETE FROM snapshots WHERE kind = 'posture_history' AND ts < ?",
            (history_cutoff,))
        cur = self.db.execute(
            "DELETE FROM snapshots WHERE kind != 'posture_history' AND ts < ? AND rowid NOT IN "
            "(SELECT rowid FROM snapshots s WHERE s.ts = "
            " (SELECT MAX(ts) FROM snapshots WHERE kind = s.kind))", (cutoff,))
        deleted["snapshots"] = cur.rowcount
        for table in ("patrols", "actions", "tokens_spent"):
            cur = self.db.execute(f"DELETE FROM {table} WHERE ts < ?", (history_cutoff,))
            deleted[table] = cur.rowcount
        cur = self.db.execute("DELETE FROM approvals WHERE expires < ?", (history_cutoff,))
        deleted["approvals"] = cur.rowcount
        self.db.commit()
        return deleted

    def maybe_prune(self, retention_days: int = 30, every_s: float = 6 * 3600) -> dict | None:
        """Prune at most once per ``every_s`` — cheap enough to call on every patrol."""
        last = self.cache_get("_last_prune", every_s)
        if last is not None:
            return None
        deleted = self.prune(retention_days)
        self.cache_put("_last_prune", {"deleted": deleted})
        return deleted

    def table_counts(self) -> dict[str, int]:
        out = {}
        for table in ("samples", "anomalies", "snapshots", "diffs", "patrols",
                      "actions", "fleet_nodes", "fleet_reports"):
            out[table] = self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        return out

    def close(self) -> None:
        self.db.close()
