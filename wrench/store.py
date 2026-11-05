"""sqlite store for wrench: samples, snapshots, diffs, patrols, actions, token spend."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

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


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path))
        self.db.executescript(SCHEMA)
        self.db.commit()

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
            sd = ewvar**0.5
            if n >= 20 and sd > 1e-9:
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

    # ---- housekeeping ----
    def prune(self, retention_days: int = 30) -> None:
        cutoff = time.time() - retention_days * 86400
        for table in ("samples", "anomalies", "snapshots", "diffs"):
            self.db.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))
        self.db.commit()

    def close(self) -> None:
        self.db.close()
