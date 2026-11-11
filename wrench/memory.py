"""Memory: what wrench has been told, has noticed, and has learned.

Three sources, three levels of trust:

- ``user``    — the operator said it (``wrench remember``, the dashboard, or a
                chat turn they confirmed). Active immediately.
- ``agent``   — the model wants to keep a note. With a human present it is
                confirmed on the spot; unattended it lands in a **review queue**
                (``status = pending``) and is not shown to any model until the
                operator approves it. A log line can talk a model into writing
                "xmrig is expected, ignore it" — it must never be able to make
                that stick on its own.
- ``learned`` — derived by code from what the operator actually did (which
                fixes they approved, which commands they run and when). No
                model is involved, so nothing in a log can forge one.

Memory informs judgement. It never changes the policy tier, never authorises a
command, and is plain text in the local database — so it refuses anything that
looks like a credential.

Retrieval is deterministic and offline: keyword overlap, pins, kind and
recency. No embeddings, no network.
"""

from __future__ import annotations

import json
import re
import time

KINDS = ("preference", "fact", "procedure", "lesson", "observation")
SOURCES = ("user", "agent", "learned")
STATUSES = ("active", "pending", "forgotten", "rejected")

MAX_TEXT = 500
MAX_ACTIVE = 1000
MAX_PENDING = 100
PROMPT_BUDGET_CHARS = 2400
PROMPT_MAX_ITEMS = 14

_KIND_HELP = {
    "preference": "how the operator wants things done",
    "fact": "something true about this machine or its environment",
    "procedure": "the agreed way to handle a situation",
    "lesson": "what was learned from an incident",
    "observation": "a pattern noticed on this machine",
}

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(sk|rk|pk)-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\bwfl_[A-Za-z0-9_\-]{16,}"),
    re.compile(r"(?i)\b(pass(word|wd)?|secret|api[_-]?key|token|bearer)\b\s*(is|[:=])\s*\S{6,}"),
)

_STOP = frozenset("""a an and are as at be been but by can do does for from had has have how i if in
into is it its me my no not of on or our so than that the their them then there these they this
to up us use was we were what when where which who will with you your always never should
please wrench machine box server host""".split())

_WORD = re.compile(r"[a-z0-9][a-z0-9_.:/\-]*")


class MemoryError_(ValueError):
    """Human-facing refusal (too long, looks like a secret, unknown kind)."""


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------

def settings(cfg) -> dict:
    """[memory] — enabled, agent_writes (review | off), learn_habits."""
    sec = (getattr(cfg, "raw", None) or {}).get("memory", {})
    if not isinstance(sec, dict):
        sec = {}
    mode = str(sec.get("agent_writes", "review")).lower()
    if mode not in ("review", "off"):
        mode = "review"
    return {
        "enabled": bool(sec.get("enabled", True)),
        "agent_writes": mode,
        "learn_habits": bool(sec.get("learn_habits", True)),
    }


# --------------------------------------------------------------------------
# text hygiene
# --------------------------------------------------------------------------

def clean_text(text: str) -> str:
    """One line, printable, bounded. Memory is shown to a model and to people;
    neither should receive control characters or a wall of text."""
    t = "".join(ch if ch.isprintable() else " " for ch in str(text or ""))
    return re.sub(r"\s+", " ", t).strip()


def looks_secret(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)


def _tokens(text: str) -> set[str]:
    return {w.strip(".:-/") for w in _WORD.findall(text.lower())
            if len(w) > 1 and w not in _STOP}


def _norm(text: str) -> str:
    """The identity of a memory: lower-case, single-spaced, no end punctuation."""
    return re.sub(r"\s+", " ", str(text).lower()).strip(" .!;,")


# --------------------------------------------------------------------------
# rows
# --------------------------------------------------------------------------

_COLS = "id, ts, updated, kind, text, source, status, pinned, uses, last_used, origin"


def _row(r) -> dict:
    return {"id": r[0], "ts": r[1], "updated": r[2], "kind": r[3], "text": r[4],
            "source": r[5], "status": r[6], "pinned": bool(r[7]), "uses": r[8],
            "last_used": r[9], "origin": r[10] or ""}


def get(store, mem_id: int) -> dict | None:
    r = store.db.execute(f"SELECT {_COLS} FROM memories WHERE id = ?", (int(mem_id),)).fetchone()
    return _row(r) if r else None


def list_memories(store, status: str = "active", kind: str | None = None,
                  limit: int = 500) -> list[dict]:
    sql = f"SELECT {_COLS} FROM memories WHERE status = ?"
    args: list = [status]
    if kind:
        sql += " AND kind = ?"
        args.append(kind)
    sql += " ORDER BY pinned DESC, updated DESC LIMIT ?"
    args.append(int(limit))
    return [_row(r) for r in store.db.execute(sql, args).fetchall()]


def counts(store) -> dict:
    out = {s: 0 for s in ("active", "pending")}
    for status, n in store.db.execute(
            "SELECT status, COUNT(*) FROM memories GROUP BY status").fetchall():
        if status in out:
            out[status] = n
    out["pinned"] = store.db.execute(
        "SELECT COUNT(*) FROM memories WHERE status = 'active' AND pinned = 1").fetchone()[0]
    return out


# --------------------------------------------------------------------------
# writes
# --------------------------------------------------------------------------

def add(store, text: str, kind: str = "fact", source: str = "user",
        status: str | None = None, pinned: bool = False, origin: str = "",
        cfg=None, now: float | None = None) -> dict:
    """Save one memory. Returns the row, with ``"duplicate": True`` when an
    equivalent one already existed (it is refreshed instead of copied).

    Raises MemoryError_ for text that is empty, too long, or looks like a secret.
    """
    text = clean_text(text)
    kind = (kind or "fact").lower()
    if kind not in KINDS:
        raise MemoryError_(f"unknown kind '{kind}' — use one of: {', '.join(KINDS)}")
    if source not in SOURCES:
        raise MemoryError_(f"unknown source '{source}'")
    if not text:
        raise MemoryError_("nothing to remember")
    if len(text) > MAX_TEXT:
        raise MemoryError_(f"too long ({len(text)} chars) — keep a memory under {MAX_TEXT}; "
                           "split it, or put the detail in a runbook and remember where it is")
    if looks_secret(text):
        raise MemoryError_("that looks like a credential. Memory is plain text in wrench's "
                           "database and is shown to the model — keep secrets in a key file")
    status = status or "active"
    if status not in ("active", "pending"):
        raise MemoryError_(f"cannot create a memory as '{status}'")
    now = now if now is not None else time.time()

    key = _norm(text)
    with store.immediate():
        # De-duplication is EXACT (case, spacing and end punctuation aside).
        # A fuzzy match would let "never page me about X" be swallowed by
        # "always page me about X" — or let a model's pending note ride into
        # the active set on the back of a similar-looking write.
        for row in store.db.execute(
                f"SELECT {_COLS} FROM memories WHERE status IN ('active', 'pending')").fetchall():
            m = _row(row)
            if _norm(m["text"]) != key:
                continue
            if m["status"] == "pending" and not (source == "user" and status == "active"):
                if status == "pending":            # the same note queued twice
                    m["duplicate"] = True
                    return m
                continue                           # code never approves a model's note
            # active duplicate → refresh; pending + the operator typing the very
            # same sentence → that is an approval, and it becomes their word
            promote = m["status"] == "pending"
            store.db.execute(
                "UPDATE memories SET updated = ?, pinned = MAX(pinned, ?), status = 'active', "
                "source = ?, kind = ? WHERE id = ?",
                (now, int(pinned), source if promote else m["source"],
                 kind if promote else m["kind"], m["id"]))
            m = get(store, m["id"]) or m
            m["duplicate"] = True
            return m
        cap, label = (MAX_PENDING, "pending") if status == "pending" else (MAX_ACTIVE, "active")
        n = store.db.execute("SELECT COUNT(*) FROM memories WHERE status = ?",
                             (status,)).fetchone()[0]
        if n >= cap:
            raise MemoryError_(
                f"{n} {label} memories already — " + (
                    "review them first (wrench memory review)" if status == "pending"
                    else "forget some first (wrench memory, wrench memory forget <id>)"))
        cur = store.db.execute(
            "INSERT INTO memories (ts, updated, kind, text, source, status, pinned, origin) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (now, now, kind, text, source, status, int(pinned), origin[:120]))
        mem_id = cur.lastrowid
    m = get(store, mem_id)
    _audit(cfg, "memory.add", {"id": mem_id, "kind": kind, "source": source,
                               "status": status, "text": text})
    return m


def set_status(store, mem_id: int, status: str, cfg=None) -> dict | None:
    """approve (pending→active), reject (pending→rejected), forget (→forgotten)."""
    if status not in STATUSES:
        raise MemoryError_(f"unknown status '{status}'")
    m = get(store, mem_id)
    if m is None:
        return None
    store.db.execute("UPDATE memories SET status = ?, updated = ? WHERE id = ?",
                     (status, time.time(), int(mem_id)))
    store.db.commit()
    _audit(cfg, {"active": "memory.approve", "forgotten": "memory.forget",
                 "rejected": "memory.reject"}.get(status, "memory.update"),
           {"id": mem_id, "was": m["status"], "text": m["text"]})
    return get(store, mem_id)


def set_pinned(store, mem_id: int, pinned: bool = True) -> dict | None:
    if get(store, mem_id) is None:
        return None
    store.db.execute("UPDATE memories SET pinned = ? WHERE id = ?", (int(pinned), int(mem_id)))
    store.db.commit()
    return get(store, mem_id)


def _audit(cfg, kind: str, detail: dict) -> None:
    if cfg is None:
        return
    try:
        from . import audit
        audit.log_event(cfg, kind, detail)
    except Exception:  # noqa: BLE001 — bookkeeping never breaks a memory write
        pass


# --------------------------------------------------------------------------
# retrieval
# --------------------------------------------------------------------------

_KIND_WEIGHT = {"preference": 0.30, "procedure": 0.25, "lesson": 0.15, "fact": 0.10,
                "observation": 0.0}


def score(mem: dict, query_tokens: set[str], now: float) -> float:
    """Relevance of one memory to a query. Pure, so it is testable."""
    mt = _tokens(mem["text"])
    overlap = len(mt & query_tokens)
    s = 0.0
    if overlap:
        s += 2.0 * overlap / (len(query_tokens) ** 0.5 or 1.0)
        s += 0.6 * overlap / (len(mt) or 1)
    if mem.get("pinned"):
        s += 5.0
    s += _KIND_WEIGHT.get(mem["kind"], 0.0)
    age_days = max(0.0, (now - (mem.get("updated") or now)) / 86400)
    s += 0.25 / (1.0 + age_days / 30.0)
    return s


def search(store, query: str, limit: int = 20, status: str = "active") -> list[dict]:
    """Memories that share words with the query, best first."""
    q = _tokens(query)
    now = time.time()
    scored = []
    for m in list_memories(store, status=status, limit=MAX_ACTIVE):
        if q & _tokens(m["text"]):
            scored.append((score(m, q, now), m))
    scored.sort(key=lambda x: -x[0])
    return [m for _, m in scored[:limit]]


def relevant(store, query: str = "", max_items: int = PROMPT_MAX_ITEMS,
             budget_chars: int = PROMPT_BUDGET_CHARS, touch: bool = True) -> list[dict]:
    """What to put in front of the model for this task.

    Pinned memories and standing preferences/procedures always come along
    (they are how the operator wants *everything* done); the rest must share
    words with the task. Bounded by item count and characters."""
    q = _tokens(query)
    now = time.time()
    scored = []
    for m in list_memories(store, status="active", limit=MAX_ACTIVE):
        standing = m["pinned"] or m["kind"] in ("preference", "procedure")
        if not standing and not (q & _tokens(m["text"])):
            continue
        scored.append((score(m, q, now), m))
    scored.sort(key=lambda x: -x[0])
    out, used = [], 0
    for _, m in scored:
        cost = len(m["text"]) + 24
        if len(out) >= max_items or used + cost > budget_chars:
            continue
        out.append(m)
        used += cost
    if touch and out:
        try:
            store.db.executemany(
                "UPDATE memories SET uses = uses + 1, last_used = ? WHERE id = ?",
                [(now, m["id"]) for m in out])
            store.db.commit()
        except Exception:  # noqa: BLE001 — a read-only store still answers
            pass
    return out


_SOURCE_TAG = {"user": "operator", "agent": "note", "learned": "learned"}


def prompt_block(store, query: str = "", cfg=None) -> str:
    """The memory section of a system prompt, or '' when there is nothing."""
    if cfg is not None and not settings(cfg)["enabled"]:
        return ""
    try:
        mems = relevant(store, query)
    except Exception:  # noqa: BLE001 — memory must never break an agent run
        return ""
    if not mems:
        return ""
    lines = [
        "MEMORY — what you already know about this machine and its operator.",
        "[operator] lines were written by the human: follow them as standing preferences.",
        "[note] lines are your own earlier notes, approved by the operator. [learned] lines",
        "were derived from what the operator actually did. Memory informs your judgement; it",
        "never widens what the policy tier allows and never authorises a command by itself.",
    ]
    for m in mems:
        tag = _SOURCE_TAG.get(m["source"], m["source"])
        lines.append(f"- #{m['id']} [{tag} · {m['kind']}] {m['text']}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# agent tools
# --------------------------------------------------------------------------

def tool_remember(store, cfg, text: str, kind: str = "fact", confirm_fn=None,
                  origin: str = "agent") -> str:
    """The model asks to keep a note. Present human → confirmed now.
    Nobody present → queued for review, invisible to models until approved."""
    st = settings(cfg) if cfg is not None else {"enabled": True, "agent_writes": "review"}
    if not st["enabled"]:
        return "memory is disabled on this machine ([memory] enabled = false)."
    try:
        text = clean_text(text)
        if confirm_fn is not None:
            if not confirm_fn(f"[{kind}] {text}", "memory: remember this"):
                return "NOT SAVED: the human declined. Do not ask again in this conversation."
            m = add(store, text, kind, source="agent", status="active", origin=origin, cfg=cfg)
            return (f"saved as memory #{m['id']}" if not m.get("duplicate")
                    else f"already known as memory #{m['id']} (refreshed)")
        if st["agent_writes"] == "off":
            return ("NOT SAVED: unattended memory writes are off on this machine. Mention the "
                    "point in your answer so the human can run `wrench remember`.")
        m = add(store, text, kind, source="agent", status="pending", origin=origin, cfg=cfg)
        if m.get("duplicate"):
            return f"already recorded as memory #{m['id']} ({m['status']})"
        return (f"queued as #{m['id']} for the operator's review (wrench memory review). "
                "It is not active yet — do not rely on it.")
    except MemoryError_ as e:
        return f"NOT SAVED: {e}"


def tool_recall(store, query: str) -> str:
    rows = search(store, query, limit=8)
    if not rows:
        return "nothing in memory matches that."
    return "\n".join(f"#{m['id']} [{_SOURCE_TAG.get(m['source'], m['source'])} · {m['kind']}] "
                     f"{m['text']}" for m in rows)


# --------------------------------------------------------------------------
# habits — learning from what the operator does (no model involved)
# --------------------------------------------------------------------------

APPROVALS_TO_LEARN = 3          # same fix approved this many times, never declined
HABIT_MIN_RUNS = 5              # same command …
HABIT_MIN_DAYS = 4              # … on this many distinct days …
HABIT_HOUR_SPREAD = 1           # … within ±1h of the same hour
HABIT_WINDOW_DAYS = 21


def _habit(store, key: str) -> dict | None:
    r = store.db.execute(
        "SELECT key, kind, n, first, last, payload FROM habits WHERE key = ?", (key,)).fetchone()
    if not r:
        return None
    try:
        payload = json.loads(r[5]) if r[5] else {}
    except ValueError:
        payload = {}
    return {"key": r[0], "kind": r[1], "n": r[2], "first": r[3], "last": r[4],
            "payload": payload}


def _put_habit(store, key: str, kind: str, n: int, first: float, last: float,
               payload: dict) -> None:
    store.db.execute(
        "INSERT INTO habits (key, kind, n, first, last, payload) VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET n = excluded.n, last = excluded.last, "
        "payload = excluded.payload", (key, kind, n, first, last, json.dumps(payload)))
    store.db.commit()


def note_decision(store, command: str, approved: bool, cfg=None,
                  now: float | None = None) -> dict | None:
    """The operator answered a "run this fix?" prompt. After the same command
    has been approved APPROVALS_TO_LEARN times and never declined, remember it
    — and say what would stop the asking. Returns the new memory, if any."""
    command = clean_text(command)[:200]
    if not command:
        return None
    now = now if now is not None else time.time()
    key = f"fix:{command}"
    h = _habit(store, key) or {"n": 0, "first": now, "payload": {}}
    p = h["payload"]
    p["approved"] = int(p.get("approved", 0)) + (1 if approved else 0)
    p["declined"] = int(p.get("declined", 0)) + (0 if approved else 1)
    _put_habit(store, key, "fix", h["n"] + 1, h["first"], now, p)
    if approved and p["approved"] >= APPROVALS_TO_LEARN and not p["declined"] \
            and not p.get("remembered"):
        p["remembered"] = True
        _put_habit(store, key, "fix", h["n"] + 1, h["first"], now, p)
        try:
            return add(store, f"The operator has approved `{command}` {p['approved']} times and "
                              "never declined it. It still needs confirmation at the repair "
                              "tier; the autonomous tier runs allowlisted fixes without asking.",
                       "observation", source="learned", origin="approvals", cfg=cfg, now=now)
        except MemoryError_:
            return None
    return None


def note_command(store, name: str, now: float | None = None) -> None:
    """Record that a read-only wrench command was run, and at what hour.
    Local only; feeds ``routine_candidates``. Never raises."""
    try:
        now = now if now is not None else time.time()
        key = f"cmd:{name}"
        h = _habit(store, key) or {"n": 0, "first": now, "payload": {}}
        lt = time.localtime(now)
        runs = [r for r in h["payload"].get("runs", [])
                if now - r[0] < HABIT_WINDOW_DAYS * 86400][-60:]
        runs.append([round(now), lt.tm_hour, time.strftime("%Y-%m-%d", lt)])
        payload = dict(h["payload"])
        payload["runs"] = runs
        _put_habit(store, key, "cmd", h["n"] + 1, h["first"], now, payload)
    except Exception:  # noqa: BLE001
        pass


def routine_candidates(store, now: float | None = None) -> list[dict]:
    """Commands the operator runs by hand at about the same time on several
    days — work wrench could simply do for them. [{command, hour, days, runs}]"""
    now = now if now is not None else time.time()
    out = []
    for r in store.db.execute("SELECT key FROM habits WHERE kind = 'cmd'").fetchall():
        h = _habit(store, r[0])
        if not h or h["payload"].get("proposed"):
            continue
        runs = [x for x in h["payload"].get("runs", [])
                if now - x[0] < HABIT_WINDOW_DAYS * 86400]
        if len(runs) < HABIT_MIN_RUNS:
            continue
        best = None
        for hour in range(24):
            near = [x for x in runs
                    if min((x[1] - hour) % 24, (hour - x[1]) % 24) <= HABIT_HOUR_SPREAD]
            days = {x[2] for x in near}
            # ties between neighbouring hours go to the one the runs sit on
            rank = (len(near), sum(1 for x in near if x[1] == hour))
            if len(near) >= HABIT_MIN_RUNS and len(days) >= HABIT_MIN_DAYS \
                    and (best is None or rank > best["rank"]):
                best = {"command": h["key"][4:], "hour": hour, "days": len(days),
                        "runs": len(near), "rank": rank}
        if best:
            best.pop("rank")
            out.append(best)
    return sorted(out, key=lambda c: -c["runs"])


def mark_proposed(store, command: str) -> None:
    h = _habit(store, f"cmd:{command}")
    if h:
        h["payload"]["proposed"] = True
        _put_habit(store, h["key"], "cmd", h["n"], h["first"], h["last"], h["payload"])


# --------------------------------------------------------------------------
# export / import
# --------------------------------------------------------------------------

def export(store) -> list[dict]:
    return [{"kind": m["kind"], "text": m["text"], "pinned": m["pinned"],
             "source": m["source"]} for m in reversed(list_memories(store, limit=MAX_ACTIVE))]


def import_(store, items: list, cfg=None) -> dict:
    """Load memories from an export. Everything imported is the operator's
    word (``source = user``): they chose to load the file."""
    added = dup = skipped = 0
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict):
            skipped += 1
            continue
        try:
            m = add(store, str(it.get("text", "")), str(it.get("kind", "fact")),
                    source="user", pinned=bool(it.get("pinned")), origin="import", cfg=cfg)
        except MemoryError_:
            skipped += 1
            continue
        if m.get("duplicate"):
            dup += 1
        else:
            added += 1
    return {"added": added, "duplicates": dup, "skipped": skipped}


def kind_help() -> dict:
    return dict(_KIND_HELP)
