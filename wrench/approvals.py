"""wrench approvals — async, out-of-band approval for consent-gated actions.

Some changes should be approved by a *second* channel (a human in Slack/Teams,
a change-management bot) rather than whoever happens to be at the terminal.
This module gives wrench a dependency-free way to do that:

  1. a consent-gated operation running non-interactively mints a single-use
     token, stores its **hash** in sqlite with a TTL, and POSTs a pending
     approval ``{action, detail, token, expiry}`` to ``approval_webhook_url``;
  2. a second channel runs ``wrench approve <token>`` — the token is validated
     (exists, not expired, not already used) and the approval is recorded;
  3. the next run of that operation *claims* the approval (single execution)
     and proceeds.

Config (``[approvals]`` in config.toml) — **empty/missing = off** (unchanged
behavior)::

    [approvals]
    approval_webhook_url = "https://hooks.example.com/wrench"
    ttl_minutes          = 60

Design rules (house style): stdlib only; the token *plaintext* is never stored
or logged (only its sha256); lifecycle helpers take a Store + injected clock so
tests pin time with no host state; a webhook failure is never fatal.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import urllib.request
from dataclasses import dataclass

WEBHOOK_TIMEOUT_S = 5
DEFAULT_TTL_S = 3600.0


@dataclass
class ApprovalSettings:
    approval_webhook_url: str = ""
    ttl_s: float = DEFAULT_TTL_S

    @property
    def enabled(self) -> bool:
        """Approvals are active only when a webhook URL is configured."""
        return bool(self.approval_webhook_url)


def settings_from(cfg) -> ApprovalSettings:
    sec = (getattr(cfg, "raw", None) or {}).get("approvals", {})
    if not isinstance(sec, dict):
        sec = {}
    return ApprovalSettings(
        approval_webhook_url=str(sec.get("approval_webhook_url", "") or ""),
        ttl_s=max(60.0, float(sec.get("ttl_minutes", 60)) * 60.0),
    )


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    """URL-safe, high-entropy, single-use token (plaintext; never persisted)."""
    return secrets.token_urlsafe(24)


# ---------------- lifecycle (Store + injected clock) ----------------

def create_pending(store, action: str, detail: str, ttl_s: float = DEFAULT_TTL_S,
                   now: float | None = None) -> tuple[str, dict]:
    """Mint a pending approval. Returns (plaintext_token, record).

    Only the token hash is stored; the plaintext is returned once for the
    webhook payload and the operator message, then forgotten.
    """
    now = now if now is not None else time.time()
    token = generate_token()
    th = hash_token(token)
    expires = now + max(1.0, ttl_s)
    store.add_approval(th, action, detail, now, expires)
    rec = {"action": action, "detail": detail, "created": now,
           "expires": expires, "approved": False, "claimed": False}
    return token, rec


def webhook_payload(action: str, detail: str, token: str, expires: float) -> dict:
    return {
        "type": "wrench.approval.request",
        "action": action,
        "detail": detail,
        "token": token,
        "expiry": round(expires, 3),
        "expiry_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(expires)),
        "instructions": f"approve with: wrench approve {token}",
    }


def post_webhook(url: str, payload: dict, timeout: float = WEBHOOK_TIMEOUT_S,
                 opener=None) -> bool:
    """POST the pending-approval JSON. Failures are swallowed, never raised."""
    if not url:
        return False
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "wrench-approvals"})
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as resp:
            getattr(resp, "status", 200)
        return True
    except Exception:  # noqa: BLE001 — best-effort by contract
        return False


def approve(store, token: str, now: float | None = None) -> dict:
    """Validate and record an approval for a token.

    Returns {status, action, detail}. status in:
      approved | not_found | expired | already_used
    A token can be approved exactly once (reuse is rejected).
    """
    now = now if now is not None else time.time()
    th = hash_token(token)
    row = store.get_approval(th)
    if not row:
        return {"status": "not_found", "action": None, "detail": None}
    if row["approved"]:
        return {"status": "already_used", "action": row["action"],
                "detail": row["detail"]}
    if now > row["expires"]:
        return {"status": "expired", "action": row["action"],
                "detail": row["detail"]}
    store.set_approval_flags(th, approved=True)
    return {"status": "approved", "action": row["action"], "detail": row["detail"]}


def is_approved(store, action: str, now: float | None = None) -> bool:
    """True when an approved, unclaimed, unexpired approval exists for action."""
    now = now if now is not None else time.time()
    return store.approved_unclaimed_for(action, now) is not None


def claim_approval(store, action: str, now: float | None = None) -> bool:
    """Consume one approved, unexpired approval for action (single execution)."""
    now = now if now is not None else time.time()
    row = store.approved_unclaimed_for(action, now)
    if not row:
        return False
    store.set_approval_flags(row["token_hash"], claimed=True)
    return True


def create_and_notify(cfg, store, action: str, detail: str,
                      now: float | None = None, opener=None) -> tuple[str, bool]:
    """Mint a pending approval and POST the webhook. Returns (token, posted)."""
    st = settings_from(cfg)
    token, rec = create_pending(store, action, detail, st.ttl_s, now=now)
    # Offline guarantee: a token is still minted (so `wrench approve` works on
    # the LAN), but the webhook POST is skipped when the hook is a public host.
    from . import offline as _offline
    if _offline.is_offline(cfg) and not _offline.url_is_private(st.approval_webhook_url):
        return token, False
    posted = post_webhook(st.approval_webhook_url,
                          webhook_payload(action, detail, token, rec["expires"]),
                          opener=opener)
    return token, posted
