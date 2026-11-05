"""wrench offline — the zero-egress guarantee.

Most of wrench already works on a disconnected box: the brain can be a local
ollama/vLLM endpoint, and OSV/webintel/EOL lookups fail soft. This module turns
offline from an *accident of fail-softs* into a *declared, enforced mode*.

Declare it in config.toml::

    [general]
    offline = true          # or a top-level  offline = true

When offline is on, wrench NEVER reaches a public host: OSV/CVE lookups,
endoflife.date, webintel, update checks, and provider calls to non-private
base_urls are refused with a clear, actionable message. What still works:
everything local — the local brain (ollama/vLLM/llama.cpp on 127.0.0.1 or a
LAN IP), status/drift/comply/forecast/backups/audit, and fleet push to a hub on
a private CIDR (fleet is LAN by design).

"Private" is decided with the stdlib ``ipaddress`` module — loopback,
RFC1918 (10/8, 172.16/12, 192.168/16), link-local, CGNAT (100.64/10, which
covers Tailscale), unique-local IPv6 (fc00::/7), and the literal host
``localhost``. No DNS resolution happens here (DNS is itself egress, and may be
dead on an air-gapped box); a bare hostname that is not ``localhost`` is treated
as public and refused.

Design rules:
  - stdlib only (ipaddress, urllib.parse).
  - Zero behavior change when offline is unset/false: ``is_offline`` is False,
    ``egress_allowed`` is always True, ``guard`` always allows.
  - Pure + deterministic: easy to unit-test, no network, no clock.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit


# ---------------- config knob ----------------

def is_offline(cfg) -> bool:
    """True when offline mode is declared.

    Accepts ``[general] offline = true`` or a top-level ``offline = true`` in
    config.toml. Also honours a ``cfg.offline`` attribute if a Config grows one.
    """
    val = getattr(cfg, "offline", None)
    if val is not None:
        return bool(val)
    raw = getattr(cfg, "raw", {}) or {}
    gen = raw.get("general", {})
    if isinstance(gen, dict) and "offline" in gen:
        return bool(gen.get("offline"))
    return bool(raw.get("offline", False))


# ---------------- private / loopback detection ----------------

def _ip_is_private(ip: ipaddress._BaseAddress) -> bool:
    """RFC1918 + loopback + link-local + CGNAT (Tailscale) + ULA → private."""
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return True
    # 100.64.0.0/10 (CGNAT, used by Tailscale) is .is_private on modern stdlib,
    # but be explicit for older interpreters.
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False


def host_is_private(host: str) -> bool:
    """Is this host local/private (no network egress needed to reach it)?

    - ``localhost`` / ``*.localhost`` → True (loopback by convention).
    - an IP literal (incl. bracketed IPv6 and zone ids) that is loopback,
      RFC1918, link-local, CGNAT, or ULA → True.
    - anything else (a real hostname, or empty) → False. We do NOT resolve DNS:
      resolution is egress, and on an air-gapped box it would just fail.
    """
    if not host:
        return False
    h = host.strip().lower()
    # strip IPv6 brackets and any %zone suffix
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    h = h.split("%", 1)[0]
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        return _ip_is_private(ipaddress.ip_address(h))
    except ValueError:
        return False


def url_is_private(url: str) -> bool:
    """True when the URL's host is local/private. Malformed/relative → False."""
    if not url:
        return False
    try:
        parts = urlsplit(url if "://" in url else "//" + url, scheme="")
    except ValueError:
        return False
    return host_is_private(parts.hostname or "")


# ---------------- the guard ----------------

@dataclass
class GuardResult:
    allowed: bool
    reason: str          # human-readable; empty when allowed and online

    def __bool__(self) -> bool:  # `if guard(...):`
        return self.allowed


def egress_allowed(cfg, url: str) -> bool:
    """Would a request to ``url`` be allowed under the current config?

    Online (offline unset/false): always True — zero behavior change.
    Offline: True only for private/loopback hosts.
    """
    if not is_offline(cfg):
        return True
    return url_is_private(url)


def guard(cfg, url: str, feature: str) -> GuardResult:
    """Gate one egress attempt. Returns a GuardResult (truthy when allowed).

    - online → always allowed.
    - offline + private/loopback host → allowed (local brain, LAN fleet hub…).
    - offline + public host → refused with an actionable message naming the
      feature and the host, so the operator knows exactly what was skipped and
      why.
    """
    if not is_offline(cfg):
        return GuardResult(True, "")
    if url_is_private(url):
        return GuardResult(True, "")
    host = ""
    try:
        host = urlsplit(url if "://" in url else "//" + url, scheme="").hostname or url
    except ValueError:
        host = url
    return GuardResult(
        False,
        f"{feature}: skipped — wrench is in offline mode (offline = true) and "
        f"{host or 'this endpoint'} is not a local/private address. "
        f"Disable offline mode or point this at a private endpoint to use it.",
    )


def status_summary(cfg) -> dict:
    """Small dict for doctor/status/bundle. What offline disables when on."""
    off = is_offline(cfg)
    return {
        "offline": off,
        "egress": "blocked (local/private only)" if off else "allowed",
        "disabled": (
            ["OSV/CVE lookups", "endoflife.date (EOL)", "webintel",
             "update checks", "provider calls to public endpoints"]
            if off else []
        ),
        "still_allowed": (
            ["local brain (loopback/LAN)", "fleet push to a private hub",
             "all local checks (status, drift, comply, forecast, backups, audit)"]
            if off else []
        ),
    }
