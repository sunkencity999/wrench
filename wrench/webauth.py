"""Access control for the wrench web surfaces (dashboard, fleet console, API).

The dashboard used to have exactly one defence: it bound 127.0.0.1. That holds
until someone runs `wrench web --bind 0.0.0.0` on a server — or until a web page
in the operator's own browser reaches http://127.0.0.1:8787 through DNS
rebinding and reads the whole machine's telemetry. This module closes both.

Model
-----
* **Loopback, no token configured** — zero-config local use stays zero-config:
  no login. But the ``Host`` header must be a loopback name, so a rebound
  hostname (evil.example → 127.0.0.1) is refused.
* **Anything else** (non-loopback bind, or a token configured) — every page
  and API call needs a credential: an ``Authorization: Bearer <token>`` header
  (scrapers, curl) or a signed session cookie (browsers, set by the login
  page). With no token configured for a non-loopback bind, one is generated
  and stored owner-only in the data dir, and printed at startup.
* **A password.** `wrench password` (or the prompt in `wrench init`) sets a
  dashboard password. Once one is set, sign-in is required on *every* bind,
  loopback included, and the password signs in as ``admin``. Only a salted
  scrypt hash is kept, owner-only, at ``<data_dir>/web_password``; the file is
  re-read when it changes, so setting, changing or clearing the password takes
  effect on a running server and signs out every browser session.
* **Two roles.** ``admin`` may read everything and act (chat with the agent,
  mark notifications read, retire fleet nodes). ``viewer`` is read-only — the
  wall display, the manager's bookmark.
* Node report ingest (``POST /api/fleet/report``) is *not* covered here: nodes
  authenticate each request with an HMAC signature (see wrench/fleet.py).

Everything is stdlib. Sessions are stateless (an HMAC-signed
``role.expiry`` pair), so a hub restart does not log everyone out and nothing
needs storing. Comparisons are constant-time; failed logins are rate-limited
per client address.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

COOKIE_NAME = "wrench_session"
SESSION_TTL_S = 12 * 3600
TOKEN_FILE = "web_token"
PASSWORD_FILE = "web_password"
PASSWORD_MIN = 8
PASSWORD_MAX = 256
# scrypt cost: 64 MiB, roughly 0.1-0.2 s per guess on current hardware
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 16, 8, 1
_PBKDF2_ITERS = 600_000          # fallback where OpenSSL was built without scrypt
_verify_lock = threading.Lock()  # one 64 MiB derivation at a time
ROLES = ("admin", "viewer")
_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "[::1]"}


def is_loopback_bind(bind: str) -> bool:
    """True when the listening address is only reachable from this machine."""
    b = (bind or "").strip().strip("[]").lower()
    if b == "localhost":
        return True
    try:
        return ipaddress.ip_address(b).is_loopback
    except ValueError:
        return False


def host_header_name(host_header: str) -> str:
    """The hostname part of a Host header (port stripped, IPv6 brackets kept off)."""
    h = (host_header or "").strip().lower()
    if h.startswith("["):                      # [::1]:8787
        return h[1:].split("]", 1)[0]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


# --------------------------------------------------------------- password
def password_problem(password: str) -> str | None:
    """Why this password cannot be used, or None when it can. Length is the
    only rule: composition rules make passwords worse, not better."""
    if not isinstance(password, str) or len(password) < PASSWORD_MIN:
        return f"use at least {PASSWORD_MIN} characters"
    if len(password) > PASSWORD_MAX:
        return f"use at most {PASSWORD_MAX} characters"
    if "\n" in password or "\r" in password or "\0" in password:
        return "a password cannot contain a line break"
    return None


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _derive(scheme: str, params: list[int], salt: bytes, password: str) -> bytes | None:
    pw = password.encode("utf-8", "replace")
    try:
        if scheme == "scrypt":
            n, r, p = params
            if not (2 ** 10 <= n <= 2 ** 20 and 1 <= r <= 32 and 1 <= p <= 16):
                return None        # a tampered file must not become a memory bomb
            return hashlib.scrypt(pw, salt=salt, n=n, r=r, p=p, dklen=32,
                                  maxmem=256 * 1024 * 1024)
        if scheme == "pbkdf2-sha256":
            (iters,) = params
            if not 10_000 <= iters <= 10_000_000:
                return None
            return hashlib.pbkdf2_hmac("sha256", pw, salt, iters, dklen=32)
    except (ValueError, AttributeError, MemoryError, OverflowError):
        return None
    return None


def hash_password(password: str) -> str:
    """A self-describing salted hash: ``scheme$params$salt$digest``."""
    salt = secrets.token_bytes(16)
    dk = _derive("scrypt", [_SCRYPT_N, _SCRYPT_R, _SCRYPT_P], salt, password)
    if dk is not None:
        return f"scrypt${_SCRYPT_N},{_SCRYPT_R},{_SCRYPT_P}${_b64(salt)}${_b64(dk)}"
    dk = _derive("pbkdf2-sha256", [_PBKDF2_ITERS], salt, password)
    return f"pbkdf2-sha256${_PBKDF2_ITERS}${_b64(salt)}${_b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored hash. Anything
    malformed is simply a mismatch."""
    try:
        scheme, params, salt, digest = (stored or "").strip().split("$")
        want = base64.b64decode(digest, validate=True)
        dk = _derive(scheme, [int(x) for x in params.split(",")],
                     base64.b64decode(salt, validate=True), password)
    except (ValueError, TypeError):
        return False
    return dk is not None and hmac.compare_digest(dk, want)


def password_path(data_dir: Path | str) -> Path:
    return Path(data_dir) / PASSWORD_FILE


def password_is_set(data_dir: Path | str) -> bool:
    return bool(_read_token_file(password_path(data_dir)))


def set_password(data_dir: Path | str, password: str) -> Path:
    """Store the hash of ``password`` owner-only. Raises ValueError when the
    password is unusable, OSError when the file cannot be written."""
    problem = password_problem(password)
    if problem:
        raise ValueError(problem)
    path = password_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".new")
    # created owner-only from the first byte, then swapped in whole: a server
    # reading mid-write sees the old hash or the new one, never half of one
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(hash_password(password) + "\n")
    if os.name == "posix":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def clear_password(data_dir: Path | str) -> bool:
    """Remove the password. True when there was one."""
    try:
        password_path(data_dir).unlink()
        return True
    except FileNotFoundError:
        return False


@dataclass
class AuthConfig:
    """Resolved web access policy for one server instance."""
    bind: str = "127.0.0.1"
    admin_token: str = ""
    viewer_token: str = ""
    allowed_hosts: list[str] = field(default_factory=list)
    tls: bool = False
    generated: bool = False        # the admin token was minted at startup
    password_file: Path | None = None
    _pw_cache: tuple = field(default=(None, ""), repr=False, compare=False)

    @property
    def password_hash(self) -> str:
        """The stored password hash ("" when none). Re-read when the file
        changes, so `wrench password` reaches a server that is already up."""
        if self.password_file is None:
            return ""
        try:
            st = os.stat(self.password_file)
            stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            self._pw_cache = (None, "")
            return ""
        if self._pw_cache[0] != stamp:
            self._pw_cache = (stamp, _read_token_file(self.password_file))
        return self._pw_cache[1]

    @property
    def has_password(self) -> bool:
        return bool(self.password_hash)

    @property
    def required(self) -> bool:
        # a network bind is never open: if its credentials vanish while it is
        # serving (password cleared), it locks rather than opens
        return bool(self.admin_token or self.viewer_token or self.password_hash) \
            or not self.loopback

    @property
    def loopback(self) -> bool:
        return is_loopback_bind(self.bind)

    def _session_key(self) -> bytes:
        # derived from the credentials: rotating a token or changing the
        # password invalidates every session
        return hashlib.sha256(
            b"wrench-web-session\0" + self.admin_token.encode() + b"\0"
            + self.viewer_token.encode() + b"\0" + self.password_hash.encode()).digest()

    # ---- credentials ----
    def role_for_token(self, token: str) -> str | None:
        """Constant-time match of a presented token against both roles."""
        token = (token or "").strip()
        role = None
        if self.admin_token and hmac.compare_digest(token.encode("utf-8", "replace"), self.admin_token.encode("utf-8", "replace")):
            role = "admin"
        if self.viewer_token and hmac.compare_digest(token.encode("utf-8", "replace"), self.viewer_token.encode("utf-8", "replace")) \
                and role is None:
            role = "viewer"
        return role

    def role_for_secret(self, secret: str) -> str | None:
        """What the sign-in form accepts: an access token, or the password."""
        role = self.role_for_token(secret)
        if role is not None:
            return role
        stored = self.password_hash
        if not stored or not secret or len(secret) > PASSWORD_MAX:
            return None
        with _verify_lock:
            return "admin" if verify_password(secret, stored) else None

    def make_session(self, role: str, now: float | None = None) -> str:
        exp = int((now if now is not None else time.time()) + SESSION_TTL_S)
        payload = f"{role}.{exp}"
        sig = hmac.new(self._session_key(), payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def role_for_session(self, cookie_value: str, now: float | None = None) -> str | None:
        try:
            role, exp, sig = (cookie_value or "").split(".", 2)
        except ValueError:
            return None
        want = hmac.new(self._session_key(), f"{role}.{exp}".encode("utf-8", "replace"),
                        hashlib.sha256).hexdigest()
        # compare bytes: compare_digest raises TypeError on non-ASCII str
        if not hmac.compare_digest(want.encode(), sig.encode("utf-8", "replace")) \
                or role not in ROLES:
            return None
        try:
            if int(exp) < (now if now is not None else time.time()):
                return None
        except ValueError:
            return None
        return role

    def session_cookie(self, role: str) -> str:
        attrs = [f"{COOKIE_NAME}={self.make_session(role)}", "Path=/", "HttpOnly",
                 "SameSite=Strict", f"Max-Age={SESSION_TTL_S}"]
        if self.tls:
            attrs.append("Secure")
        return "; ".join(attrs)

    @staticmethod
    def clear_cookie() -> str:
        return f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"

    # ---- request checks ----
    def host_allowed(self, host_header: str) -> bool:
        """Reject requests addressed to a name this server does not answer to.

        On a loopback bind that is the DNS-rebinding defence. On a wider bind
        it applies only when the operator listed ``allowed_hosts`` (credentials
        already stop a rebound origin there: it has no cookie for this host).
        """
        name = host_header_name(host_header)
        extra = {h.strip().lower() for h in self.allowed_hosts if h.strip()}
        if self.loopback:
            return name in _LOOPBACK_NAMES or name in extra
        return (not extra) or name in extra or name in _LOOPBACK_NAMES

    def role_for_request(self, headers) -> str | None:
        """The caller's role, or None when they must authenticate."""
        if not self.required:
            return "admin"                     # open loopback mode
        auth = headers.get("Authorization", "") or ""
        if auth.lower().startswith("bearer "):
            return self.role_for_token(auth[7:])
        for part in (headers.get("Cookie", "") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME:
                return self.role_for_session(value)
        return None

    def same_origin(self, headers) -> bool:
        """CSRF guard for state-changing requests.

        A browser attaches ``Origin`` to cross-site POSTs; it must name the
        host the request was sent to. No Origin (curl, scripts) is fine — those
        carry a bearer token, which a hostile page cannot.
        """
        origin = headers.get("Origin")
        if not origin:
            return True
        if origin == "null":          # sandboxed frame / opaque origin: never ours
            return False
        try:
            from urllib.parse import urlparse
            o = urlparse(origin)
            return (o.netloc or "").lower() == (headers.get("Host", "") or "").lower()
        except ValueError:
            return False


def _read_token_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def resolve(cfg, bind: str, data_dir: Path | None = None, tls: bool = False) -> AuthConfig:
    """Build the access policy from ``[web]`` config, env, and the bind address.

    A password set with `wrench password` (``<data_dir>/web_password``) turns
    sign-in on for every bind. Precedence for the admin token: WRENCH_WEB_TOKEN → ``[web] auth_token`` →
    ``[web] auth_token_file`` → (non-loopback, and no password set) a generated
    token persisted at ``<data_dir>/web_token``.
    """
    sec = (getattr(cfg, "raw", None) or {}).get("web", {})
    if not isinstance(sec, dict):
        sec = {}
    admin = (os.environ.get("WRENCH_WEB_TOKEN") or str(sec.get("auth_token", "") or "")).strip()
    if not admin and sec.get("auth_token_file"):
        admin = _read_token_file(Path(str(sec["auth_token_file"])).expanduser())
    viewer = (os.environ.get("WRENCH_WEB_VIEWER_TOKEN")
              or str(sec.get("viewer_token", "") or "")).strip()
    hosts = sec.get("allowed_hosts") or []
    if isinstance(hosts, str):
        hosts = [hosts]
    dd = Path(data_dir) if data_dir is not None else Path(cfg.data_dir)
    ac = AuthConfig(bind=bind, admin_token=admin, viewer_token=viewer,
                    allowed_hosts=[str(h) for h in hosts], tls=tls,
                    password_file=password_path(dd))
    if not ac.loopback and not ac.admin_token and not ac.has_password:
        # Never serve a machine's telemetry (or its agent) to a network
        # unauthenticated. Mint a token once and keep it, Jupyter-style.
        path = dd / TOKEN_FILE
        tok = _read_token_file(path)
        if not tok:
            tok = secrets.token_urlsafe(32)
            try:
                dd.mkdir(parents=True, exist_ok=True)
                path.write_text(tok + "\n", encoding="utf-8")
                if os.name == "posix":
                    os.chmod(path, 0o600)
            except OSError:
                pass
        ac.admin_token = tok
        ac.generated = True
    return ac


class RateLimiter:
    """Sliding-window failure counter per client (failed logins, bad signatures)."""

    def __init__(self, max_failures: int = 10, window_s: float = 60.0):
        self.max = max_failures
        self.window = window_s
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, client: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        with self._lock:
            hits = [t for t in self._hits.get(client, []) if now - t < self.window]
            if hits:
                self._hits[client] = hits
            else:
                self._hits.pop(client, None)
            return len(hits) >= self.max

    def fail(self, client: str, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        with self._lock:
            self._hits.setdefault(client, []).append(now)
            if len(self._hits) > 10_000:           # bound memory under a spray
                oldest = sorted(self._hits, key=lambda k: self._hits[k][-1])[:5000]
                for k in oldest:
                    self._hits.pop(k, None)


def security_headers(nonce: str = "", tls: bool = False) -> list[tuple[str, str]]:
    """Response headers for every page and API reply."""
    script = f"'nonce-{nonce}'" if nonce else "'none'"
    csp = ("default-src 'none'; "
           f"script-src {script}; "
           "style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; "
           "connect-src 'self'; "
           "font-src 'self'; "
           "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    out = [
        ("Content-Security-Policy", csp),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("Cache-Control", "no-store"),
    ]
    if tls:
        out.append(("Strict-Transport-Security", "max-age=31536000"))
    return out
