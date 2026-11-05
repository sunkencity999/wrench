"""certwrench — SSL/TLS certificate lifecycle for wrench.

What this module does, in one paragraph:

    Discover TLS certificates by scanning web-server config files
    (nginx/apache/caddy/haproxy ``ssl_certificate`` directives and friends)
    plus the well-known cert stores (/etc/letsencrypt/live, /etc/ssl,
    /etc/pki), parse each x509 via the ``openssl`` binary (expiry, subject,
    SANs, issuer, key type/strength, self-signed + chain-completeness), flag
    weak TLS configuration found in the same config files, and — only under
    the consent ceremony and policy tiers — orchestrate renewals through
    certbot or acme.sh with dry-run-first, validate-then-reload discipline.

Safety architecture (mirrors fixxer):
    Every external command is a HAND-WRITTEN argv list run with NO shell.
    The model never authors a command. Discovery/parse/audit are read-only.
    Renewal runs only allowlisted binaries (certbot/acme.sh/openssl/nginx/...)
    with dry-run first and automatic rollback messaging on failed validation.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ---------------- subprocess seam (tests monkeypatch this) ----------------

def _run(argv: list[str], timeout: int = 30, env_extra: dict | None = None) -> tuple[int, str]:
    """Run argv with no shell. Returns (exit_code, combined_output)."""
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
        out = (r.stdout or "") + (("\n[stderr] " + r.stderr.strip()) if r.stderr.strip() else "")
        return r.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return 124, f"(timed out after {timeout}s)"
    except FileNotFoundError:
        return 127, f"(command not found: {argv[0]})"
    except Exception as e:  # noqa: BLE001
        return 1, f"(error: {e.__class__.__name__}: {e})"


# ---------------- where certs and configs live ----------------
# Config roots scanned for ssl_certificate-style directives.
CONFIG_ROOTS: list[tuple[str, Path]] = [
    ("nginx", Path("/etc/nginx")),
    ("apache", Path("/etc/apache2")),
    ("apache", Path("/etc/httpd")),
    ("caddy", Path("/etc/caddy")),
    ("haproxy", Path("/etc/haproxy")),
]

# Well-known cert stores scanned directly (leaf certs, not CA bundles).
WELLKNOWN_CERT_DIRS: list[Path] = [
    Path("/etc/letsencrypt/live"),
    Path("/etc/ssl/certs"),
    Path("/etc/ssl/private"),
    Path("/etc/pki/tls/certs"),
    Path("/etc/pki/tls"),
]

CERT_SUFFIXES = (".pem", ".crt", ".cer", ".cert")

# Directives that name a certificate file, per server family.
_CERT_DIRECTIVES = {
    "nginx": [r"^\s*ssl_certificate\s+([^;#]+);"],
    # Apache: SSLCertificateFile (leaf+maybe chain), SSLCertificateChainFile
    "apache": [r"^\s*SSLCertificateFile\s+(\S+)",
               r"^\s*SSLCertificateChainFile\s+(\S+)"],
    # Caddy: `tls <cert> <key>` in a site block
    "caddy": [r"^\s*tls\s+(\S+\.(?:pem|crt|cer|cert))\b"],
    # HAProxy: `bind ... ssl crt /path/to/bundle.pem`
    "haproxy": [r"\bcrt\s+(\S+\.(?:pem|crt|cer|cert))\b"],
}

# Weak-TLS detection patterns (read from config text; best-effort, never fatal).
_TLS_VERSION_DIRECTIVES = [
    r"^\s*ssl_protocols\s+([^;#]+);",                 # nginx
    r"^\s*SSLProtocol\s+([^\n#]+)",                    # apache
]
_WEAK_TLS_TOKENS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1")
# "TLSv1" alone (not TLSv1.2/.3) means <1.2 — handled specially below.


# ---------------- data model ----------------

@dataclass
class CertInfo:
    """One parsed certificate, or a parse error bound to its path."""
    path: str
    source: str = ""                 # "nginx:/etc/nginx/..." or "wellknown:/etc/ssl/..."
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: float = 0.0          # epoch seconds
    not_after: float = 0.0           # epoch seconds
    days_left: int | None = None
    sans: list[str] = field(default_factory=list)
    key_type: str = ""               # RSA / EC / Ed25519 / ...
    key_bits: int | None = None
    sig_algo: str = ""
    is_ca: bool = False
    self_signed: bool = False
    chain_complete: bool | None = None
    fingerprint_sha256: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def common_name(self) -> str:
        m = re.search(r"CN\s*=\s*([^,/]+)", self.subject or "")
        return m.group(1).strip() if m else (self.sans[0] if self.sans else self.path)

    @property
    def weak_key(self) -> bool:
        if self.key_type.upper() == "RSA" and self.key_bits is not None:
            return self.key_bits < 2048
        # EC < 256-bit is weak; Ed25519 is fine
        if self.key_type.upper() in ("EC", "ECDSA") and self.key_bits is not None:
            return self.key_bits < 256
        return False

    def expiry_severity(self) -> str | None:
        """Map days_left onto the notification ladder. None => no alert."""
        d = self.days_left
        if d is None:
            return None
        if d < 0:
            return "critical"       # expired
        if d <= 7:
            return "critical"
        if d <= 14:
            return "warning"
        if d <= 30:
            return "info"
        return None

    def to_row(self) -> dict:
        return {
            "path": self.path, "source": self.source, "subject": self.subject,
            "issuer": self.issuer, "serial": self.serial,
            "not_before": self.not_before, "not_after": self.not_after,
            "days_left": self.days_left, "sans": list(self.sans),
            "key_type": self.key_type, "key_bits": self.key_bits,
            "sig_algo": self.sig_algo, "is_ca": self.is_ca,
            "self_signed": self.self_signed, "chain_complete": self.chain_complete,
            "fingerprint_sha256": self.fingerprint_sha256, "error": self.error,
        }


@dataclass
class ConfigWeakness:
    """A weak-TLS-configuration finding discovered while scanning configs."""
    kind: str                        # tls_version | hsts_missing | weak_key
    severity: str                    # info | warning | critical
    detail: str
    source: str                      # the config file (or cert path) it came from


# ---------------- config scanning ----------------

def _iter_config_files(root: Path):
    """Yield readable text config files under a server config root."""
    root = Path(root)
    if not root.exists():
        return
    try:
        for p in sorted(root.rglob("*")):
            try:
                if not p.is_file():
                    continue
            except OSError:
                continue
            name = p.name.lower()
            if name.endswith((".conf", ".cfg")) or "conf" in str(p.parent).lower() \
                    or root.name in ("caddy", "haproxy") or name in ("caddyfile", "haproxy.cfg"):
                yield p
    except OSError:
        return


def _read_text(p: Path) -> str:
    try:
        return p.read_text(errors="replace")
    except OSError:
        return ""


def scan_config_certs(roots: list[tuple[str, Path]] | None = None
                      ) -> tuple[list[tuple[str, str, str]], list[ConfigWeakness]]:
    """Scan web-server configs.

    Returns (cert_refs, weaknesses) where cert_refs is a list of
    (server_family, cert_path, source_config_file) and weaknesses is a list of
    ConfigWeakness found in the same files.
    """
    roots = roots if roots is not None else CONFIG_ROOTS
    refs: list[tuple[str, str, str]] = []
    weaknesses: list[ConfigWeakness] = []
    seen: set[tuple[str, str]] = set()
    for family, root in roots:
        pats = _CERT_DIRECTIVES.get(family, [])
        for cf in _iter_config_files(root):
            text = _read_text(cf)
            if not text:
                continue
            for line in text.splitlines():
                for pat in pats:
                    m = re.search(pat, line)
                    if m:
                        cert_path = m.group(1).strip().strip('"').strip("'")
                        # nginx allows "ssl_certificate a.pem" with trailing args; take first token
                        cert_path = cert_path.split()[0] if cert_path.split() else cert_path
                        key = (family, cert_path)
                        if key not in seen:
                            seen.add(key)
                            refs.append((family, cert_path, str(cf)))
            weaknesses.extend(_config_weaknesses(family, cf, text))
    return refs, weaknesses


def _config_weaknesses(family: str, cf: Path, text: str) -> list[ConfigWeakness]:
    out: list[ConfigWeakness] = []
    enables_tls = False
    has_hsts = False
    for line in text.splitlines():
        low = line.strip()
        if low.startswith("#"):
            continue
        for pat in _TLS_VERSION_DIRECTIVES:
            m = re.search(pat, line)
            if m:
                enabled = m.group(1)
                weak = _weak_tls_versions(enabled)
                if weak:
                    out.append(ConfigWeakness(
                        "tls_version", "warning",
                        f"{family}: TLS < 1.2 enabled ({', '.join(weak)}) in `{low}`",
                        str(cf)))
        if "ssl_certificate" in low or "SSLEngine on" in low or "listen" in low and "ssl" in low:
            enables_tls = True
        if re.search(r"Strict-Transport-Security", line, re.I):
            has_hsts = True
    if enables_tls and not has_hsts and family in ("nginx", "apache"):
        out.append(ConfigWeakness(
            "hsts_missing", "info",
            f"{family}: TLS is served but no Strict-Transport-Security (HSTS) header "
            f"was found in this config",
            str(cf)))
    return out


def _weak_tls_versions(enabled: str) -> list[str]:
    """Return the weak protocol tokens present in an ssl_protocols/SSLProtocol value."""
    tokens = re.split(r"[\s,]+", enabled.strip())
    weak = []
    for t in tokens:
        t = t.strip()
        if t.startswith("-"):
            continue  # explicitly disabled (e.g. Apache `all -SSLv3`)
        tt = t.lstrip("+").strip()
        if tt in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
            # "TLSv1" here means 1.0
            weak.append("TLSv1.0" if tt == "TLSv1" else tt)
    return weak


# ---------------- well-known store discovery ----------------

def scan_wellknown_certs(dirs: list[Path] | None = None) -> list[str]:
    """Return candidate leaf-cert paths from well-known stores.

    Prefers letsencrypt live fullchain/cert files; for generic dirs returns
    *.pem/*.crt files but skips obvious CA bundles (ca-certificates.crt etc).
    """
    dirs = dirs if dirs is not None else WELLKNOWN_CERT_DIRS
    out: list[str] = []
    for d in dirs:
        d = Path(d)
        if not d.exists():
            continue
        try:
            if d.name == "live":  # /etc/letsencrypt/live/<domain>/fullchain.pem
                for sub in sorted(d.iterdir()):
                    if sub.is_dir():
                        for leaf in ("cert.pem", "fullchain.pem"):
                            p = sub / leaf
                            if p.exists():
                                out.append(str(p))
                                break
                continue
            for p in sorted(d.iterdir()):
                try:
                    if not p.is_file():
                        continue
                except OSError:
                    continue
                if p.suffix.lower() not in CERT_SUFFIXES:
                    continue
                if _looks_like_ca_bundle(p.name):
                    continue
                out.append(str(p))
        except OSError:
            continue
    return out


def _looks_like_ca_bundle(name: str) -> bool:
    low = name.lower()
    return any(tok in low for tok in ("ca-certificates", "ca-bundle", "cacert", "chain-only"))


# ---------------- x509 parsing (openssl) ----------------

_OPENSSL_DATE_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_openssl_date(s: str) -> float:
    s = s.strip()
    try:
        dt = datetime.strptime(s, _OPENSSL_DATE_FMT)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        # some openssl builds print "GMT", some a numeric offset
        try:
            dt = datetime.strptime(s.rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y")
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            return 0.0


def parse_cert(path: str, source: str = "", now: float | None = None) -> CertInfo:
    """Parse one certificate file with the openssl binary. Read-only."""
    info = CertInfo(path=path, source=source)
    p = Path(path)
    if not p.exists():
        info.error = "file not found"
        return info
    code, out = _run(["openssl", "x509", "-in", path, "-noout",
                      "-subject", "-issuer", "-startdate", "-enddate", "-serial",
                      "-fingerprint", "-sha256", "-nameopt", "RFC2253",
                      "-ext", "subjectAltName"], timeout=20)
    if code != 0:
        info.error = f"openssl parse failed: {out[:160]}"
        return info
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("subject="):
            info.subject = s[len("subject="):].strip()
        elif s.startswith("issuer="):
            info.issuer = s[len("issuer="):].strip()
        elif s.startswith("notBefore="):
            info.not_before = _parse_openssl_date(s[len("notBefore="):])
        elif s.startswith("notAfter="):
            info.not_after = _parse_openssl_date(s[len("notAfter="):])
        elif s.startswith("serial="):
            info.serial = s[len("serial="):].strip()
        elif "Fingerprint=" in s:
            info.fingerprint_sha256 = s.split("Fingerprint=", 1)[1].strip()
        elif s.startswith("DNS:") or ", DNS:" in s or s.startswith("IP Address:"):
            for tok in re.findall(r"(?:DNS|IP Address):([^,\s]+)", s):
                if tok not in info.sans:
                    info.sans.append(tok)
    info.self_signed = bool(info.subject) and info.subject == info.issuer
    nowt = now if now is not None else time.time()
    if info.not_after:
        info.days_left = int((info.not_after - nowt) // 86400)
    _augment_key_and_ca(path, info)
    return info


def _augment_key_and_ca(path: str, info: CertInfo) -> None:
    """Fill key_type/key_bits/sig_algo/is_ca from `openssl x509 -text`."""
    code, out = _run(["openssl", "x509", "-in", path, "-noout", "-text"], timeout=20)
    if code != 0:
        return
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Public Key Algorithm:"):
            algo = s.split(":", 1)[1].strip()
            if "rsa" in algo.lower():
                info.key_type = "RSA"
            elif "ed25519" in algo.lower():
                info.key_type = "Ed25519"
            elif "ec" in algo.lower() or "id-ecpublickey" in algo.lower():
                info.key_type = "EC"
            else:
                info.key_type = algo
        elif s.startswith("Public-Key:"):
            m = re.search(r"\((\d+)\s*bit\)", s)
            if m:
                info.key_bits = int(m.group(1))
        elif s.startswith("Signature Algorithm:") and not info.sig_algo:
            info.sig_algo = s.split(":", 1)[1].strip()
        elif "CA:TRUE" in s.replace(" ", ""):
            info.is_ca = True


def verify_chain(path: str, untrusted: str | None = None) -> tuple[bool | None, str]:
    """Best-effort chain completeness via `openssl verify`. Read-only.

    Returns (complete, note). None means "could not determine" (e.g. self-signed
    leaf or openssl missing) rather than a hard failure.
    """
    if not shutil.which("openssl"):
        return None, "openssl not available"
    argv = ["openssl", "verify"]
    if untrusted:
        argv += ["-untrusted", untrusted]
    argv.append(path)
    code, out = _run(argv, timeout=20)
    if code == 0 and out.strip().endswith("OK"):
        return True, "chain verified against system trust store"
    low = out.lower()
    if "self signed" in low or "self-signed" in low:
        return None, "self-signed (no chain to verify)"
    if "unable to get local issuer" in low:
        return False, "incomplete chain: local issuer not found (missing intermediates?)"
    return False, f"verify failed: {out.splitlines()[-1][:120] if out else 'unknown'}"


# ---------------- live TLS probe (read-only) ----------------

def probe_tls(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Open a TLS connection and report negotiated protocol + peer cert expiry.

    Read-only: connects, reads the handshake, closes. Returns a dict with
    'ok', 'protocol', 'cipher', 'days_left', 'error'.
    """
    res: dict = {"ok": False, "host": host, "port": port, "protocol": "",
                 "cipher": "", "days_left": None, "error": ""}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                res["protocol"] = ss.version() or ""
                c = ss.cipher()
                res["cipher"] = c[0] if c else ""
                cert = ss.getpeercert()
                if cert and cert.get("notAfter"):
                    exp = ssl.cert_time_to_seconds(cert["notAfter"])
                    res["days_left"] = int((exp - time.time()) // 86400)
                res["ok"] = True
    except Exception as e:  # noqa: BLE001 — probe is best-effort
        res["error"] = f"{e.__class__.__name__}: {e}"
    return res


def protocol_is_weak(protocol: str) -> bool:
    """True if a negotiated protocol string is below TLS 1.2."""
    return protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1")


# ---------------- top-level inventory ----------------

def inventory(config_roots=None, wellknown_dirs=None, now: float | None = None
              ) -> tuple[list[CertInfo], list[ConfigWeakness]]:
    """Discover + parse every cert reachable from configs and well-known stores.

    Fully read-only. De-duplicates by resolved path. Returns (certs, weaknesses).
    """
    refs, weaknesses = scan_config_certs(config_roots)
    certs: list[CertInfo] = []
    seen: set[str] = set()
    for family, cert_path, cf in refs:
        rp = _resolve(cert_path)
        if rp in seen:
            continue
        seen.add(rp)
        certs.append(parse_cert(rp, source=f"{family}:{cf}", now=now))
    for wp in scan_wellknown_certs(wellknown_dirs):
        rp = _resolve(wp)
        if rp in seen:
            continue
        seen.add(rp)
        certs.append(parse_cert(rp, source=f"wellknown:{wp}", now=now))
    # weak-key weaknesses derived from parsed certs
    for c in certs:
        if c.ok and c.weak_key:
            weaknesses.append(ConfigWeakness(
                "weak_key", "warning",
                f"{c.common_name}: weak key {c.key_type}-{c.key_bits} "
                f"(RSA keys should be ≥2048-bit)",
                c.path))
    return certs, weaknesses


def _resolve(path: str) -> str:
    try:
        return str(Path(path).resolve())
    except (OSError, RuntimeError):
        return path


# ---------------- patrol integration (cached, offline-safe) ----------------

CACHE_KEY = "cert_inventory"
DEFAULT_CADENCE_S = 6 * 3600


def cached_inventory(cfg, store, cadence_s: int = DEFAULT_CADENCE_S,
                     force: bool = False) -> tuple[list[CertInfo], list[ConfigWeakness]]:
    """Run inventory at most once per cadence; persist rows + cache the snapshot.

    Reuses the store's TTL cache table. Never raises — a patrol must not die
    because a cert scan hiccuped. On cache hit returns the cached snapshot
    (days_left recomputed against now so the ladder stays accurate).
    """
    if not force:
        cached = store.cache_get(CACHE_KEY, cadence_s)
        if cached:
            certs_out = [_cert_from_cache(d) for d in cached.get("certs", [])]
            weak_out = [ConfigWeakness(**w) for w in cached.get("weaknesses", [])]
            return certs_out, weak_out
    cert_list, weaknesses = inventory()
    for c in cert_list:
        try:
            store.upsert_cert(c.to_row())
        except Exception:  # noqa: BLE001
            pass
    store.cache_put(CACHE_KEY, {
        "certs": [c.to_row() for c in cert_list],
        "weaknesses": [vars(w) for w in weaknesses],
    })
    return cert_list, weaknesses


def _cert_from_cache(d: dict) -> CertInfo:
    c = CertInfo(
        path=d.get("path", ""), source=d.get("source", ""),
        subject=d.get("subject", ""), issuer=d.get("issuer", ""),
        serial=d.get("serial", ""), not_before=d.get("not_before", 0.0) or 0.0,
        not_after=d.get("not_after", 0.0) or 0.0, sans=list(d.get("sans") or []),
        key_type=d.get("key_type", ""), key_bits=d.get("key_bits"),
        sig_algo=d.get("sig_algo", ""), is_ca=bool(d.get("is_ca")),
        self_signed=bool(d.get("self_signed")),
        chain_complete=d.get("chain_complete"),
        fingerprint_sha256=d.get("fingerprint_sha256", "") or d.get("fingerprint", ""),
        error=d.get("error", "") or "",
    )
    # recompute days_left against current time so the ladder stays fresh
    if c.not_after:
        c.days_left = int((c.not_after - time.time()) // 86400)
    else:
        c.days_left = d.get("days_left")
    return c


def patrol_findings(cfg, store, cadence_s: int = DEFAULT_CADENCE_S) -> list[dict]:
    """Deterministic cert findings for a patrol — expiry ladder + weak config.

    Returns a list of {severity, text} dicts using the same severity vocabulary
    the notification ladder understands (critical/warning/info). Never raises.
    """
    try:
        cert_list, weaknesses = cached_inventory(cfg, store, cadence_s)
    except Exception:  # noqa: BLE001 — patrol never dies on a cert scan
        return []
    out: list[dict] = []
    for c in cert_list:
        if not c.ok:
            continue
        sev = c.expiry_severity()
        if sev:
            if c.days_left is not None and c.days_left < 0:
                msg = f"certificate {c.common_name} EXPIRED {-c.days_left}d ago ({c.path})"
            else:
                msg = f"certificate {c.common_name} expires in {c.days_left}d ({c.path})"
            out.append({"severity": sev, "text": msg})
        if c.chain_complete is False:
            out.append({"severity": "warning",
                        "text": f"certificate {c.common_name} has an incomplete chain ({c.path})"})
    for w in weaknesses:
        out.append({"severity": w.severity, "text": w.detail})
    return out


def patrol_summary_line(cfg, store, cadence_s: int = DEFAULT_CADENCE_S) -> str:
    """One context line for the patrol / dashboards."""
    try:
        cert_list, weaknesses = cached_inventory(cfg, store, cadence_s)
    except Exception:  # noqa: BLE001
        return "certs: scan unavailable"
    if not cert_list:
        return "certs: none found in configs or well-known stores"
    soon = [c for c in cert_list if c.ok and c.expiry_severity()]
    expired = [c for c in cert_list if c.ok and c.days_left is not None and c.days_left < 0]
    bits = [f"{len(cert_list)} tracked"]
    if expired:
        bits.append(f"{len(expired)} EXPIRED")
    if soon:
        worst = min((c.days_left for c in soon if c.days_left is not None), default=None)
        bits.append(f"{len(soon)} expiring ≤30d (soonest {worst}d)")
    else:
        bits.append("none expiring ≤30d")
    if weaknesses:
        bits.append(f"{len(weaknesses)} weak-TLS config finding(s)")
    return "certs: " + ", ".join(bits)
