"""wrench webintel — built-in web intelligence.

Two free, keyless sources:
  - OSV.dev        known vulnerabilities in installed packages
                   (POST api.osv.dev/v1/querybatch, then per-vuln detail)
  - endoflife.date end-of-life status for the OS, kernel, python, node, ...

Design rules:
  - A sensible high-value subset, not all 2000 dpkg packages: pip + npm
    globals (versions are exact) plus a curated watchlist of security-critical
    distro packages (openssl, openssh, sudo, systemd, ...) queried by SOURCE
    package name against the distro ecosystem.
  - Every HTTP call has a short timeout. Results cache in sqlite with a TTL
    (default 24h). Offline? We serve the stale cache and say so. A patrol
    NEVER fails because the internet is down.
  - Zero new dependencies: requests is already a core dep.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field

import requests

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
EOL_URL = "https://endoflife.date/api/{product}.json"

HTTP_TIMEOUT = 8          # seconds per request — webintel is a guest, not a hostage
DETAIL_CAP = 150          # max NETWORK detail fetches per scan (cached ones are free)
BATCH_CHUNK = 100         # OSV querybatch page size
DEFAULT_TTL_HOURS = 24

# Security-critical distro packages worth asking OSV about (by source package).
# Curated, not exhaustive — the point is signal, not a 2000-package scan.
DISTRO_WATCHLIST = [
    "openssl", "openssh", "sudo", "curl", "wget", "bash", "systemd", "glibc",
    "nginx", "apache2", "git", "tar", "gnupg2", "xz-utils", "zlib",
    "libxml2", "sqlite3", "polkit", "dbus", "pam",
]

# endoflife.date products we check, with best-effort local version detection.
EOL_PRODUCTS = ("os", "linux-kernel", "python", "nodejs")


# ---------------- data model ----------------

@dataclass
class Vuln:
    package: str
    version: str
    ecosystem: str
    source: str                 # pip | npm | distro
    vuln_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = ""          # e.g. CVSS score string or qualitative
    fixed: str = ""             # fixed version, if OSV knows one


@dataclass
class EolStatus:
    product: str
    cycle: str
    eol: str                    # ISO date, "false" (supported), or "unknown"
    is_eol: bool
    label: str                  # human line


# ---------------- subprocess seam (tests monkeypatch) ----------------

def _run(argv: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, (r.stdout or "").strip()
    except Exception as e:  # noqa: BLE001
        return 1, f"(error: {e})"


# ---------------- inventory: what's installed, with knowable versions ----------------

def _os_release() -> dict:
    try:
        out = {}
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"')
        return out
    except OSError:
        return {}


def pip_packages() -> list[dict]:
    # inventory the interpreter wrench itself runs under — "python3 on PATH"
    # is the Microsoft Store stub on Windows and some unrelated Homebrew
    # python on a Mac
    import sys as _sys
    code, out = _run([_sys.executable, "-m", "pip", "list", "--format=json",
                      "--disable-pip-version-check"])
    if code != 0 or not out:
        return []
    try:
        rows = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [{"name": r["name"], "version": r["version"], "ecosystem": "PyPI",
             "source": "pip"} for r in rows if r.get("name") and r.get("version")]


def npm_packages() -> list[dict]:
    npm = shutil.which("npm")     # resolved path: on Windows it is npm.cmd,
    if not npm:                    # which a bare "npm" argv cannot launch
        return []
    code, out = _run([npm, "ls", "-g", "--depth=0", "--json"], timeout=20)
    if not out:
        return []
    try:
        deps = json.loads(out).get("dependencies", {})
    except json.JSONDecodeError:
        return []
    return [{"name": n, "version": m.get("version", ""), "ecosystem": "npm",
             "source": "npm"} for n, m in deps.items() if m.get("version")]


def distro_packages(watchlist: list[str] | None = None) -> list[dict]:
    """Curated security-critical dpkg packages, queried by SOURCE package name."""
    if not shutil.which("dpkg-query"):
        return []
    osrel = _os_release()
    distro_id = osrel.get("ID", "").lower()
    eco = {"ubuntu": "Ubuntu", "debian": "Debian"}.get(distro_id)
    if not eco:
        return []
    watch = set(watchlist or DISTRO_WATCHLIST)
    code, out = _run(["dpkg-query", "-W", "-f", "${source:Package}\t${Version}\n"])
    if code != 0:
        return []
    seen: dict[str, str] = {}
    for line in out.splitlines():
        if "\t" not in line:
            continue
        src, ver = line.split("\t", 1)
        src = src.split(" ")[0].strip()  # "src (ver)" → "src"
        if src in watch and src not in seen and ver.strip():
            seen[src] = ver.strip()
    return [{"name": n, "version": v, "ecosystem": eco, "source": "distro"}
            for n, v in sorted(seen.items())]


def inventory(cfg=None) -> list[dict]:
    watch = None
    if cfg is not None:
        watch = _wi_cfg(cfg).get("distro_watchlist")
    pkgs = pip_packages() + npm_packages() + distro_packages(watch)
    return pkgs


# ---------------- OSV ----------------

def osv_querybatch(pkgs: list[dict]) -> list[list[str]]:
    """Returns, per package, the list of OSV vuln ids affecting it."""
    hits: list[list[str]] = []
    for i in range(0, len(pkgs), BATCH_CHUNK):
        chunk = pkgs[i:i + BATCH_CHUNK]
        queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]},
                    "version": p["version"]} for p in chunk]
        r = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        results = r.json().get("results", [])
        for res in results:
            hits.append([v["id"] for v in (res or {}).get("vulns", [])])
        # keep alignment even if OSV returns short
        while len(hits) < min(i + BATCH_CHUNK, len(pkgs)):
            hits.append([])
    return hits


def _severity_of(detail: dict) -> str:
    for sev in detail.get("severity", []):
        if sev.get("type", "").startswith("CVSS"):
            return sev.get("score", "")
    db = detail.get("database_specific", {})
    return str(db.get("severity", "") or "")


def _fixed_of(detail: dict, package: str) -> str:
    for aff in detail.get("affected", []):
        if aff.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return ev["fixed"]
    return ""


_CVSS3_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.x base score from a vector string (FIRST.org formula). None if
    the vector is not a parseable v3 vector.

    OSV publishes vectors, not numbers. Ranking by "any High impact flag"
    could never produce *critical* (a 10.0 scored "high") and called a
    local, high-complexity bug as urgent as a remote one.
    """
    import math
    if not vector or not vector.upper().startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
              "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CVSS3_W["C"][m["C"]]) * (1 - _CVSS3_W["I"][m["I"]]) \
            * (1 - _CVSS3_W["A"][m["A"]])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed \
            else 6.42 * iss
        expl = 8.22 * _CVSS3_W["AV"][m["AV"]] * _CVSS3_W["AC"][m["AC"]] * pr \
            * _CVSS3_W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
    return math.ceil(raw * 10 - 1e-9) / 10     # CVSS "round up to one decimal"


def cached_vuln_detail(store, vuln_id: str, ttl_s: float) -> dict | None:
    """A previously fetched detail record, or None — never touches the network."""
    return store.cache_get(f"osv_vuln:{vuln_id}", ttl_s)


def osv_vuln_detail(store, vuln_id: str, ttl_s: float) -> dict:
    key = f"osv_vuln:{vuln_id}"
    cached = store.cache_get(key, ttl_s)
    if cached is not None:
        return cached
    r = requests.get(OSV_VULN_URL.format(id=vuln_id), timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    d = r.json()
    slim = {
        "id": d.get("id", vuln_id),
        "aliases": [a for a in d.get("aliases", []) if a.startswith("CVE-")],
        "summary": (d.get("summary") or d.get("details", ""))[:300],
        "severity": _severity_of(d),
        "affected": d.get("affected", []),
    }
    store.cache_put(key, slim)
    return slim


# ---------------- endoflife.date ----------------

def _local_versions() -> dict[str, tuple[str, str]]:
    """product → (endoflife.date product slug, local cycle string)."""
    out: dict[str, tuple[str, str]] = {}
    osrel = _os_release()
    if osrel.get("ID") and osrel.get("VERSION_ID"):
        out["os"] = (osrel["ID"].lower(), osrel["VERSION_ID"])
    system = platform.system()
    if system == "Linux":
        rel = platform.release()                  # e.g. 7.0.0-38-generic
        parts = rel.split(".")
        if len(parts) >= 2 and parts[0].isdigit():
            out["linux-kernel"] = ("linux", f"{parts[0]}.{parts[1]}")
    elif system == "Darwin":
        ver = platform.mac_ver()[0]               # e.g. 15.1 → cycle "15"
        if ver:
            major = ver.split(".")[0]
            # endoflife.date keys macOS 10.x by minor ("10.15"), 11+ by major
            out["os"] = ("macos", ".".join(ver.split(".")[:2]) if major == "10" else major)
    elif system == "Windows":
        cyc = _windows_cycle()
        if cyc:
            out["os"] = cyc
    pv = platform.python_version_tuple()
    out["python"] = ("python", f"{pv[0]}.{pv[1]}")
    if shutil.which("node"):
        code, v = _run(["node", "--version"])
        if code == 0 and v.startswith("v"):
            out["nodejs"] = ("nodejs", v[1:].split(".")[0])
    return out


def _windows_cycle() -> tuple[str, str] | None:
    """(product, cycle) for this Windows install on endoflife.date, or None.

    Client cycles look like "11-24h2-w" / "10-22h2"; servers like "2022".
    """
    try:
        edition = platform.win32_edition() or ""
        build = int(platform.version().split(".")[-1])
    except (AttributeError, ValueError, IndexError):
        return None
    if "Server" in edition:
        for floor, year in ((26100, "2025"), (20348, "2022"), (17763, "2019"), (14393, "2016")):
            if build >= floor:
                return ("windows-server", year)
        return None
    releases = ((26200, "11-25h2"), (26100, "11-24h2"), (22631, "11-23h2"), (22621, "11-22h2"),
                (22000, "11-21h2"), (19045, "10-22h2"), (19044, "10-21h2"))
    for floor, cyc in releases:
        if build >= floor:
            suffix = "-e" if "Enterprise" in edition or "Education" in edition else "-w"
            return ("windows", cyc + (suffix if cyc.startswith("11") else ""))
    return None


def eol_check(store, ttl_s: float) -> list[EolStatus]:
    statuses: list[EolStatus] = []
    today = time.strftime("%Y-%m-%d")
    for label, (product, cycle) in _local_versions().items():
        key = f"eol:{product}"
        data = store.cache_get(key, ttl_s)
        if data is None:
            r = requests.get(EOL_URL.format(product=product), timeout=HTTP_TIMEOUT)
            if r.status_code != 200:
                continue
            data = r.json()
            store.cache_put(key, data)
        row = next((c for c in data if str(c.get("cycle")) == cycle), None)
        if row is None:
            statuses.append(EolStatus(label, cycle, "unknown", False,
                                      f"{label} {cycle}: not in endoflife.date"))
            continue
        eol = row.get("eol")
        if eol is False or eol is None:
            statuses.append(EolStatus(label, cycle, "false", False,
                                      f"{label} {cycle}: supported (no EOL date)"))
        elif eol is True:
            # the API uses a bare `true` for "end of life, date not recorded"
            statuses.append(EolStatus(label, cycle, "true", True,
                                      f"{label} {cycle}: REACHED EOL"))
        else:
            is_eol = str(eol) <= today
            verb = "REACHED EOL" if is_eol else "supported until"
            statuses.append(EolStatus(label, cycle, str(eol), is_eol,
                                      f"{label} {cycle}: {verb} {eol}"))
    return statuses


# ---------------- the scan ----------------

def _wi_cfg(cfg) -> dict:
    raw = getattr(cfg, "raw", {}) or {}
    sec = raw.get("webintel", {})
    return sec if isinstance(sec, dict) else {}


def enabled(cfg) -> bool:
    return bool(_wi_cfg(cfg).get("enable", True))


def ttl_s(cfg) -> float:
    return float(_wi_cfg(cfg).get("cadence_hours", DEFAULT_TTL_HOURS)) * 3600


def scan(cfg, store, force: bool = False, on_step=None) -> dict:
    """Full web-intel scan. Returns a dict and caches it under 'webintel_scan'.

    Never raises for network reasons: on failure returns the stale cache
    (marked offline) or a minimal offline result.
    """
    ttl = ttl_s(cfg)
    if not force:
        cached = store.cache_get("webintel_scan", ttl)
        if cached is not None:
            return cached

    # Offline guarantee: OSV.dev and endoflife.date are public hosts. In declared
    # offline mode, never attempt them — serve the stale cache (marked offline)
    # or a minimal offline result. No network is touched.
    from . import offline as _offline
    if _offline.is_offline(cfg) and not _offline.egress_allowed(cfg, OSV_BATCH_URL):
        stale = store.cache_get("webintel_scan", float("inf"))
        if stale is not None:
            stale = dict(stale)
            stale["online"] = False
            stale["offline_mode"] = True
            stale["errors"] = ["offline mode (offline = true): serving cached scan, "
                               "no network attempted"]
            return stale
        return {"ts": time.time(), "online": False, "offline_mode": True,
                "packages_checked": 0, "vulns": [], "eol": [],
                "errors": ["offline mode (offline = true): OSV/EOL lookups disabled"]}

    def step(msg):
        if on_step:
            on_step("webintel", msg)

    step("collecting package inventory (pip, npm, distro watchlist)")
    pkgs = inventory(cfg)
    result = {"ts": time.time(), "online": True, "packages_checked": len(pkgs),
              "vulns": [], "eol": [], "errors": []}
    try:
        step(f"querying OSV.dev for {len(pkgs)} packages")
        hits = osv_querybatch(pkgs)
        detail_budget = DETAIL_CAP
        for pkg, ids in zip(pkgs, hits):
            for vid in ids:
                v = Vuln(package=pkg["name"], version=pkg["version"],
                         ecosystem=pkg["ecosystem"], source=pkg["source"], vuln_id=vid)
                if detail_budget > 0:
                    try:
                        d = osv_vuln_detail(store, vid, ttl)
                        detail_budget -= 1
                        v.aliases = d.get("aliases", [])
                        v.summary = d.get("summary", "")
                        v.severity = d.get("severity", "")
                        v.fixed = _fixed_of(d, pkg["name"])
                    except requests.RequestException as e:
                        result["errors"].append(f"detail {vid}: {e.__class__.__name__}")
                result["vulns"].append(asdict(v))
        step("checking endoflife.date (os, kernel, python, node)")
        result["eol"] = [asdict(s) for s in eol_check(store, ttl)]
    except requests.RequestException as e:
        # offline / API down → degrade to stale cache if we have one
        stale = store.cache_get("webintel_scan", float("inf"))
        if stale is not None:
            stale["online"] = False
            stale["errors"] = [f"refresh failed ({e.__class__.__name__}); serving cached scan"]
            return stale
        result["online"] = False
        result["errors"].append(f"web intel offline: {e.__class__.__name__}")
        return result

    store.cache_put("webintel_scan", result)
    return result


def cached_or_refresh(cfg, store, on_step=None) -> dict | None:
    """For patrol: respect the enable knob; use cache within cadence; offline-safe."""
    if not enabled(cfg):
        return None
    try:
        return scan(cfg, store, force=False, on_step=on_step)
    except Exception:  # noqa: BLE001 — patrol must never die here
        return None


# ---------------- summaries ----------------

def summary_line(res: dict) -> str:
    """One line for the patrol context / dashboards."""
    if not res:
        return "web intel: unavailable"
    n = len(res.get("vulns", []))
    vul_pkgs = sorted({v["package"] for v in res.get("vulns", [])})
    eol_hits = [e for e in res.get("eol", []) if e.get("is_eol")]
    bits = []
    if n:
        bits.append(f"{n} known vulnerability(ies) in {len(vul_pkgs)} package(s): "
                    + ", ".join(vul_pkgs[:6]))
    else:
        bits.append(f"no known CVEs in {res.get('packages_checked', 0)} checked packages")
    if eol_hits:
        bits.append("EOL: " + "; ".join(e["label"] for e in eol_hits))
    else:
        bits.append("no EOL products")
    if not res.get("online", True):
        bits.append("(offline — cached data)")
    return "web intel (OSV.dev + endoflife.date): " + " | ".join(bits)


def distro_vuln_packages(res: dict) -> list[str]:
    """Distro-source packages with known vulns — candidates for targeted upgrade."""
    return sorted({v["package"] for v in (res or {}).get("vulns", [])
                   if v.get("source") == "distro"})


def eol_advisories(res: dict) -> list[str]:
    return [e["label"] for e in (res or {}).get("eol", []) if e.get("is_eol")]
