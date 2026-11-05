"""wrench security — watch the doors.

Four read-only watchers, one severity ladder:

  auth       SSH/sudo anomalies out of auth.log / journald: brute-force bursts,
             a success right after a burst, logins from never-seen source IPs,
             users newly invoking sudo.
  access     privilege drift: sudoers (+ /etc/sudoers.d) content hashes,
             per-user authorized_keys hashes, extra UID-0 accounts, empty
             password hashes (when /etc/shadow is readable — degrade politely
             when it isn't), world-writable files in sensitive paths.
  listeners  listening sockets with owning process + systemd unit; new
             listeners since the accepted baseline, and "ownerless" ones no
             process admits to.
  cve        full installed-package inventory (dpkg/rpm) matched against the
             OSV.dev batch API. Free, keyless, cached in sqlite with a TTL,
             and strictly fail-soft: no network, no scan, no drama.

Design rules (same house style as certs/webintel):
  - Everything here is READ-ONLY. No file is written outside the wrench data
    dir, no command mutates state.
  - A baseline is only ever blessed by explicit consent (`wrench security
    accept`). Scans compare against it; they never silently update it.
  - Pure parsing/analysis functions take plain data in and return plain data
    out, so tests feed synthetic fixtures without touching the host.
  - A patrol must never die because a security scan did.

Config (``[security]`` in config.toml):
    enabled              = true
    burst_threshold      = 8      # failed passwords from one IP inside the window
    window_minutes       = 10     # sliding window for burst detection
    auth_lookback_hours  = 24     # how far back to read auth events
    cve                  = true   # OSV scan on full scans (never on patrol quick scans)
    cve_ttl_hours        = 24     # cache lifetime for the OSV verdict
    cve_max_packages     = 3000   # inventory cap (chunked 100/request)
    world_writable_paths = ["/etc", "/usr/local/bin"]
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field

# severity vocabulary — the notification ladder understands all of these
SEV_ORDER = {"info": 0, "warning": 1, "critical": 2}

BASELINE_KIND = "security_baseline"
LASTSCAN_KIND = "security_scan"

AUTH_LOG_PATHS = ("/var/log/auth.log", "/var/log/secure")
SENSITIVE_WW_PATHS = ("/etc", "/usr/local/bin")

DEFAULT_BURST_THRESHOLD = 8
DEFAULT_WINDOW_S = 600
DEFAULT_LOOKBACK_S = 24 * 3600
CVE_SEEN_KEY = "security_cve_seen"
CVE_SCAN_KEY = "security_cve_scan"


@dataclass
class Finding:
    severity: str          # info | warning | critical
    category: str          # auth | access | listeners | cve
    title: str
    detail: str = ""
    meta: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"severity": self.severity, "category": self.category,
                "title": self.title, "detail": self.detail, "meta": self.meta}


def _sev_rank(sev: str) -> int:
    return SEV_ORDER.get((sev or "").lower(), 0)


def worst_severity(findings: list[Finding | dict]) -> str:
    worst = "info"
    for f in findings:
        sev = f.severity if isinstance(f, Finding) else f.get("severity", "info")
        if _sev_rank(sev) > _sev_rank(worst):
            worst = sev
    return worst


def _run(argv: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout
    except Exception:  # noqa: BLE001
        return 1, ""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# ---------------- settings ----------------

@dataclass
class SecuritySettings:
    enabled: bool = True
    burst_threshold: int = DEFAULT_BURST_THRESHOLD
    window_s: int = DEFAULT_WINDOW_S
    lookback_s: int = DEFAULT_LOOKBACK_S
    cve: bool = True
    cve_ttl_s: float = 24 * 3600.0
    cve_max_packages: int = 3000
    ww_paths: tuple = SENSITIVE_WW_PATHS


def settings_from(cfg) -> SecuritySettings:
    sec = (getattr(cfg, "raw", None) or {}).get("security", {})
    if not isinstance(sec, dict):
        sec = {}
    return SecuritySettings(
        enabled=bool(sec.get("enabled", True)),
        burst_threshold=max(2, int(sec.get("burst_threshold", DEFAULT_BURST_THRESHOLD))),
        window_s=max(60, int(sec.get("window_minutes", 10)) * 60),
        lookback_s=max(600, int(sec.get("auth_lookback_hours", 24)) * 3600),
        cve=bool(sec.get("cve", True)),
        cve_ttl_s=max(600.0, float(sec.get("cve_ttl_hours", 24)) * 3600.0),
        cve_max_packages=max(10, int(sec.get("cve_max_packages", 3000))),
        ww_paths=tuple(sec.get("world_writable_paths", list(SENSITIVE_WW_PATHS))),
    )


# =====================================================================
# 1. auth log — SSH + sudo events
# =====================================================================

# "Nov  5 12:01:02" (classic syslog) or "2026-11-05T12:01:02.123456-08:00" (ISO)
_SYSLOG_TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
                        r"(?P<time>\d{2}:\d{2}:\d{2})\s+")
_ISO_TS = re.compile(r"^(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?P<user>\S+) from (?P<ip>\S+)")
_SUDO_CMD = re.compile(
    r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*?COMMAND=(?P<cmd>.+)$")
_SUDO_FAIL = re.compile(
    r"sudo(?:\[\d+\])?:\s+(?P<user>\S+) : .*?(?:incorrect password attempts|"
    r"command not allowed|user NOT in sudoers)")


def _parse_ts(line: str, now: float | None = None) -> float | None:
    """Best-effort epoch seconds from a syslog/ISO-prefixed line."""
    now = now or time.time()
    m = _ISO_TS.match(line)
    if m:
        try:
            lt = time.strptime(m.group("iso").replace(" ", "T"), "%Y-%m-%dT%H:%M:%S")
            return time.mktime(lt)
        except ValueError:
            return None
    m = _SYSLOG_TS.match(line)
    if m and m.group("mon") in _MONTHS:
        year = time.localtime(now).tm_year
        try:
            lt = time.strptime(
                f"{year} {m.group('mon')} {m.group('day')} {m.group('time')}",
                "%Y %b %d %H:%M:%S")
            ts = time.mktime(lt)
            if ts > now + 86400:  # "Dec 31" parsed in January → last year
                lt = time.strptime(
                    f"{year - 1} {m.group('mon')} {m.group('day')} {m.group('time')}",
                    "%Y %b %d %H:%M:%S")
                ts = time.mktime(lt)
            return ts
        except ValueError:
            return None
    return None


def parse_auth_events(lines: list[str], now: float | None = None) -> list[dict]:
    """Parse raw auth-log lines into typed events. Pure; fixture-friendly.

    Event: {ts, kind, user, ip, detail} with kind in
    failed_login | accepted_login | sudo_command | sudo_fail.
    """
    now = now or time.time()
    events: list[dict] = []
    for line in lines:
        ts = _parse_ts(line, now)
        m = _FAILED.search(line)
        if m:
            events.append({"ts": ts, "kind": "failed_login",
                           "user": m.group("user"), "ip": m.group("ip"),
                           "detail": "invalid user" if m.group("invalid") else ""})
            continue
        m = _ACCEPTED.search(line)
        if m:
            events.append({"ts": ts, "kind": "accepted_login",
                           "user": m.group("user"), "ip": m.group("ip"),
                           "detail": m.group("method")})
            continue
        m = _SUDO_FAIL.search(line)
        if m:
            events.append({"ts": ts, "kind": "sudo_fail",
                           "user": m.group("user"), "ip": "", "detail": ""})
            continue
        m = _SUDO_CMD.search(line)
        if m:
            events.append({"ts": ts, "kind": "sudo_command",
                           "user": m.group("user"), "ip": "",
                           "detail": m.group("cmd").strip()[:200]})
    return events


def read_auth_lines(lookback_s: int = DEFAULT_LOOKBACK_S,
                    max_lines: int = 100_000) -> tuple[list[str], str]:
    """Read recent auth lines from auth.log(+.1) or journald. Returns (lines, source)."""
    for path in AUTH_LOG_PATHS:
        if os.path.exists(path):
            lines: list[str] = []
            for p in (path + ".1", path):  # rotated first, chronological-ish
                try:
                    with open(p, errors="replace") as fh:
                        lines.extend(fh.read().splitlines()[-max_lines:])
                except OSError:
                    continue
            if lines:
                return lines[-max_lines:], path
    if shutil.which("journalctl"):
        code, out = _run(
            ["journalctl", "-t", "sshd", "-t", "sudo", "-t", "sshd-session",
             "--since", f"-{int(lookback_s)}s", "-o", "short-iso",
             "--no-pager", "-q"], timeout=30)
        if code == 0 and out.strip():
            return out.splitlines()[-max_lines:], "journald"
    return [], "unavailable"


def _is_local_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a.is_loopback or a.is_link_local
    except ValueError:
        return False


def analyze_auth(events: list[dict], baseline: dict | None,
                 st: SecuritySettings | None = None,
                 now: float | None = None) -> tuple[list[Finding], dict]:
    """Pure analysis: events + baseline → (findings, observed-state).

    observed = {"known_ips": [...], "sudo_users": [...]} — what `accept`
    would bless. Baseline None = first run: observations become info-only.
    """
    st = st or SecuritySettings()
    now = now or time.time()
    baseline = baseline or {}
    base_ips = set(baseline.get("known_ips", []))
    base_sudo = set(baseline.get("sudo_users", []))
    has_baseline = bool(baseline)
    findings: list[Finding] = []

    cutoff = now - st.lookback_s
    recent = [e for e in events if e.get("ts") is None or e["ts"] >= cutoff]

    # --- brute-force bursts: sliding window of failures per source IP ---
    fails_by_ip: dict[str, list[float]] = {}
    for e in recent:
        if e["kind"] == "failed_login" and e.get("ip"):
            fails_by_ip.setdefault(e["ip"], []).append(e.get("ts") or now)
    bursts: dict[str, tuple[int, float]] = {}  # ip -> (max count in window, last fail ts)
    for ip, times in fails_by_ip.items():
        times.sort()
        best, lo = 0, 0
        for hi in range(len(times)):
            while times[hi] - times[lo] > st.window_s:
                lo += 1
            best = max(best, hi - lo + 1)
        if best >= st.burst_threshold:
            bursts[ip] = (best, times[-1])
    for ip, (count, last_ts) in sorted(bursts.items()):
        findings.append(Finding(
            "warning", "auth", f"brute-force burst from {ip}",
            f"{count} failed logins within {st.window_s // 60} min "
            f"(threshold {st.burst_threshold})",
            {"ip": ip, "count": count, "last_ts": last_ts}))

    # --- success right after a burst from the same IP = likely compromise ---
    for e in recent:
        if e["kind"] != "accepted_login" or e.get("ip") not in bursts:
            continue
        ets = e.get("ts") or now
        prior = [t for t in fails_by_ip.get(e["ip"], [])
                 if ets - st.window_s <= t <= ets]
        if len(prior) >= st.burst_threshold:
            findings.append(Finding(
                "critical", "auth",
                f"successful login after brute-force burst: {e['user']}@{e['ip']}",
                f"{len(prior)} failures in the {st.window_s // 60} min before "
                f"this accepted {e.get('detail') or 'login'} — treat as compromised "
                f"until proven otherwise",
                {"ip": e["ip"], "user": e["user"], "failures_before": len(prior)}))

    # --- logins from never-seen source IPs ---
    seen_ips: dict[str, set[str]] = {}
    for e in recent:
        if e["kind"] == "accepted_login" and e.get("ip") and not _is_local_ip(e["ip"]):
            seen_ips.setdefault(e["ip"], set()).add(e["user"])
    for ip in sorted(seen_ips):
        if has_baseline and ip not in base_ips:
            findings.append(Finding(
                "warning" if ip in bursts else "info", "auth",
                f"login from new source IP {ip}",
                f"user(s) {', '.join(sorted(seen_ips[ip]))} — first time this "
                f"address appears since the accepted baseline",
                {"ip": ip, "users": sorted(seen_ips[ip])}))

    # --- users newly invoking sudo ---
    sudo_users = {e["user"] for e in recent
                  if e["kind"] in ("sudo_command", "sudo_fail") and e.get("user")}
    for user in sorted(sudo_users):
        if has_baseline and user not in base_sudo:
            findings.append(Finding(
                "warning", "auth", f"new sudo user: {user}",
                "this account used sudo for the first time since the accepted baseline",
                {"user": user}))
    sudo_fails = [e for e in recent if e["kind"] == "sudo_fail"]
    if len(sudo_fails) >= 3:
        who = sorted({e["user"] for e in sudo_fails})
        findings.append(Finding(
            "warning", "auth", "repeated sudo failures",
            f"{len(sudo_fails)} failed sudo attempts by {', '.join(who)}",
            {"count": len(sudo_fails), "users": who}))

    observed = {
        "known_ips": sorted(base_ips | set(seen_ips)),
        "sudo_users": sorted(base_sudo | sudo_users),
    }
    return findings, observed


# =====================================================================
# 2. access drift — sudoers / authorized_keys / uid0 / shadow / world-writable
# =====================================================================

_SUDOERS_DIR = "/etc/sudoers.d"
_SUDOERS_MAIN = "/etc/sudoers"


def _normalize_sudoers(text: str) -> str:
    out = []
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return "\n".join(out)


def sudoers_state(main: str = _SUDOERS_MAIN, dropin_dir: str = _SUDOERS_DIR) -> dict:
    """{files: {path: sha256}, unreadable: [paths]} — visudo-safe (pure reads)."""
    files: dict[str, str] = {}
    unreadable: list[str] = []
    candidates = [main]
    try:
        if os.path.isdir(dropin_dir):
            candidates += sorted(
                os.path.join(dropin_dir, n) for n in os.listdir(dropin_dir)
                if not n.startswith(".") and not n.endswith("~"))
    except OSError:
        unreadable.append(dropin_dir)
    for path in candidates:
        try:
            with open(path, errors="replace") as fh:
                files[path] = _sha256(_normalize_sudoers(fh.read()))
        except OSError:
            if os.path.exists(path):
                unreadable.append(path)
    return {"files": files, "unreadable": unreadable}


def _passwd_entries(passwd_path: str = "/etc/passwd") -> list[dict]:
    out = []
    try:
        with open(passwd_path, errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(":")
                if len(parts) >= 7:
                    try:
                        uid = int(parts[2])
                    except ValueError:
                        continue
                    out.append({"user": parts[0], "uid": uid,
                                "home": parts[5], "shell": parts[6]})
    except OSError:
        pass
    return out


def authorized_keys_state(passwd_path: str = "/etc/passwd") -> dict:
    """{user: {hash, count}} for every account with a readable authorized_keys."""
    state: dict[str, dict] = {}
    for ent in _passwd_entries(passwd_path):
        home = ent["home"]
        if not home or home in ("/", "/nonexistent"):
            continue
        keys: list[str] = []
        for name in ("authorized_keys", "authorized_keys2"):
            path = os.path.join(home, ".ssh", name)
            try:
                with open(path, errors="replace") as fh:
                    keys += [ln.strip() for ln in fh
                             if ln.strip() and not ln.strip().startswith("#")]
            except OSError:
                continue
        if keys:
            state[ent["user"]] = {"hash": _sha256("\n".join(sorted(keys))),
                                  "count": len(keys)}
    return state


def uid0_accounts(passwd_path: str = "/etc/passwd") -> list[str]:
    return sorted(e["user"] for e in _passwd_entries(passwd_path) if e["uid"] == 0)


def empty_password_accounts(shadow_path: str = "/etc/shadow") -> tuple[list[str] | None, bool]:
    """(accounts-with-empty-hash, readable). (None, False) when shadow is unreadable."""
    try:
        with open(shadow_path, errors="replace") as fh:
            rows = fh.read().splitlines()
    except OSError:
        return None, False
    empties = []
    for line in rows:
        parts = line.split(":")
        if len(parts) >= 2 and parts[0] and parts[1] == "":
            empties.append(parts[0])
    return sorted(empties), True


def world_writable_files(paths: tuple = SENSITIVE_WW_PATHS, max_depth: int = 3,
                         cap: int = 50) -> list[str]:
    """Regular files with the o+w bit in sensitive paths (symlinks skipped)."""
    hits: list[str] = []
    for root_path in paths:
        root_depth = root_path.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
            if dirpath.count("/") - root_depth >= max_depth:
                dirnames[:] = []
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    st_ = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISREG(st_.st_mode) and st_.st_mode & stat.S_IWOTH:
                    hits.append(full)
                    if len(hits) >= cap:
                        return hits
    return hits


def collect_access_state(st: SecuritySettings | None = None) -> dict:
    """Everything the access watcher observes, as plain data."""
    st = st or SecuritySettings()
    empties, shadow_readable = empty_password_accounts()
    return {
        "sudoers": sudoers_state(),
        "authorized_keys": authorized_keys_state(),
        "uid0": uid0_accounts(),
        "empty_passwords": empties if shadow_readable else None,
        "shadow_readable": shadow_readable,
        "world_writable": world_writable_files(st.ww_paths),
    }


def analyze_access(current: dict, baseline: dict | None) -> tuple[list[Finding], dict]:
    """Pure analysis of access state vs baseline → (findings, observed)."""
    baseline = baseline or {}
    has_baseline = bool(baseline)
    findings: list[Finding] = []

    cur_sudoers = current.get("sudoers", {}).get("files", {})
    base_sudoers = baseline.get("sudoers", {})
    if has_baseline:
        for path, digest in sorted(cur_sudoers.items()):
            if path not in base_sudoers:
                findings.append(Finding(
                    "warning", "access", f"new sudoers file: {path}",
                    "a sudoers entry appeared since the accepted baseline",
                    {"path": path}))
            elif base_sudoers[path] != digest:
                findings.append(Finding(
                    "warning", "access", f"sudoers changed: {path}",
                    "content hash differs from the accepted baseline",
                    {"path": path}))
        for path in sorted(set(base_sudoers) - set(cur_sudoers)):
            findings.append(Finding(
                "info", "access", f"sudoers file removed: {path}",
                "present in the baseline, gone now", {"path": path}))
    for path in current.get("sudoers", {}).get("unreadable", []):
        findings.append(Finding(
            "info", "access", f"sudoers unreadable: {path}",
            "run as root for full sudoers coverage", {"path": path}))

    cur_keys = current.get("authorized_keys", {})
    base_keys = baseline.get("authorized_keys", {})
    if has_baseline:
        for user, rec in sorted(cur_keys.items()):
            if user not in base_keys:
                findings.append(Finding(
                    "warning", "access", f"new authorized_keys for {user}",
                    f"{rec['count']} key(s) now grant SSH access to this account",
                    {"user": user, "count": rec["count"]}))
            elif base_keys[user].get("hash") != rec["hash"]:
                delta = rec["count"] - int(base_keys[user].get("count", 0))
                word = "added" if delta > 0 else ("removed" if delta < 0 else "changed")
                findings.append(Finding(
                    "warning", "access", f"authorized_keys changed for {user}",
                    f"key list hash differs from baseline ({abs(delta) or 'content'} "
                    f"{word})", {"user": user, "count": rec["count"]}))

    cur_uid0 = current.get("uid0", [])
    base_uid0 = set(baseline.get("uid0", ["root"]))
    for user in cur_uid0:
        if user == "root":
            continue
        sev = "critical" if (not has_baseline or user not in base_uid0) else "warning"
        findings.append(Finding(
            sev, "access", f"UID-0 account besides root: {user}",
            "a second superuser account — verify it is intentional",
            {"user": user}))

    empties = current.get("empty_passwords")
    if empties is None:
        if not current.get("shadow_readable", False):
            findings.append(Finding(
                "info", "access", "shadow file unreadable — empty-password check skipped",
                "run wrench as root to audit password hashes", {}))
    else:
        for user in empties:
            findings.append(Finding(
                "critical", "access", f"account with EMPTY password: {user}",
                "anyone can log in as this account without a password",
                {"user": user}))

    for path in current.get("world_writable", []):
        findings.append(Finding(
            "warning", "access", f"world-writable file in sensitive path: {path}",
            "any local user can modify this file", {"path": path}))

    observed = {
        "sudoers": dict(cur_sudoers),
        "authorized_keys": {u: dict(r) for u, r in cur_keys.items()},
        "uid0": list(cur_uid0),
    }
    return findings, observed


# =====================================================================
# 3. listener ownership
# =====================================================================

def _unit_of_pid(pid: int) -> str:
    """systemd unit owning a pid, from /proc/<pid>/cgroup. '' when unknown."""
    try:
        with open(f"/proc/{pid}/cgroup") as fh:
            for line in fh:
                seg = line.rstrip("\n").rsplit(":", 1)[-1]
                for part in reversed(seg.split("/")):
                    if part.endswith((".service", ".scope")):
                        return part
    except OSError:
        pass
    return ""


def listener_inventory() -> list[dict]:
    """[{key, proto, port, addr, process, pid, unit, ownerless}] via ss (or psutil)."""
    rows: list[dict] = []
    seen: set[str] = set()
    code, out = _run(["ss", "-tulnpH"]) if shutil.which("ss") else (1, "")
    if code == 0 and out.strip():
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto, local = parts[0], parts[4]
            addr, _, port = local.rpartition(":")
            if not port.isdigit():
                continue
            proc, pid = "", 0
            if 'users:(("' in line:
                try:
                    blob = line.split("users:((", 1)[1]
                    proc = blob.split('"')[1]
                    pid = int(blob.split("pid=", 1)[1].split(",", 1)[0])
                except (IndexError, ValueError):
                    pass
            key = f"{proto}/{port}"
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "key": key, "proto": proto, "port": int(port), "addr": addr,
                "process": proc, "pid": pid,
                "unit": _unit_of_pid(pid) if pid else "",
                "ownerless": not proc,
            })
        return sorted(rows, key=lambda r: (r["proto"], r["port"]))
    # psutil fallback (non-Linux / no ss)
    try:
        import psutil
        for c in psutil.net_connections(kind="inet"):
            is_listener = (str(c.status) == "LISTEN") or (c.type == 2 and not c.raddr)
            if not is_listener or not c.laddr:
                continue
            proto = "tcp" if c.type == 1 else "udp"
            key = f"{proto}/{c.laddr.port}"
            if key in seen:
                continue
            seen.add(key)
            proc = ""
            if c.pid:
                try:
                    proc = psutil.Process(c.pid).name()
                except Exception:  # noqa: BLE001
                    proc = ""
            rows.append({"key": key, "proto": proto, "port": c.laddr.port,
                         "addr": str(c.laddr.ip), "process": proc,
                         "pid": c.pid or 0, "unit": "", "ownerless": not proc})
    except Exception:  # noqa: BLE001
        pass
    return sorted(rows, key=lambda r: (r["proto"], r["port"]))


def analyze_listeners(current: list[dict], baseline: dict | None) -> tuple[list[Finding], dict]:
    """Pure: listener rows + baseline {key: label} → (findings, observed)."""
    baseline = baseline or {}
    base_keys = set(baseline.get("listeners", {}))
    has_baseline = bool(baseline)
    findings: list[Finding] = []
    for row in current:
        label = row.get("process") or "?"
        if has_baseline and row["key"] not in base_keys:
            findings.append(Finding(
                "warning", "listeners",
                f"NEW listener {row['key']} ({label})",
                f"listening on {row.get('addr') or '*'}:{row['port']}"
                + (f", unit {row['unit']}" if row.get("unit") else "")
                + " — not in the accepted baseline",
                {"key": row["key"], "process": label, "unit": row.get("unit", "")}))
        if row.get("ownerless"):
            findings.append(Finding(
                "warning", "listeners",
                f"ownerless listener {row['key']}",
                f"no process admits to {row.get('addr') or '*'}:{row['port']} "
                f"(needs root to resolve, or the owner is hiding)",
                {"key": row["key"]}))
    observed = {"listeners": {r["key"]: (r.get("process") or "") for r in current}}
    return findings, observed
