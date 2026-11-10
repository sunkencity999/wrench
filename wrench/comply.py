"""Compliance packs — prove the box meets the baseline.

``wrench comply`` audits the host against declarative hardening packs:
JSON files of rules whose checks are **data, not code** — each check names a
primitive (file mode, sshd_config key, sysctl value, …) that maps to a safe
internal function. Nothing in a pack is ever executed as a shell string.

Design rules (consistent with the rest of wrench):
- **Deterministic.** Checks are code; the model is never asked whether the
  box is compliant. The optional brain briefing only narrates results.
- **Read-only.** Every primitive observes; none mutates host state.
- **Degrade politely.** A file we cannot read without root is a ``skip``
  (counted and said once), never a fake pass or a crying-wolf fail.
- **Consent-gated baseline.** ``wrench comply accept`` blesses the current
  fail-set; patrols then raise findings only for NEW failures. The accept is
  sealed into the audit chain.

Results snapshot to the store (``comply_scan`` / ``comply_baseline``) and feed
``--json`` (``wrench.comply.v1``), patrols, and the Prometheus exporter.
"""

from __future__ import annotations

import glob as _glob
import json
import re
import shutil
import stat as _stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SCAN_KIND = "comply_scan"
BASELINE_KIND = "comply_baseline"

SEVERITIES = ("critical", "high", "medium", "low")

_PACK_DIR = Path(__file__).parent / "packs"
_SYSCTL_ROOT = "/proc/sys"     # live kernel settings (module-level so tests can point it at a fixture tree)


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    title: str
    severity: str
    rationale: str
    check: dict

    def validate(self) -> None:
        if not self.id or not re.match(r"^[a-z0-9][a-z0-9._-]*$", self.id):
            raise ValueError(f"bad rule id: {self.id!r}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"rule {self.id}: bad severity {self.severity!r}")
        kind = self.check.get("kind")
        if kind not in CHECKS:
            raise ValueError(f"rule {self.id}: unknown check kind {kind!r}")
        if kind == "probe":
            from . import probes
            if self.check.get("name") not in probes.PROBES:
                raise ValueError(f"rule {self.id}: unknown probe {self.check.get('name')!r}")
            if not any(k in self.check for k in ("expect", "max", "min")):
                raise ValueError(f"rule {self.id}: probe check needs expect / max / min")


@dataclass
class Pack:
    name: str
    title: str
    description: str
    rules: list[Rule] = field(default_factory=list)
    platforms: list[str] = field(default_factory=lambda: ["linux"])


@dataclass
class Result:
    rule: Rule
    status: str          # pass | fail | skip
    detail: str = ""

    def to_dict(self) -> dict:
        return {"id": self.rule.id, "title": self.rule.title,
                "severity": self.rule.severity, "status": self.status,
                "detail": self.detail}


# --------------------------------------------------------------------------
# pack loading
# --------------------------------------------------------------------------

def pack_dir() -> Path:
    return _PACK_DIR


def list_packs() -> list[Pack]:
    packs = []
    for p in sorted(pack_dir().glob("*.json")):
        packs.append(load_pack(p.stem))
    return packs


def load_pack(name: str) -> Pack:
    """Load + validate one shipped pack. Bad packs raise ValueError."""
    if not re.match(r"^[a-z0-9][a-z0-9._-]*$", name):
        raise ValueError(f"bad pack name: {name!r}")
    path = pack_dir() / f"{name}.json"
    if not path.exists():
        known = ", ".join(p.stem for p in pack_dir().glob("*.json")) or "none"
        raise ValueError(f"unknown pack {name!r} (shipped: {known})")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"pack {name}: invalid JSON — {e}") from None
    for key in ("name", "title", "rules"):
        if key not in data:
            raise ValueError(f"pack {name}: missing {key!r}")
    plats = data.get("platforms") or ["linux"]
    if not isinstance(plats, list) or not all(p in PLATFORMS for p in plats):
        raise ValueError(f"pack {name}: platforms must be a list drawn from {PLATFORMS}")
    pack = Pack(name=data["name"], title=data["title"],
                description=data.get("description", ""), platforms=list(plats))
    seen: set[str] = set()
    for raw in data["rules"]:
        rule = Rule(id=str(raw.get("id", "")), title=str(raw.get("title", "")),
                    severity=str(raw.get("severity", "")),
                    rationale=str(raw.get("rationale", "")),
                    check=raw.get("check") or {})
        rule.validate()
        if rule.id in seen:
            raise ValueError(f"pack {name}: duplicate rule id {rule.id}")
        seen.add(rule.id)
        pack.rules.append(rule)
    return pack


def find_rule(rule_id: str) -> tuple[Pack, Rule] | None:
    for pack in list_packs():
        for rule in pack.rules:
            if rule.id == rule_id:
                return pack, rule
    return None


# --------------------------------------------------------------------------
# check primitives — every one read-only; packs are data, not code
# --------------------------------------------------------------------------

def _read(path: str) -> tuple[str | None, str]:
    """Return (text, detail). text None => unreadable/missing."""
    p = Path(path)
    if not p.exists():
        return None, f"{path} does not exist"
    try:
        return p.read_text(errors="replace"), ""
    except PermissionError:
        return None, f"{path} unreadable without root"
    except OSError as e:
        return None, f"{path}: {e.__class__.__name__}"


def _check_file_mode(c: dict) -> tuple[str, str]:
    """{kind, path, max_mode: "0644"} — fail when perms exceed max_mode."""
    p = Path(c["path"])
    if not p.exists():
        if c.get("missing_ok"):
            return "pass", f"{p} absent (ok)"
        return "skip", f"{p} does not exist"
    try:
        mode = _stat.S_IMODE(p.stat().st_mode)
    except PermissionError:
        return "skip", f"{p} stat denied"
    max_mode = int(str(c["max_mode"]), 8)
    if mode & ~max_mode:
        return "fail", f"{p} is {oct(mode)}, want <= {oct(max_mode)}"
    return "pass", f"{p} is {oct(mode)}"


def _check_file_owner(c: dict) -> tuple[str, str]:
    """{kind, path, owner: "root", group: "root"(opt)}"""
    p = Path(c["path"])
    if not p.exists():
        return "skip", f"{p} does not exist"
    try:
        st = p.stat()
    except PermissionError:
        return "skip", f"{p} stat denied"
    import grp
    import pwd
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    if owner != c["owner"]:
        return "fail", f"{p} owned by {owner}, want {c['owner']}"
    if c.get("group"):
        try:
            gname = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            gname = str(st.st_gid)
        if gname != c["group"]:
            return "fail", f"{p} group {gname}, want {c['group']}"
    return "pass", f"{p} owner ok"


def _strip_comments(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _check_file_contains(c: dict) -> tuple[str, str]:
    """{kind, path, regex, absent: bool(opt)} — effective (non-comment) lines."""
    text, why = _read(c["path"])
    if text is None:
        return "skip", why
    rx = re.compile(c["regex"])
    hit = next((ln for ln in _strip_comments(text) if rx.search(ln)), None)
    if c.get("absent"):
        if hit:
            return "fail", f"{c['path']} contains {hit!r}"
        return "pass", f"no match for /{c['regex']}/"
    if hit:
        return "pass", f"matched {hit!r}"
    return "fail", f"{c['path']}: no line matches /{c['regex']}/"


def _sshd_effective(text: str) -> dict[str, str]:
    """First-wins sshd_config semantics; Match blocks end global scope."""
    eff: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, val = parts[0].lower(), parts[1].strip()
        if key == "match":
            break    # per-condition overrides are out of scope — global only
        if key not in eff:   # sshd: first occurrence wins
            eff[key] = val
    return eff


def _check_sshd_config(c: dict) -> tuple[str, str]:
    """{kind, key, value, default: value-when-unset(opt)}"""
    path = c.get("path", "/etc/ssh/sshd_config")
    text, why = _read(path)
    if text is None:
        return "skip", why
    eff = _sshd_effective(text)
    # fold in drop-ins (Include is default on modern Ubuntu, first-wins order)
    # — the drop-in directory sits beside the file being checked, so a pack
    # pointed at another path never picks up this host's /etc/ssh drop-ins
    for inc in sorted(_glob.glob(_glob.escape(str(path) + ".d") + "/*.conf")):
        t2, _ = _read(inc)
        if t2:
            for k, v in _sshd_effective(t2).items():
                eff.setdefault(k, v)
    key = c["key"].lower()
    actual = eff.get(key, c.get("default"))
    want = str(c["value"]).lower()
    if actual is None:
        return "fail", f"{c['key']} unset (want {c['value']})"
    if str(actual).lower() == want:
        return "pass", f"{c['key']} = {actual}"
    return "fail", f"{c['key']} = {actual}, want {c['value']}"


def _check_sysctl(c: dict) -> tuple[str, str]:
    """{kind, key, value} — read /proc/sys (live kernel truth)."""
    path = Path(_SYSCTL_ROOT) / c["key"].replace(".", "/")
    text, why = _read(str(path))
    if text is None:
        return "skip", why
    actual = text.strip()
    if actual == str(c["value"]):
        return "pass", f"{c['key']} = {actual}"
    return "fail", f"{c['key']} = {actual}, want {c['value']}"


def _dpkg_installed(name: str) -> bool | None:
    dpkg = shutil.which("dpkg-query")
    if not dpkg:
        return None
    try:
        r = subprocess.run([dpkg, "-W", "-f", "${Status}", name],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10)
        return r.returncode == 0 and "install ok installed" in r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None


def _check_package(c: dict) -> tuple[str, str]:
    """{kind, name, state: present|absent}"""
    inst = _dpkg_installed(c["name"])
    if inst is None:
        return "skip", "dpkg-query unavailable"
    want_present = c.get("state", "present") == "present"
    if inst == want_present:
        return "pass", f"{c['name']} {'installed' if inst else 'absent'}"
    return "fail", (f"{c['name']} installed (want absent)" if inst
                    else f"{c['name']} not installed")


def _check_service_state(c: dict) -> tuple[str, str]:
    """{kind, name, state: active|inactive|enabled}"""
    sysctl_bin = shutil.which("systemctl")
    if not sysctl_bin:
        return "skip", "systemctl unavailable"
    verb = "is-enabled" if c["state"] == "enabled" else "is-active"
    try:
        r = subprocess.run([sysctl_bin, verb, "--quiet", c["name"]],
                           capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return "skip", "systemctl query failed"
    ok = r.returncode == 0
    want_on = c["state"] in ("active", "enabled")
    if ok == want_on:
        return "pass", f"{c['name']} {c['state']}: ok"
    return "fail", f"{c['name']} not {c['state']}"


def _check_mount_option(c: dict) -> tuple[str, str]:
    """{kind, mountpoint, option, missing_ok: bool(opt)}"""
    text, why = _read("/proc/mounts")
    if text is None:
        return "skip", why
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1] == c["mountpoint"]:
            opts = parts[3].split(",")
            if c["option"] in opts:
                return "pass", f"{c['mountpoint']} has {c['option']}"
            return "fail", f"{c['mountpoint']} lacks {c['option']} ({parts[3]})"
    if c.get("missing_ok"):
        return "pass", f"{c['mountpoint']} not a separate mount (ok)"
    return "skip", f"{c['mountpoint']} not mounted"


def _check_login_defs(c: dict) -> tuple[str, str]:
    """{kind, key, op: max|min|eq, value} — numeric compare on login.defs."""
    text, why = _read(c.get("path", "/etc/login.defs"))
    if text is None:
        return "skip", why
    val = None
    for line in _strip_comments(text):
        parts = line.split()
        if len(parts) >= 2 and parts[0] == c["key"]:
            val = parts[1]
    if val is None:
        return "fail", f"{c['key']} unset"
    op = c.get("op", "eq")

    def _num(x) -> int | None:
        s = str(x)
        try:
            return int(s, 0)        # 0o027, 0x..., plain decimal
        except ValueError:
            try:
                return int(s, 8)    # bare-octal convention: UMASK 027
            except ValueError:
                return None

    have, want = _num(val), _num(c["value"])
    if have is None or want is None:
        return ("pass", f"{c['key']} = {val}") if str(val) == str(c["value"]) \
            else ("fail", f"{c['key']} = {val}, want {c['value']}")
    ok = {"max": have <= want, "min": have >= want, "eq": have == want}[op]
    return ("pass" if ok else "fail",
            f"{c['key']} = {have} (want {op} {want})")


def _check_no_empty_passwords(c: dict) -> tuple[str, str]:
    """{kind} — /etc/shadow second field empty => critical fail."""
    text, why = _read("/etc/shadow")
    if text is None:
        return "skip", why
    bad = [ln.split(":", 1)[0] for ln in text.splitlines()
           if ln and len(ln.split(":")) > 1 and ln.split(":")[1] == ""]
    if bad:
        return "fail", f"empty password: {', '.join(bad)}"
    return "pass", "no empty password hashes"


def _check_single_uid0(c: dict) -> tuple[str, str]:
    """{kind} — only root may have UID 0."""
    text, why = _read("/etc/passwd")
    if text is None:
        return "skip", why
    uid0 = [ln.split(":")[0] for ln in text.splitlines()
            if ln and len(ln.split(":")) > 3 and ln.split(":")[2] == "0"]
    extra = [u for u in uid0 if u != "root"]
    if extra:
        return "fail", f"extra UID-0 accounts: {', '.join(extra)}"
    return "pass", "root is the only UID-0 account"


def _check_probe(c: dict) -> tuple[str, str]:
    """{kind, name, expect: "on" | [..]} or {kind, name, max: N} / {min: N}.

    ``name`` selects a hand-written, read-only probe from wrench/probes.py —
    the pack supplies no command, only the name and the expected answer.
    """
    from . import probes
    value, detail = probes.run(c["name"])
    if value is None:
        return "skip", detail
    if "expect" in c:
        want = c["expect"] if isinstance(c["expect"], list) else [c["expect"]]
        ok = value in [str(w) for w in want]
        return ("pass" if ok else "fail"), detail
    try:
        num = float(value)
    except ValueError:
        # a non-numeric answer to a numeric rule ("off") is a failure of the rule
        return "fail", detail
    if "max" in c and num > float(c["max"]):
        return "fail", f"{detail} (limit {c['max']})"
    if "min" in c and num < float(c["min"]):
        return "fail", f"{detail} (minimum {c['min']})"
    return "pass", detail


CHECKS = {
    "probe": _check_probe,
    "file_mode": _check_file_mode,
    "file_owner": _check_file_owner,
    "file_contains": _check_file_contains,
    "sshd_config": _check_sshd_config,
    "sysctl": _check_sysctl,
    "package": _check_package,
    "service_state": _check_service_state,
    "mount_option": _check_mount_option,
    "login_defs": _check_login_defs,
    "no_empty_passwords": _check_no_empty_passwords,
    "single_uid0": _check_single_uid0,
}


def run_rule(rule: Rule) -> Result:
    try:
        status, detail = CHECKS[rule.check["kind"]](rule.check)
    except Exception as e:  # noqa: BLE001 — a broken check is a skip, not a crash
        status, detail = "skip", f"check error: {e.__class__.__name__}: {e}"
    return Result(rule=rule, status=status, detail=detail)


# --------------------------------------------------------------------------
# scan + scoring + baseline + patrol
# --------------------------------------------------------------------------

def run_pack(pack: Pack) -> dict:
    results = [run_rule(r) for r in pack.rules]
    counts = {"pass": 0, "fail": 0, "skip": 0}
    sev_fails = dict.fromkeys(SEVERITIES, 0)
    for r in results:
        counts[r.status] += 1
        if r.status == "fail":
            sev_fails[r.rule.severity] += 1
    graded = counts["pass"] + counts["fail"]
    # a pack where nothing could be graded has no score — 0% would be a lie
    score = round(100.0 * counts["pass"] / graded, 1) if graded else None
    return {"pack": pack.name, "title": pack.title, "score": score,
            "platforms": list(pack.platforms),
            "counts": counts, "severity_fails": sev_fails,
            "results": [r.to_dict() for r in results]}


PLATFORMS = ("linux", "macos", "windows")


def applicable_packs(plat: str | None = None) -> list[str]:
    """Shipped packs whose ``platforms`` include this OS (pure given ``plat``)."""
    from . import platforms as _pl
    plat = plat or _pl.current_platform()
    out = []
    for p in sorted(pack_dir().glob("*.json")):
        try:
            if plat in load_pack(p.stem).platforms:
                out.append(p.stem)
        except ValueError:
            continue
    return out


def scan(store, packs: list[str] | None = None) -> dict:
    """Run packs, snapshot a slim record, return the full report."""
    # An explicitly named pack always runs (auditing a Linux pack from a Mac is a
    # legitimate "what would fail?" question); the default set is the packs
    # written for this OS.
    names = packs or applicable_packs()
    reports = [run_pack(load_pack(n)) for n in names]
    out = {"packs": reports,
           "fail_ids": sorted({r["id"] for rep in reports
                               for r in rep["results"] if r["status"] == "fail"}),
           "critical_fails": sum(rep["severity_fails"]["critical"]
                                 for rep in reports)}
    if store is not None:
        try:
            slim = {"packs": [{k: rep[k] for k in
                               ("pack", "score", "counts", "severity_fails")}
                              for rep in reports],
                    "fail_ids": out["fail_ids"],
                    "critical_fails": out["critical_fails"],
                    "fails": [{"id": r["id"], "title": r["title"],
                               "severity": r["severity"]}
                              for rep in reports for r in rep["results"]
                              if r["status"] == "fail"]}
            store.add_snapshot(SCAN_KIND, slim)
        except Exception:  # noqa: BLE001
            pass
    return out


def accept_baseline(store, data_dir=None) -> dict:
    """Consent already gathered by the CLI. Bless the current fail-set."""
    report = scan(store)
    payload = {"fail_ids": report["fail_ids"]}
    store.add_snapshot(BASELINE_KIND, payload)
    try:
        from . import audit
        if data_dir is not None:
            audit.append(data_dir, "comply.baseline_accept",
                         {"fail_count": len(report["fail_ids"])})
    except Exception:  # noqa: BLE001
        pass
    return payload


def baseline_fail_ids(store) -> set[str] | None:
    row = store.last_snapshot(BASELINE_KIND)
    if not row:
        return None
    return set(row[1].get("fail_ids") or [])


_SEV_TO_FINDING = {"critical": "critical", "high": "warning",
                   "medium": "warning", "low": "info"}


def patrol_findings(cfg, store, cadence_s: int = 6 * 3600) -> list[dict]:
    """NEW failures vs accepted baseline, from the cached scan. Never raises."""
    try:
        import time as _t
        last = store.last_snapshot(SCAN_KIND)
        if last is None or (_t.time() - last[0]) > cadence_s:
            scan(store)
            last = store.last_snapshot(SCAN_KIND)
        if last is None:
            return []
        snap = last[1]
        base = baseline_fail_ids(store)
        out = []
        for f in snap.get("fails") or []:
            if base is not None and f["id"] in base:
                continue      # accepted debt — not news
            summary = f"{f['id']}: {f['title']}"
            out.append({"severity": _SEV_TO_FINDING.get(f["severity"], "info"),
                        "area": "comply",
                        "summary": summary,
                        # every patrol finding carries "text" — the merge and
                        # the notification summary both read it. Rule titles
                        # state the DESIRED condition, so say plainly that it
                        # is not met.
                        "text": f"compliance check failed — expected: {f['title']} "
                                f"(`wrench comply show {f['id']}`)"})
        return out
    except Exception:  # noqa: BLE001
        return []


def patrol_summary_line(cfg, store, cadence_s: int = 6 * 3600) -> str:
    try:
        last = store.last_snapshot(SCAN_KIND)
        if last is None:
            return "comply: no scan yet"
        snap = last[1]
        bits = [f"{p['pack']} " + ("n/a" if p.get("score") is None else f"{p['score']}%")
                for p in snap.get("packs") or []]
        if not bits:
            return "comply: no compliance pack applies to this OS"
        base = baseline_fail_ids(store)
        tail = "no baseline" if base is None else f"baseline {len(base)} accepted"
        return f"comply: {', '.join(bits)} ({tail})"
    except Exception:  # noqa: BLE001
        return "comply: unavailable"


def narration_context(report: dict) -> str:
    """Compact text for the optional brain briefing — analysis only."""
    lines = []
    for rep in report["packs"]:
        score = "n/a" if rep["score"] is None else f"{rep['score']}%"
        lines.append(f"pack {rep['pack']}: score {score} "
                     f"({rep['counts']['fail']} fail, {rep['counts']['skip']} skip)")
        for r in rep["results"]:
            if r["status"] == "fail":
                lines.append(f"  FAIL [{r['severity']}] {r['id']}: "
                             f"{r['title']} — {r['detail']}")
    return "\n".join(lines)
