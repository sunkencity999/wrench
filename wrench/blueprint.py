"""wrench blueprint — declarative config automation.

The brain drafts a config change as a UNIFIED DIFF against the real current
files; the model NEVER executes anything — it only produces diff text. Code
owns everything that touches the system:

    draft (LLM → diff) → preview → consent → timestamped backup → apply →
    validate with the daemon's OWN checker (nginx -t, sshd -t, visudo -c,
    named-checkconf, …) → service reload (allowlisted systemctl verbs only) →
    health probe → AUTOMATIC ROLLBACK from backup on any failure.

Safety rails:
  * target allowlist (default: /etc) + hard denylist (/etc/passwd, shadow,
    sudoers direct — sudoers only via visudo-checked /etc/sudoers.d staging)
  * diff size caps, target-file count cap, binary-file refusal
  * dry-run by default; --execute gated by policy tier exactly like fixxer
  * every application audited to an append-only JSONL + labeled drift snapshot
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import policy

MAX_DIFF_BYTES = 64 * 1024          # a config change is not a novel
MAX_TARGET_FILES = 8                # one intent, few files
MAX_FILE_READ_BYTES = 256 * 1024    # refuse to diff against huge files

AUDIT_FILENAME = "blueprint_audit.jsonl"
BACKUP_DIRNAME = "blueprint_backups"
CONSENT_FILENAME = "blueprint_consent.json"

APPLY_ALLOWED_TIERS = ("repair", "autonomous")

# Paths no blueprint may EVER touch, regardless of allowlist.
DENY_PATTERNS = (
    "/etc/passwd", "/etc/passwd-",
    "/etc/shadow", "/etc/shadow-",
    "/etc/gshadow", "/etc/gshadow-",
    "/etc/group", "/etc/group-",
    "/etc/sudoers",              # direct writes forbidden; use /etc/sudoers.d
    "/etc/crypttab",
    "/etc/fstab",
    "/etc/ssl/private/*",
    "/etc/ssh/ssh_host_*",       # host private keys
    "*.key", "*.pem",            # never rewrite key material via diff
    "/etc/machine-id",
    "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d/*",   # loader hijack
    "/etc/pam.d/*", "/etc/pam.conf", "/etc/security/*",                # auth stack
    "/etc/nsswitch.conf",
    "/etc/ssh/sshd_config.d/../*",
    "/etc/sudoers.d/../*",
)

# Files that are *executed* by root (cron, shell profiles, unit files, hooks).
# A diff here is root code execution, not configuration — so it is never a
# target unless the operator opts the directory in explicitly with
# `[blueprint] allow_exec_paths = true`, and even then never with --yes.
EXEC_VECTOR_PATTERNS = (
    "/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.hourly/*", "/etc/cron.weekly/*",
    "/etc/cron.monthly/*", "/etc/crontab", "/etc/anacrontab",
    "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc", "/etc/bashrc",
    "/etc/zshrc", "/etc/zshenv", "/etc/zprofile", "/etc/environment",
    "/etc/systemd/system/*", "/etc/systemd/user/*", "/etc/init.d/*", "/etc/rc.local",
    "/etc/rc*.d/*", "/etc/udev/rules.d/*", "/etc/NetworkManager/dispatcher.d/*",
    "/etc/update-motd.d/*", "/etc/apt/apt.conf.d/*", "/etc/dpkg/dpkg.cfg.d/*",
    "/etc/logrotate.d/../*", "/etc/xdg/autostart/*", "/etc/periodic/*",
    "/Library/LaunchDaemons/*", "/Library/LaunchAgents/*",
)


# Windows: the registry hives and credential stores are never a target, and a
# script or scheduled task is code that runs later, not configuration.
# Patterns are written with forward slashes; paths are compared the same way.
WINDOWS_DENY_PATTERNS = (
    "?:/windows/system32/config/*",      # SAM / SECURITY / SYSTEM hives
    "?:/windows/ntds/*",
    "*/microsoft/protect/*", "*/microsoft/credentials/*", "*/microsoft/crypto/*",
    "*/.ssh/*",
)
WINDOWS_EXEC_VECTOR_PATTERNS = (
    "*.bat", "*.cmd", "*.ps1", "*.psm1", "*.psd1", "*.vbs", "*.vbe", "*.js", "*.jse",
    "*.wsf", "*.wsh", "*.hta", "*.reg", "*.lnk", "*.scr", "*.msi", "*.exe", "*.dll",
    "?:/windows/system32/tasks/*", "?:/windows/tasks/*",
    "*/start menu/programs/startup/*",
    "?:/windows/system32/grouppolicy/*",
)

_WIN = os.name == "nt"


def _slashed(path: str) -> str:
    """The path as the deny patterns spell it: forward slashes, case-folded."""
    p = str(path).replace("\\", "/") if _WIN else str(path)
    return p.casefold()


def _is_abs(p: str) -> bool:
    """Absolute and local. On Windows that means a drive letter — no UNC
    shares, no device paths, no drive-relative `C:foo`."""
    if _WIN:
        drive, rest = os.path.splitdrive(p)
        return (len(drive) == 2 and drive[0].isalpha() and drive[1] == ":"
                and rest[:1] in ("\\", "/"))
    return p.startswith("/") and not p.startswith("//")


def _parts(p: str) -> list[str]:
    return re.split(r"[\\/]", p) if _WIN else p.split("/")


def _same_spelling(a: str, b: str) -> bool:
    """Is `a` the normalized form of `b`, ignoring a trailing separator (and,
    on Windows, which slash was typed)?"""
    if _WIN:
        a, b = a.replace("\\", "/"), b.replace("\\", "/")
    return a == b or a == b.rstrip("/")


def _within(path: str, root: str) -> bool:
    """Is `path` the root itself or somewhere beneath it? Case-insensitive
    where the filesystem is (os.path.normcase)."""
    a, b = os.path.normcase(path), os.path.normcase(root)
    b = b.rstrip(os.sep)
    if not b:                      # the filesystem root
        return a.startswith(os.sep)
    return a == b or a.startswith(b + os.sep)


def backup_relpath(path: str) -> str:
    """Where a target is stored under a backup directory. Never absolute:
    `C:\\x\\y` becomes `C/x/y`, so joining it cannot escape the backup dir."""
    drive, rest = os.path.splitdrive(str(path))
    rel = rest.lstrip("\\/") if _WIN else rest.lstrip("/")
    letter = "".join(ch for ch in drive if ch.isalnum())
    return os.path.join(letter, rel) if letter else rel


def is_exec_vector(path: str) -> bool:
    """True when writing this path means code runs as root later."""
    cmp = _slashed(os.path.normpath(str(path)))
    pats = EXEC_VECTOR_PATTERNS + (WINDOWS_EXEC_VECTOR_PATTERNS if _WIN else ())
    return any(fnmatch.fnmatchcase(cmp, pat.casefold()) for pat in pats)


class BlueprintError(Exception):
    """Validation / parse / apply failure. Message is human-facing."""


# ---------------- subprocess seam (tests monkeypatch this) ----------------

def _run(argv: list[str], timeout: int = 120) -> tuple[int, str]:
    """Run argv with no shell. Returns (exit_code, combined_output)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        out = (r.stdout or "") + (("\n[stderr] " + r.stderr.strip()) if r.stderr.strip() else "")
        return r.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return 124, f"(timed out after {timeout}s)"
    except FileNotFoundError:
        return 127, f"(command not found: {argv[0]})"
    except Exception as e:  # noqa: BLE001
        return 1, f"(error: {e.__class__.__name__}: {e})"


# ---------------- config ----------------

def _bp_cfg(cfg) -> dict:
    raw = getattr(cfg, "raw", {}) or {}
    sec = raw.get("blueprint", {})
    return sec if isinstance(sec, dict) else {}


def allowed_roots(cfg) -> list[str]:
    roots = _bp_cfg(cfg).get("allowed_roots", ["/etc"])
    if not isinstance(roots, list) or not roots:
        roots = ["/etc"]
    if _WIN:
        return [str(r).rstrip("\\/") + ("\\" if len(str(r).rstrip("\\/")) == 2 else "")
                for r in roots]
    return [str(r).rstrip("/") or "/" for r in roots]


def path_allowed(cfg, path: str) -> tuple[bool, str]:
    """Is this target path permitted? (allowed, reason)."""
    p = str(path)
    if not _is_abs(p) or ".." in _parts(p) or "\x00" in p:
        return False, "target must be an absolute, normalized path"
    norm = os.path.normpath(p)
    if not _same_spelling(norm, p):
        return False, f"non-normalized path (did you mean {norm}?)"
    # Confinement is decided on where the write would really land: resolve
    # symlinks in the parent chain (and the file itself, if it is one). A link
    # inside /etc pointing at /root/.ssh must not smuggle a write out.
    real = os.path.realpath(norm)
    for cand in dict.fromkeys((norm, real)):
        # deny rules compare case-insensitively: on APFS/NTFS "/etc/Sudoers"
        # IS /etc/sudoers, and on Linux nothing legitimate differs only by case
        low = _slashed(cand)
        for pat in DENY_PATTERNS + (WINDOWS_DENY_PATTERNS if _WIN else ()):
            if fnmatch.fnmatchcase(low, pat.casefold()):
                return False, f"denylisted target ({pat}) — wrench never edits this via blueprint"
        if is_exec_vector(cand) and not bool(_bp_cfg(cfg).get("allow_exec_paths", False)):
            return False, ("this path is executed by root (cron / profile / unit file) — a "
                           "blueprint there is code execution, not configuration. Set "
                           "[blueprint] allow_exec_paths = true to permit it deliberately")
    for root in allowed_roots(cfg):
        real_root = os.path.realpath(root)
        inside = _within(real, real_root)
        lexical = _within(norm, root)
        if lexical and inside:
            return True, f"within allowed root {root}"
        if lexical and not inside:
            return False, (f"{norm} resolves to {real}, outside allowed root {root} "
                           "(symlink escape)")
    return False, (f"outside allowed roots {allowed_roots(cfg)} — "
                   "add to [blueprint] allowed_roots in config.toml to permit")


# ---------------- unified diff: parse + apply (pure python, no `patch`) ----

@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[tuple[str, str]] = field(default_factory=list)  # (tag, text); tag in ' -+'


@dataclass
class FilePatch:
    path: str
    hunks: list[Hunk] = field(default_factory=list)
    is_new: bool = False


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _strip_ab(p: str) -> str:
    p = p.strip().split("\t")[0]
    for pre in ("a/", "b/"):
        if p.startswith(pre):
            rest = p[len(pre):]
            if _WIN and re.match(r"/*[A-Za-z]:[\\/]", rest):
                return rest.lstrip("/")          # a/C:/ProgramData/app.conf
            return rest if rest.startswith("/") else "/" + rest
    return p


def parse_unified_diff(text: str) -> list[FilePatch]:
    """Parse unified diff text into FilePatch objects. Strict but tolerant of
    git-style headers. Refuses binary patches and file deletions."""
    if len(text.encode()) > MAX_DIFF_BYTES:
        raise BlueprintError(f"diff exceeds size cap ({MAX_DIFF_BYTES} bytes)")
    patches: list[FilePatch] = []
    cur: FilePatch | None = None
    hunk: Hunk | None = None
    old_path = ""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("Binary files") or ln.startswith("GIT binary patch"):
            raise BlueprintError("binary patches are refused")
        if ln.startswith("--- "):
            old_path = _strip_ab(ln[4:])
            i += 1
            continue
        if ln.startswith("+++ "):
            new_path = _strip_ab(ln[4:])
            if new_path in ("/dev/null", "dev/null"):
                raise BlueprintError("file deletions are refused — remove files by hand")
            cur = FilePatch(path=new_path,
                            is_new=old_path in ("/dev/null", "dev/null"))
            patches.append(cur)
            hunk = None
            i += 1
            continue
        m = _HUNK_RE.match(ln)
        if m:
            if cur is None:
                raise BlueprintError("hunk header before any file header")
            hunk = Hunk(int(m.group(1)), int(m.group(2) or 1),
                        int(m.group(3)), int(m.group(4) or 1))
            cur.hunks.append(hunk)
            i += 1
            continue
        if hunk is not None and ln[:1] in (" ", "-", "+"):
            hunk.lines.append((ln[0], ln[1:]))
            i += 1
            continue
        if hunk is not None and ln == "":
            # tolerate a bare empty line inside a hunk as empty context
            hunk.lines.append((" ", ""))
            i += 1
            continue
        if ln.startswith("\\ No newline"):
            i += 1
            continue
        # anything else (diff --git, index, prose) — skip between hunks
        hunk = None
        i += 1
    patches = [p for p in patches if p.hunks]
    if not patches:
        raise BlueprintError("no applicable hunks found in diff")
    if len(patches) > MAX_TARGET_FILES:
        raise BlueprintError(f"diff touches {len(patches)} files (cap {MAX_TARGET_FILES})")
    for p in patches:
        for h in p.hunks:
            olds = sum(1 for t, _ in h.lines if t in (" ", "-"))
            news = sum(1 for t, _ in h.lines if t in (" ", "+"))
            if olds != h.old_count or news != h.new_count:
                raise BlueprintError(
                    f"{p.path}: hunk @@ -{h.old_start},{h.old_count} "
                    f"+{h.new_start},{h.new_count} @@ line counts don't match body")
    return patches


def _find_hunk_pos(src: list[str], h: Hunk) -> int:
    """Locate where the hunk's old-side matches, preferring the stated line.
    Returns a 0-based index, or raises BlueprintError."""
    old_side = [text for tag, text in h.lines if tag in (" ", "-")]
    if not old_side:  # pure insertion
        return max(0, min(h.old_start, len(src)))
    want = h.old_start - 1  # unified diffs are 1-based

    def matches(at: int) -> bool:
        if at < 0 or at + len(old_side) > len(src):
            return False
        return src[at:at + len(old_side)] == old_side

    if matches(want):
        return want
    # small fuzz: search ±200 lines around the stated position, then whole file
    for delta in range(1, 201):
        for cand in (want - delta, want + delta):
            if matches(cand):
                return cand
    # Beyond the fuzz window, accept a match only if it is the ONLY one. Short
    # context (a lone "}" or "PasswordAuthentication no") matches in many
    # blocks; landing in the wrong server{}/Match block still passes a syntax
    # check, so ambiguity is an error, not a guess.
    hits = [cand for cand in range(0, max(1, len(src) - len(old_side) + 1)) if matches(cand)]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise BlueprintError(
            f"hunk near line {h.old_start} matches {len(hits)} places in the file — "
            "ambiguous context; redraft the diff with more surrounding lines")
    ctx = old_side[0][:60] if old_side else ""
    raise BlueprintError(
        f"hunk context not found near line {h.old_start} (looking for {ctx!r}) — "
        "the file has drifted since the diff was drafted")


def apply_patch_text(original: str, patch: FilePatch) -> str:
    """Apply one FilePatch to original content. Raises BlueprintError on any
    context mismatch. Preserves a trailing newline if the original had one."""
    had_nl = original.endswith("\n") or original == ""
    # split on "\n" ONLY. str.splitlines() also breaks on \r, form feed, NEL and
    # U+2028, silently rewriting lines the diff never touched (CRLF configs
    # became LF; a form feed became a line break).
    src = original.split("\n")
    if had_nl and src and src[-1] == "":
        src.pop()
    out: list[str] = []
    pos = 0
    for h in patch.hunks:
        at = _find_hunk_pos(src, h)
        if at < pos:
            raise BlueprintError(f"{patch.path}: overlapping or out-of-order hunks")
        out.extend(src[pos:at])
        i = at
        for tag, text in h.lines:
            if tag == " ":
                if i >= len(src) or src[i] != text:
                    raise BlueprintError(f"{patch.path}: context mismatch at line {i + 1}")
                out.append(text)
                i += 1
            elif tag == "-":
                if i >= len(src) or src[i] != text:
                    raise BlueprintError(f"{patch.path}: removal mismatch at line {i + 1}")
                i += 1
            else:  # '+'
                out.append(text)
        pos = i
    out.extend(src[pos:])
    result = "\n".join(out)
    if had_nl and result:
        result += "\n"
    return result


def _read_target(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    if p.stat().st_size > MAX_FILE_READ_BYTES:
        raise BlueprintError(f"{path} exceeds {MAX_FILE_READ_BYTES} bytes — refusing")
    raw = p.read_bytes()
    if b"\x00" in raw:
        raise BlueprintError(f"{path} looks binary — blueprints only edit text configs")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        # decoding with replacement would write U+FFFD over every non-UTF-8
        # byte in the file (a Latin-1 comment, say) on apply — refuse instead
        raise BlueprintError(
            f"{path} is not valid UTF-8 — refusing to rewrite it (bytes would be corrupted)"
        ) from None


@dataclass
class BlueprintPlan:
    intent: str
    diff_text: str
    patches: list[FilePatch] = field(default_factory=list)
    new_contents: dict = field(default_factory=dict)   # path -> post-apply text
    model: str = ""
    notes: str = ""
    created_iso: str = ""

    @property
    def files(self) -> list[str]:
        return [p.path for p in self.patches]

    def digest(self) -> str:
        return hashlib.sha256(self.diff_text.encode()).hexdigest()[:16]


def validate_plan(cfg, intent: str, diff_text: str, model: str = "") -> BlueprintPlan:
    """Parse + fully validate a diff against the live filesystem. Returns a
    ready-to-apply plan or raises BlueprintError."""
    patches = parse_unified_diff(diff_text)
    plan = BlueprintPlan(intent=intent, diff_text=diff_text, patches=patches,
                         model=model, created_iso=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    for p in patches:
        ok, reason = path_allowed(cfg, p.path)
        if not ok:
            raise BlueprintError(f"{p.path}: {reason}")
        current = _read_target(p.path)
        if not p.is_new and not Path(p.path).exists():
            # model said "modify" but the file isn't there; treat as new file
            # only when the old side is pure insertion, else it's drift.
            if any(t in (" ", "-") for h in p.hunks for t, _ in h.lines):
                raise BlueprintError(f"{p.path}: file does not exist on disk")
            p.is_new = True
        plan.new_contents[p.path] = apply_patch_text(current, p)
    return plan


# ---------------- checker dispatch (the daemon's own validator) ----------

@dataclass
class CheckerSpec:
    id: str
    patterns: tuple[str, ...]
    staged_argv: object = None   # callable(staged_path) -> argv — pre-apply check
    live_argv: tuple = ()        # post-apply whole-daemon check, e.g. nginx -t
    reload_units: tuple = ()     # candidate systemd units to reload after apply
    note: str = ""


def _sshd_staged(p: str) -> list[str]:
    return ["sshd", "-t", "-f", p]


def _visudo_staged(p: str) -> list[str]:
    return ["visudo", "-c", "-f", p]


def _logrotate_staged(p: str) -> list[str]:
    return ["logrotate", "-d", p]


def _sysctl_syntax(text: str) -> tuple[bool, str]:
    """Pure-python sysctl.conf syntax check (sysctl has no true dry-run)."""
    for n, ln in enumerate(text.splitlines(), 1):
        s = ln.strip()
        if not s or s.startswith(("#", ";")):
            continue
        if "=" not in s:
            return False, f"line {n}: expected key = value, got {s[:60]!r}"
        key = s.split("=", 1)[0].strip()
        if not re.fullmatch(r"[A-Za-z0-9._/\-]+", key):
            return False, f"line {n}: suspicious sysctl key {key!r}"
    return True, "sysctl syntax ok"


CHECKERS: list[CheckerSpec] = [
    CheckerSpec("sshd", ("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*"),
                staged_argv=_sshd_staged, live_argv=("sshd", "-t"),
                reload_units=("ssh", "sshd")),
    CheckerSpec("nginx", ("/etc/nginx/*",),
                live_argv=("nginx", "-t"), reload_units=("nginx",)),
    CheckerSpec("sudoers", ("/etc/sudoers.d/*",),
                staged_argv=_visudo_staged, live_argv=("visudo", "-c"),
                note="sudoers edits only via visudo-checked /etc/sudoers.d files"),
    CheckerSpec("named", ("/etc/bind/*", "/etc/named.conf", "/etc/named/*"),
                live_argv=("named-checkconf",), reload_units=("named", "bind9")),
    CheckerSpec("sysctl", ("/etc/sysctl.conf", "/etc/sysctl.d/*"),
                note="apply with `sysctl --system` manually after review"),
    CheckerSpec("logrotate", ("/etc/logrotate.conf", "/etc/logrotate.d/*"),
                staged_argv=_logrotate_staged),
    CheckerSpec("fail2ban", ("/etc/fail2ban/*",),
                live_argv=("fail2ban-client", "-t"), reload_units=("fail2ban",)),
    CheckerSpec("systemd", ("/etc/systemd/system/*",),
                note="run `systemctl daemon-reload` after review"),
]


def checker_for(path: str) -> CheckerSpec | None:
    for spec in CHECKERS:
        for pat in spec.patterns:
            if fnmatch.fnmatch(path, pat):
                return spec
    return None


def plan_checkers(plan: BlueprintPlan) -> dict:
    """path -> CheckerSpec|None for every file in the plan."""
    return {p.path: checker_for(p.path) for p in plan.patches}


# ---------------- consent gate (mirrors certs renew) ----------------

def consent_path(cfg) -> Path:
    from .config import CONFIG_DIR
    return CONFIG_DIR / CONSENT_FILENAME


def load_consent(cfg) -> dict | None:
    p = consent_path(cfg)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        if not (isinstance(data, dict) and data.get("granted")):
            return None
        import platform as _pfm
        host = data.get("host")
        if host and host != (_pfm.node() or "localhost"):
            return None      # consent recorded on a different machine
        return data
    except (ValueError, OSError):
        return None


def write_consent(cfg) -> Path:
    import platform as _pf
    p = consent_path(cfg)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({
        "granted": True,
        "granted_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": _pf.node() or "localhost",
        "statement": "I authorize wrench to apply reviewed blueprint diffs to "
                     "allowlisted config files, validate with the daemon's own "
                     "checker, reload via allowlisted systemctl verbs, and roll "
                     "back automatically from a timestamped backup on failure.",
    }, indent=2))
    return p


def revoke_consent(cfg) -> bool:
    p = consent_path(cfg)
    if p.exists():
        p.unlink()
        return True
    return False


def apply_permitted(cfg) -> tuple[bool, str]:
    """May a real (non-dry-run) apply proceed? (allowed, reason)."""
    tier = getattr(cfg, "policy_tier", "suggest")
    if tier in APPLY_ALLOWED_TIERS:
        return True, f"policy tier '{tier}' permits allowlisted mutations"
    if load_consent(cfg):
        return True, "blueprint consent on record"
    return False, (f"policy tier '{tier}' is suggest-only and no blueprint consent "
                   "is recorded — run `wrench blueprint consent` first")


# ---------------- ceremony: backup → apply → validate → reload → probe ----

@dataclass
class Step:
    name: str
    ok: bool
    detail: str


@dataclass
class ApplyOutcome:
    ok: bool
    rolled_back: bool
    message: str
    steps: list[Step] = field(default_factory=list)
    backup_dir: str = ""
    label: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "rolled_back": self.rolled_back, "message": self.message,
                "steps": [{"name": s.name, "ok": s.ok, "detail": s.detail} for s in self.steps],
                "backup_dir": self.backup_dir, "label": self.label}


def _write_file(path: str, content: str) -> None:
    """Atomic same-directory write that leaves the file's identity alone.

    Preserves mode AND owner/group (a `root:bind 0640` zone file that comes
    back `root:root` passes the syntax check and then the daemon can't read
    it). A symlinked target is written through to the file it points at, so
    `sites-enabled/x → sites-available/x` stays a link. New sudoers drop-ins
    are created 0440 — visudo rejects anything looser.
    """
    p = Path(os.path.realpath(path))
    p.parent.mkdir(parents=True, exist_ok=True)
    st = p.stat() if p.exists() else None
    if st is not None:
        mode = st.st_mode & 0o7777
    else:
        mode = 0o440 if str(p).startswith("/etc/sudoers.d/") else 0o644
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.bp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if st is not None and hasattr(os, "chown"):
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                pass    # not root: the file keeps the writer's ownership
        os.replace(tmp, str(p))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def make_backup(cfg, plan: BlueprintPlan, now: float | None = None) -> Path:
    """Copy every existing target into a timestamped backup dir + manifest."""
    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime(now or time.time()))
    bdir = Path(cfg.data_dir) / BACKUP_DIRNAME / f"{ts}-{plan.digest()}"
    bdir.mkdir(parents=True, exist_ok=True)
    manifest = {"created": ts, "intent": plan.intent, "files": {}}
    for p in plan.patches:
        src = Path(p.path)
        if src.exists():
            dst = bdir / backup_relpath(p.path)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))
            st = src.stat()
            manifest["files"][p.path] = {"backed_up": True, "new_file": False,
                                         "uid": st.st_uid, "gid": st.st_gid,
                                         "mode": st.st_mode & 0o7777}
        else:
            manifest["files"][p.path] = {"backed_up": False, "new_file": True}
    (bdir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (bdir / "blueprint.diff").write_text(plan.diff_text)
    return bdir


def rollback_from_backup(backup_dir: Path) -> list[str]:
    """Restore every backed-up file; delete files the blueprint created.
    Returns human-readable notes. Never raises."""
    notes: list[str] = []
    try:
        manifest = json.loads((backup_dir / "manifest.json").read_text())
    except (OSError, ValueError) as e:
        return [f"ROLLBACK FAILED: cannot read manifest: {e}"]
    for path, info in manifest.get("files", {}).items():
        try:
            if info.get("backed_up"):
                src = backup_dir / backup_relpath(path)
                # restore content through the same identity-preserving write,
                # then put the recorded mode/owner back explicitly
                _write_file(path, src.read_bytes().decode("utf-8"))
                real = os.path.realpath(path)
                if info.get("mode") is not None:
                    os.chmod(real, int(info["mode"]))
                if info.get("uid") is not None and hasattr(os, "chown"):
                    try:
                        os.chown(real, int(info["uid"]), int(info["gid"]))
                    except OSError:
                        pass
                notes.append(f"restored {path}")
            elif info.get("new_file") and Path(path).exists():
                Path(path).unlink()
                notes.append(f"removed created file {path}")
        except OSError as e:
            notes.append(f"ROLLBACK FAILED for {path}: {e}")
    return notes


def _reload_cmd_allowed(cfg, argv: list[str]) -> bool:
    """May this reload run?

    The command must be on the policy repair allowlist (shape + protected
    units). The *tier* requirement is satisfied either by repair/autonomous or
    by the recorded blueprint consent — the same two doors that permit the
    apply itself. (Before 3.0 consent permitted the write but not the reload,
    so every daemon blueprint at the default tier was applied and then rolled
    back.)
    """
    tier = getattr(cfg, "policy_tier", "suggest")
    if tier not in APPLY_ALLOWED_TIERS:
        try:
            consented = bool(load_consent(cfg))
        except Exception:  # noqa: BLE001
            consented = False
        if not consented:
            return False
        tier = "repair"
    return policy.check_repair(" ".join(argv), tier).allowed


def apply_plan(cfg, store, plan: BlueprintPlan, *, execute: bool = False,
               run=None, on_step=None) -> ApplyOutcome:
    """The ceremony. Pure of consent policy — the CLI gates it (mirrors certs).

    execute=False re-validates and reports what WOULD happen (dry-run).
    execute=True: backup → apply → staged+live validation → reload → probe,
    with automatic rollback from backup on any failure past the write."""
    run = run or _run
    res = ApplyOutcome(ok=False, rolled_back=False, message="",
                       label=f"blueprint:{plan.digest()}")

    def step(name: str, ok: bool, detail: str) -> None:
        res.steps.append(Step(name, ok, detail[:600]))
        if on_step:
            on_step(name, detail)

    # 1. re-validate against current disk (files may have drifted since draft)
    try:
        fresh = validate_plan(cfg, plan.intent, plan.diff_text, model=plan.model)
    except BlueprintError as e:
        step("revalidate", False, str(e))
        res.message = f"validation failed — nothing touched: {e}"
        return res
    step("revalidate", True, f"{len(fresh.patches)} file(s) apply cleanly")
    plan.new_contents = fresh.new_contents
    plan.patches = fresh.patches

    checkers = plan_checkers(plan)

    # 2. staged validation (daemon's own checker against a temp copy, pre-apply)
    with tempfile.TemporaryDirectory(prefix="wrench-bp-") as staging:
        for p in plan.patches:
            spec = checkers.get(p.path)
            new_text = plan.new_contents[p.path]
            if spec and spec.id == "sysctl":
                ok, note = _sysctl_syntax(new_text)
                step("check_staged", ok, f"{p.path}: {note}")
                if not ok:
                    res.message = f"staged syntax check failed — nothing touched: {note}"
                    return res
            elif spec and spec.staged_argv:
                staged = Path(staging) / Path(p.path).name
                staged.write_text(new_text)
                argv = spec.staged_argv(str(staged))
                code, out = run(argv, timeout=60)
                if code == 127:  # checker binary not installed — skip w/ warning
                    step("check_staged", True,
                         f"{p.path}: {argv[0]} not installed — staged validation "
                         "skipped (warning)")
                    continue
                ok = code == 0
                step("check_staged", ok, f"{' '.join(argv)} → exit {code} {out[:200]}")
                if not ok:
                    res.message = (f"{spec.id} rejected the staged config — nothing "
                                   f"touched: {out[:300]}")
                    return res
            elif spec is None:
                step("check_staged", True,
                     f"{p.path}: no checker available — syntax validation skipped (warning)")

    if not execute:
        res.ok = True
        res.message = ("dry-run complete — diff validated, staged checks passed. "
                       "Re-run with --execute (and consent) to apply.")
        return res

    # 3. timestamped backup
    try:
        bdir = make_backup(cfg, plan)
    except OSError as e:
        step("backup", False, str(e))
        res.message = f"backup failed — nothing touched: {e}"
        return res
    res.backup_dir = str(bdir)
    step("backup", True, str(bdir))

    def fail_and_rollback(msg: str) -> ApplyOutcome:
        notes = rollback_from_backup(bdir)
        res.rolled_back = all("ROLLBACK FAILED" not in n for n in notes)
        step("rollback", res.rolled_back, "; ".join(notes) or "nothing to restore")
        res.message = msg + (" — rolled back from backup" if res.rolled_back
                             else " — ROLLBACK INCOMPLETE, restore manually from " + str(bdir))
        _audit(cfg, store, plan, res)
        return res

    # Steps 4-7 mutate the box. Anything that escapes them — Ctrl-C during a
    # 60s `nginx -t`, SIGTERM, an unexpected exception — must still put the
    # old config back and leave an audit record before propagating.
    try:
        # 4. apply writes
        for p in plan.patches:
            try:
                _write_file(p.path, plan.new_contents[p.path])
                step("apply", True, p.path)
            except OSError as e:
                step("apply", False, f"{p.path}: {e}")
                return fail_and_rollback(f"write failed for {p.path}: {e}")

        # 5. post-apply live validation (the daemon checks its own full config)
        done_live: set[tuple] = set()
        for p in plan.patches:
            spec = checkers.get(p.path)
            if not spec or not spec.live_argv or spec.live_argv in done_live:
                continue
            done_live.add(spec.live_argv)
            code, out = run(list(spec.live_argv), timeout=60)
            if code == 127:  # checker binary not installed — skip w/ warning
                step("check_live", True,
                     f"{spec.live_argv[0]} not installed — live validation skipped (warning)")
                continue
            ok = code == 0
            step("check_live", ok, f"{' '.join(spec.live_argv)} → exit {code} {out[:200]}")
            if not ok:
                return fail_and_rollback(
                    f"{spec.id} rejected the applied config ({out[:200]})")

        # 6. service reload — allowlisted systemctl verbs only, active units only
        reloaded: list[str] = []
        done_units: set[str] = set()
        for p in plan.patches:
            spec = checkers.get(p.path)
            if not spec or not spec.reload_units:
                continue
            unit = None
            for cand in spec.reload_units:
                if cand in done_units:
                    unit = ""
                    break
                code, _ = run(["systemctl", "is-active", "--quiet", cand], timeout=15)
                if code == 0:
                    unit = cand
                    break
            if unit == "":
                continue
            if unit is None:
                step("reload", True, f"{spec.id}: no active unit among "
                                     f"{spec.reload_units} — reload skipped")
                continue
            done_units.add(unit)
            argv = ["systemctl", "reload", unit]
            if not _reload_cmd_allowed(cfg, argv):
                return fail_and_rollback(
                    f"reload command not permitted at tier "
                    f"'{getattr(cfg, 'policy_tier', 'suggest')}': {' '.join(argv)}")
            code, out = run(argv, timeout=60)
            step("reload", code == 0, f"{' '.join(argv)} → exit {code} {out[:200]}")
            if code != 0:
                out2 = fail_and_rollback(f"reload of {unit} failed ({out[:200]})")
                # after restoring old config, try to reload again so the daemon
                # returns to its previous (known-good) state
                rcode, rout = run(argv, timeout=60)
                step("reload_after_rollback", rcode == 0, f"exit {rcode} {rout[:150]}")
                return out2
            reloaded.append(unit)

        # 7. health probe
        for unit in reloaded:
            code, out = run(["systemctl", "is-active", unit], timeout=15)
            ok = code == 0
            step("probe", ok, f"{unit}: {'active' if ok else out[:120]}")
            if not ok:
                out2 = fail_and_rollback(f"{unit} unhealthy after reload ({out[:120]})")
                rcode, rout = run(["systemctl", "reload", unit], timeout=60)
                step("reload_after_rollback", rcode == 0, f"exit {rcode} {rout[:150]}")
                return out2

    except BaseException as e:  # noqa: BLE001 — includes KeyboardInterrupt/SystemExit
        fail_and_rollback(f"interrupted during apply ({e.__class__.__name__})")
        raise

    res.ok = True
    res.message = ("applied " + ", ".join(plan.files)
                   + (f"; reloaded {', '.join(reloaded)}" if reloaded else "")
                   + f"; backup at {bdir}")
    _audit(cfg, store, plan, res)
    _drift_snapshot(cfg, store, plan, res)
    return res


# ---------------- audit + drift integration + history ----------------

def audit_path(cfg) -> Path:
    return Path(cfg.data_dir) / AUDIT_FILENAME


def _audit(cfg, store, plan: BlueprintPlan, res: ApplyOutcome) -> None:
    entry = {
        "ts": time.time(), "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "intent": plan.intent, "files": plan.files, "digest": plan.digest(),
        "model": plan.model, "ok": res.ok, "rolled_back": res.rolled_back,
        "message": res.message, "backup_dir": res.backup_dir,
        "steps": [{"name": s.name, "ok": s.ok, "detail": s.detail[:200]}
                  for s in res.steps],
    }
    try:
        p = audit_path(cfg)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # auditing must never block
    if store is not None:
        try:
            store.add_action(getattr(cfg, "policy_tier", "suggest"),
                             f"blueprint:{'apply' if res.ok else 'fail'}",
                             f"{plan.intent} → {', '.join(plan.files)}",
                             res.ok, res.message[:500])
        except Exception:  # noqa: BLE001
            pass
    # fan out to configured notification sinks (desktop/webhook/syslog/SIEM)
    try:
        from . import notifications
        if res.ok:
            kind, sev = "blueprint.apply", "attention"
        elif res.rolled_back:
            kind, sev = "blueprint.rollback", "error"
        else:
            kind, sev = "blueprint.failed", "critical"
        notifications.emit_event(
            cfg, kind, sev,
            f"blueprint {plan.intent[:140]} → {', '.join(plan.files)}: {res.message[:200]}")
    except Exception:  # noqa: BLE001 — notification must never block the ceremony
        pass


def _drift_snapshot(cfg, store, plan: BlueprintPlan, res: ApplyOutcome) -> None:
    """Every applied blueprint becomes a labeled drift snapshot (audit trail)."""
    if store is None:
        return
    try:
        store.add_snapshot("blueprint", {
            "label": res.label, "intent": plan.intent, "files": plan.files,
            "digest": plan.digest(), "ok": res.ok, "rolled_back": res.rolled_back,
            "backup_dir": res.backup_dir,
        })
        store.add_diff("blueprint",
                       f"blueprint applied: {plan.intent[:120]} "
                       f"({', '.join(plan.files)})",
                       {"digest": plan.digest(), "label": res.label})
        from . import driftscan
        driftscan.scan(store)  # refresh baselines so the change is "known"
    except Exception:  # noqa: BLE001 — drift bookkeeping never blocks
        pass


def history(cfg, n: int = 20) -> list[dict]:
    """Past blueprint applications with outcomes, newest last."""
    p = audit_path(cfg)
    if not p.exists():
        return []
    rows: list[dict] = []
    for ln in p.read_text().strip().splitlines()[-n:]:
        try:
            rows.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return rows


# ---------------- drafting (the brain writes the diff, never commands) ----

TARGETS_PROMPT = """\
You are wrench's config-blueprint planner on a {os_info} machine.
A human wants this configuration change:

  {intent}

Name the config FILE(S) that should be edited or created to achieve it.
Rules:
- absolute paths only, at most {max_files} files, prefer drop-in dirs
  (/etc/ssh/sshd_config.d/, /etc/sysctl.d/, /etc/logrotate.d/,
  /etc/sudoers.d/, /etc/nginx/sites-available/, /etc/fail2ban/jail.d/)
  over editing a daemon's main config file
- NEVER /etc/passwd, /etc/shadow, /etc/sudoers directly
- existing files listed below may be edited; anything else will be created new

Existing candidate files on this machine:
{listing}

Reply with EXACTLY one JSON object, nothing else:
  {{"targets": ["/abs/path", ...], "reason": "<one line>"}}
"""

DIFF_PROMPT = """\
You are wrench's config-blueprint author on a {os_info} machine.
Produce a configuration change as a UNIFIED DIFF. You never run commands —
your entire job is the diff text; code will validate and apply it under a
consent ceremony with automatic rollback.

Intent:
  {intent}

Current content of each target file is below between markers. A file shown as
(NEW FILE — does not exist) must be created with a /dev/null old side.

{files_block}

STRICT output rules:
- Output ONLY a unified diff (optionally inside one ``` fence). No prose.
- Use headers exactly like:  --- a{example}   and   +++ b{example}
  (or --- /dev/null for a new file).
- Hunk headers `@@ -l,c +l,c @@` must match their body line counts.
- Context lines must be copied VERBATIM from the current content shown.
- Keep the change minimal and idiomatic for the daemon. Include comments in
  the config explaining non-obvious choices.
- Never touch files other than the targets listed.
{retry_note}"""


def _default_target_listing(cfg) -> str:
    """A short listing of plausible existing config files to ground phase 1."""
    roots = allowed_roots(cfg)
    hints = ("ssh/sshd_config", "ssh/sshd_config.d", "nginx/nginx.conf",
             "nginx/sites-available", "sysctl.conf", "sysctl.d", "logrotate.conf",
             "logrotate.d", "fail2ban/jail.conf", "fail2ban/jail.d",
             "sudoers.d", "systemd/system")
    lines: list[str] = []
    for root in roots:
        for h in hints:
            p = Path(root) / h
            if p.is_file():
                lines.append(str(p))
            elif p.is_dir():
                try:
                    kids = sorted(x.name for x in p.iterdir() if x.is_file())[:12]
                except OSError:
                    kids = []
                lines.append(f"{p}/ (dir: {', '.join(kids) if kids else 'empty'})")
    return "\n".join(f"- {ln}" for ln in lines) or "(none found)"


def _extract_diff(text: str) -> str:
    """Pull the unified diff out of model output (tolerates one code fence)."""
    t = text.strip()
    if "```" in t:
        # take the largest fenced block that contains a '--- ' header
        blocks = re.findall(r"```(?:diff|patch)?\n(.*?)```", t, flags=re.S)
        candidates = [b for b in blocks if "--- " in b and "+++ " in b]
        if candidates:
            t = max(candidates, key=len).strip()
    # drop any prose before the first file header
    idx = t.find("--- ")
    if idx > 0:
        t = t[idx:]
    if not t.startswith("--- "):
        raise BlueprintError("model did not produce a unified diff")
    return t.rstrip() + "\n"


def _os_info() -> str:
    import platform as _pf
    return f"{_pf.system()} {_pf.release()} ({_pf.node() or 'localhost'})"


def propose_targets(cfg, store, intent: str, client=None, on_step=None) -> list[str]:
    """Phase 1: the model names target files; code validates every one."""
    from .providers import LLMClient, extract_json
    client = client or LLMClient(cfg, store)
    if on_step:
        on_step("draft", "asking the brain which files to touch")
    raw = client.chat(
        [{"role": "user", "content": TARGETS_PROMPT.format(
            os_info=_os_info(), intent=intent, max_files=MAX_TARGET_FILES,
            listing=_default_target_listing(cfg))}],
        purpose="blueprint-targets", temperature=0.2)
    obj = extract_json(raw)
    if not obj or not isinstance(obj.get("targets"), list) or not obj["targets"]:
        raise BlueprintError(f"planner returned no usable targets: {raw[:200]}")
    targets = [str(t) for t in obj["targets"]][:MAX_TARGET_FILES]
    for t in targets:
        ok, reason = path_allowed(cfg, t)
        if not ok:
            raise BlueprintError(f"proposed target {t}: {reason}")
    return targets


def _files_block(targets: list[str]) -> str:
    parts: list[str] = []
    for t in targets:
        content = _read_target(t)
        if content == "" and not Path(t).exists():
            parts.append(f"===== {t} (NEW FILE — does not exist) =====\n(empty)\n")
        else:
            parts.append(f"===== {t} (current content) =====\n{content}\n"
                         f"===== end {t} =====\n")
    return "\n".join(parts)


def draft(cfg, store, intent: str, targets: list[str] | None = None,
          client=None, on_step=None, retries: int = 1) -> BlueprintPlan:
    """Full draft: (optionally) pick targets, then produce a validated plan.

    The model outputs TEXT ONLY; validate_plan() proves the diff parses, stays
    on allowlisted paths, and applies cleanly against the live files before a
    plan is ever returned."""
    from .providers import LLMClient
    client = client or LLMClient(cfg, store)
    if not targets:
        targets = propose_targets(cfg, store, intent, client=client, on_step=on_step)
    else:
        for t in targets:
            ok, reason = path_allowed(cfg, t)
            if not ok:
                raise BlueprintError(f"target {t}: {reason}")
    if on_step:
        on_step("draft", f"drafting diff for {', '.join(targets)}")
    example = targets[0]
    retry_note = ""
    last_err: BlueprintError | None = None
    for attempt in range(retries + 1):
        raw = client.chat(
            [{"role": "user", "content": DIFF_PROMPT.format(
                os_info=_os_info(), intent=intent,
                files_block=_files_block(targets), example=example,
                retry_note=retry_note)}],
            purpose="blueprint-draft", temperature=0.2)
        try:
            diff_text = _extract_diff(raw)
            plan = validate_plan(cfg, intent, diff_text,
                                 model=getattr(cfg, "model", ""))
        except BlueprintError as e:
            last_err = e
            retry_note = (f"\nYOUR PREVIOUS ATTEMPT FAILED VALIDATION: {e}\n"
                          "Fix that exact problem and output the corrected diff only.")
            if on_step:
                on_step("draft", f"attempt {attempt + 1} rejected: {e}")
            continue
        extra = [p.path for p in plan.patches if p.path not in targets]
        if extra:
            last_err = BlueprintError(f"diff touches non-target files: {extra}")
            retry_note = (f"\nYOUR PREVIOUS ATTEMPT touched files outside the "
                          f"target list: {extra}. Only edit {targets}.")
            continue
        return plan
    raise BlueprintError(f"could not draft a valid diff: {last_err}")
