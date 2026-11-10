"""Listening-socket census for the platforms without `ss`.

Linux keeps using `ss -tulnpH` (it attributes sockets to processes without
root). Everywhere else this module answers "what is listening, and who owns
it?" — and it must not answer "nothing" just because it lacked the privilege
to look: on macOS ``psutil.net_connections()`` raises AccessDenied for a normal
user, which the old code swallowed into an empty inventory (zero listeners,
zero drift, a clean-looking security scan). The fallback is ``lsof -i``, which
without root sees this user's sockets — a partial but *stable* view (the same
answer from a login shell and from launchd, so drift does not flap). ``netstat
-anv`` is the last resort; macOS returns it empty to processes without the
Local Network privacy grant, so an empty reply is treated as "unavailable".

``listeners()`` returns ``(rows, complete)``; ``complete`` is False when the
census could not be taken at all, so callers can say so instead of reporting
an empty box.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from . import platforms

# IANA dynamic range. An unconnected UDP socket up here is a client's source
# port (DNS lookups, QUIC, mDNS replies), not a service — counting those made
# every scan report "port opened / port closed".
EPHEMERAL_MIN = 49152
_LINUX_EPHEMERAL_FILE = "/proc/sys/net/ipv4/ip_local_port_range"

# "… rhiwat shiwat  process name:pid  state …" — the leading greedy .* pushes
# the two-number anchor as far right as it will go, so a process name with
# spaces ("Google Chrome He:1817") is captured whole and nothing before it is.
_NETSTAT_TAIL = re.compile(
    r"^.*\s\d+\s+\d+\s+(?P<proc>\S.*?):(?P<pid>\d+)\s+[0-9a-f]{4,6}(?:\s|$)")


def ephemeral_floor() -> int:
    """Lowest port the OS hands out as a client source port."""
    if platforms.is_linux():
        try:
            with open(_LINUX_EPHEMERAL_FILE) as fh:
                return int(fh.read().split()[0])
        except (OSError, ValueError, IndexError):
            return 32768
    return EPHEMERAL_MIN


def is_ephemeral_udp(proto: str, port: int, floor: int | None = None) -> bool:
    return proto.startswith("udp") and port >= (floor if floor is not None else ephemeral_floor())


def parse_netstat_anv(text: str) -> list[dict]:
    """Parse BSD/macOS `netstat -anv` into listener rows (pure)."""
    rows: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[0].startswith(("tcp", "udp")):
            continue
        proto = "tcp" if parts[0].startswith("tcp") else "udp"
        local, foreign = parts[3], parts[4]
        if proto == "tcp" and "LISTEN" not in parts:
            continue
        if proto == "udp" and foreign != "*.*":
            continue
        addr, _, port = local.rpartition(".")
        if not port.isdigit():
            continue
        m = _NETSTAT_TAIL.search(line)
        rows.append({"proto": proto, "addr": addr or "*", "port": int(port),
                     "pid": int(m.group("pid")) if m else 0,
                     "process": m.group("proc").strip() if m else ""})
    return rows


def _netstat_rows() -> list[dict] | None:
    exe = shutil.which("netstat")
    if not exe:
        return None
    rows: list[dict] = []
    for proto in ("tcp", "udp"):
        try:
            r = subprocess.run([exe, "-anv", "-p", proto], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if r.returncode != 0 or not r.stdout.strip():
            return None      # empty = denied by macOS Local Network privacy
        rows.extend(parse_netstat_anv(r.stdout))
    return rows


def parse_lsof_fields(text: str) -> list[dict]:
    """Parse `lsof -nP -i -F pcPnT` field output into listener rows (pure)."""
    rows: list[dict] = []
    pid, proc = 0, ""
    cur: dict | None = None

    def flush():
        if not cur or "name" not in cur:
            return
        name, proto = cur["name"], cur.get("proto", "")
        listening = (proto == "tcp" and cur.get("state") == "LISTEN") or \
                    (proto == "udp" and "->" not in name)
        addr, _, port = name.rpartition(":")
        if listening and port.isdigit():
            rows.append({"proto": proto, "addr": addr.strip("[]") or "*",
                         "port": int(port), "pid": pid, "process": proc})

    for line in text.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            flush()
            cur = None
            pid = int(val) if val.isdigit() else 0
        elif tag == "c":
            proc = val
        elif tag == "f":
            flush()
            cur = {}
        elif cur is not None:
            if tag == "P":
                cur["proto"] = val.lower()
            elif tag == "n":
                cur["name"] = val
            elif tag == "T" and val.startswith("ST="):
                cur["state"] = val[3:]
    flush()
    return rows


def _lsof_rows() -> list[dict] | None:
    exe = platforms.find_tool("lsof")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-nP", "-i", "-F", "pcPnT"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    # lsof exits 1 when some files could not be examined; output is still valid
    return parse_lsof_fields(r.stdout) if r.stdout.strip() else None


def _psutil_rows() -> list[dict]:
    import psutil
    rows = []
    for c in psutil.net_connections(kind="inet"):   # may raise AccessDenied
        is_listener = (str(c.status) == "LISTEN") or (c.type == 2 and not c.raddr)
        if not is_listener or not c.laddr:
            continue
        name = ""
        if c.pid:
            try:
                name = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = ""
        rows.append({"proto": "tcp" if c.type == 1 else "udp", "addr": c.laddr.ip,
                     "port": c.laddr.port, "pid": c.pid or 0, "process": name})
    return rows


def listeners(include_ephemeral_udp: bool = False) -> tuple[list[dict], bool]:
    """Listening sockets → ([{proto, addr, port, pid, process}], complete)."""
    rows: list[dict] | None
    try:
        rows = _psutil_rows()
    except Exception:  # noqa: BLE001 — AccessDenied on macOS, odd platforms
        rows = None
        if not platforms.is_windows():
            rows = _lsof_rows()
            if rows is None:
                rows = _netstat_rows()
    if rows is None:
        return [], False
    floor = ephemeral_floor()
    seen: set[tuple] = set()
    out = []
    for r in rows:
        if not include_ephemeral_udp and is_ephemeral_udp(r["proto"], r["port"], floor):
            continue
        key = (r["proto"], r["addr"], r["port"], r["pid"])
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    out.sort(key=lambda r: (r["proto"], r["port"], r["addr"]))
    return out, True
