"""Named, read-only OS posture probes for the compliance engine.

Compliance packs are data, not code — a pack can never carry a command. So the
macOS and Windows checks that have no file to read (is the disk encrypted? is
the firewall on?) live here as a **closed registry**: each probe is a fixed
argv (or registry / plist read) plus a parser, written by hand and reviewed
like any other code. A pack rule only *names* a probe:

    {"kind": "probe", "name": "macos.filevault", "expect": "on"}

Every probe returns ``(value, detail)``. ``value`` is a short normalized string
("on", "off", "300", …) or ``None`` when the answer could not be determined
(wrong OS, tool missing, needs elevation) — which the engine reports as a
counted *skip*, never a pass and never a fail.

Nothing here mutates anything, and nothing here takes input from a pack beyond
the probe's name.
"""

from __future__ import annotations

import plistlib
import re
import shutil
import subprocess
from pathlib import Path

from . import platforms

Probe = tuple[str | None, str]
_TIMEOUT = 12


def _run(argv: list[str], timeout: int = _TIMEOUT) -> tuple[int, str]:
    """(exit code, combined output). exit 127 when the binary is missing."""
    exe = argv[0] if "/" in argv[0] or "\\" in argv[0] else shutil.which(argv[0])
    if not exe or not Path(exe).exists():
        return 127, f"{argv[0]} not available"
    try:
        r = subprocess.run([exe, *argv[1:]], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout,
                           stdin=subprocess.DEVNULL)
        return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return 124, f"{argv[0]} timed out"
    except OSError as e:
        return 126, f"{argv[0]}: {e.__class__.__name__}"


def _first_line(text: str) -> str:
    return (text.splitlines() or [""])[0].strip()[:160]


# ---------------- macOS ----------------

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def _mac_filevault() -> Probe:
    code, out = _run(["fdesetup", "status"])
    if code != 0:
        return None, out or "fdesetup failed"
    return ("on" if "FileVault is On" in out else "off"), _first_line(out)


def _mac_gatekeeper() -> Probe:
    code, out = _run(["spctl", "--status"])
    if "assessments enabled" in out:
        return "on", "Gatekeeper assessments enabled"
    if "assessments disabled" in out:
        return "off", "Gatekeeper assessments disabled"
    return None, out or f"spctl exit {code}"


def _mac_sip() -> Probe:
    code, out = _run(["csrutil", "status"])
    low = out.lower()
    if "status: enabled" in low:
        return "on", _first_line(out)
    if "status: disabled" in low:
        return "off", _first_line(out)
    return None, out or f"csrutil exit {code}"


def _mac_firewall() -> Probe:
    code, out = _run([_SOCKETFILTERFW, "--getglobalstate"])
    if code != 0:
        return None, out
    m = re.search(r"State = (\d)", out)
    if not m:
        return None, _first_line(out)
    return ("off" if m.group(1) == "0" else "on"), _first_line(out)


def _mac_firewall_stealth() -> Probe:
    code, out = _run([_SOCKETFILTERFW, "--getstealthmode"])
    if code != 0:
        return None, out
    low = out.lower()
    if "is on" in low or "enabled" in low:
        return "on", _first_line(out)
    if "is off" in low or "disabled" in low:
        return "off", _first_line(out)
    return None, _first_line(out)


def _read_plist(path: str) -> dict | None:
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None


def _mac_pref(path: str, key: str, default: str | None) -> Probe:
    """A boolean-ish system preference. ``default`` is what macOS does when the
    key is absent (None = can't know → skip)."""
    data = _read_plist(path)
    if data is None:
        if not Path(path).exists():
            return (default, f"{Path(path).name} not present — macOS default applies") \
                if default else (None, f"{path} not present")
        return None, f"{path} unreadable"
    if key not in data:
        if default is None:
            return None, f"{key} not set"
        return default, f"{key} not set — macOS default ({default})"
    val = data[key]
    if isinstance(val, bool) or val in (0, 1):
        return ("on" if val else "off"), f"{key} = {int(bool(val))}"
    return str(val), f"{key} = {val}"


_SU_PLIST = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
_LOGIN_PLIST = "/Library/Preferences/com.apple.loginwindow.plist"


def _mac_auto_update_check() -> Probe:
    return _mac_pref(_SU_PLIST, "AutomaticCheckEnabled", "on")


def _mac_auto_update_download() -> Probe:
    return _mac_pref(_SU_PLIST, "AutomaticDownload", "on")


def _mac_auto_security_updates() -> Probe:
    # "Install Security Responses and system files" — on unless switched off
    return _mac_pref(_SU_PLIST, "CriticalUpdateInstall", "on")


def _mac_guest_account() -> Probe:
    return _mac_pref(_LOGIN_PLIST, "GuestEnabled", "off")


def _mac_auto_login() -> Probe:
    data = _read_plist(_LOGIN_PLIST)
    if data is None and Path(_LOGIN_PLIST).exists():
        return None, f"{_LOGIN_PLIST} unreadable"
    user = (data or {}).get("autoLoginUser")
    if user:
        return "on", "automatic login is enabled for a user"
    return "off", "automatic login is disabled"


def _mac_screen_lock() -> Probe:
    """Seconds between screensaver/sleep and the password prompt."""
    code, out = _run(["sysadminctl", "-screenLock", "status"])
    low = out.lower()
    if "immediate" in low:
        return "0", "screen locks immediately"
    m = re.search(r"delay is (\d+) seconds", low)
    if m:
        return m.group(1), f"screen locks after {m.group(1)}s"
    if "off" in low or "disabled" in low:
        return "off", "screen lock is off"
    return None, _first_line(out) or f"sysadminctl exit {code}"


# ---------------- Windows ----------------

def _reg_value(hive_name: str, key: str, value: str):
    """Read one registry value. Returns the value, or None when absent."""
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return None
    hive = getattr(winreg, hive_name)
    try:
        with winreg.OpenKey(hive, key) as k:
            return winreg.QueryValueEx(k, value)[0]
    except OSError:
        return None


def _powershell(expr: str) -> tuple[int, str]:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return 127, "powershell not available"
    return _run([exe, "-NoProfile", "-NonInteractive", "-Command", expr], timeout=25)


def _ps_bool(expr: str, what: str) -> Probe:
    code, out = _powershell(expr)
    val = out.strip().splitlines()[-1].strip().lower() if out.strip() else ""
    if code == 0 and val in ("true", "false"):
        return ("on" if val == "true" else "off"), f"{what}: {val}"
    return None, (_first_line(out) or f"{what}: unavailable (may need elevation)")


def _win_defender_realtime() -> Probe:
    return _ps_bool("(Get-MpComputerStatus).RealTimeProtectionEnabled",
                    "Defender real-time protection")


def _win_firewall() -> Probe:
    code, out = _powershell(
        "Get-NetFirewallProfile | ForEach-Object { $_.Name + '=' + $_.Enabled }")
    pairs = dict(ln.strip().split("=", 1) for ln in out.splitlines() if "=" in ln)
    if code != 0 or not pairs:
        return None, _first_line(out) or "firewall profiles unavailable"
    off = sorted(n for n, v in pairs.items() if v.strip().lower() != "true")
    if off:
        return "off", "firewall disabled for profile(s): " + ", ".join(off)
    return "on", "firewall enabled for " + ", ".join(sorted(pairs))


def _win_uac() -> Probe:
    v = _reg_value("HKEY_LOCAL_MACHINE",
                   r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    if v is None:
        return None, "EnableLUA not readable"
    return ("on" if int(v) == 1 else "off"), f"EnableLUA = {v}"


def _win_smb1() -> Probe:
    return _ps_bool("(Get-SmbServerConfiguration).EnableSMB1Protocol", "SMBv1 server")


def _win_rdp_nla() -> Probe:
    deny = _reg_value("HKEY_LOCAL_MACHINE",
                      r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    if deny is None:
        return None, "Remote Desktop state not readable"
    if int(deny) == 1:
        return "on", "Remote Desktop is disabled (nothing to protect)"
    nla = _reg_value(
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
        "UserAuthentication")
    if nla is None:
        return None, "RDP NLA setting not readable"
    return ("on" if int(nla) == 1 else "off"), \
        f"Remote Desktop enabled, Network Level Authentication = {nla}"


def _win_guest_account() -> Probe:
    return _ps_bool("(Get-LocalUser -Name Guest).Enabled", "Guest account enabled")


def _win_auto_update() -> Probe:
    v = _reg_value("HKEY_LOCAL_MACHINE",
                   r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate")
    if v is not None and int(v) == 1:
        return "off", "automatic updates disabled by policy (NoAutoUpdate = 1)"
    return "on", "automatic updates not disabled by policy"


def _win_bitlocker() -> Probe:
    code, out = _powershell(
        "(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus")
    val = out.strip().splitlines()[-1].strip().lower() if out.strip() else ""
    if code == 0 and val in ("on", "1"):
        return "on", "BitLocker protection is on for the system drive"
    if code == 0 and val in ("off", "0"):
        return "off", "BitLocker protection is off for the system drive"
    return None, "BitLocker status needs an elevated session"


def _win_lsa_protection() -> Probe:
    v = _reg_value("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
    if v is None:
        return "off", "RunAsPPL not set"
    return ("on" if int(v) in (1, 2) else "off"), f"RunAsPPL = {v}"


# ---------------- registry ----------------

# name → (platform, function, one-line description)
PROBES: dict[str, tuple[str, object, str]] = {
    "macos.filevault": ("macos", _mac_filevault, "FileVault full-disk encryption"),
    "macos.gatekeeper": ("macos", _mac_gatekeeper, "Gatekeeper app assessment"),
    "macos.sip": ("macos", _mac_sip, "System Integrity Protection"),
    "macos.firewall": ("macos", _mac_firewall, "application firewall"),
    "macos.firewall_stealth": ("macos", _mac_firewall_stealth, "firewall stealth mode"),
    "macos.auto_update_check": ("macos", _mac_auto_update_check, "automatic update checks"),
    "macos.auto_update_download": ("macos", _mac_auto_update_download,
                                   "automatic update downloads"),
    "macos.auto_security_updates": ("macos", _mac_auto_security_updates,
                                    "automatic security responses"),
    "macos.guest_account": ("macos", _mac_guest_account, "guest account"),
    "macos.auto_login": ("macos", _mac_auto_login, "automatic login"),
    "macos.screen_lock_delay": ("macos", _mac_screen_lock, "screen lock delay (seconds)"),
    "windows.defender_realtime": ("windows", _win_defender_realtime,
                                  "Defender real-time protection"),
    "windows.firewall": ("windows", _win_firewall, "Windows Firewall, all profiles"),
    "windows.uac": ("windows", _win_uac, "User Account Control"),
    "windows.smb1": ("windows", _win_smb1, "SMBv1 server protocol"),
    "windows.rdp_nla": ("windows", _win_rdp_nla, "RDP Network Level Authentication"),
    "windows.guest_account": ("windows", _win_guest_account, "Guest account"),
    "windows.auto_update": ("windows", _win_auto_update, "automatic updates"),
    "windows.bitlocker": ("windows", _win_bitlocker, "BitLocker on the system drive"),
    "windows.lsa_protection": ("windows", _win_lsa_protection, "LSA protection (RunAsPPL)"),
}


def run(name: str) -> Probe:
    """Run one named probe. Unknown name / wrong OS → (None, reason). Never raises."""
    entry = PROBES.get(name)
    if entry is None:
        return None, f"unknown probe {name!r}"
    plat, fn, _desc = entry
    if plat != platforms.current_platform():
        return None, f"{plat}-only check"
    try:
        return fn()  # type: ignore[operator]
    except Exception as e:  # noqa: BLE001 — a broken probe is a skip
        return None, f"probe error: {e.__class__.__name__}: {e}"
