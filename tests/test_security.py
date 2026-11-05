"""wrench security — watch the doors.

Pure-function coverage against synthetic fixtures (no host state touched):
auth-log parsing + burst/compromise/delta analysis, privilege/access drift,
listener ownership baselines, the OSV CVE client (mocked + offline fail-soft),
the severity ladder, scan orchestration + consent-gated baselines, the
``wrench.security.v1`` JSON schema, Prometheus security gauges, and the
consent gate on ``security accept``.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

import pytest

from wrench import security as sec
from wrench.security import Finding, SecuritySettings
from wrench.store import Store


@dataclass
class FakeCfg:
    raw: dict = field(default_factory=dict)
    data_dir: object = None
    db_path: str = ""
    api_key: str = ""
    provider: str = "meta"
    model: str = "test-model"


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "wrench.db")
    yield s
    s.close()


# a fixed "now" so synthetic syslog timestamps land inside the lookback window
NOW = time.mktime(time.strptime("2026-11-05 12:30:00", "%Y-%m-%d %H:%M:%S"))


def _syslog(ts_str: str, body: str) -> str:
    # ts_str like "Nov  5 12:01:02"
    return f"{ts_str} host {body}"


# =====================================================================
# group 1 — auth log parsing + analysis
# =====================================================================

def test_parse_ts_syslog_and_iso():
    assert sec._parse_ts("Nov  5 12:01:02 host sshd[1]: hi", NOW) is not None
    iso = sec._parse_ts("2026-11-05T12:01:02-08:00 host sshd[1]: hi", NOW)
    assert iso is not None
    assert sec._parse_ts("not a timestamped line", NOW) is None


def test_parse_auth_events_classifies_all_kinds():
    lines = [
        _syslog("Nov  5 12:00:01", "sshd[11]: Failed password for root from 10.9.9.9 port 1 ssh2"),
        _syslog("Nov  5 12:00:02", "sshd[11]: Failed password for invalid user bob from 10.9.9.9 port 1 ssh2"),
        _syslog("Nov  5 12:00:03", "sshd[12]: Accepted publickey for alice from 203.0.113.5 port 2 ssh2"),
        _syslog("Nov  5 12:00:04", "sudo[13]:  carol : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"),
        _syslog("Nov  5 12:00:05", "sudo[14]:  dave : 3 incorrect password attempts"),
    ]
    ev = sec.parse_auth_events(lines, NOW)
    kinds = [e["kind"] for e in ev]
    assert kinds == ["failed_login", "failed_login", "accepted_login",
                     "sudo_command", "sudo_fail"]
    assert ev[1]["detail"] == "invalid user"
    assert ev[2]["user"] == "alice" and ev[2]["ip"] == "203.0.113.5"
    assert ev[3]["user"] == "carol" and ev[3]["detail"].endswith("/bin/ls")
    assert ev[4]["user"] == "dave"


def test_analyze_auth_brute_force_burst():
    # 9 failures from one IP inside the window → warning burst
    lines = [_syslog(f"Nov  5 12:0{i//10}{i%10}:00",
                     f"sshd[1]: Failed password for root from 10.0.0.66 port 1 ssh2")
             for i in range(9)]
    ev = sec.parse_auth_events(lines, NOW)
    findings, observed = sec.analyze_auth(ev, None, SecuritySettings(), NOW)
    bursts = [f for f in findings if f.title.startswith("brute-force burst")]
    assert len(bursts) == 1
    assert bursts[0].severity == "warning"
    assert bursts[0].meta["ip"] == "10.0.0.66"
    assert bursts[0].meta["count"] >= 8


def test_analyze_auth_below_threshold_is_quiet():
    lines = [_syslog("Nov  5 12:00:0%d" % i,
                     "sshd[1]: Failed password for root from 10.0.0.66 port 1 ssh2")
             for i in range(4)]
    ev = sec.parse_auth_events(lines, NOW)
    findings, _ = sec.analyze_auth(ev, None, SecuritySettings(), NOW)
    assert not [f for f in findings if "brute-force" in f.title]


def test_analyze_auth_success_after_burst_is_critical():
    lines = [_syslog("Nov  5 12:00:%02d" % i,
                     "sshd[1]: Failed password for root from 10.0.0.70 port 1 ssh2")
             for i in range(9)]
    lines.append(_syslog("Nov  5 12:00:30",
                         "sshd[2]: Accepted password for root from 10.0.0.70 port 2 ssh2"))
    ev = sec.parse_auth_events(lines, NOW)
    findings, _ = sec.analyze_auth(ev, None, SecuritySettings(), NOW)
    crit = [f for f in findings if f.severity == "critical"]
    assert crit and "after brute-force burst" in crit[0].title
    assert crit[0].meta["user"] == "root"


def test_analyze_auth_new_ip_and_new_sudo_against_baseline():
    lines = [
        _syslog("Nov  5 12:00:03", "sshd[1]: Accepted publickey for alice from 203.0.113.9 port 2 ssh2"),
        _syslog("Nov  5 12:00:04", "sudo[2]:  newguy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/id"),
    ]
    ev = sec.parse_auth_events(lines, NOW)
    baseline = {"known_ips": ["198.51.100.1"], "sudo_users": ["alice"]}
    findings, observed = sec.analyze_auth(ev, baseline, SecuritySettings(), NOW)
    assert any(f.title == "login from new source IP 203.0.113.9" for f in findings)
    assert any(f.title == "new sudo user: newguy" and f.severity == "warning"
               for f in findings)
    # observed merges baseline + newly seen
    assert "203.0.113.9" in observed["known_ips"]
    assert "newguy" in observed["sudo_users"]


def test_analyze_auth_first_run_no_baseline_is_info_only():
    lines = [_syslog("Nov  5 12:00:03",
                     "sshd[1]: Accepted publickey for alice from 203.0.113.9 port 2 ssh2")]
    ev = sec.parse_auth_events(lines, NOW)
    findings, observed = sec.analyze_auth(ev, None, SecuritySettings(), NOW)
    # no baseline → new-IP deltas don't fire
    assert not [f for f in findings if "new source IP" in f.title]
    assert "203.0.113.9" in observed["known_ips"]


def test_analyze_auth_repeated_sudo_failures():
    lines = [_syslog("Nov  5 12:00:0%d" % i,
                     "sudo[1]:  mallory : %d incorrect password attempts" % (i + 1))
             for i in range(3)]
    ev = sec.parse_auth_events(lines, NOW)
    findings, _ = sec.analyze_auth(ev, None, SecuritySettings(), NOW)
    assert any(f.title == "repeated sudo failures" and f.severity == "warning"
               for f in findings)


def test_analyze_auth_local_ip_never_flagged_as_new():
    lines = [_syslog("Nov  5 12:00:03",
                     "sshd[1]: Accepted password for alice from 127.0.0.1 port 2 ssh2")]
    ev = sec.parse_auth_events(lines, NOW)
    findings, observed = sec.analyze_auth(ev, {"known_ips": []}, SecuritySettings(), NOW)
    assert not [f for f in findings if "new source IP" in f.title]
