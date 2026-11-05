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


# =====================================================================
# group 2 — access drift: sudoers / authorized_keys / uid0 / shadow / ww
# =====================================================================

def test_sudoers_state_hashes_and_normalizes(tmp_path):
    main = tmp_path / "sudoers"
    main.write_text("# comment\n\nroot ALL=(ALL) ALL\n")
    dropin = tmp_path / "sudoers.d"
    dropin.mkdir()
    (dropin / "90-cloud").write_text("ubuntu ALL=(ALL) NOPASSWD:ALL\n")
    (dropin / "README~").write_text("ignore me\n")  # backup file skipped
    state = sec.sudoers_state(str(main), str(dropin))
    assert str(main) in state["files"]
    assert str(dropin / "90-cloud") in state["files"]
    assert not any("README~" in p for p in state["files"])
    # comments/blank lines don't change the hash
    main.write_text("root ALL=(ALL) ALL\n# a brand new comment\n\n")
    state2 = sec.sudoers_state(str(main), str(dropin))
    assert state2["files"][str(main)] == state["files"][str(main)]


def test_authorized_keys_state(tmp_path):
    home = tmp_path / "home" / "alice"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text(
        "ssh-ed25519 AAAA alice@laptop\n# a comment\n\nssh-rsa BBBB backup\n")
    passwd = tmp_path / "passwd"
    passwd.write_text(f"alice:x:1000:1000:Alice:{home}:/bin/bash\n")
    state = sec.authorized_keys_state(str(passwd))
    assert state["alice"]["count"] == 2
    assert len(state["alice"]["hash"]) == 64


def test_uid0_accounts(tmp_path):
    passwd = tmp_path / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n"
                      "toor:x:0:0:backdoor:/root:/bin/bash\n"
                      "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
    assert sec.uid0_accounts(str(passwd)) == ["root", "toor"]


def test_empty_password_accounts_readable_and_not(tmp_path):
    shadow = tmp_path / "shadow"
    shadow.write_text("root:$6$hash:19000:0:99999:7:::\n"
                      "guest::19000:0:99999:7:::\n")
    empties, readable = sec.empty_password_accounts(str(shadow))
    assert readable is True
    assert empties == ["guest"]
    # unreadable → (None, False), degrade politely
    empties2, readable2 = sec.empty_password_accounts(str(tmp_path / "nope"))
    assert empties2 is None and readable2 is False


def test_world_writable_files(tmp_path):
    (tmp_path / "ok.txt").write_text("fine")
    bad = tmp_path / "bad.sh"
    bad.write_text("danger")
    import os as _os
    _os.chmod(bad, 0o666)
    hits = sec.world_writable_files((str(tmp_path),))
    assert str(bad) in hits
    assert str(tmp_path / "ok.txt") not in hits


def test_analyze_access_new_and_changed_sudoers():
    baseline = {"sudoers": {"/etc/sudoers": "aaa"},
                "authorized_keys": {}, "uid0": ["root"]}
    current = {"sudoers": {"files": {"/etc/sudoers": "bbb",
                                     "/etc/sudoers.d/99-new": "ccc"},
                           "unreadable": []},
               "authorized_keys": {}, "uid0": ["root"],
               "empty_passwords": [], "shadow_readable": True,
               "world_writable": []}
    findings, observed = sec.analyze_access(current, baseline)
    assert any(f.title == "sudoers changed: /etc/sudoers" for f in findings)
    assert any(f.title == "new sudoers file: /etc/sudoers.d/99-new" for f in findings)


def test_analyze_access_authorized_keys_delta():
    baseline = {"authorized_keys": {"alice": {"hash": "old", "count": 1}},
                "sudoers": {}, "uid0": ["root"]}
    current = {"sudoers": {"files": {}, "unreadable": []},
               "authorized_keys": {"alice": {"hash": "new", "count": 2},
                                   "bob": {"hash": "x", "count": 1}},
               "uid0": ["root"], "empty_passwords": [],
               "shadow_readable": True, "world_writable": []}
    findings, _ = sec.analyze_access(current, baseline)
    assert any(f.title == "authorized_keys changed for alice" for f in findings)
    assert any(f.title == "new authorized_keys for bob" and f.severity == "warning"
               for f in findings)


def test_analyze_access_uid0_and_empty_password_are_critical():
    current = {"sudoers": {"files": {}, "unreadable": []},
               "authorized_keys": {}, "uid0": ["root", "toor"],
               "empty_passwords": ["guest"], "shadow_readable": True,
               "world_writable": []}
    findings, _ = sec.analyze_access(current, None)
    sevs = {f.title: f.severity for f in findings}
    assert sevs.get("UID-0 account besides root: toor") == "critical"
    assert sevs.get("account with EMPTY password: guest") == "critical"


def test_analyze_access_shadow_unreadable_degrades_to_info():
    current = {"sudoers": {"files": {}, "unreadable": []},
               "authorized_keys": {}, "uid0": ["root"],
               "empty_passwords": None, "shadow_readable": False,
               "world_writable": []}
    findings, _ = sec.analyze_access(current, None)
    info = [f for f in findings if "shadow file unreadable" in f.title]
    assert info and info[0].severity == "info"


def test_analyze_access_world_writable_warns():
    current = {"sudoers": {"files": {}, "unreadable": []},
               "authorized_keys": {}, "uid0": ["root"],
               "empty_passwords": [], "shadow_readable": True,
               "world_writable": ["/etc/cron.d/evil"]}
    findings, _ = sec.analyze_access(current, None)
    assert any(f.title.startswith("world-writable file") and f.severity == "warning"
               for f in findings)


# =====================================================================
# group 3 — listener ownership baselines
# =====================================================================

def _lrow(key, port, proc="", unit="", addr="0.0.0.0", proto="tcp"):
    return {"key": key, "proto": proto, "port": port, "addr": addr,
            "process": proc, "pid": 1 if proc else 0, "unit": unit,
            "ownerless": not proc}


def test_analyze_listeners_new_listener_warns_against_baseline():
    baseline = {"listeners": {"tcp/22": "sshd"}}
    current = [_lrow("tcp/22", 22, "sshd"),
               _lrow("tcp/4444", 4444, "nc", unit="")]
    findings, observed = sec.analyze_listeners(current, baseline, can_resolve_owners=True)
    new = [f for f in findings if f.title.startswith("NEW listener tcp/4444")]
    assert new and new[0].severity == "warning"
    assert observed["listeners"] == {"tcp/22": "sshd", "tcp/4444": "nc"}


def test_analyze_listeners_first_run_no_baseline_quiet():
    current = [_lrow("tcp/22", 22, "sshd")]
    findings, _ = sec.analyze_listeners(current, None, can_resolve_owners=True)
    assert not [f for f in findings if "NEW listener" in f.title]


def test_analyze_listeners_ownerless_root_warns():
    current = [_lrow("tcp/9999", 9999, proc="")]  # no owning process
    findings, _ = sec.analyze_listeners(current, {"listeners": {"tcp/9999": ""}},
                                        can_resolve_owners=True)
    owner = [f for f in findings if f.title.startswith("ownerless listener")]
    assert owner and owner[0].severity == "warning"


def test_analyze_listeners_ownerless_nonroot_collapses_to_one_info():
    # non-root scan can't attribute other users' sockets → one info, not N warnings
    current = [_lrow(f"tcp/{p}", p, proc="") for p in (8001, 8002, 8003)]
    base = {"listeners": {f"tcp/{p}": "" for p in (8001, 8002, 8003)}}
    findings, _ = sec.analyze_listeners(current, base, can_resolve_owners=False)
    infos = [f for f in findings if "unresolved owner" in f.title]
    assert len(infos) == 1 and infos[0].severity == "info"
    assert "3 listener(s)" in infos[0].title
    # and no per-socket ownerless warnings in the non-root case
    assert not [f for f in findings if f.title.startswith("ownerless listener")]


def test_analyze_listeners_new_listener_alarms_even_without_root():
    base = {"listeners": {"tcp/22": "sshd"}}
    current = [_lrow("tcp/22", 22, proc=""), _lrow("tcp/1337", 1337, proc="")]
    findings, _ = sec.analyze_listeners(current, base, can_resolve_owners=False)
    assert any(f.title.startswith("NEW listener tcp/1337") for f in findings)


# =====================================================================
# group 4 — OSV CVE client: mocked, offline fail-soft, cached, ranked
# =====================================================================

def test_severity_bucket_variants():
    assert sec._severity_bucket("9.8") == "critical"
    assert sec._severity_bucket("7.0") == "high"
    assert sec._severity_bucket("5.0") == "medium"
    assert sec._severity_bucket("2.0") == "low"
    assert sec._severity_bucket("") == "unknown"
    assert sec._severity_bucket("CRITICAL") == "critical"
    assert sec._severity_bucket("moderate") == "medium"
    # CVSS vector with a high impact flag
    assert sec._severity_bucket("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "high"


def _wire_cve(monkeypatch, ids_per_pkg, detail=None):
    from wrench import webintel
    pkgs = [{"name": "openssl", "version": "3.0.1", "ecosystem": "Ubuntu"},
            {"name": "curl", "version": "7.80.0", "ecosystem": "Ubuntu"}]
    monkeypatch.setattr(sec, "package_inventory",
                        lambda cap=3000: (pkgs, "dpkg"))
    monkeypatch.setattr(webintel, "osv_querybatch", lambda p: ids_per_pkg)
    detail = detail or {"severity": [{"type": "CVSS_V3", "score": "9.8"}],
                        "affected": [{"package": {"name": "openssl"},
                                      "ranges": [{"events": [{"fixed": "3.0.2"}]}]}]}
    monkeypatch.setattr(webintel, "osv_vuln_detail",
                        lambda store, vid, ttl: detail)
    return pkgs


def test_cve_scan_matches_and_buckets(monkeypatch, store):
    _wire_cve(monkeypatch, [["CVE-2026-0001"], []])
    res = sec.cve_scan(FakeCfg(), store, force=True)
    assert res["available"] is True
    assert res["checked"] == 2
    assert res["manager"] == "dpkg"
    assert len(res["vulns"]) == 1
    v = res["vulns"][0]
    assert v["id"] == "CVE-2026-0001" and v["package"] == "openssl"
    assert v["bucket"] == "critical" and v["fixed"] == "3.0.2"
    # first sight of a critical is tracked as new-serious
    assert any(x["id"] == "CVE-2026-0001" for x in res["new_serious"])


def test_cve_scan_offline_fail_soft(monkeypatch, store):
    from wrench import webintel
    monkeypatch.setattr(sec, "package_inventory",
                        lambda cap=3000: ([{"name": "x", "version": "1",
                                            "ecosystem": "Ubuntu"}], "dpkg"))

    def boom(_p):
        raise OSError("network down")
    monkeypatch.setattr(webintel, "osv_querybatch", boom)
    res = sec.cve_scan(FakeCfg(), store, force=True)
    assert res["available"] is False
    assert res["vulns"] == [] and res["new_serious"] == []
    assert "OSV unreachable" in res["error"]


def test_cve_scan_no_inventory_fail_soft(monkeypatch, store):
    monkeypatch.setattr(sec, "package_inventory", lambda cap=3000: ([], "none"))
    res = sec.cve_scan(FakeCfg(), store, force=True)
    assert res["available"] is False
    assert "no supported package inventory" in res["error"]


def test_cve_scan_uses_cache_within_ttl(monkeypatch, store):
    _wire_cve(monkeypatch, [["CVE-2026-0001"], []])
    first = sec.cve_scan(FakeCfg(), store, force=True)
    assert first["cached"] is False
    # a second non-forced scan must NOT hit the network again
    from wrench import webintel
    monkeypatch.setattr(webintel, "osv_querybatch",
                        lambda p: (_ for _ in ()).throw(AssertionError("rescanned")))
    second = sec.cve_scan(FakeCfg(), store, force=False)
    assert second["cached"] is True
    assert second["vulns"] == first["vulns"]


def test_cve_findings_severity_ladder_and_new_flag(monkeypatch, store):
    _wire_cve(monkeypatch, [["CVE-2026-0001"], []])
    res = sec.cve_scan(FakeCfg(), store, force=True)
    findings = sec.cve_findings(res)
    assert findings and findings[0].severity == "critical"
    assert "[NEW]" in findings[0].title
    assert findings[0].meta["new"] is True


def test_cve_findings_skipped_notice_when_unavailable():
    findings = sec.cve_findings({"available": False, "error": "OSV unreachable (x)"})
    assert len(findings) == 1 and findings[0].severity == "info"
    assert findings[0].category == "cve"
    # truly empty/unavailable with no error → no noise
    assert sec.cve_findings({"available": False}) == []
