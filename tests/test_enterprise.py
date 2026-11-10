"""3.0 hardening: posture score, OS probes, strict policy allowlists, audit
truncation/concurrency, real-volume filtering, listener parsers, deterministic
patrols, retention, config editing, Time Machine, blueprint confinement."""

from __future__ import annotations

import datetime as dt
import json
import threading
import time
from collections import namedtuple
from pathlib import Path

import pytest

from wrench import (agent, audit, backups, blueprint, comply, config, fixxer, forecast,
                    netinfo, platforms, policy, posture, probes, tools, windows)
from wrench.store import Store


# ---------------- posture ----------------

def test_posture_unknown_is_not_healthy():
    p = posture.combine([posture.score_capacity(None), posture.score_security(None),
                         posture.score_backups(None)])
    assert p["score"] is None and p["grade"] == "–" and p["state"] == "unknown"
    assert p["coverage"] == {"measured": 0, "total": 3}


def test_posture_scores_and_critical_cap():
    full = posture.score_capacity({"disk_pct": {"/": 97.0, "/data": 20.0}, "mem_pct": 40.0})
    assert full["state"] == "critical" and "97%" in full["detail"]
    fine = posture.score_security({"counts": {"critical": 0, "warning": 0},
                                   "baseline_exists": True})
    assert fine["score"] == 100.0
    combined = posture.combine([full, fine, posture.score_forecast(None)])
    # one critical pillar must not hide inside a decent average
    assert combined["score"] <= 69.0 and combined["state"] != "ok"
    assert combined["coverage"] == {"measured": 2, "total": 3}
    assert combined["top_issues"][0]["pillar"] == "capacity"


def test_posture_pillar_details():
    assert posture.score_backups({"no_jobs": True, "jobs": []})["score"] == 40.0
    c = posture.score_compliance({"packs": [{"score": 92.0, "counts": {"pass": 11, "fail": 1}}],
                                  "fail_ids": ["x"], "critical_fails": 1})
    assert c["score"] <= 59.0                                   # a critical failure caps it
    assert posture.score_compliance({"packs": [{"score": None, "counts": {"pass": 0, "fail": 0}}]}
                                    )["score"] is None          # nothing graded → unknown
    assert posture.score_certificates([{"days_left": 3}])["state"] == "critical"
    assert posture.score_certificates([{"days_left": 200}])["score"] == 100.0
    stale = posture.score_patrol({"status": "ok", "ts": 0}, interval_min=15, now=10 * 86400)
    assert stale["score"] <= 60 and "not running" in stale["detail"]
    assert posture.grade_for(95) == "A" and posture.grade_for(59.9) == "F"


def test_posture_compute_on_a_fresh_store(tmp_path):
    class Cfg:
        patrol_interval_min = 15
    store = Store(tmp_path / "w.db")
    p = posture.compute(Cfg(), store)
    assert p["score"] is None and len(p["pillars"]) == len(posture.WEIGHTS)
    store.add_sample("os", {"disk_pct": {"/": 30.0}, "mem_pct": 50.0})
    thin = posture.compute(Cfg(), store)
    # one clean pillar out of eight is a number, not a verdict
    assert thin["score"] == 100.0 and thin["provisional"]
    assert thin["grade"] == "–" and thin["state"] == "unknown"
    assert posture.record(Cfg(), store, min_gap_s=0) is None      # and it is not charted
    store.close()


# ---------------- probes + packs ----------------

def test_every_shipped_pack_loads_and_declares_platforms():
    names = {p.stem for p in comply.pack_dir().glob("*.json")}
    assert {"macos-baseline", "windows-baseline", "cis-ubuntu-essentials",
            "wrench-baseline"} <= names
    for n in names:
        pack = comply.load_pack(n)
        assert pack.platforms and set(pack.platforms) <= set(comply.PLATFORMS)
    assert comply.applicable_packs("macos") == ["macos-baseline"]
    assert comply.applicable_packs("windows") == ["windows-baseline"]
    assert "macos-baseline" not in comply.applicable_packs("linux")


def test_probe_check_semantics(monkeypatch):
    def rule(check):
        return comply.Rule(id="t.x", title="t", severity="high", rationale="", check=check)

    monkeypatch.setattr(probes, "run", lambda name: ("on", "it is on"))
    assert comply.run_rule(rule({"kind": "probe", "name": "macos.filevault",
                                 "expect": "on"})).status == "pass"
    assert comply.run_rule(rule({"kind": "probe", "name": "macos.filevault",
                                 "expect": "off"})).status == "fail"
    monkeypatch.setattr(probes, "run", lambda name: (None, "needs elevation"))
    r = comply.run_rule(rule({"kind": "probe", "name": "macos.filevault", "expect": "on"}))
    assert r.status == "skip" and "elevation" in r.detail        # unknown is never a pass
    monkeypatch.setattr(probes, "run", lambda name: ("900", "locks after 900s"))
    assert comply.run_rule(rule({"kind": "probe", "name": "macos.screen_lock_delay",
                                 "max": 300})).status == "fail"
    monkeypatch.setattr(probes, "run", lambda name: ("off", "screen lock is off"))
    assert comply.run_rule(rule({"kind": "probe", "name": "macos.screen_lock_delay",
                                 "max": 300})).status == "fail"


def test_a_pack_cannot_name_an_unknown_probe_or_carry_a_command():
    bad = comply.Rule(id="t.y", title="t", severity="low", rationale="",
                      check={"kind": "probe", "name": "rm -rf /", "expect": "on"})
    with pytest.raises(ValueError):
        bad.validate()
    assert probes.run("no.such.probe")[0] is None
    other = "windows.uac" if platforms.current_platform() != "windows" else "macos.sip"
    value, detail = probes.run(other)
    assert value is None and "only" in detail                    # wrong OS → skip


def test_comply_patrol_findings_carry_text():
    class S:
        def last_snapshot(self, kind):
            if kind == comply.SCAN_KIND:
                return (time.time(), {"fails": [{"id": "a.b", "title": "firewall is on",
                                                 "severity": "high"}]})
            return None
    f = comply.patrol_findings(None, S())[0]
    assert "expected: firewall is on" in f["text"]               # the old KeyError: 'text'


# ---------------- policy ----------------

@pytest.mark.parametrize("cmd", [
    "journalctl --vacuum-time=1s", "journalctl --rotate",
    "journalctl --cursor-file=/etc/cron.d/x -n 1", "ss -t -D /etc/shadow",
    "ss -t -K dst 0.0.0.0/0", "cat /proc/1/environ", "ps auxeww", "ls -R /",
    "docker inspect web --format {{json .Config.Env}}", "systemctl status -Hroot@evil",
    "du -sh /etc --files0-from=/x", "df -h\nrm -rf /", "cat /proc/kcore",
])
def test_diag_allowlist_refuses_writes_secrets_and_injection(cmd):
    assert not policy.check_diag(cmd).allowed


@pytest.mark.parametrize("cmd", [
    "journalctl -u nginx -n 50 --no-pager", "journalctl -p err -b --no-pager",
    "journalctl --since '1 hour ago' -u ssh", "ss -tulnp", "df -h", "du -sh /var/log",
    "ps aux --sort=-%mem", "top -b -n 1", "cat /proc/meminfo", "ls -la /var/log",
    "docker ps -a", "systemctl list-units --failed --no-pager", "uptime",
    "log show --last 10m --predicate 'process == \"sshd\"'", "tmutil latestbackup",
])
def test_diag_allowlist_keeps_real_diagnostics(cmd):
    assert policy.check_diag(cmd).allowed


@pytest.mark.parametrize("cmd", [
    "systemctl start poweroff.target", "systemctl start debug-shell.service",
    "systemctl start systemd-poweroff.service", "systemctl restart multi-user.target",
    "systemctl stop sshd", "systemctl stop auditd.service", "net stop EventLog",
    "launchctl stop com.openssh.sshd", "systemctl start emergency.target",
])
def test_repair_allowlist_protects_the_box(cmd):
    assert not policy.check_repair(cmd, "autonomous").allowed


def test_repair_allowlist_still_repairs():
    for cmd in ("systemctl restart nginx", "systemctl restart sshd",
                "systemctl --user restart app.service", "journalctl --vacuum-size=500M"):
        assert policy.check_repair(cmd, "autonomous").allowed
    assert policy.check_repair("systemctl restart nginx", "repair").needs_confirm
    assert not policy.check_repair("systemctl restart nginx", "suggest").allowed


def test_agent_fix_obeys_the_maintenance_window(tmp_path, monkeypatch):
    class Cfg:
        raw = {"maintenance": {"windows": ["Sat 02:00-03:00"]}}
        data_dir = tmp_path
    store = Store(tmp_path / "w.db")
    ran = []
    monkeypatch.setattr(tools, "_exec_rc", lambda argv, timeout=60: (ran.append(argv), (0, "ok"))[1])
    monkeypatch.setattr(windows, "now_for", lambda st, now=None: dt.datetime(2026, 11, 10, 14, 0))
    out = tools.fix_action(store, "systemctl restart nginx", "autonomous", cfg=Cfg())
    assert out.startswith("DENIED") and "maintenance window" in out and not ran
    monkeypatch.setattr(windows, "now_for", lambda st, now=None: dt.datetime(2026, 11, 14, 2, 30))
    assert tools.fix_action(store, "systemctl restart nginx", "autonomous",
                            cfg=Cfg()).startswith("EXECUTED")
    # a failing command is reported — and logged — as a failure
    monkeypatch.setattr(tools, "_exec_rc", lambda argv, timeout=60: (5, "Unit not found"))
    assert tools.fix_action(store, "systemctl restart nginx", "autonomous",
                            cfg=Cfg()).startswith("FAILED")
    assert store.recent_actions(1)[0]["approved"] is False
    store.close()


def test_maintenance_window_typo_fails_closed():
    class Cfg:
        raw = {"maintenance": {"windows": ["Saturday 2am-6am"]}}
    d = windows.gate(Cfg(), "fixxer apply", override=True, has_consent=True)
    assert not d.allowed and "errors" in d.reason                # not "no windows configured"

    class NoWindows:
        raw = {}
    assert windows.gate(NoWindows(), "fixxer apply", False, False).allowed


def test_tool_arguments_cannot_be_options(tmp_path):
    store = Store(tmp_path / "w.db")
    assert tools.service_status(store, "-Hroot@evil").startswith("DENIED")
    assert tools.read_logs(store, unit='x" OR 1==1 OR "').startswith("DENIED")
    store.close()


# ---------------- audit ----------------

def test_audit_detects_tail_truncation_and_records_the_gap(tmp_path):
    for i in range(6):
        audit.append(tmp_path, "evt", {"i": i})
    assert audit.verify(tmp_path)["intact"]
    p = audit.audit_path(tmp_path)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:-2]) + "\n")                   # cut the tail off
    v = audit.verify(tmp_path)
    assert not v["intact"] and "truncated" in v["reason"]
    # the next event does not paper over it: the discontinuity itself is sealed
    audit.append(tmp_path, "evt", {"after": True})
    kinds = [r["kind"] for r in audit.read_records(tmp_path)]
    assert "audit.discontinuity" in kinds
    assert audit.verify(tmp_path)["discontinuities"] == 1


def test_audit_concurrent_appends_do_not_fork_the_chain(tmp_path):
    def worker(i):
        for j in range(15):
            audit.append(tmp_path, "evt", {"i": i, "j": j})
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    v = audit.verify(tmp_path)
    assert v["intact"] and v["count"] == 6 * 15 + 1               # + genesis


def test_audit_mac_catches_a_full_rewrite(tmp_path, monkeypatch):
    key = tmp_path / "audit.key"
    key.write_text("k" * 32)
    monkeypatch.setenv(audit.KEY_ENV, str(key))
    data = tmp_path / "data"
    for i in range(3):
        audit.append(data, "evt", {"i": i})
    assert audit.verify(data)["mac_checked"] and audit.verify(data)["intact"]
    # an attacker rewrites a record AND recomputes every hash (no key)
    recs = audit.read_records(data)
    recs[1]["detail"] = {"i": "forged"}
    prev = audit.GENESIS_PREV
    for r in recs:
        r["prev_hash"] = prev
        r["hash"] = audit.record_hash(prev, r)
        prev = r["hash"]
    audit.audit_path(data).write_text("".join(json.dumps(r) + "\n" for r in recs))
    audit._write_head(data, len(recs), prev)                      # …and re-seals the head
    v = audit.verify(data)
    assert not v["intact"] and "MAC" in v["reason"]


# ---------------- platforms / sensors ----------------

Part = namedtuple("Part", "mountpoint fstype opts")
Usage = namedtuple("Usage", "total used free percent")


def test_macos_volume_filter_and_container_usage():
    parts = [Part("/", "apfs", "ro,local,rootfs"), Part("/System/Volumes/Data", "apfs", "rw"),
             Part("/System/Volumes/VM", "apfs", "rw"), Part("/Volumes/Recovery", "apfs", "rw"),
             Part("/Volumes/Installer", "hfs", "ro,nosuid"), Part("/Volumes/Backup", "apfs", "rw")]
    usage = {"/": Usage(1000, 12, 750, 1.6), "/Volumes/Backup": Usage(500, 450, 50, 90.0)}
    out = platforms.volume_usage(parts, lambda m: usage[m], plat="macos")
    # "/" reports container fill (1 − free/total), not the sealed system volume's 1.6%
    assert out == {"/": 25.0, "/Volumes/Backup": 90.0}


def test_linux_and_windows_volume_filters():
    assert platforms.is_monitored_volume("/", "ext4", "rw", "linux")
    assert not platforms.is_monitored_volume("/snap/core/1", "squashfs", "ro", "linux")
    assert not platforms.is_monitored_volume("/var/lib/docker/overlay2/x", "overlay", "rw", "linux")
    assert not platforms.is_monitored_volume("/mnt/iso", "ext4", "ro", "linux")
    assert platforms.is_monitored_volume("C:\\", "NTFS", "rw,fixed", "windows")
    assert not platforms.is_monitored_volume("D:\\", "", "cdrom", "windows")


def test_zscore_floor(tmp_path):
    store = Store(tmp_path / "w.db")
    for _ in range(60):
        store.update_baseline("os", "swap_pct", 0.0)
    assert store.update_baseline("os", "swap_pct", 80.0) > 3       # a real jump IS an anomaly
    for _ in range(100):
        store.update_baseline("os", "disk_root_pct", 24.7)
    assert abs(store.update_baseline("os", "disk_root_pct", 24.8)) < 1   # a 0.1 tick is not
    store.close()


def test_listener_parsers():
    lsof = "p101\ncnginx\nf6\nPTCP\nn*:443\nTST=LISTEN\nf7\nPTCP\nn10.0.0.2:51000->1.1.1.1:443\n" \
           "TST=ESTABLISHED\np202\ncmdnsd\nf3\nPUDP\nn*:5353\n"
    rows = netinfo.parse_lsof_fields(lsof)
    assert {(r["proto"], r["port"], r["process"]) for r in rows} == {
        ("tcp", 443, "nginx"), ("udp", 5353, "mdnsd")}
    ns = ("tcp4  0  0  *.22   *.*   LISTEN   0  0  131072  131072   sshd:88   00100 00000006\n"
          "tcp4  0  0  10.0.0.2.5000  1.2.3.4.443  ESTABLISHED  1 1 1 1  curl:9  00102 00000008\n"
          "udp4  0  0  *.5353  *.*      0  0  786896  9216   mDNSResponder:300   00100 00000204\n")
    got = netinfo.parse_netstat_anv(ns)
    assert [(r["proto"], r["port"], r["process"], r["pid"]) for r in got] == [
        ("tcp", 22, "sshd", 88), ("udp", 5353, "mDNSResponder", 300)]
    assert netinfo.is_ephemeral_udp("udp", 60000, 49152)
    assert not netinfo.is_ephemeral_udp("tcp", 60000, 49152)
    assert not netinfo.is_ephemeral_udp("udp", 53, 49152)


# ---------------- deterministic patrol + retention ----------------

class _PatrolCfg:
    provider = "meta"
    api_key = ""
    base_url = "https://api.example/v1"
    model = "m"
    deep_model = "d"
    policy_tier = "suggest"
    offline = False
    retention_days = 30
    patrol_interval_min = 15
    raw: dict = {}

    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)


def _stub_context(monkeypatch, raw):
    monkeypatch.setattr(agent.Agent, "gather_context", lambda self: ("ctx", raw))


def test_patrol_without_a_brain_is_a_real_patrol(tmp_path, monkeypatch):
    store = Store(tmp_path / "w.db")
    raw = {"sensor": {"os": {"disk_pct": {"/": 96.0, "/data": 40.0}, "mem_pct": 50.0}},
           "drift": [{"kind": "ports", "changes": ["port opened: tcp/8081 (python3)"]}],
           "anomalies": [], "comply_findings": [{"severity": "warning", "area": "comply",
                                                 "summary": "x.y: z"}]}
    _stub_context(monkeypatch, raw)
    assert agent.brain_status(_PatrolCfg(tmp_path)) == (False, "no API key for provider 'meta'")
    p = agent.run_patrol(_PatrolCfg(tmp_path), store)
    assert p["deterministic"] and p["model"] == agent.DETERMINISTIC_MODEL and p["tokens"] == 0
    assert p["status"] == "critical" and "96%" in p["summary"]     # not "error"
    sevs = [f["severity"] for f in p["findings"]]
    assert sevs == sorted(sevs, key=["critical", "warning", "info"].index)
    assert any("comply: x.y: z" in f["text"] for f in p["findings"])
    assert store.recent_patrols(1)[0]["status"] == "critical"
    store.close()


def test_patrol_falls_back_when_the_provider_fails(tmp_path, monkeypatch):
    store = Store(tmp_path / "w.db")
    _stub_context(monkeypatch, {"sensor": {"os": {"disk_pct": {"/": 20.0}}}})

    class Cfg(_PatrolCfg):
        provider = "ollama"
    monkeypatch.setattr(agent.Agent, "run", lambda self, *a, **k: {
        "answer": "(provider error)", "steps": [], "tokens": 0, "error": "connection refused"})
    p = agent.run_patrol(Cfg(tmp_path), store)
    assert p["status"] == "ok" and p["deterministic"]
    assert "connection refused" in p["brain_note"]
    store.close()


def test_prune_keeps_live_baselines_and_history(tmp_path):
    store = Store(tmp_path / "w.db")
    old = time.time() - 90 * 86400
    store.db.execute("INSERT INTO snapshots (ts, kind, payload) VALUES (?,?,?)",
                     (old - 10, "security_baseline", "{}"))
    store.db.execute("INSERT INTO snapshots (ts, kind, payload) VALUES (?,?,?)",
                     (old, "security_baseline", '{"accepted": true}'))
    store.db.execute("INSERT INTO samples (ts, sensor, payload) VALUES (?,?,?)", (old, "os", "{}"))
    store.db.execute("INSERT INTO patrols (ts, status) VALUES (?,?)", (old, "ok"))
    store.db.commit()
    deleted = store.prune(30)
    assert deleted["samples"] == 1 and deleted["snapshots"] == 1
    # the newest accepted baseline survives retention; so does 90-day-old patrol history
    assert store.last_snapshot("security_baseline")[1] == {"accepted": True}
    assert len(store.recent_patrols(5)) == 1
    assert store.maybe_prune(30) is not None and store.maybe_prune(30) is None   # throttled
    store.close()


def test_store_is_owner_only_and_migrates(tmp_path):
    import os
    import sqlite3
    db = tmp_path / "data" / "w.db"
    db.parent.mkdir()
    con = sqlite3.connect(db)           # a 2.x database: fleet_nodes without the new columns
    con.execute("CREATE TABLE fleet_nodes (node_id TEXT PRIMARY KEY, hostname TEXT, token_hash TEXT,"
                " first_seen REAL NOT NULL, last_seen REAL NOT NULL, status TEXT, worst_severity TEXT,"
                " summary TEXT, cadence_s REAL, wrench_version TEXT, findings TEXT, gauges TEXT,"
                " report_count INTEGER NOT NULL DEFAULT 0, silent INTEGER NOT NULL DEFAULT 0)")
    con.execute("INSERT INTO fleet_nodes (node_id, first_seen, last_seen) VALUES ('old', 1, 2)")
    con.commit()
    con.close()
    store = Store(db)
    assert store.schema_version >= 2
    assert store.get_fleet_node("old")["meta"] == {}             # upgraded in place
    if os.name == "posix":
        assert oct(db.stat().st_mode & 0o777) == "0o600"
        assert oct(db.parent.stat().st_mode & 0o777) == "0o700"
    store.close()


# ---------------- config editing ----------------

def test_set_section_values_preserves_the_file(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('# my notes\n[provider]\nname = "ollama"\n\n[fleet]\n# hub_url = "x"\n'
                 'node_id = "old"\n\n[notify]\nenabled = true\n')
    config.set_section_values("fleet", {"hub_url": "https://hub:8788", "token": 'wfl_"q',
                                        "node_id": "web-01", "tags": ["a", "b"]}, path=p)
    text = p.read_text()
    assert "# my notes" in text and '# hub_url = "x"' in text       # comments survive
    data = config.tomllib.loads(text)
    assert data["fleet"] == {"hub_url": "https://hub:8788", "token": 'wfl_"q',
                             "node_id": "web-01", "tags": ["a", "b"]}
    assert data["provider"]["name"] == "ollama" and data["notify"]["enabled"] is True
    config.set_section_values("web", {"auth_token": "t"}, path=p)   # a new section
    assert config.tomllib.loads(p.read_text())["web"]["auth_token"] == "t"
    import os
    if os.name == "posix":
        assert oct(p.stat().st_mode & 0o777) == "0o600"


# ---------------- backups / forecast / fixxer / blueprint ----------------

def test_time_machine_job_from_preferences():
    now = dt.datetime.now(dt.timezone.utc)
    prefs = {"AutoBackup": True, "AutoBackupInterval": 3600, "Destinations": [{
        "LastKnownVolumeName": "Vault", "RESULT": 0,
        "SnapshotDates": [now - dt.timedelta(days=3), now - dt.timedelta(minutes=20)]}]}
    job = backups.parse_time_machine(prefs)
    backups.check_freshness(job)
    assert job.tool == "timemachine" and job.freshness == "fresh" and job.integrity == "ok"
    prefs["Destinations"][0]["SnapshotDates"] = [now - dt.timedelta(days=40)]
    prefs["Destinations"][0].update(RESULT=101, MessageParameters=["Insufficient battery"])
    stale = backups.parse_time_machine(prefs)
    backups.check_freshness(stale)
    assert stale.freshness == "stale" and "Insufficient battery" in stale.integrity_note
    assert backups.job_severity(stale) == "warning"
    assert backups.parse_time_machine({"Destinations": []}) is None


def test_forecast_severity_needs_a_believable_trend():
    assert forecast.cap_severity("critical", "low", 5.0, "disk") == "info"
    assert forecast.cap_severity("critical", "high", 0.2, "disk") == "info"
    assert forecast.cap_severity("critical", "high", 5.0, "memory") == "info"
    assert forecast.cap_severity("critical", "high", 5.0, "disk") == "critical"
    assert forecast.cap_severity("info", "low", 0.1, "disk") == "info"


def test_fixxer_command_building(monkeypatch):
    monkeypatch.setattr(fixxer, "_sudo_prefix", lambda ni: ["sudo", "-n"])
    cmd = fixxer.build_command(["apt-get", "upgrade", "-y"], True, True,
                               {"DEBIAN_FRONTEND": "noninteractive"})
    # the env rides AFTER sudo (sudo's env_reset would strip it otherwise)
    assert cmd[:4] == ["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive"]
    assert "Dpkg::Options::=--force-confold" in cmd and cmd[-2:] == ["upgrade", "-y"]
    # a user-scope command is never elevated
    assert fixxer.build_command(["systemctl", "--user", "reset-failed"], True, True) == [
        "systemctl", "--user", "reset-failed"]
    assert fixxer.build_command(["apt-get", "update"], True, True)[:3] == ["sudo", "-n", "apt-get"]


@pytest.mark.skipif(__import__("os").name == "nt", reason="POSIX /etc paths")
def test_blueprint_confinement():
    class Cfg:
        raw: dict = {}
    for bad in ("/etc/Sudoers", "/etc/SHADOW", "/etc/ssl/Private/x.KEY", "/etc/cron.d/x",
                "/etc/ld.so.preload", "/etc/pam.d/sshd", "/etc/profile.d/x.sh",
                "/etc/systemd/system/x.service", "//etc/passwd", "/root/.ssh/authorized_keys"):
        assert not blueprint.path_allowed(Cfg, bad)[0], bad
    for ok in ("/etc/hosts", "/etc/ssh/sshd_config.d/50-x.conf", "/etc/nginx/nginx.conf"):
        assert blueprint.path_allowed(Cfg, ok)[0], ok

    class Opt:
        raw = {"blueprint": {"allow_exec_paths": True}}
    assert blueprint.path_allowed(Opt, "/etc/cron.d/x")[0]          # explicit opt-in only


def test_blueprint_symlink_escape(tmp_path):
    root = tmp_path / "etc"
    (root / "app").mkdir(parents=True)
    outside = tmp_path / "secrets"
    outside.mkdir()
    try:
        (root / "app" / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("cannot create symlinks here")

    class Cfg:
        raw = {"blueprint": {"allowed_roots": [str(root)]}}
    ok, why = blueprint.path_allowed(Cfg, str(root / "app" / "link" / "id_rsa.conf"))
    assert not ok and "symlink" in why
    assert blueprint.path_allowed(Cfg, str(root / "app" / "real.conf"))[0]


def test_blueprint_patch_is_exact():
    patch = blueprint.parse_unified_diff(
        "--- a/etc/x.conf\n+++ b/etc/x.conf\n@@ -2,1 +2,1 @@\n-b\n+B\n")[0]
    # CRLF and a form feed in lines the diff never touched are preserved byte for byte
    out = blueprint.apply_patch_text("a\r\nb\nkeep\x0cff\r\n", patch)
    assert out == "a\r\nB\nkeep\x0cff\r\n"
    amb = blueprint.parse_unified_diff(
        "--- a/etc/x.conf\n+++ b/etc/x.conf\n@@ -900,1 +900,1 @@\n-}\n+} # end\n")[0]
    with pytest.raises(blueprint.BlueprintError):
        blueprint.apply_patch_text("server {\n}\nserver {\n}\n", amb)   # ambiguous context


# ---------------- regressions from the independent review of 3.0 ----------------

@pytest.mark.parametrize("cmd", [
    "cat /proc/sys/../../etc/shadow", "cat /proc/sys/kernel/../../1/environ",
    "journalctl -g x --vacuum-time 1s", "journalctl -g x --rotate",
    "journalctl -g error -D x", "ls / -R",
])
def test_diag_allowlist_review_regressions(cmd):
    assert not policy.check_diag(cmd).allowed


def test_diag_allowlist_accepts_everyday_forms():
    for cmd in ("journalctl -xe", "top -bn1", "systemctl status nginx -l", "ls -la", "ss -s",
                "journalctl -g 'out of memory' -n 50", "cat /proc/sys/vm/swappiness"):
        assert policy.check_diag(cmd).allowed, cmd
    for cmd in ("launchctl stop system/com.openssh.sshd", "net stop termservice x"):
        assert not policy.check_repair(cmd, "autonomous").allowed, cmd


def test_audit_wipe_and_head_removal_are_not_forgotten(tmp_path):
    for i in range(4):
        audit.append(tmp_path, "evt", {"i": i})
    audit.audit_path(tmp_path).unlink()                         # wipe the whole log
    assert not audit.verify(tmp_path)["intact"]
    audit.append(tmp_path, "evt", {"after": "wipe"})            # e.g. a failed web login
    kinds = [r["kind"] for r in audit.read_records(tmp_path)]
    assert kinds[:2] == ["genesis", "audit.discontinuity"]      # the wipe is on the record
    assert audit.verify(tmp_path)["discontinuities"] == 1

    other = tmp_path / "b"
    for i in range(3):
        audit.append(other, "evt", {"i": i})
    audit.head_path(other).unlink()                             # remove the seal instead
    v = audit.verify(other)
    assert not v["intact"] and "head" in v["reason"]


def test_audit_verify_never_raises_and_oversize_detail_is_bounded(tmp_path):
    audit.append(tmp_path, "evt", {"blob": "x" * 200_000})
    audit.append(tmp_path, "evt", {"next": True})               # the tail is still found
    v = audit.verify(tmp_path)
    assert v["intact"] and v["count"] == 3
    assert audit.read_records(tmp_path)[1]["detail"]["truncated"] is True
    audit.audit_path(tmp_path).write_text('{"hash": 5, "prev_hash": {}}\n')
    assert audit.verify(tmp_path)["intact"] is False            # garbage → not intact, no raise


def test_audit_mac_is_mandatory_once_used(tmp_path, monkeypatch):
    key = tmp_path / "k"
    key.write_text("k" * 32)
    monkeypatch.setenv(audit.KEY_ENV, str(key))
    data = tmp_path / "d"
    for i in range(3):
        audit.append(data, "evt", {"i": i})
    recs = audit.read_records(data)
    prev = audit.GENESIS_PREV
    for r in recs:                                              # rewrite, dropping every MAC
        r.pop("mac", None)
        r["prev_hash"] = prev
        r["hash"] = audit.record_hash(prev, r)
        prev = r["hash"]
    audit.audit_path(data).write_text("".join(json.dumps(r) + "\n" for r in recs[:1])
                                      + json.dumps({**recs[1], "mac": "00"}) + "\n")
    assert not audit.verify(data)["intact"]


def test_fleet_ingest_sanitizes_hostile_node_data(tmp_path):
    from wrench import fleet
    store = Store(tmp_path / "w.db")
    st = fleet.FleetSettings(max_skew_s=0)
    auth = fleet.AuthResult(True, credential="key:k", key_id="", version=2)
    row = fleet.ingest(store, st, {
        "node_id": "evil", "ts": 10.0, "status": "ok",
        "gauges": {"disk_pct": [1], "mem_pct": "x", "cpu_pct": float("nan"), "junk": {"a": 1}},
        "meta": {"score": float("nan"), "tags": 5, "grade": {"x": 1},
                 "os": '"><a href=//evil>', "pillars": {"capacity": "inf"}},
    }, auth, now=10.0)
    assert row["gauges"] == {"disk_pct": {}}                    # nothing malformed survives
    assert "score" not in row["meta"] and row["meta"]["tags"] == []
    assert row["meta"]["pillars"] == {"capacity": None}
    json.dumps(row, allow_nan=False)                            # always valid JSON
    assert store.fleet_report_history("evil")[0]["disk_max_pct"] is None
    # a report with no finite timestamp has no replay protection → refused
    with pytest.raises(fleet.IngestRejected):
        fleet.ingest(store, st, {"node_id": "evil", "ts": "nan"}, auth, now=11.0)
    # non-latin-1 node names can be sent (header is percent-encoded)
    hdrs = fleet.signed_headers(fleet.FleetSettings(hub_url="http://h", token="t"), b"{}", "サーバー")
    hdrs[fleet.NODE_HEADER].encode("latin-1")
    store.close()


def test_fleet_ingest_is_atomic(tmp_path):
    from wrench import fleet
    store = Store(tmp_path / "w.db")
    st = fleet.FleetSettings(max_skew_s=0)
    auth = fleet.AuthResult(True, credential="key:k", version=2)
    fleet.ingest(store, st, {"node_id": "n", "ts": 5.0}, auth, now=5.0)
    with pytest.raises(fleet.IngestRejected):                   # replay: nothing is written
        fleet.ingest(store, st, {"node_id": "n", "ts": 5.0}, auth, now=6.0)
    assert store.get_fleet_node("n")["report_count"] == 1
    assert store.db.in_transaction is False
    store.close()


def test_set_section_values_edge_cases(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[fleet]\ntags = [\n  "a",\n  "b",\n]\nnode_id = "x"\n\n'
                 '[[backups.job]]\ntoken = "keepme"\n')
    config.set_section_values("fleet", {"token": "wfl_new", "tags": ["z"], "note": "héllo 🚀"},
                              path=p)
    data = config.tomllib.loads(p.read_text(encoding="utf-8"))
    assert data["fleet"] == {"token": "wfl_new", "tags": ["z"], "node_id": "x",
                             "note": "héllo 🚀"}
    assert data["backups"]["job"][0]["token"] == "keepme"       # a later table is untouched


def test_csv_guard_and_session_with_odd_bytes():
    from wrench import webapp, webauth
    csv_text = webapp._fleet_csv([{
        "node_id": "\t=cmd", "silent": False, "color": "green", "last_seen": 0,
        "findings": [{"severity": "critical", "text": "\r@SUM(1)"}]}])
    assert "'\t=cmd" in csv_text and "'\r@SUM" in csv_text
    a = webauth.AuthConfig(admin_token="tok")
    assert a.role_for_session("admin.999.\xe9") is None         # no TypeError
    assert a.role_for_token("\udcff") is None


def test_posture_evidence_history_and_checklist(tmp_path):
    class Cfg:
        patrol_interval_min = 15
        provider = "none"
        api_key = ""
        base_url = ""
    store = Store(tmp_path / "w.db")
    assert posture.evidence(Cfg(), store, "nope") is None
    ev = posture.evidence(Cfg(), store, "backups")
    assert ev["score"] is None and ev["items"] == [] and ev["explain"]
    store.add_sample("os", {"disk_pct": {"/": 93.0, "/data": 40.0}, "mem_pct": 50.0})
    store.add_snapshot("backups_report", {"no_jobs": True, "jobs": []})
    store.add_snapshot("security_scan", {"counts": {"critical": 1, "warning": 0},
                                         "baseline_exists": True,
                                         "findings": [{"severity": "critical", "title": "new root account",
                                                       "detail": "uid 0: backdoor"}]})
    cap = posture.evidence(Cfg(), store, "capacity")
    assert cap["items"][0]["state"] == "critical" and "93%" in cap["items"][0]["title"]
    assert posture.evidence(Cfg(), store, "security")["items"][0]["title"] == "new root account"
    assert "no backup job" in posture.evidence(Cfg(), store, "backups")["items"][0]["title"]
    # history + trend
    assert posture.record(Cfg(), store, now=1000.0, min_gap_s=0)["score"] is not None
    assert posture.record(Cfg(), store, min_gap_s=3600) is None          # throttled
    pts = [{"ts": 0, "score": 70.0}, {"ts": 8 * 86400, "score": 82.0}]
    assert posture.trend(pts, now=8 * 86400)["delta"] == 12.0
    assert posture.trend(pts[:1])["delta"] is None
    # checklist: nothing done on a box with no patrol, and it names the commands
    steps = {s["key"]: s for s in posture.checklist(Cfg(), store)}
    assert not steps["patrol"]["done"] and steps["patrol"]["command"] == "wrench patrol"
    assert not steps["brain"]["done"] and not steps["backups"]["done"]
    assert steps["baseline"]["done"]
    store.close()
