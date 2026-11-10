"""Backup verification — detection, ladder, severities, patrol, metrics."""

from __future__ import annotations

import time

import pytest

import os

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX paths / permission bits")

from wrench import backups as bk
from wrench.backups import (BackupJob, _cadence_from_cron, _follow_wrapper,
                            _parse_cron_text, _parse_src_dest, _timer_cadence,
                            _tool_in_command, job_severity, job_severity_dict,
                            narration_lines)


# ---- command-line tool recognition -----------------------------------------


def test_tool_in_command_direct():
    assert _tool_in_command("/usr/bin/borg create ::arch /etc") == "borg"
    assert _tool_in_command("restic -r /srv/repo backup /home") == "restic"
    assert _tool_in_command("rsync -a /src/ /dst/") == "rsync"
    assert _tool_in_command("pg_dump -f /tmp/db.sql mydb") == "pg_dump"


def test_tool_in_command_negative():
    assert _tool_in_command("echo hello world") == ""
    assert _tool_in_command("python3 /opt/notbackup.py") == ""
    # tool name embedded in another word must not match
    assert _tool_in_command("/usr/bin/borgmatic-like-tool run") == ""


def test_tool_in_command_unbalanced_quotes():
    # shlex would raise; fallback splitter must survive
    assert _tool_in_command("borg create 'unterminated") == "borg"


# ---- cron parsing -----------------------------------------------------------


CRON_SYSTEM = """\
SHELL=/bin/sh
# m h dom mon dow user command
30 2 * * * root /usr/bin/borg create ::daily-{now} /etc /home
0 3 * * 0 root rsync -a /data/ /mnt/backup/data/
15 * * * * root /usr/local/bin/other-task
"""


def test_parse_cron_system_finds_backup_jobs():
    jobs = _parse_cron_text(CRON_SYSTEM, "/etc/crontab", has_user_field=True)
    tools = sorted(j.tool for j in jobs)
    assert tools == ["borg", "rsync"]
    borg = next(j for j in jobs if j.tool == "borg")
    assert borg.cadence_s == pytest.approx(86400.0)
    rsync = next(j for j in jobs if j.tool == "rsync")
    assert rsync.cadence_s == pytest.approx(7 * 86400.0)
    assert rsync.source == "/data/"
    assert rsync.dest == "/mnt/backup/data/"


def test_parse_cron_user_no_user_field():
    text = "@daily pg_dump -f /var/backups/app.sql appdb\n"
    jobs = _parse_cron_text(text, "crontab(user)", has_user_field=False)
    assert len(jobs) == 1
    assert jobs[0].tool == "pg_dump"
    assert jobs[0].dest == "/var/backups/app.sql"
    assert jobs[0].schedule == "@daily"
    assert jobs[0].cadence_s == pytest.approx(86400.0)


def test_parse_cron_skips_comments_env_and_nonbackup():
    text = "# 0 1 * * * root borg create ::x /etc\nPATH=/usr/bin\n0 1 * * * root ls /\n"
    assert _parse_cron_text(text, "/etc/crontab", has_user_field=True) == []


def test_cadence_from_cron_ladder():
    assert _cadence_from_cron("*/5", "*", "*", "*")[0] == pytest.approx(3600.0)
    assert _cadence_from_cron("0", "*", "*", "*")[0] == pytest.approx(3600.0)
    assert _cadence_from_cron("0", "2", "*", "*")[0] == pytest.approx(86400.0)
    assert _cadence_from_cron("0", "2", "*", "0")[0] == pytest.approx(7 * 86400.0)
    assert _cadence_from_cron("0", "2", "1", "*")[0] == pytest.approx(30 * 86400.0)


def test_timer_cadence():
    assert _timer_cadence("daily") == pytest.approx(86400.0)
    assert _timer_cadence("Sun *-*-* 03:00:00") == pytest.approx(7 * 86400.0) or \
        _timer_cadence("Sun *-*-* 03:00:00") == pytest.approx(86400.0)
    assert _timer_cadence("") == pytest.approx(bk.DEFAULT_CADENCE_S)


# ---- wrapper following + env resolution -------------------------------------


@posix_only
def test_follow_wrapper_resolves_tool_and_env(tmp_path):
    script = tmp_path / "nightly-backup.sh"
    script.write_text(
        "#!/bin/bash\n"
        "# backs up the world\n"
        'export BORG_REPO="/srv/backups/borg-main"\n'
        'borg create --stats "::nightly-{now}" /etc /home\n')
    script.chmod(0o755)
    tool, path, inner, env = _follow_wrapper(str(script))
    assert tool == "borg"
    assert path == str(script)
    assert env["BORG_REPO"] == "/srv/backups/borg-main"
    out = _parse_src_dest("borg", inner, env)
    assert out["dest"] == "/srv/backups/borg-main"
    assert "/etc" in out["source"]


@posix_only
def test_follow_wrapper_substitutes_vars(tmp_path):
    script = tmp_path / "dump.sh"
    script.write_text(
        'DEST="/var/backups/db.sql"\n'
        "pg_dump -f $DEST mydb\n")
    tool, _path, inner, env = _follow_wrapper(str(script))
    assert tool == "pg_dump"
    assert _parse_src_dest("pg_dump", inner, env)["dest"] == "/var/backups/db.sql"


def test_follow_wrapper_nonscript_returns_empty(tmp_path):
    assert _follow_wrapper("/nonexistent/script.sh") == ("", "", "", {})
    data = tmp_path / "blob.tar"
    data.write_text("not a script")
    assert _follow_wrapper(str(data))[0] == ""


# ---- src/dest parsing per tool ----------------------------------------------


def test_parse_src_dest_borg_explicit_repo():
    out = _parse_src_dest("borg", "borg create /srv/repo::arch-{now} /etc /home /var")
    assert out["dest"] == "/srv/repo"
    assert out["source"] == "/etc /home /var"


def test_parse_src_dest_restic():
    out = _parse_src_dest("restic", "restic -r /srv/restic backup /home")
    assert out["dest"] == "/srv/restic"
    assert "/home" in out["source"]


def test_parse_src_dest_mysqldump_redirect():
    out = _parse_src_dest("mysqldump", "mysqldump appdb > /var/backups/app.sql")
    assert out["dest"] == "/var/backups/app.sql"


# ---- freshness (L1) ----------------------------------------------------------


def _job(**kw) -> BackupJob:
    base = dict(name="t:j", tool="rsync", command="rsync -a /a/ /b/",
                origin="/etc/crontab")
    base.update(kw)
    return BackupJob(**base)


@posix_only
def test_freshness_fresh_via_dest_mtime(tmp_path):
    dest = tmp_path / "backupdir"
    dest.mkdir()
    (dest / "latest").write_text("x")
    j = _job(dest=str(dest), cadence_s=86400.0)
    bk.check_freshness(j, now=time.time())
    assert j.freshness == "fresh"
    assert j.last_run_evidence == "dest-mtime"


@posix_only
def test_freshness_stale_when_old(tmp_path):
    import os
    dest = tmp_path / "old"
    dest.mkdir()
    old = time.time() - 10 * 86400
    os.utime(dest, (old, old))
    j = _job(dest=str(dest), cadence_s=86400.0)
    bk.check_freshness(j, now=time.time())
    assert j.freshness == "stale"


def test_freshness_unknown_without_evidence():
    j = _job(dest="")
    bk.check_freshness(j)
    assert j.freshness == "unknown"
    assert j.last_run_ts is None


def test_freshness_remote_dest_is_unknown():
    j = _job(dest="user@host:/srv/backup")
    bk.check_freshness(j)
    assert j.freshness == "unknown"


def test_parse_systemd_ts():
    ts = bk._parse_systemd_ts("Wed 2026-11-04 02:30:01 PST")
    assert ts is not None and ts > 0
    assert bk._parse_systemd_ts("") is None
    assert bk._parse_systemd_ts("n/a") is None


# ---- integrity (L2) ----------------------------------------------------------


def test_integrity_dump_ok_and_empty(tmp_path):
    good = tmp_path / "db.sql"
    good.write_text("CREATE TABLE ...")
    j = _job(tool="pg_dump", dest=str(good))
    bk.check_integrity(j)
    assert j.integrity == "ok"

    empty = tmp_path / "empty.sql"
    empty.write_text("")
    j2 = _job(tool="pg_dump", dest=str(empty))
    bk.check_integrity(j2)
    assert j2.integrity == "failed"


@posix_only
def test_integrity_rsync_local_and_remote(tmp_path):
    j = _job(tool="rsync", dest=str(tmp_path))
    bk.check_integrity(j)
    assert j.integrity == "ok"

    j2 = _job(tool="rsync", dest="user@host:/srv/x")
    bk.check_integrity(j2)
    assert j2.integrity == "skipped"


def test_integrity_borg_states(monkeypatch):
    j = _job(tool="borg", dest="/srv/repo")

    monkeypatch.setattr(bk, "_run", lambda *a, **k: (0, "arch-2026\n"))
    bk.check_integrity(j)
    assert j.integrity == "ok" and "arch-2026" in j.integrity_note

    monkeypatch.setattr(bk, "_run", lambda *a, **k: (2, "passphrase required"))
    bk.check_integrity(j)
    assert j.integrity == "locked"

    monkeypatch.setattr(bk, "_run",
                        lambda *a, **k: (2, "Failed to create/acquire the lock"))
    bk.check_integrity(j)
    assert j.integrity == "locked"

    monkeypatch.setattr(bk, "_run", lambda *a, **k: (2, "repository does not exist"))
    bk.check_integrity(j)
    assert j.integrity == "failed"

    monkeypatch.setattr(bk, "_run", lambda *a, **k: (0, ""))
    bk.check_integrity(j)
    assert j.integrity == "failed"      # zero archives


def test_integrity_unparsed_repo_is_unknown():
    j = _job(tool="borg", dest="")
    bk.check_integrity(j)
    assert j.integrity == "unknown"


# ---- restore test (L3) -------------------------------------------------------


def test_restore_test_borg_ok(monkeypatch):
    calls = []

    def fake_run(argv, timeout=0, env=None):
        calls.append(argv)
        if argv[:2] == ["borg", "list"]:
            return 0, "latest-arch\n"
        if argv[:2] == ["borg", "extract"]:
            assert "--dry-run" in argv
            return 0, ""
        return 1, "?"

    monkeypatch.setattr(bk, "_run", fake_run)
    j = _job(tool="borg", dest="/srv/repo")
    bk.restore_test(j)
    assert j.restore_test == "ok"
    assert any("extract" in c for call in calls for c in call)


def test_restore_test_unsupported_tool():
    j = _job(tool="rsync")
    bk.restore_test(j)
    assert j.restore_test == "unsupported"


# ---- severity ladder ---------------------------------------------------------


def test_job_severity_ladder():
    assert job_severity(_job(freshness="fresh", integrity="ok")) == "none"
    assert job_severity(_job(freshness="stale", integrity="ok")) == "warning"
    assert job_severity(_job(freshness="fresh", integrity="failed")) == "critical"
    assert job_severity(_job(freshness="unknown", integrity="unknown")) == "warning"
    assert job_severity(_job(freshness="fresh", integrity="locked")) == "info"
    assert job_severity_dict({"freshness": "stale", "integrity": "ok"}) == "warning"


# ---- scan / patrol / notify --------------------------------------------------


class _FakeStore:
    def __init__(self):
        self.snapshots = {}

    def add_snapshot(self, kind, payload):
        self.snapshots[kind] = (time.time(), payload)

    def last_snapshot(self, kind):
        return self.snapshots.get(kind)


def test_scan_empty_box_warns(monkeypatch):
    monkeypatch.setattr(bk, "detect_jobs", lambda: [])
    monkeypatch.setattr(bk, "detection_supported", lambda: True)
    store = _FakeStore()
    rep = bk.scan(None, store)
    assert rep["no_jobs"] is True
    assert rep["worst"] == "warning"
    assert bk.BACKUPS_KIND in store.snapshots


def test_scan_persists_and_counts(monkeypatch, tmp_path):
    dest = tmp_path / "d"
    dest.mkdir()
    jobs = [_job(name="a", dest=str(dest)), _job(name="b", dest="")]
    monkeypatch.setattr(bk, "detect_jobs", lambda: jobs)
    store = _FakeStore()
    rep = bk.scan(None, store)
    assert rep["count"] == 2
    assert rep["worst"] == "warning"       # job b: unknown/unknown
    assert rep["severity_counts"].get("warning") == 1


def test_notify_scan_no_jobs(monkeypatch):
    sent = {}

    def fake_emit(cfg, kind, severity, summary, **kw):
        sent.update(kind=kind, severity=severity, summary=summary)
        return {"ok": True}

    import wrench.notifications as notif
    monkeypatch.setattr(notif, "emit_event", fake_emit)
    bk.notify_scan(None, {"no_jobs": True})
    assert sent["severity"] == "warning"
    assert "no backup jobs" in sent["summary"]


def test_notify_scan_worst_none_is_silent(monkeypatch):
    import wrench.notifications as notif
    monkeypatch.setattr(notif, "emit_event",
                        lambda *a, **k: pytest.fail("should not notify"))
    assert bk.notify_scan(None, {"no_jobs": False, "worst": "none",
                                 "jobs": []}) is None


def test_patrol_findings_uses_cache(monkeypatch):
    store = _FakeStore()
    store.add_snapshot(bk.BACKUPS_KIND, {
        "no_jobs": False,
        "jobs": [{"name": "borg:x", "freshness": "stale", "integrity": "ok",
                  "integrity_note": ""}],
    })
    monkeypatch.setattr(bk, "scan",
                        lambda *a, **k: pytest.fail("cache should be used"))
    out = bk.patrol_findings(None, store, cadence_s=3600)
    assert out == [{"severity": "warning", "area": "backups",
                    "summary": "borg:x: freshness=stale, integrity=ok"}]


def test_patrol_findings_never_raises(monkeypatch):
    class Boom:
        def last_snapshot(self, kind):
            raise RuntimeError("db gone")

    assert bk.patrol_findings(None, Boom()) == []


def test_patrol_summary_line(monkeypatch):
    store = _FakeStore()
    store.add_snapshot(bk.BACKUPS_KIND, {
        "no_jobs": False, "count": 2, "worst": "info",
        "jobs": [{"freshness": "fresh"}, {"freshness": "stale"}],
    })
    line = bk.patrol_summary_line(None, store)
    assert "2 job(s)" in line and "1 fresh" in line and "worst=info" in line


def test_narration_lines():
    rep = {"no_jobs": False,
           "jobs": [{"name": "borg:x", "tool": "borg", "origin": "t.timer",
                     "schedule": "daily", "age_s": 7200.0,
                     "last_run_evidence": "systemd", "freshness": "fresh",
                     "integrity": "ok", "integrity_note": "latest: a1"}]}
    lines = narration_lines(rep)
    assert len(lines) == 1
    assert "borg:x" in lines[0] and "2.0h ago" in lines[0]
    assert narration_lines({"no_jobs": True})[0].startswith("No backup jobs")


# ---- metrics exporter --------------------------------------------------------


def test_metrics_include_backup_gauges(tmp_path):
    from wrench.metrics import render
    from wrench.store import Store
    store = Store(tmp_path / "t.sqlite")
    store.add_snapshot(bk.BACKUPS_KIND, {
        "count": 2, "no_jobs": False, "worst": "warning",
        "jobs": [
            {"name": "borg:x", "age_s": 3600.0, "freshness": "fresh",
             "integrity": "ok"},
            {"name": "rsync:y", "age_s": None, "freshness": "unknown",
             "integrity": "unknown"},
        ],
    })
    text = render(store, tmp_path)
    assert "wrench_backup_jobs 2" in text
    assert 'wrench_backup_freshness_seconds{job="borg:x"} 3600' in text
    assert 'wrench_backup_job_severity{job="rsync:y"} 2' in text
    store.close()
