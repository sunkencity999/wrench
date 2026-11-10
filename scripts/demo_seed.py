#!/usr/bin/env python3
"""Seed a throwaway wrench data dir with a realistic, fictional machine and
fleet, then serve the dashboard — for screenshots, demos and UI work.

Nothing here reads the real machine: every hostname, process and finding is
made up, so the result is safe to publish.

    python scripts/demo_seed.py /tmp/wrench-demo            # seed + serve on :8799
    python scripts/demo_seed.py /tmp/wrench-demo --no-serve
"""

from __future__ import annotations

import math
import os
import random
import sys
import time
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    root = Path(sys.argv[1]).resolve()
    os.environ["WRENCH_DATA_DIR"] = str(root / "data")
    os.environ["WRENCH_CONFIG_DIR"] = str(root / "config")
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    from wrench import audit, fleet, notifications, webapp
    from wrench.config import load_config
    from wrench.store import Store

    cfg = load_config(provider_override="ollama", model_override="qwen2.5:14b")
    store = Store(cfg.db_path)
    rnd = random.Random(11)
    now = time.time()

    base = {
        "mem_used_gb": 19.8, "mem_total_gb": 32.0, "swap_pct": 4.0, "load_5m": 1.4,
        "load_15m": 1.2, "n_procs": 312, "uptime_s": 41 * 86400,
        "disk_pct": {"/": 61.0, "/var": 88.4, "/srv/data": 43.2},
        "inode_pct": {"/": 12.0, "/var": 31.0}, "log_dirs": {},
        "net_bytes_recv": 0, "net_bytes_sent": 0, "net_sent_rate_kbs": 40.0,
        "top_cpu": [{"name": "postgres", "cpu_pct": 38.2}, {"name": "nginx", "cpu_pct": 11.4},
                    {"name": "node", "cpu_pct": 7.9}, {"name": "redis-server", "cpu_pct": 2.1},
                    {"name": "sshd", "cpu_pct": 0.3}],
        "top_mem": [{"name": "postgres", "mem_pct": 24.6}, {"name": "node", "mem_pct": 9.8},
                    {"name": "redis-server", "mem_pct": 6.1}, {"name": "nginx", "mem_pct": 1.2},
                    {"name": "systemd-journald", "mem_pct": 0.7}],
    }
    for i in range(2000, 0, -1):                       # ~7 days at 5-minute steps
        t = now - i * 300
        day = math.sin((t % 86400) / 86400 * 2 * math.pi - 1.6)
        p = dict(base)
        p["cpu_pct"] = max(2, 24 + 16 * day + rnd.uniform(-6, 8) + (30 if 60 < i < 72 else 0))
        p["mem_pct"] = 60 + 5 * day + rnd.uniform(-1, 1)
        p["load_1m"] = max(0.1, 1.5 + 1.1 * day + rnd.uniform(-0.3, 0.5))
        p["net_recv_rate_kbs"] = max(0, 260 + 190 * day + rnd.uniform(-60, 120))
        p["disk_root_pct"] = 61.0
        p["disk_pct"] = {"/": 61.0, "/var": round(88.4 - i * 0.004, 1), "/srv/data": 43.2}
        store.add_sample("os", p, ts=t)

    store.add_snapshot("security_scan", {"counts": {"critical": 0, "warning": 1, "info": 2},
                                         "baseline_exists": True, "worst": "warning"})
    store.add_snapshot("comply_scan", {
        "packs": [{"pack": "cis-ubuntu-essentials", "score": 87.5,
                   "counts": {"pass": 35, "fail": 5, "skip": 0},
                   "severity_fails": {"critical": 0, "high": 2, "medium": 3, "low": 0}}],
        "fail_ids": ["sshd.passwordauth", "login.umask", "a", "b", "c"], "critical_fails": 0,
        "fails": []})
    store.add_snapshot("backups_report", {
        "ts": now, "count": 2, "no_jobs": False, "worst": "none", "severity_counts": {"none": 2},
        "jobs": [{"name": "borg:system", "freshness": "fresh", "integrity": "ok"},
                 {"name": "pg_dump:nightly", "freshness": "fresh", "integrity": "ok"}]})
    store.add_snapshot("forecast_feed", {
        "worst": "warning", "counts": {"critical": 0, "warning": 1, "info": 0, "none": 3},
        "soonest": {"kind": "disk", "resource": "/var", "eta_days": 6.0}, "incidents": []})
    store.upsert_cert({"path": "/etc/letsencrypt/live/shop.example.com/fullchain.pem",
                       "source": "nginx", "subject": "CN=shop.example.com", "days_left": 23})
    store.cache_put("webintel_scan", {
        "ts": now - 5400, "online": True, "packages_checked": 214,
        "vulns": [{"package": "aiohttp", "version": "3.9.1", "vuln_id": "GHSA-5m98-qgg9-wh84",
                   "aliases": ["CVE-2024-30251"], "severity": "high", "fixed": "3.9.4",
                   "summary": "Denial of service when parsing malformed POST requests"}],
        "eol": [{"label": "ubuntu 24.04: supported until 2029-05-31", "is_eol": False},
                {"label": "nodejs 18: REACHED EOL 2025-04-30", "is_eol": True}]})
    store.add_diff("ports", "port opened: tcp/8081 (python3)", ["port opened: tcp/8081 (python3)"])
    store.add_diff("packages", "2 packages upgraded",
                   ["package upgraded: openssl 3.0.13-0ubuntu3.6",
                    "package upgraded: libssl3 3.0.13-0ubuntu3.6"])
    store.add_diff("services", "service stopped: user:reports.service",
                   ["service stopped: user:reports.service"])
    findings = [
        {"severity": "warning", "text": "/var is at 88% and growing ~0.7%/day — "
                                        "PostgreSQL WAL archive holds 41 GB under /var/lib/postgresql/wal_archive"},
        {"severity": "warning", "text": "aiohttp 3.9.1 has a known high-severity CVE (fixed in 3.9.4)"},
        {"severity": "info", "text": "port opened since last scan: tcp/8081 (python3), bound to 127.0.0.1"},
        {"severity": "recommendation", "text": "wrench fixxer"},
    ]
    report_md = ("STATUS: attention\nSUMMARY: /var will cross 95% in about six days; "
                 "the WAL archive is the cause.\nFINDINGS:\n"
                 + "\n".join(f"- [{f['severity']}] {f['text']}" for f in findings[:3])
                 + "\nRECOMMENDATIONS:\n- wrench fixxer")
    store.add_patrol("qwen2.5:14b", "attention",
                     "/var will cross 95% in about six days; the WAL archive is the cause.",
                     findings, report_md, 18240)
    store.add_tokens("ollama", "qwen2.5:14b", 150000, 32000, 182000, "patrol")
    store.add_action("suggest", "diag:disk usage", "du -sh /var/lib/postgresql", True, "41G")
    store.add_action("suggest", "diag:journal read", "journalctl -u postgresql -n 50 --no-pager",
                     True, "")
    audit.append(cfg.data_dir, "security.baseline.accept", {"listeners": 9})
    notifications.record(cfg.data_dir, "attention",
                         "/var will cross 95% in about six days", kind="forecast")

    # ---- a fictional fleet ----
    st = fleet.FleetSettings(max_skew_s=0)
    key = fleet.enroll(store, label="demo")
    auth = fleet.AuthResult(True, credential="key:" + key["key_id"], key_id=key["key_id"], version=2)
    oses = [("linux", "Ubuntu 24.04.1 LTS"), ("linux", "Debian GNU/Linux 12"),
            ("linux", "Rocky Linux 9.4"), ("macos", "macOS 15.1"),
            ("windows", "Windows Server 2022 (20348)")]
    roster = [("db-01", "critical", 41, ["prod", "db"]), ("web-01", "ok", 94, ["prod", "web"]),
              ("web-02", "attention", 72, ["prod", "web"]), ("web-03", "ok", 91, ["prod", "web"]),
              ("build-win-03", "attention", 68, ["ci"]), ("dc-edge-07", "ok", 88, ["edge"]),
              ("design-mbp-14", "ok", 86, ["laptop"]), ("cache-01", "ok", 97, ["prod"]),
              ("queue-02", "attention", 74, ["prod"]), ("staging-01", "ok", 83, ["staging"])]
    texts = {"db-01": "disk /var/lib/postgresql is 96% full",
             "web-02": "certificate shop.example.com expires in 9d",
             "build-win-03": "compliance check failed — expected: SMBv1 server protocol is disabled",
             "queue-02": "backups: restic:queue-state is stale (2.4d)"}
    for i, (node, status, score, tags) in enumerate(roster):
        osn, label = (oses[4] if "win" in node else oses[3] if "mbp" in node else oses[i % 3])
        disk = {"/": rnd.randint(22, 70)} if osn != "windows" else {"C:\\": 77}
        if node == "db-01":
            disk["/var/lib/postgresql"] = 96
        text = texts.get(node)
        for back in (3, 2, 1, 0):                      # a little history per node
            ts = now - back * 900 - (700 if node == "dc-edge-07" else 0)
            fleet.ingest(store, st, {
                "node_id": node, "hostname": f"{node}.corp.example", "wrench_version": "3.0.0",
                "ts": ts, "status": status,
                "worst_severity": {"critical": "critical", "attention": "warning"}.get(status, "ok"),
                "cadence_s": 300 if node == "dc-edge-07" else 900,
                "summary": text or "all clear",
                "findings": [{"severity": "critical" if status == "critical" else "warning",
                              "text": text}] if text else [],
                "gauges": {"mem_pct": rnd.randint(28, 90), "cpu_pct": rnd.randint(3, 60),
                           "disk_pct": disk},
                "meta": {"os": osn, "os_label": label, "arch": "arm64" if osn == "macos" else "x86_64",
                         "score": score + rnd.randint(-2, 2) * (1 if back else 0),
                         "grade": "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70
                         else "D" if score >= 60 else "F",
                         "tags": tags, "uptime_s": rnd.randint(3600, 5_000_000),
                         "policy_tier": "suggest", "brain": "ollama",
                         "pillars": {"capacity": score, "security": 90, "compliance": 85,
                                     "backups": 100 if node != "queue-02" else 75}},
            }, auth, now=ts)
    store.close()
    print(f"seeded {root}")

    if "--no-serve" in sys.argv:
        return
    httpd = webapp.serve(cfg.db_path, port=8799, host_label="app-prod-01", bind="127.0.0.1",
                         sample_thread=False, cfg=cfg, fleet_hub=True,
                         os_label="Ubuntu 24.04.1 LTS")
    print("demo dashboard: http://127.0.0.1:8799/   fleet: http://127.0.0.1:8799/fleet")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
