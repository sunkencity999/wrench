"""Prometheus exporter — hand-rolled text exposition, zero new dependencies.

``render()`` produces the standard text format (version 0.0.4) from the same
sqlite store and notification inbox everything else reads. It is served at
``/metrics`` on the web dashboard and by ``wrench metrics serve``; ``wrench
metrics`` prints one scrape to stdout (handy for node_exporter's textfile
collector).

Counters here are derived from retained history (``retention_days`` window for
patrols; the audit log for blueprints), so after a prune they can go down —
Prometheus treats that as a counter reset, which is exactly what it is.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import __version__


def _esc(v: object) -> str:
    """Escape a label value per the exposition format."""
    return (str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"'))


class _Buf:
    def __init__(self):
        self.lines: list[str] = []
        self._typed: set[str] = set()

    def metric(self, name: str, help_: str, mtype: str) -> None:
        if name not in self._typed:
            self._typed.add(name)
            self.lines.append(f"# HELP {name} {help_}")
            self.lines.append(f"# TYPE {name} {mtype}")

    def sample(self, name: str, value, labels: dict | None = None) -> None:
        if value is None:
            return
        lab = ""
        if labels:
            lab = "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items()) + "}"
        v = float(value)
        rendered = str(int(v)) if v.is_integer() else repr(v)  # full precision
        self.lines.append(f"{name}{lab} {rendered}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def render(store, data_dir: Path) -> str:
    """One scrape: sensors, notifications, certs, patrols, blueprints, drift."""
    b = _Buf()

    b.metric("wrench_info", "wrench build info.", "gauge")
    b.sample("wrench_info", 1, {"version": __version__})

    # ---- sensor gauges (latest os sample) ----
    last = store.last_sample("os")
    if last:
        ts, os_ = last
        b.metric("wrench_sample_timestamp_seconds",
                 "Unix time of the newest os sensor sample.", "gauge")
        b.sample("wrench_sample_timestamp_seconds", ts)
        b.metric("wrench_cpu_percent", "CPU utilization percent.", "gauge")
        b.sample("wrench_cpu_percent", os_.get("cpu_pct"))
        b.metric("wrench_mem_percent", "Memory utilization percent.", "gauge")
        b.sample("wrench_mem_percent", os_.get("mem_pct"))
        b.metric("wrench_swap_percent", "Swap utilization percent.", "gauge")
        b.sample("wrench_swap_percent", os_.get("swap_pct"))
        b.metric("wrench_disk_percent", "Disk utilization percent per mount.", "gauge")
        for mount, pct in (os_.get("disk_pct") or {}).items():
            b.sample("wrench_disk_percent", pct, {"mount": mount})
        b.metric("wrench_load_1m", "1-minute load average.", "gauge")
        b.sample("wrench_load_1m", os_.get("load_1m"))
        b.metric("wrench_procs", "Process count.", "gauge")
        b.sample("wrench_procs", os_.get("n_procs"))
        b.metric("wrench_uptime_seconds", "Host uptime in seconds.", "gauge")
        b.sample("wrench_uptime_seconds", os_.get("uptime_s"))
        b.metric("wrench_net_receive_kilobytes_per_second",
                 "Network receive rate (KB/s) at last sample.", "gauge")
        b.sample("wrench_net_receive_kilobytes_per_second",
                 os_.get("net_recv_rate_kbs"))
        b.metric("wrench_net_transmit_kilobytes_per_second",
                 "Network transmit rate (KB/s) at last sample.", "gauge")
        b.sample("wrench_net_transmit_kilobytes_per_second",
                 os_.get("net_sent_rate_kbs"))

    b.metric("wrench_anomalies_24h",
             "Sensor anomalies (|z| >= 3) flagged in the last 24h.", "gauge")
    b.sample("wrench_anomalies_24h", len(store.recent_anomalies(86400)))

    # ---- notifications by severity ----
    try:
        from . import notifications
        rows = notifications.read_all(data_dir)
    except Exception:  # noqa: BLE001
        rows = []
    by_sev: dict[str, int] = {}
    unread = 0
    for r in rows:
        sev = (r.get("severity") or "unknown").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        if not r.get("read"):
            unread += 1
    b.metric("wrench_notifications_total",
             "Notifications recorded in the inbox, by severity.", "counter")
    for sev in sorted(by_sev):
        b.sample("wrench_notifications_total", by_sev[sev], {"severity": sev})
    b.metric("wrench_notifications_unread", "Unread notifications.", "gauge")
    b.sample("wrench_notifications_unread", unread)

    # ---- certificates: days to expiry per cert ----
    try:
        certs = store.recent_certs()
    except Exception:  # noqa: BLE001
        certs = []
    import re as _re
    b.metric("wrench_cert_expiry_days",
             "Days until certificate expiry (negative = expired).", "gauge")
    b.metric("wrench_cert_not_after_timestamp_seconds",
             "Certificate notAfter as Unix time.", "gauge")
    tracked = 0
    for c in certs:
        if c.get("error"):
            continue
        tracked += 1
        m = _re.search(r"CN\s*=\s*([^,/]+)", c.get("subject") or "")
        cn = m.group(1).strip() if m else (c.get("sans") or [c["path"]])[0]
        labels = {"cn": cn, "path": c["path"]}
        if c.get("days_left") is not None:
            b.sample("wrench_cert_expiry_days", c["days_left"], labels)
        if c.get("not_after"):
            b.sample("wrench_cert_not_after_timestamp_seconds",
                     c["not_after"], labels)
    b.metric("wrench_certs_tracked", "Certificates in the inventory.", "gauge")
    b.sample("wrench_certs_tracked", tracked)

    # ---- patrols ----
    patrols = store.recent_patrols(1000)
    by_status: dict[str, int] = {}
    for p in patrols:
        st = (p.get("status") or "unknown").lower()
        by_status[st] = by_status.get(st, 0) + 1
    b.metric("wrench_patrols_total",
             "Patrol runs in retained history, by status.", "counter")
    for st in sorted(by_status):
        b.sample("wrench_patrols_total", by_status[st], {"status": st})
    b.metric("wrench_patrol_last_run_timestamp_seconds",
             "Unix time of the newest patrol run.", "gauge")
    b.metric("wrench_patrol_last_ok_timestamp_seconds",
             "Unix time of the newest patrol with status ok.", "gauge")
    if patrols:
        b.sample("wrench_patrol_last_run_timestamp_seconds", patrols[0]["ts"])
        ok_ts = next((p["ts"] for p in patrols if p.get("status") == "ok"), None)
        b.sample("wrench_patrol_last_ok_timestamp_seconds", ok_ts)

    # ---- blueprints (from the audit log) ----
    applies = rollbacks = failures = 0
    try:
        from . import blueprint as bp

        class _Cfg:  # history() only needs data_dir
            pass
        _c = _Cfg()
        _c.data_dir = data_dir
        for r in bp.history(_c, n=10000):
            if r.get("ok"):
                applies += 1
            elif r.get("rolled_back"):
                rollbacks += 1
            else:
                failures += 1
    except Exception:  # noqa: BLE001
        pass
    b.metric("wrench_blueprint_applies_total",
             "Blueprint applications that succeeded.", "counter")
    b.sample("wrench_blueprint_applies_total", applies)
    b.metric("wrench_blueprint_rollbacks_total",
             "Blueprint applications rolled back after a failed check.", "counter")
    b.sample("wrench_blueprint_rollbacks_total", rollbacks)
    b.metric("wrench_blueprint_failures_total",
             "Blueprint applications that failed without a clean rollback.", "counter")
    b.sample("wrench_blueprint_failures_total", failures)

    # ---- drift ----
    diffs = store.recent_diffs(86400 * 7)
    b.metric("wrench_drift_changes_7d",
             "Drift change events recorded in the last 7 days.", "gauge")
    b.sample("wrench_drift_changes_7d", len(diffs))
    b.metric("wrench_drift_last_change_timestamp_seconds",
             "Unix time of the newest drift change.", "gauge")
    if diffs:
        b.sample("wrench_drift_last_change_timestamp_seconds",
                 max(d["ts"] for d in diffs))

    # ---- security ----
    try:
        from .security import BASELINE_KIND, LASTSCAN_KIND
        last_scan = store.last_snapshot(LASTSCAN_KIND)
        b.metric("wrench_security_findings",
                 "Security findings in the newest scan, by severity.", "gauge")
        counts = (last_scan[1].get("counts", {}) if last_scan else {})
        for sev in ("critical", "warning", "info"):
            b.sample("wrench_security_findings", counts.get(sev, 0),
                     {"severity": sev})
        b.metric("wrench_security_last_scan_timestamp_seconds",
                 "Unix time of the newest security scan.", "gauge")
        if last_scan:
            b.sample("wrench_security_last_scan_timestamp_seconds", last_scan[0])
        b.metric("wrench_security_baseline_accepted",
                 "1 when a security baseline has been accepted.", "gauge")
        b.sample("wrench_security_baseline_accepted",
                 1 if store.last_snapshot(BASELINE_KIND) else 0)
        if last_scan:
            comp = last_scan[1].get("components", {})
            lst = comp.get("listeners", {})
            b.metric("wrench_security_listeners",
                     "Listening sockets at the newest security scan.", "gauge")
            b.sample("wrench_security_listeners", lst.get("count", 0))
            b.metric("wrench_security_listeners_ownerless",
                     "Listeners with no attributable owner at the newest scan.",
                     "gauge")
            b.sample("wrench_security_listeners_ownerless", lst.get("ownerless", 0))
            cve = comp.get("cve", {})
            if cve.get("available"):
                b.metric("wrench_security_cves_known",
                         "Known CVEs matched against installed packages.", "gauge")
                b.sample("wrench_security_cves_known", cve.get("vuln_count", 0))
    except Exception:  # noqa: BLE001 — a scrape never dies on one family
        pass

    # ---- backups (from the last verification report) ----
    try:
        from .backups import BACKUPS_KIND, job_severity_dict
        bk = store.last_snapshot(BACKUPS_KIND)
        if bk:
            _, rep = bk
            b.metric("wrench_backup_jobs",
                     "Backup jobs detected at the newest verification scan.", "gauge")
            b.sample("wrench_backup_jobs", rep.get("count", 0))
            b.metric("wrench_backup_freshness_seconds",
                     "Seconds since each backup job last ran.", "gauge")
            b.metric("wrench_backup_job_severity",
                     "Severity rank per backup job (0 none, 1 info, 2 warning, "
                     "3 critical).", "gauge")
            rank = {"none": 0, "info": 1, "warning": 2, "critical": 3}
            for j in rep.get("jobs", []):
                if j.get("age_s") is not None:
                    b.sample("wrench_backup_freshness_seconds", round(j["age_s"]),
                             {"job": j["name"]})
                b.sample("wrench_backup_job_severity",
                         rank.get(job_severity_dict(j), 0), {"job": j["name"]})
    except Exception:  # noqa: BLE001
        pass

    # ---- compliance (from the last comply scan snapshot) ----
    try:
        from .comply import BASELINE_KIND as _CB, SCAN_KIND as _CS
        snap = store.last_snapshot(_CS)
        if snap:
            _, rep = snap
            b.metric("wrench_comply_score",
                     "Compliance score percentage per pack at the newest scan.",
                     "gauge")
            b.metric("wrench_comply_fails",
                     "Failing compliance rules per pack and severity.", "gauge")
            for p in rep.get("packs", []):
                if p.get("score") is not None:      # an ungradable pack has no score
                    b.sample("wrench_comply_score", p["score"], {"pack": p["pack"]})
                for sev, n in (p.get("severity_fails") or {}).items():
                    b.sample("wrench_comply_fails", n,
                             {"pack": p["pack"], "severity": sev})
            b.metric("wrench_comply_baseline_accepted",
                     "1 when a compliance baseline has been accepted by "
                     "consent.", "gauge")
            b.sample("wrench_comply_baseline_accepted",
                     1 if store.last_snapshot(_CB) else 0)
    except Exception:  # noqa: BLE001
        pass

    # ---- capacity forecast (from the last computed feed snapshot) ----
    try:
        from .forecast import FORECAST_KIND
        snap = store.last_snapshot(FORECAST_KIND)
        b.metric("wrench_forecast_incidents",
                 "Projected future incidents by lead-time severity.", "gauge")
        counts = (snap[1].get("counts", {}) if snap else {})
        for sev in ("critical", "warning", "info"):
            b.sample("wrench_forecast_incidents", counts.get(sev, 0),
                     {"severity": sev})
        b.metric("wrench_forecast_days_to_threshold",
                 "Projected days until a resource crosses its danger threshold.",
                 "gauge")
        b.metric("wrench_forecast_growth_per_day",
                 "Fitted growth rate per day (percent for capacity metrics).",
                 "gauge")
        if snap:
            for inc in snap[1].get("incidents", []):
                if inc.get("kind") == "cert":
                    continue  # certs already have wrench_cert_expiry_days
                labels = {"kind": inc.get("kind"), "resource": inc.get("resource")}
                if inc.get("eta_days") is not None:
                    b.sample("wrench_forecast_days_to_threshold",
                             inc["eta_days"], labels)
                if inc.get("unit") == "%":
                    b.sample("wrench_forecast_growth_per_day",
                             inc.get("growth_per_day"), labels)
        b.metric("wrench_forecast_last_run_timestamp_seconds",
                 "Unix time of the newest capacity-forecast computation.", "gauge")
        if snap:
            b.sample("wrench_forecast_last_run_timestamp_seconds", snap[0])
    except Exception:  # noqa: BLE001 — a scrape never dies on one family
        pass

    # ---- audit log (hash-chained, tamper-evident) ----
    try:
        from . import audit
        chain = audit.verify(data_dir)
        b.metric("wrench_audit_entries",
                 "Sealed records in the audit chain (incl. genesis).", "gauge")
        b.sample("wrench_audit_entries", chain.get("count", 0))
        b.metric("wrench_audit_intact",
                 "1 when the audit hash chain verifies end-to-end, 0 when broken.",
                 "gauge")
        b.sample("wrench_audit_intact", 1 if chain.get("intact") else 0)
        recs = audit.recent(data_dir, limit=1)
        b.metric("wrench_audit_last_event_timestamp_seconds",
                 "Unix time of the newest audit event.", "gauge")
        if recs:
            b.sample("wrench_audit_last_event_timestamp_seconds", recs[-1].get("ts"))
    except Exception:  # noqa: BLE001 — a scrape never dies on one family
        pass

    # ---- approvals (async webhook approval tokens) ----
    try:
        rows = store.recent_approvals(1000)
        now = time.time()
        states = {"pending": 0, "approved": 0, "claimed": 0, "expired": 0}
        for r in rows:
            if r["claimed"]:
                states["claimed"] += 1
            elif r["approved"]:
                states["approved"] += 1
            elif now > r["expires"]:
                states["expired"] += 1
            else:
                states["pending"] += 1
        b.metric("wrench_approvals",
                 "Approval tokens by state (pending/approved/claimed/expired).",
                 "gauge")
        for stt, n in sorted(states.items()):
            b.sample("wrench_approvals", n, {"state": stt})
    except Exception:  # noqa: BLE001
        pass

    # ---- fleet (hub side: aggregated node reports + dead-man's switch) ----
    try:
        from . import fleet
        nodes = store.fleet_nodes()
        if nodes:
            from .config import load_config
            try:
                st = fleet.settings_from(load_config())
            except Exception:  # noqa: BLE001
                st = fleet.FleetSettings()
            states = fleet.node_states(store, st)
            summ = fleet.fleet_summary(states)
            b.metric("wrench_fleet_nodes", "Nodes known to this fleet hub.", "gauge")
            b.sample("wrench_fleet_nodes", summ["total"])
            b.metric("wrench_fleet_nodes_silent",
                     "Nodes whose last report is older than factor × cadence.", "gauge")
            b.sample("wrench_fleet_nodes_silent", summ["silent"])
            b.metric("wrench_fleet_nodes_by_color",
                     "Fleet nodes by grid color (green/yellow/red/silent).", "gauge")
            for color in ("green", "yellow", "red", "silent"):
                b.sample("wrench_fleet_nodes_by_color", summ.get(color, 0),
                         {"color": color})
            color_rank = {"green": 0, "yellow": 1, "red": 2, "silent": 3}
            b.metric("wrench_fleet_node_status",
                     "Per-node status rank (0 ok, 1 attention, 2 critical, 3 silent).",
                     "gauge")
            b.metric("wrench_fleet_node_last_seen_timestamp_seconds",
                     "Unix time of each node's most recent report.", "gauge")
            b.metric("wrench_fleet_node_reports_total",
                     "Reports received from each node.", "counter")
            for n in states:
                lab = {"node": n["node_id"], "hostname": n.get("hostname") or ""}
                b.sample("wrench_fleet_node_status",
                         color_rank.get(n.get("color"), 0), lab)
                if n.get("last_seen"):
                    b.sample("wrench_fleet_node_last_seen_timestamp_seconds",
                             n["last_seen"], lab)
                b.sample("wrench_fleet_node_reports_total",
                         n.get("report_count", 0), lab)
    except Exception:  # noqa: BLE001 — a scrape never dies on one family
        pass

    # ---- posture: the health score and its pillars ----
    try:
        from . import posture
        from .config import load_config
        pos = posture.compute(load_config(), store)
        if pos.get("score") is not None:
            b.metric("wrench_health_score", "Overall health score, 0-100.", "gauge")
            b.sample("wrench_health_score", pos["score"])
        b.metric("wrench_health_pillar_score",
                 "Health score per pillar, 0-100 (absent when the pillar is unmeasured).",
                 "gauge")
        for pl in pos["pillars"]:
            if pl["score"] is not None:
                b.sample("wrench_health_pillar_score", pl["score"], {"pillar": pl["key"]})
        b.metric("wrench_health_pillars_measured",
                 "How many posture pillars have data.", "gauge")
        b.sample("wrench_health_pillars_measured", pos["coverage"]["measured"])
    except Exception:  # noqa: BLE001 — metrics never fail the scrape
        pass

    b.metric("wrench_scrape_timestamp_seconds", "Unix time of this scrape.", "gauge")
    b.sample("wrench_scrape_timestamp_seconds", time.time())
    return b.text()


CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def serve(db_path, port: int = 9465, bind: str = "127.0.0.1"):
    """A bare metrics-only HTTP server (no dashboard, no chat)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from .store import Store

    data_dir = Path(db_path).parent

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def do_GET(self):  # noqa: N802
            if self.path.split("?")[0] not in ("/metrics", "/"):
                self.send_response(404)
                self.end_headers()
                return
            store = Store(db_path)
            try:
                body = render(store, data_dir).encode()
            finally:
                store.close()
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer((bind, port), Handler)
