# Machine-readable output — `--json`, `/metrics`, and SIEM sinks

wrench is scriptable end to end: every read/report command speaks JSON, the
dashboard exposes a Prometheus endpoint, and notifications can stream into a
syslog/SIEM pipeline. No formatting surprises, no scraping rich tables.

## `--json` — one stable JSON document per command

Every command below accepts `--json`. Output is **exactly one JSON object on
stdout** — no banners, no spinners, no color codes — so it pipes straight into
`jq`, CI assertions, or a collector. Exit codes keep their interactive meaning.

### The envelope

```json
{
  "schema": "wrench.status.v1",
  "generated_at": 1793909627.5,
  "host": "devbox",
  "version": "1.6.0",
  "...": "command-specific fields"
}
```

- `schema` — `wrench.<command>.v1`; the suffix only changes on a breaking
  change. Additive fields do **not** bump the version.
- `generated_at` — epoch seconds.
- `--json` commands are **read-only against wrench state**: unlike the rich
  view, `wrench report --json` does *not* mark notifications read. Use
  `wrench notifications --mark-read` when you want that explicitly.

### Commands and schemas

| command | schema | fields | exit code |
|---|---|---|---|
| `wrench status --json` | `wrench.status.v1` | `os` (cpu_pct, mem_pct, swap_pct, disk_pct{mount: pct}, load_1m/5m/15m, n_procs, uptime_s, net rates, top_cpu/top_mem), `docker`, `gpu` (null when absent), `anomalies_24h[]`, `unread_notifications` | 0 |
| `wrench report --json [-n N]` | `wrench.report.v1` | `count`, `patrols[]` — ts, status (`ok\|attention\|critical`), summary, model, tokens, findings[] | 0 |
| `wrench drift --json` | `wrench.drift.v1` | `baseline_recorded` (true on first scan), `change_count`, `changes[]` — kind (`ports\|services\|packages\|users\|cron`), changes[] (English lines) | 0 |
| `wrench certs --json` | `wrench.certs.v1` | `count`, `needing_attention`, `certs[]` — path, source, subject, common_name, issuer, days_left, expiry_severity (`info\|warning\|critical\|null`), sans[], key_type, key_bits, weak_key, is_ca, self_signed, chain_complete, fingerprint_sha256, error; `weaknesses[]` | 0 |
| `wrench certs audit --json` | `wrench.certs.audit.v1` | `certs[]` (as above), `weaknesses[]` — kind, severity, detail, source; `probes[]` — port, protocol, cipher | 0 |
| `wrench blueprint --history --json` | `wrench.blueprint.history.v1` | `count`, `history[]` — ts, iso, intent, files[], digest, model, ok, rolled_back, message, backup_dir, steps[] | 0 |
| `wrench notifications --json [--all]` | `wrench.notifications.v1` | `count`, `unread_count`, `notifications[]` — id, ts, severity, summary, kind, report_id, read | 0 |
| `wrench doctor --json` | `wrench.doctor.v1` | `healthy`, `checks{}` — platform, scheduler, log_backend, provider, base_url, model, policy_tier, api_key_present, db_path, sensor_os/docker/gpu, provider_ping{ok, detail} | **1 when the provider is unreachable** |
| `wrench version --json` | `wrench.version.v1` | envelope only | 0 |

Examples:

```bash
wrench status --json | jq '.os.disk_pct'
wrench certs --json | jq '.certs[] | select(.days_left < 30) | {common_name, days_left}'
wrench doctor --json || echo "provider down"
wrench report --json -n 1 | jq -e '.patrols[0].status == "ok"'   # CI gate
```

## `/metrics` — Prometheus exporter

The standard text exposition format, hand-rolled (zero new dependencies),
served two ways:

- **On the dashboard**: `wrench web` exposes `GET /metrics` alongside the UI
  (default port 8787).
- **Bare exporter**: `wrench metrics serve --port 9465` serves *only*
  `/metrics` — no dashboard, no chat endpoint.
- **One-shot**: `wrench metrics` prints a single scrape to stdout — drop it in
  cron with node_exporter's textfile collector if you don't want a port.

Metric families:

| metric | type | labels | meaning |
|---|---|---|---|
| `wrench_info` | gauge | version | build info, always 1 |
| `wrench_cpu_percent`, `wrench_mem_percent`, `wrench_swap_percent` | gauge | | latest sensor sample |
| `wrench_disk_percent` | gauge | mount | per-mount usage |
| `wrench_load_1m`, `wrench_procs`, `wrench_uptime_seconds` | gauge | | |
| `wrench_net_receive_kilobytes_per_second`, `wrench_net_transmit_kilobytes_per_second` | gauge | | |
| `wrench_sample_timestamp_seconds` | gauge | | freshness of the above |
| `wrench_anomalies_24h` | gauge | | z-score anomalies in 24h |
| `wrench_notifications_total` | counter | severity | inbox records by severity |
| `wrench_notifications_unread` | gauge | | |
| `wrench_cert_expiry_days` | gauge | cn, path | days to expiry (negative = expired) |
| `wrench_cert_not_after_timestamp_seconds` | gauge | cn, path | |
| `wrench_certs_tracked` | gauge | | parseable certs in inventory |
| `wrench_patrols_total` | counter | status | patrol runs in retained history |
| `wrench_patrol_last_run_timestamp_seconds` | gauge | | |
| `wrench_patrol_last_ok_timestamp_seconds` | gauge | | alert when stale |
| `wrench_blueprint_applies_total` / `_rollbacks_total` / `_failures_total` | counter | | from the audit log |
| `wrench_drift_changes_7d` | gauge | | drift events, last 7 days |
| `wrench_drift_last_change_timestamp_seconds` | gauge | | |
| `wrench_scrape_timestamp_seconds` | gauge | | |

Counters derive from retained history (pruned at `retention_days`), so they can
reset downward — Prometheus `rate()`/`increase()` handle that as a normal
counter reset.

Scrape config:

```yaml
scrape_configs:
  - job_name: wrench
    static_configs: [{ targets: ["127.0.0.1:9465"] }]
```

Alert ideas: `wrench_cert_expiry_days < 14`,
`time() - wrench_patrol_last_ok_timestamp_seconds > 7200`,
`wrench_disk_percent > 90`.

## Syslog / SIEM sinks

Alongside the desktop and webhook sinks, notifications can stream to:

- **RFC 5424 syslog** — local `/dev/log`, or remote `udp://host:514` /
  `tcp://host:601` (TCP uses RFC 6587 octet-counted framing). Structured data
  carries `severity`, `kind`, and the notification id:

  ```
  <10>1 2026-11-05T12:30:00-08:00 devbox wrench 4242 patrol
    [wrench@32473 severity="critical" kind="patrol" id="a1b2c3"] disk / at 97%
  ```

- **JSON-lines over HTTP** — one ndjson object per event, POSTed with
  `Content-Type: application/x-ndjson`. The shape is Splunk-HEC-flavored and
  digestible by ELK/Vector/Fluent Bit HTTP inputs:

  ```json
  {"time": 1793909627.5, "host": "devbox", "source": "wrench",
   "sourcetype": "wrench:notification",
   "event": {"id": "a1b2c3", "kind": "blueprint.rollback",
             "severity": "error", "summary": "...", "report_id": null}}
  ```

Configure in `config.toml` — each sink has its own severity threshold
(defaulting to the global `min_severity`):

```toml
[notify]
enabled = true
min_severity = "attention"          # global default threshold

syslog_address = "/dev/log"          # or "udp://siem.example.com:514" / "tcp://…:601"
syslog_min_severity = "attention"    # per-sink override

http_jsonl_url = "https://splunk.example.com:8088/services/collector/raw"
http_jsonl_min_severity = "error"
```

**What flows through the sinks**: patrol findings (including the cert expiry
ladder — 14d `warning`, 7d/expired `critical`), real certificate renewals
(`certs.renew`), and every blueprint outcome (`blueprint.apply` at attention,
`blueprint.rollback` at error, `blueprint.failed` at critical). All sinks are
best-effort by contract: a dead collector is logged to
`notifications.log` and never breaks a patrol or a ceremony.
