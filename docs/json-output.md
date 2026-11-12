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
  "version": "1.7.0",
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
| `wrench status --json` | `wrench.status.v1` | `os` (cpu_pct, mem_pct, swap_pct, disk_pct{mount: pct}, load_1m/5m/15m, n_procs, uptime_s, net rates, top_cpu/top_mem), `docker`, `gpu` (null when absent), `anomalies_24h[]`, `unread_notifications`, `posture{score, grade, state, measured, total}` | 0 |
| `wrench score --json` | `wrench.score.v1` | `score`, `grade`, `state`, `coverage{measured,total}`, `pillars[]`, `top_issues[]` — see below | **1 attention · 2 critical** |
| `wrench patrol --json [--no-llm]` | `wrench.patrol.v1` | `status`, `summary`, `findings[]`, `model`, `deterministic`, `tokens`, `duration_s`, `ts` | **1 attention · 2 critical/error** |
| `wrench report --json [-n N]` | `wrench.report.v1` | `count`, `patrols[]` — ts, status (`ok\|attention\|critical`), summary, model, tokens, findings[] | 0 |
| `wrench drift --json` | `wrench.drift.v1` | `baseline_recorded` (true on first scan), `change_count`, `changes[]` — kind (`ports\|services\|packages\|users\|cron`), changes[] (English lines) | 0 |
| `wrench certs --json` | `wrench.certs.v1` | `count`, `needing_attention`, `certs[]` — path, source, subject, common_name, issuer, days_left, expiry_severity (`info\|warning\|critical\|null`), sans[], key_type, key_bits, weak_key, is_ca, self_signed, chain_complete, fingerprint_sha256, error; `weaknesses[]` | 0 |
| `wrench certs audit --json` | `wrench.certs.audit.v1` | `certs[]` (as above), `weaknesses[]` — kind, severity, detail, source; `probes[]` — port, protocol, cipher | 0 |
| `wrench blueprint --history --json` | `wrench.blueprint.history.v1` | `count`, `history[]` — ts, iso, intent, files[], digest, model, ok, rolled_back, message, backup_dir, steps[] | 0 |
| `wrench security --json` | `wrench.security.v1` | `worst`, `counts{}`, `baseline_exists`, `baseline_accepted_at`, `findings[]` — severity, category, title, detail; `components{}` — auth, access, listeners{rows[]}, cve | **1 on a critical finding** |
| `wrench forecast --json` | `wrench.forecast.v1` | `count`, `worst`, `incidents[]` — kind (`capacity\|cert`), what, current, growth_per_day, threshold, eta_days, eta_date, severity, confidence, r2, samples | 0 |
| `wrench backups --json` | `wrench.backups.v1` | `count`, `worst`, `no_jobs`, `severity_counts{}`, `jobs[]` — name, tool, command, origin, schedule, cadence_s, source, dest, last_run_ts, last_run_evidence, age_s, freshness (`fresh\|stale\|unknown`), integrity (`ok\|locked\|failed\|unknown\|skipped`), integrity_note, restore_test | **1 when worst is critical** |
| `wrench notifications --json [--all]` | `wrench.notifications.v1` | `count`, `unread_count`, `notifications[]` — id, ts, severity, summary, kind, report_id, read | 0 |
| `wrench comply --json [--pack N]` | `wrench.comply.v1` | `packs[]` — pack, title, score (`null` when nothing could be graded), platforms[], counts{pass,fail,skip}, severity_fails{}; `critical_fails`; `results[]` — pack, id, title, severity, status (`pass\|fail\|skip`), detail | **1 when any critical rule fails** |
| `wrench bundle --json [--out PATH]` | `wrench.bundle.v1` | `path`, `bytes`, `files[]` (SUMMARY.md + per-section JSON), `offline` — writes a portable tar.gz evidence bundle; no secrets (config redacted) | 0 |
| `wrench doctor --json` | `wrench.doctor.v1` | `healthy`, `checks{}` — platform, scheduler, log_backend, provider, base_url, model, policy_tier, api_key_present, db_path, sensor_os/docker/gpu, `brain{configured, reason}`, provider_ping{ok, detail}, `admin`, `data_dir_mode`, `schema_version`, `audit{intact, count, reason, mac_checked}`, `last_patrol_age_s`, `fleet`, `offline{offline, egress, disabled[], still_allowed[], brain_is_local}` | **1 when a configured provider is unreachable or the audit chain is broken** (no brain configured is healthy: deterministic mode) |
| `wrench policy --json` | `wrench.policy.v1` | `tier`, `env_override`, `tiers[]` — tier, name, allows, current. With a tier argument (`wrench policy repair --yes --json`): `tier`, `changed`, `from` | **2 when refused** |
| `wrench fleet setup [hub\|node] --json` | `wrench.fleet.setup.v1` | `role`, `state{password_set, hub{…}, node{…}, schedule{…}}`, `steps{hub[], node[]}` — key, title, done, optional, detail, command. Read-only | 0 |
| `wrench model --json` | `wrench.model.v1` | `provider`, `model`, `deep_model`, `base_url`, `hosted`, `key{present, source}` — never the key | 0 |
| `wrench model list --json` | `wrench.model.list.v1` | `provider`, `current`, `suggested{everyday, deep}`, `models[]` — id, name, created, fast | **1 when the provider cannot be asked** |
| `wrench show [id] --json` | `wrench.show.v1` | `ok`, `url`, `started`, `detail`, `notification` | **1 when the dashboard could not be reached or started** |
| `wrench password --json` | `wrench.password.v1` | `set`, `changed`. Works with `--status`, `--clear`, `--stdin`; never contains the password or its hash | `--status`: **1 when none is set** |
| `wrench commands --json` | `wrench.commands.v1` | `os`, `tier`, `counts{diag, fix, packs}`, `disabled_packs[]`, `sudo`, `allow_diag[]`, `allow_fix[]`, `packs[]` — pack, title, enabled, diag, fix, asks, diag_tools[], fix_tools[]; with a pack name or `--fixes`, `commands[]` — kind, pack, os, label, examples[], asks_every_time, timeout_s. `--all` covers every OS | 2 for an unknown pack |
| `wrench commands --check "<cmd>" --json` | `wrench.commands.check.v1` | `command`, `verdict` (`look` \| `fix` \| `refused`), `tier`, `allowed_now`, `needs_confirm`, `label`, `pack`, `reason` | **1 when refused** |
| `wrench memory --json [-k KIND]` | `wrench.memory.v1` | `enabled`, `memories[]` and `pending[]` — id, ts, updated, kind (`preference\|fact\|procedure\|lesson\|observation`), text, source (`user\|agent\|learned`), status, pinned, uses, last_used, origin | 0 |
| `wrench remember "…" --json` | `wrench.remember.v1` | `ok`, `memory{…, duplicate}` or `error` | **2 when refused** |
| `wrench jobs --json` | `wrench.jobs.v1` | `jobs[]` — id, name, schedule, action, args{}, status (`active\|paused\|proposed\|done`), created_by (`user\|agent\|learned\|system`), note, next_run, last_run, last_status, last_summary, runs, fail_streak; `heartbeat{…}` as below | 0 |
| `wrench jobs run NAME --json` | `wrench.jobs.run.v1` | `name`, `action`, `status` (`ok\|attention\|critical\|error`), `summary`, `duration_s`, `next_run`, `job_status` | **2 on critical or error** |
| `wrench jobs log --json` | `wrench.jobs.log.v1` | `runs[]` — name, ts, duration_s, status, summary | 0 |
| `wrench heartbeat --json` | `wrench.heartbeat.v1` | `ts`, `ran[]` (as `jobs run`), `skipped` (why this beat did nothing, else `""`), `proposals[]` | 0 |
| `wrench heartbeat --status --json` | `wrench.heartbeat.status.v1` | `last_tick`, `age_s`, `alive` (`null` if it has never run), `ticks`, `last_ran[]`, `jobs{active,paused,proposed}`, `next{name, at}` | **1 when not alive** |
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

## `wrench audit` → `wrench.audit.v1`

Recent sealed events plus the chain verdict. Each entry is a full chain record.

```json
{
  "schema": "wrench.audit.v1",
  "generated_at": 1793914272.825,
  "host": "devbox",
  "version": "2.2.0",
  "count": 7,
  "shown": 7,
  "intact": true,
  "entries": [
    {"ts": 1793914200.1, "actor": "wrench", "kind": "genesis",
     "detail": {"msg": "audit chain initialized", "version": "2.2.0"},
     "prev_hash": "0000…0000", "hash": "4dd6…ef75"},
    {"ts": 1793914260.4, "actor": "alice", "kind": "fixxer:disk-clean",
     "detail": {"tier": "repair", "command": "…", "approved": true, "result": "…"},
     "prev_hash": "4dd6…ef75", "hash": "6798…e45c"}
  ]
}
```

## `wrench audit verify` → `wrench.audit.verify.v1`

Re-walks the on-disk chain. **Exit 0 = INTACT, exit 1 = tampered.**

```json
{
  "schema": "wrench.audit.verify.v1",
  "generated_at": 1793914272.9,
  "host": "devbox",
  "version": "2.2.0",
  "intact": false,
  "count": 7,
  "broken_index": 3,
  "reason": "record altered: stored hash does not match its contents"
}
```

## `wrench approvals` → `wrench.approvals.v1`

Approval-token states (hashes only; plaintext tokens are never stored or emitted).
`state` is one of `pending | approved | claimed | expired`.

```json
{
  "schema": "wrench.approvals.v1",
  "generated_at": 1793914300.0,
  "host": "devbox",
  "version": "2.2.0",
  "count": 1,
  "approvals": [
    {"action": "blueprint --execute", "detail": "harden sshd",
     "created": 1793914000.0, "expires": 1793917600.0, "state": "approved"}
  ]
}
```

New Prometheus gauges: `wrench_audit_entries`, `wrench_audit_intact` (1/0),
`wrench_audit_last_event_timestamp_seconds`, and `wrench_approvals{state=…}`.

## `wrench fleet status` → `wrench.fleet.v1`

Hub-side: every known node with its live status, last-seen age, and the dead-man
verdict. **Exit 1 when any node is `silent` or `red`, else 0.** `color` is one of
`green | yellow | red | silent`; `silent` is true when `age_s > silent_factor ×
cadence_s`.

```json
{
  "schema": "wrench.fleet.v1",
  "generated_at": 1793914400.0,
  "host": "hub",
  "version": "2.2.0",
  "summary": {"total": 3, "green": 1, "yellow": 1, "red": 0, "silent": 1},
  "nodes": [
    {"node_id": "web-01", "hostname": "web-01", "status": "attention",
     "color": "yellow", "silent": false, "last_seen": 1793914380.0,
     "age_s": 20.0, "worst_severity": "warning", "summary": "/mnt at 94%",
     "cadence_s": 600, "wrench_version": "2.0.1", "report_count": 42,
     "findings": [{"severity": "warning", "text": "/mnt at 94%"}],
     "gauges": {"disk_pct": {"/": 61.0, "/mnt": 94.0}, "mem_pct": 23.4}},
    {"node_id": "db-02", "hostname": "db-02", "status": "ok",
     "color": "silent", "silent": true, "last_seen": 1793912000.0,
     "age_s": 2400.0, "worst_severity": "ok", "summary": "all quiet",
     "cadence_s": 600, "wrench_version": "2.0.1", "report_count": 7,
     "findings": [], "gauges": {}}
  ]
}
```

## `wrench fleet report` → `wrench.fleet.report.v1`

Node-side: the compact snapshot that was built (from cached scans) and whether it
was pushed. `--dry-run` builds without pushing; a queued report means the hub was
unreachable and the report will retry next patrol.

```json
{
  "schema": "wrench.fleet.report.v1",
  "generated_at": 1793914400.0,
  "host": "web-01",
  "version": "2.2.0",
  "pushed": true,
  "queued": false,
  "detail": "HTTP 200",
  "report": {
    "node_id": "web-01", "hostname": "web-01", "wrench_version": "2.0.1",
    "ts": 1793914399.2, "status": "attention", "worst_severity": "warning",
    "cadence_s": 600, "summary": "/mnt at 94%",
    "findings": [{"severity": "warning", "text": "/mnt at 94%"}],
    "gauges": {"disk_pct": {"/": 61.0, "/mnt": 94.0}, "mem_pct": 23.4,
               "cert_worst_days": 9}
  }
}
```

New Prometheus gauges (hub side): `wrench_fleet_nodes`,
`wrench_fleet_nodes_silent`, `wrench_fleet_nodes_by_color{color=…}`, and per-node
`wrench_fleet_node_status` (0 ok, 1 attention, 2 critical, 3 silent),
`wrench_fleet_node_last_seen_timestamp_seconds`, `wrench_fleet_node_reports_total`.

## `wrench score` → `wrench.score.v1`

The deterministic health score. Exit code `0` ok / unmeasured, `1` attention,
`2` critical — usable directly as a CI or cron gate.

```json
{
  "schema": "wrench.score.v1",
  "score": 87.0,
  "grade": "B",
  "state": "ok",
  "coverage": {"measured": 7, "total": 8},
  "pillars": [
    {"key": "capacity", "label": "Capacity", "weight": 20, "score": 100.0,
     "state": "ok", "detail": "fullest disk / at 25%, memory 62%",
     "command": "wrench status"},
    {"key": "certificates", "label": "Certificates", "weight": 8, "score": null,
     "state": "unknown", "detail": "no certificates tracked", "command": "wrench certs"}
  ],
  "top_issues": [
    {"pillar": "backups", "label": "Backups",
     "detail": "1 job(s): 0 failing integrity, 1 stale or unverified",
     "command": "wrench backups"}
  ]
}
```

`score` is `null` until at least one pillar has data. A pillar with `score:
null` is **unmeasured** and excluded from the weighted average. Any pillar in
the `critical` state caps the total at 69.

```bash
wrench score --json | jq -e '.score >= 80'          # gate
wrench score --json | jq -r '.top_issues[].command'  # what to run next
```

## `wrench patrol --json` → `wrench.patrol.v1`

Runs one patrol and prints its verdict. Exit `0` ok, `1` attention, `2`
critical. `deterministic: true` means no model was consulted (none configured,
`--no-llm`, or the provider was unreachable) — every finding is a code check.

```json
{
  "schema": "wrench.patrol.v1",
  "status": "attention",
  "summary": "disk /var is 91% full",
  "findings": [{"severity": "warning", "text": "disk /var is 91% full"}],
  "model": "deterministic",
  "deterministic": true,
  "tokens": 0,
  "duration_s": 2.6,
  "ts": 1794296991.19
}
```

## Fleet enrollment → `wrench.fleet.enroll.v1` / `wrench.fleet.keys.v1`

`wrench fleet enroll --json` returns `{key_id, token, label, single_node,
join_command}` — the only time the token is ever available. `wrench fleet keys
--json` returns `{keys: [{key_id, label, created, revoked, single_node,
last_used, nodes: [...]}]}`; it never contains a token or signing key.

## Health metrics

| metric | meaning |
|---|---|
| `wrench_health_score` | overall score, 0–100 (absent until something is measured) |
| `wrench_health_pillar_score{pillar}` | per-pillar score (absent when unmeasured) |
| `wrench_health_pillars_measured` | how many of the eight pillars have data |

```promql
wrench_health_score < 70                      # page-worthy posture
wrench_health_pillars_measured < 6            # this box is not being fully checked
```

When the dashboard has access control on, scrape with a bearer token:

```yaml
scrape_configs:
  - job_name: wrench
    authorization: {type: Bearer, credentials_file: /etc/prometheus/wrench.token}
    static_configs: [{targets: ["host:8787"]}]
```
