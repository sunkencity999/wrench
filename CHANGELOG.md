# Changelog

## 3.0.0 — the enterprise release

The theme: every machine, trusted. wrench now runs correctly on macOS as well
as Linux (verified on real hardware), patrols without a model, locks down its
own network surfaces, and manages a fleet through one command per machine.

### New

- **`wrench score` — one health number.** A deterministic 0–100 score with a
  letter grade across eight pillars (capacity, security, vulnerabilities,
  compliance, backups, certificates, forecast, patrol). Unmeasured pillars are
  shown as unmeasured and left out — never counted as healthy. Appears in
  `wrench status`, the dashboard, fleet reports, and `/metrics`
  (`wrench_health_score`, `wrench_health_pillar_score`).
- **Patrols no longer need a brain.** With no model configured (or
  `wrench patrol --no-llm`, or a provider outage mid-patrol) the patrol runs
  every code check and files a real report marked *deterministic* instead of
  failing with `error`. `wrench patrol --json` gives CI an exit code.
- **Fleet enrollment.** `wrench fleet enroll` on the hub prints a
  `wrench fleet join <url> <key>` line; running it on a machine tests the
  connection and writes the config. Keys are listable and revocable
  (`fleet keys`, `fleet revoke`), nodes retirable (`fleet forget`).
- **Fleet protocol v2.** Reports are signed over timestamp + body; the hub
  rejects replays, stale clocks, revoked keys, and node ids claimed by another
  key, and stores only a derived signing key. 2.x shared tokens still work and
  gain the same replay protection.
- **Fleet console.** Search, status/OS filters, sortable columns, health score,
  per-node drawer with report history, CSV export. Silent nodes are detected by
  the hub itself every 30 s rather than whenever the hub box next patrolled.
- **New dashboard.** Health ring and posture pillars with next steps, hover
  charts over 1h/6h/24h/7d, notification centre, audit-chain status,
  light/dark, keyboard shortcuts.
- **Dashboard access control.** Token or signed-session auth on every route for
  any non-loopback bind (a token is generated if none is set), admin and viewer
  roles, DNS-rebinding and CSRF defences, security headers, optional native TLS
  for both `wrench web` and `wrench fleet serve`.
- **macOS and Windows compliance packs** (`macos-baseline`, `windows-baseline`)
  on a new closed registry of read-only OS probes. Packs declare their
  platforms; only applicable packs run by default.
- **Time Machine** is detected and verified as a backup job on macOS.
- **CI** on Linux, macOS and Windows; `python -m wrench`; `SECURITY.md`.

### Security fixes

- Read-only diagnostic allowlist allowed log deletion, file truncation and
  connection killing (`journalctl --vacuum-time`, `--rotate`, `--cursor-file`;
  `ss -D`, `ss -K`) and exposed process environments. Every pattern is now
  full-match with explicit flags.
- Repair allowlist could start `poweroff.target` / `debug-shell.service` or
  stop sshd, auditd and the firewall. Dangerous units are refused.
- The agent's `fix_action` ignored maintenance windows and reported failed
  commands as executed.
- A mistyped maintenance window silently disabled change control; it now blocks.
- Blueprint path rules were bypassable by letter case and symlinks, and allowed
  files that root executes.
- Out-of-band approvals could be claimed by a different request, claimed twice
  under a race, and self-approved from the requesting job's own log.
- Audit log: concurrent writers forked the chain; removing the tail was
  undetectable.
- Dashboard: no authentication on non-loopback binds; no Host validation.
- Fleet: captured reports could be replayed; any token could report as any node.
- Unattended apt upgrades lost `DEBIAN_FRONTEND` under sudo and could hang on a
  conffile prompt; a timeout orphaned dpkg mid-transaction.

### Fixed

- Patrols crashed (`KeyError: 'text'`) whenever a compliance finding was the
  first to page — the default on macOS.
- macOS: a dozen APFS system volumes and mounted disk images were reported as
  disks; "/" reported the sealed system volume's 0.5% instead of the
  container's real fill; listening sockets, real user accounts and
  `authorized_keys` were invisible without root; the Darwin kernel was looked
  up as a Linux kernel; `du --max-depth` failed; Ubuntu packs ran on Macs.
- Anomaly detection never fired on a metric that had been constant, and fired
  constantly on 0.1-point ticks; anomalies are now one per excursion.
- Top CPU processes were always 0%.
- Drift flapped on ephemeral UDP ports, per-app launchd labels, Windows task
  run times, crontab line numbers, and tools missing from a scheduler's PATH.
- Certificate renewal targeted every certbot lineage, validated the old
  certificate, false-failed normal ACME chains, and reported no-op renewals as
  complete.
- CVE severity: only the first 25 findings were scored, and CVSS vectors could
  never rate *critical*. Vectors are now scored with the CVSS 3.x formula.
- Retention only ran under `wrench watch`, and deleted accepted baselines after
  30 days. Scheduled patrols now prune; the newest snapshot of each kind is kept.
- `install-service` reported success when the scheduler refused the job; the
  launchd job had no PATH and no log.
- Backups: a job that failed every night read as fresh; forecast paged on
  low-confidence trends; the notification inbox could lose records.
- The setup wizard crashed listing models (undefined name).

### Changed

- The store uses WAL with a 30 s busy timeout and versioned migrations.
- `doctor` treats "no brain configured" as a supported mode, and reports
  privileges, data-dir permissions, audit integrity and patrol freshness.
- Forecast never pages on memory or swap projections.
