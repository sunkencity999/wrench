# Changelog

## Unreleased

### New

- **Guided fleet setup, in conversation.** Tell `wrench chat` "set this
  machine up as the hub" or "connect this machine to the hub at 192.168.1.10"
  and the agent walks you through it one step at a time and carries each step
  out: the dashboard password, where the hub listens, an optional self-signed
  certificate, starting the hub, connecting a node, installing the schedule.
  Every step waits for your yes, and passwords are typed at a hidden prompt —
  they never pass through the model. `wrench fleet setup [hub|node]` is the
  same guide with no model. New agent tools: `fleet_setup_status`,
  `fleet_setup`.
- **`wrench fleet serve --detach`** and **`wrench fleet stop`** — run the hub
  in the background without keeping a terminal open.
- The agent now retries once when a model returns an empty answer, and shows
  the last thing it found instead of a blank panel if it is still empty.
- Confirmation and password prompts in `chat`, `ask` and `explain` no longer
  appear underneath the "thinking…" spinner.
- **`wrench fleet connect <hub-address>`** — connect a machine to a hub with
  the hub's dashboard password. The password is sent once and exchanged for a
  key that belongs to that machine alone; it is never stored on the machine.
  A bare address is tried over HTTPS first; the password is not sent to a hub
  without TLS unless you allow it, and never after a certificate failed to
  verify. Connecting a machine again keeps its name and history and retires
  its old key. `[fleet] connect = false` turns it off on a hub.
- **One console for every machine.** The fleet console now lists the hub
  itself beside the machines that report to it, and a machine picker in the
  top bar of the dashboard and the console switches between this machine,
  all machines, and any one connected machine (`/fleet?node=<name>` links
  straight to one).
- **A multi-machine tutorial** in the README ("Tutorial: many machines, one
  dashboard") and on the website, where it includes an interactive
  walkthrough across a hub and three machines.
- **A password on the dashboard.** `wrench init` offers to set one (or takes
  it from `WRENCH_WEB_PASSWORD` in an unattended install), and
  `wrench password` sets, changes or removes it (`--status`, `--clear`,
  `--stdin`). With a password set, the dashboard and fleet console ask for it
  on every bind, loopback included. Only a salted scrypt hash is stored,
  owner-only; a change reaches a running server at once and signs out every
  browser; sign-in attempts are rate-limited and every change is in the audit
  chain. Access tokens keep working for scripts and read-only viewers.
- **A much larger command catalog.** The agent could run about 60 kinds of
  diagnostic and 7 kinds of fix. It can now run 243 kinds of diagnostic
  and 106 kinds of fix across Linux, macOS and Windows, in 19
  packs: services, logs (including tail / grep of log files), processes,
  performance, storage (SMART, LVM, ZFS, btrfs, RAID), files (`find`, `stat`,
  checksums), network, connectivity probes, packages, containers, Kubernetes,
  security, users and directory, hardware, time, and application config
  checks. The full list is `docs/commands.md`, generated from the code.
- **Fixes that always ask.** Stopping a service or container, package updates and installs, `kill`, enabling
  or disabling a service, growing a volume, and every Kubernetes change need
  a person's yes every time — even at `autonomous`, where they are refused if
  nobody is present.
- **`wrench commands`** — list the catalog by pack, or test one command:
  `wrench commands --check "systemctl restart nginx"`.
- **`[policy]` knobs** — `sudo` (accept a `sudo -n` prefix; default on),
  `disabled_packs`, and `allow_diag` / `allow_fix` for your own exact
  commands.
- Agent tool `list_commands`, and a refused command now comes back with the
  allowed forms of that tool, so the model corrects itself instead of
  retrying.
- The dashboard's policy-tier panel lists what the agent can run on that
  machine.

### Changed

- `wrench fleet report` now says "the hub refused this report" (and how to
  reconnect) when the hub rejects it, instead of "hub unreachable — queued".
  A hub with no dashboard password says so when a machine tries to connect.
- Stop-protection for remote access, logging and security services now also
  covers `disable`, `service … stop`, `sc config … start= disabled` and
  PowerShell `Stop-Service`, case-insensitively.
- The forbidden list gained "never switch a protection off or erase
  evidence": clearing event logs, deleting shadow copies, `setenforce 0`,
  disabling a firewall, BitLocker, FileVault, Gatekeeper or auditing.
- Stopping a service now always asks, at every tier (it used to run unattended
  at `autonomous`), and `journalctl --vacuum-size` must keep at least 500 MB.
- `systemctl cat` and a bare `systemctl show` are no longer diagnostics (they
  print `Environment=` lines); `systemctl show <unit> -p <property>` is.
- Command output is read with a 2 MB cap instead of being buffered whole.
- Diagnostics and fixes run with a per-command timeout from the catalog
  (package upgrades get an hour, not 60 seconds) and a non-interactive
  environment.

- **`wrench policy`** — show the four tiers and switch between them
  (`wrench policy repair`). Until now the tier could only be changed by editing
  the config file. Raising asks for confirmation; `autonomous` must be typed.
- **Dashboard policy-tier panel** (Trust & activity → the tier, or ⌘K).
  Lowering works at once; raising from the web needs
  `[web] allow_tier_raise = true`, otherwise the panel gives the command.
- The dashboard now shows the tier currently in the config, not the one read
  when the server started.

## 3.1.0 — memory and a heartbeat

wrench now remembers how you run each machine, and does scheduled work on its
own. **After upgrading, re-run `wrench install-service` once** — the timer now
runs the heartbeat, which runs the patrol and everything else.

### New

- **Memory** — `wrench remember "…"`, `wrench memory` (list, `search`,
  `forget`, `pin`, `review`, `approve`, `reject`, `export`, `import`). Every
  patrol, `ask`, `chat` and scheduled question starts with the memories that
  bear on the task; preferences, procedures and pinned items always come
  along. Retrieval is deterministic and offline.
- **Three sources, three levels of trust.** What you write is used at once.
  What the agent asks to keep is confirmed on the spot when you are present,
  and otherwise waits in a review queue that no model can see. What wrench
  learns — fixes you approve three times running, commands you run by hand at
  the same hour on several days — is derived by code.
- **Heartbeat and jobs** — `wrench jobs` (`add`, `run`, `pause`, `resume`,
  `approve`, `rm`, `log`) and `wrench heartbeat` (`--status`, `--loop`).
  Plain-language or cron schedules; one-off follow-ups (`in 2h`). Actions come
  from a closed list: patrol, brief, score, security, comply, backups, cve,
  certs, drift, forecast, remind, ask.
- **It proposes; you decide.** Jobs suggested by the agent unattended, or by
  wrench from a learned routine, do nothing until approved. A new install is
  offered a weekday morning brief.
- **Agent tools** `remember`, `recall`, `schedule_task`, `list_tasks`.
- **Dashboard** Memory and Schedule panels: approve or discard notes and
  proposals, add a memory, pause or remove jobs, see the heartbeat and recent
  runs. `/api/memory`, `/api/jobs` (writes need the admin role).
- `wrench` (home screen) shows what is waiting on you and whether the
  heartbeat is alive. `--help` gains a LEARN group.
- `[memory]` and `[heartbeat]` config sections.

### Changed

- `install-service` installs the heartbeat timer (same unit / agent / task
  names, so it replaces the old one). `--interval` now sets the patrol job's
  cadence.
- Scheduled `ask` jobs run at `[heartbeat] max_tier` (default `suggest`).
- Briefs, reminders and scheduled answers are always delivered to the inbox,
  desktop and webhook, regardless of `[notify] min_severity`.

## Also in 3.1.0

### Fixed — Windows

- **Blueprints work on Windows.** Every drive path was refused as "not an
  absolute, normalized path". Targets may now be `C:\…` or `C:/…`; UNC shares,
  device paths and drive-relative paths are refused; scripts, executables,
  scheduled tasks, registry hives and credential stores are never a target.
  Backups were being joined onto an absolute path — they now live under the
  backup directory.
- **CRLF files keep their line endings.** A diff against a CRLF file failed
  with "hunk context not found"; it now applies and writes CRLF back.
- **Piped output no longer crashes.** `wrench comply > report.txt` raised
  `UnicodeEncodeError` on a non-UTF-8 code page; unencodable glyphs are now
  substituted.
- `file_mode` / `file_owner` compliance checks and the world-writable scan
  report "skipped" on Windows instead of judging POSIX bits that do not exist.
- The Windows CI job is green and now gates.

### Changed

- wrench describes itself as the sysadmin's right hand rather than "your
  systems administrator".
- The sshd compliance check reads drop-ins beside the file being checked.

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
- **Dashboard depth.** Every posture pillar opens to its evidence (volumes,
  findings, failing rules, jobs, certificates) with a shareable link; a ⌘K
  command palette; click-to-copy commands; a health trend with week-over-week
  change; a first-run guide; phone-sized layouts.
- **`wrench` with no arguments** shows where the machine stands and the single
  next command; `wrench --help` groups commands by the five arcs.
- **Provisional scores.** Until half of the score's weight is measured there is
  no grade and no "healthy" — a new install is unmeasured, not an A.
- **Docs.** A deployment guide (servers, fleets, MDM/Ansible, reverse proxy,
  air-gap, upgrading, troubleshooting), a full configuration reference, and a
  rebuilt website.
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
