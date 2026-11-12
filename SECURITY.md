# Security

wrench runs on the machines it watches, reads their logs, and — with consent —
changes them. This page states what it defends against, what it does not, and
how to report a problem.

## Reporting a vulnerability

Please report privately through GitHub's **"Report a vulnerability"** button on
the repository's Security tab (private vulnerability reporting). Include the
wrench version (`wrench version`), the OS, and steps to reproduce. Please do not
open a public issue for anything exploitable.

## The trust model in one screen

| Surface | Control |
|---|---|
| **The model** | Never authors a command. Diagnostics and repairs are matched against full-match allowlists; fixxer/blueprint/cert commands are hand-written code. Tool output is framed to the model as untrusted data. |
| **Read-only diagnostics** | A fixed catalog (`wrench commands`, `docs/commands.md`). Every entry is full-matched and spells out its flags — no trailing wildcards — and carries examples that tests run through the policy check. Refused by design: anything that writes or follows a stream forever, and anything that prints where secrets live (`ps e`, `cat /proc/<pid>/environ`, `docker inspect` environment, `kubectl get secret`, `-o yaml`, `describe pod`, `wg showconf`). File reads are a closed list of `/etc` files plus log files. |
| **Connectivity probes** | `ping`, `dig`, `traceroute`, `nc -z`, `curl -I` are the only diagnostics that send packets off the machine. Counts are bounded, `nc` is one port with no data, `curl` is HEAD-only with no query string. They are their own pack: `[policy] disabled_packs = ["net-probe"]` removes them. |
| **Repairs** | A fixed catalog of fixes. Routine ones (service / container restart, cache cleanup, DNS flush, clock resync, graceful reloads) need a yes at `repair` and run unattended at `autonomous`. Higher-impact ones (stopping any service or container, forcing a log rotation, package updates and installs — by package name only, never a URL, tap or file — kill, enable/disable a service, growing a volume, anything in Kubernetes, firewall blocks) need a person's yes **every time at every tier** and are refused when nobody is present. Shutdown/rescue/debug units are never targets; remote access, logging and security agents cannot be *stopped or disabled* (checked case-insensitively, across systemctl / service / launchctl / sc / net / PowerShell). wrench never signals pid 1, itself, or its parent. Journal vacuum always keeps at least 500 MB or a week. Command output is read with a 2 MB cap, so a flooding command is cut off rather than buffered. Maintenance windows apply to the agent's own fixes, and a window config that fails to parse blocks changes rather than allowing them. |
| **Never, at any tier** | `rm`, `dd`, `mkfs`, reboot/shutdown, chaining or substitution (`;` `&` `|` `` ` `` `$(`), disk erase, and switching a protection off or erasing evidence: clearing event logs, deleting shadow copies or backups, `setenforce 0`, disabling a firewall, BitLocker, FileVault, Gatekeeper or auditing. Checked before the catalog and before operator-added commands — nothing overrides it. |
| **sudo** | The agent may prefix a catalog command with `sudo -n` (non-interactive: it fails rather than prompt). The command behind the prefix gets the same checks. This widens reach only where sudoers already grants that command without a password. `[policy] sudo = false` refuses the prefix. |
| **Operator-added commands** | `[policy] allow_diag` / `allow_fix` are matched as exact strings, never patterns. Anyone who can edit the config file can add one — the config file is already the root of trust (it sets the tier). |
| **Config changes (blueprint)** | Paths are confined by real path (symlinks resolved), compared case-insensitively against a denylist, and files root executes (cron, profiles, unit files, PAM, the loader) are refused unless explicitly opted in. Ownership and symlinks are preserved; any interruption rolls back. |
| **Policy tier** | Changed with `wrench policy <tier>` (raising asks for confirmation; `autonomous` must be typed out; a non-interactive raise needs `--yes`) or from the dashboard. The dashboard may always *lower* the tier; raising it there requires `[web] allow_tier_raise = true`, so a dashboard token alone cannot grant the ability to act. Every change is audit-logged with its origin. |
| **Memory** | Three sources. What the operator writes is used at once. What the **model** asks to keep while nobody is present (patrols, scheduled jobs, web chat) goes to a review queue and is shown to no model until approved — a log line cannot make itself a standing instruction. What is **learned** is derived by code from the operator's own actions. Memory text is sanitised, bounded, refused if it looks like a credential, audit-logged, and never alters the policy tier or authorises a command. Dashboard writes need the admin role. |
| **Scheduled jobs** | Actions come from a closed registry — no arbitrary command. Jobs proposed by the agent unattended, or by wrench from learned routines, do not run until approved. A scheduled agent question runs at `[heartbeat] max_tier` (default `suggest`: read-only) regardless of the interactive tier, with the usual allowlists, maintenance windows and confirmation rules. One heartbeat at a time; hung jobs time out; repeatedly failing jobs pause themselves. |
| **Dashboard / API** | With a password set (`wrench password`): sign-in on every bind, loopback included. The password is stored only as a salted scrypt hash (64 MiB per guess), owner-only; it is verified one guess at a time, is accepted only by the sign-in form (never as a bearer token), and changing or removing it invalidates every session. Without one, loopback: no sign-in, but the `Host` header must be a loopback name (DNS-rebinding defence). Any other bind: password, token or signed session cookie on every route (a network bind whose credentials are removed while it runs locks, it does not open), two roles (admin / viewer), same-origin check on writes, login rate limiting, CSP with per-response nonces, `frame-ancestors 'none'`. Optional native TLS. |
| **Fleet** | Nodes sign each report (HMAC-SHA256 over timestamp + body) with an enrollment key. The hub stores only a derived key, rejects revoked keys, clocks more than `max_skew_s` apart, replays, and a node id claimed by a different key. `wrench fleet connect` exchanges the hub's admin password, once, for a single-node key: the password is never stored on the node, the exchange shares the sign-in rate limit and audit trail, the node refuses to send the password over plain HTTP to another machine unless told to, and it never falls back from HTTPS when a certificate fails to verify. `[fleet] connect = false` turns the exchange off. |
| **Audit log** | Hash-chained, appended under a cross-process lock, with a sealed head that exposes truncation or replacement. Set `WRENCH_AUDIT_KEY_FILE` to add a per-record MAC with a key the log's writer does not need at verify time. |
| **Data at rest** | The data directory is `0700`, the database, config, consent files and tokens `0600` (POSIX). API keys and fleet tokens are never written to the database or logs. |
| **Consent** | Auto-fix, blueprint and renewal consent files are bound to the host they were granted on. Out-of-band approvals are single-use, TTL-bounded, bound to the specific request, and the token is sent only to the approval channel. |

## What wrench does not defend against

- **Root on the same box.** Someone with root can alter wrench, its data, and
  the audit log together. For tamper-evidence against a privileged local
  attacker, forward events off-box (`[notify] syslog_address` / `http_jsonl_url`)
  and use an audit MAC key held elsewhere.
- **A malicious model provider.** With a cloud brain, telemetry context is sent
  to that provider. Use a local brain or `offline = true` where that matters.
  The model still cannot run anything outside the allowlists.
- **Plain HTTP on a hostile network.** Tokens and fleet signatures are safe from
  forgery, but telemetry is readable in transit. Use `--tls-cert/--tls-key` or
  a TLS reverse proxy for any non-loopback bind.
- **Windows hardening parity.** Owner-only file modes are a POSIX control; on
  Windows wrench relies on the per-user profile ACLs.

## Supported versions

Security fixes land on the latest release line (3.x).
