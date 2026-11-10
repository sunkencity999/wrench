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
| **Read-only diagnostics** | Every allowlist entry spells out its flags — no trailing wildcards. `journalctl --vacuum-*`, `ss -D/-K`, `ps e`, `cat /proc/<pid>/environ`, `docker inspect` (env) are refused. |
| **Repairs** | Service lifecycle only. Shutdown/rescue/debug units are never targets; remote access, logging and security agents cannot be *stopped*. Maintenance windows apply to the agent's own fixes, and a window config that fails to parse blocks changes rather than allowing them. |
| **Config changes (blueprint)** | Paths are confined by real path (symlinks resolved), compared case-insensitively against a denylist, and files root executes (cron, profiles, unit files, PAM, the loader) are refused unless explicitly opted in. Ownership and symlinks are preserved; any interruption rolls back. |
| **Dashboard / API** | Loopback: no sign-in, but the `Host` header must be a loopback name (DNS-rebinding defence). Any other bind: token or signed session cookie on every route, two roles (admin / viewer), same-origin check on writes, login rate limiting, CSP with per-response nonces, `frame-ancestors 'none'`. Optional native TLS. |
| **Fleet** | Nodes sign each report (HMAC-SHA256 over timestamp + body) with an enrollment key. The hub stores only a derived key, rejects revoked keys, clocks more than `max_skew_s` apart, replays, and a node id claimed by a different key. |
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
