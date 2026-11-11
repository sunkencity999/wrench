# Configuration reference

wrench works with no configuration at all. Everything here is optional.

- **File:** `config.toml` in the config directory — `~/.config/wrench/` (Linux),
  `~/Library/Application Support/wrench/` (macOS), `%APPDATA%\wrench\` (Windows).
  `wrench init` writes a commented starting file; `wrench fleet join` edits the
  `[fleet]` section in place and keeps your comments.
- **Precedence:** environment variable → `config.toml` → built-in default.
- **Permissions:** on Linux and macOS wrench keeps the file owner-only (`0600`),
  because it can hold an API key or a fleet key.
- **Check it:** `wrench doctor` shows what was loaded and what is in effect.

## Contents

[provider](#provider--the-brain) · [policy](#policy--the-leash) · [general](#general) ·
[notify](#notify) · [web](#web--the-dashboard) · [fleet](#fleet) ·
[maintenance](#maintenance--change-windows) · [approvals](#approvals) ·
[security](#security) · [webintel](#webintel) · [fixxer](#fixxer) ·
[blueprint](#blueprint) · [memory](#memory) · [heartbeat](#heartbeat) ·
[environment variables](#environment-variables) ·
[files wrench writes](#files-wrench-writes)

## `[provider]` — the brain

```toml
[provider]
name = "ollama"     # ollama | lmstudio | openai | anthropic | meta | azure | litellm | custom | none

[ollama]            # one section per provider, named after it
model      = "qwen2.5:14b"
deep_model = "qwen3:30b"                       # used by `patrol --deep`
# base_url   = "http://127.0.0.1:11434/v1"
# api_key_file = "~/.config/wrench/ollama.key" # keeps the key out of this file and the environment
# max_tokens = 4096
```

| key | meaning |
|---|---|
| `name` | Which provider section to use. `none` runs wrench with no model: patrols are deterministic, `ask`/`chat` are unavailable. |
| `model`, `deep_model` | Everyday model and the one `--deep` uses. |
| `base_url` (`endpoint` for Azure) | Where the API lives. Required for `custom` and `azure`. |
| `api_key`, `api_key_file` | Prefer the provider's environment variable or `api_key_file`. |
| `max_tokens` | Reply budget. Reasoning models need room. |
| `[azure] api_version`, `auth` | `auth` is `api-key`, `bearer`, or `auto` (api-key, then bearer on 401). |

With no usable brain — no key for an API provider, no endpoint, or
`offline = true` with a public endpoint — wrench does not fail. Patrols run in
deterministic mode and say so.

## `[policy]` — the leash

```toml
[policy]
tier = "suggest"    # observe | suggest | repair | autonomous
```

Change it with `wrench policy <tier>` (it edits this line for you, asks before
raising, and records the change in the audit chain) or from the dashboard's
policy-tier panel. `WRENCH_POLICY` in the environment overrides the file.

| tier | may look | may propose commands | may execute |
|---|---|---|---|
| `observe` | yes | no | no |
| `suggest` (default) | yes | yes | no |
| `repair` | yes | yes | catalog fixes, each confirmed interactively |
| `autonomous` | yes | yes | routine catalog fixes unattended; higher-impact fixes still ask every time |

What "look" and "execute" cover is a fixed catalog — `wrench commands`, or
[commands.md](commands.md). Four more keys shape it:

```toml
[policy]
sudo = true                               # accept a `sudo -n ` prefix on catalog commands
disabled_packs = ["net-probe"]            # switch whole packs off (names: wrench commands)
allow_diag = ["zpool status -v tank"]     # extra read-only commands
allow_fix  = ["systemctl restart myapp"]  # extra fixes
```

| key | default | meaning |
|---|---|---|
| `sudo` | `true` | The agent may prefix a catalog command with `sudo -n`. `-n` never prompts: it works only where sudoers already allows that command without a password, and fails otherwise. The command behind the prefix is checked exactly as if it had none. Set `false` to refuse the prefix. |
| `disabled_packs` | `[]` | Packs the agent may not use at all, e.g. `net-probe` (ping, dig, traceroute, `curl -I` — the only diagnostics that send packets off the machine) or `kubernetes`. |
| `allow_diag` | `[]` | Your own read-only commands. Matched as **exact text** — no patterns, no extra arguments. They run at every tier without confirmation, so list only commands that change nothing. |
| `allow_fix` | `[]` | Your own fixes, exact text. Treated like a routine catalog fix: confirmed at `repair`, unattended at `autonomous`. |

The forbidden list (`rm`, `dd`, reboot, chaining with `;` `&` `|`, switching
off a firewall, …) is checked first and cannot be overridden by `allow_diag`
or `allow_fix`. Test any command with `wrench commands --check "<command>"`.

The dashboard chat always runs as `suggest`, whatever this is set to.

## `[general]`

```toml
[general]
patrol_interval_min = 15   # cadence `install-service` schedules; also the fleet's expected cadence
retention_days      = 30   # raw telemetry, anomalies and drift history
web_port            = 8787
offline             = false
```

`retention_days` applies to samples, anomalies and drift. The newest snapshot of
every kind is always kept (that is your accepted baseline), and patrol reports,
the action log and the health-score history are kept for at least a year.

`offline = true` is a declared zero-egress mode: CVE and end-of-life lookups
and any model endpoint that is not loopback or a private address are refused
with a clear message. A local brain, a fleet hub on a private address, and
every local check keep working.

## `[notify]`

```toml
[notify]
enabled      = true
min_severity = "attention"          # attention | error | critical
desktop      = true
# webhook_url = "https://ntfy.sh/your-topic"     # ntfy / Slack / Discord style JSON POST
# syslog_address      = "/dev/log"               # or udp://siem:514, tcp://siem:601  (RFC 5424)
# syslog_min_severity = "attention"
# http_jsonl_url          = "https://splunk:8088/services/collector/raw"
# http_jsonl_min_severity = "error"
```

Every sink is best-effort: a failed notification is logged and never breaks a
patrol. In offline mode, sinks pointing at public hosts are skipped.

## `[web]` — the dashboard

```toml
[web]
# bind          = "127.0.0.1"
# auth_token    = "<long random string>"   # full access
# viewer_token  = "<another>"              # read-only: no chat, no changes
# auth_token_file = "/etc/wrench/web.token"
# allowed_hosts = ["wrench.example.com"]   # extra Host names to answer to (behind a proxy)
# tls_cert = "/etc/wrench/tls/fullchain.pem"
# tls_key  = "/etc/wrench/tls/privkey.pem"
# allow_tier_raise = false   # true: an admin may RAISE the policy tier from the dashboard
                             # (lowering it is always allowed; default is terminal-only)
```

| situation | behaviour |
|---|---|
| bound to loopback, no token set | no sign-in; the server answers only to loopback host names |
| bound anywhere else | every page and API call needs a credential. With no token set, one is generated, stored at `<data dir>/web_token` (owner-only), and printed at startup |
| a token is set | sign-in is required even on loopback |

Browsers sign in at `/login` and receive a signed, `HttpOnly`,
`SameSite=Strict` session cookie valid for 12 hours. Scripts send
`Authorization: Bearer <token>`. `/healthz` is the only route with no
credential, and it carries no data.

## `[fleet]`

You rarely write this by hand: `wrench fleet join` fills in the node side.

```toml
[fleet]
# --- node (written by `wrench fleet join`) ---
hub_url = "https://hub.example:8788"
token   = "wfl_…"
# node_id = "web-01"             # default: hostname
# tags    = ["prod", "web"]      # searchable in the console
# ca_file = "/etc/ssl/corp-ca.pem"

# --- hub ---
# listen_host      = "127.0.0.1"
# listen_port      = 8788
# tls_cert         = "/etc/wrench/tls/fullchain.pem"
# tls_key          = "/etc/wrench/tls/privkey.pem"
# silent_factor    = 2.0    # silent when a report is overdue by factor × cadence
# max_skew_s       = 300    # accepted clock difference; 0 disables the check
# report_retention = 200    # reports kept per node
# max_findings     = 8      # findings a node sends per report
# hub              = true   # accept reports even before any key exists
# authorized_tokens = ["…"] # legacy 2.x shared tokens
```

The hub's console uses the `[web]` access rules above.

## `[maintenance]` — change windows

```toml
[maintenance]
windows  = ["Sat 02:00-06:00", "Sun 02:00-06:00", "Mon-Fri 23:00-23:59"]
timezone = "America/Los_Angeles"     # optional; local time if unset
```

Grammar: `<day> HH:MM-HH:MM`, where day is `Mon`…`Sun`, a range like
`Mon-Fri`, or `*`. An end time at or before the start crosses midnight.

Outside a window, anything that changes the machine is blocked: fixxer applies,
`blueprint --execute`, `certs renew --execute`, and the agent's own fixes.
`--override-window` proceeds only with consent and is audit-logged; the agent
has no override. **A window that cannot be parsed blocks changes** — a typo
must not silently turn change control off.

## `[approvals]`

```toml
[approvals]
approval_webhook_url = "https://hooks.example.com/wrench"
ttl_minutes          = 60        # clamped to 1 minute … 7 days
```

For non-interactive runs: wrench posts a pending approval to the webhook and
exits; a second person runs `wrench approve <token>`; the job is re-run and
proceeds. An approval is single-use and bound to the specific request it was
issued for. The token is sent only to the webhook.

## `[security]`

```toml
[security]
enabled             = true
burst_threshold     = 5      # failed sign-ins from one address…
window_minutes      = 10     # …inside this window is a brute-force burst
auth_lookback_hours = 24
cve                 = true
cve_ttl_hours       = 24
cve_max_packages    = 3000
# world_writable_paths = ["/etc", "/usr/local/bin"]
```

## `[webintel]`

```toml
[webintel]
enable        = true   # OSV.dev + endoflife.date lookups for `wrench cve` and patrols
cadence_hours = 24
# distro_watchlist = ["openssl", "openssh", "sudo"]
```

## `[fixxer]`

```toml
[fixxer]
auto_tiers        = ["safe"]   # widening to "moderate" also needs the consent record to include it
cache_max_mb      = 500        # package cache above this is offered for cleaning
journal_max_mb    = 1024
journal_vacuum_to = "500M"
tmp_age_days      = 14
```

## `[blueprint]`

```toml
[blueprint]
allowed_roots    = ["/etc"]
allow_exec_paths = false   # cron, shell profiles, unit files, PAM: refused unless you opt in
```

## `[memory]`

```toml
[memory]
enabled      = true       # false: nothing is remembered and nothing is shown to the model
agent_writes = "review"   # review: notes the agent writes unattended wait for `wrench memory review`
                          # off:    unattended notes are refused outright
learn_habits = true       # learn from approvals and from which commands you run, and when
```

With a person present (`wrench chat`, `wrench ask` in a terminal) the agent's
notes are confirmed on the spot, whatever `agent_writes` says. Memories live in
the `memories` table of the database; `wrench memory export` writes them as
JSON.

## `[heartbeat]`

```toml
[heartbeat]
enabled          = true
tick_min         = 5          # how often the OS timer beats (set at `install-service`; 1–60)
max_tier         = "suggest"  # the most a scheduled `ask` job may do: observe | suggest | repair | autonomous
job_timeout_s    = 900        # a job running longer than this is abandoned and recorded as an error
propose_routines = true       # offer to schedule what you do by hand at the same time each day
```

`max_tier` can only lower the tier, never raise it: the effective tier of a
scheduled question is the lower of `[policy] tier` and `max_tier`. The patrol
job runs at `[policy] tier`, as scheduled patrols always have. Job times are
honoured to the nearest beat, so with `tick_min = 5` a `daily 08:30` job starts
between 08:30 and 08:35. Jobs are managed with `wrench jobs`, not in this file.

## Environment variables

| variable | effect |
|---|---|
| `WRENCH_CONFIG_DIR`, `WRENCH_DATA_DIR` | Where config and data live. Use both to run an isolated instance. |
| `WRENCH_PROVIDER`, `WRENCH_MODEL`, `WRENCH_DEEP_MODEL`, `WRENCH_BASE_URL` | Override the brain. |
| `WRENCH_API_KEY`, `WRENCH_API_KEY_FILE` | Key for whichever provider is selected. |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `META_API_KEY`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_VERSION`, `CUSTOM_API_KEY`, `LITELLM_API_KEY` | Provider-specific. |
| `WRENCH_POLICY` | Policy tier. |
| `WRENCH_OFFLINE` | `1` turns on zero-egress mode. |
| `WRENCH_WEB_PORT`, `WRENCH_WEB_TOKEN`, `WRENCH_WEB_VIEWER_TOKEN` | Dashboard port and access tokens. |
| `WRENCH_AUDIT_KEY_FILE` | Path to a key that adds a MAC to every audit record. Keep it outside the data directory. |
| `WRENCH_ACTOR` | Name recorded as the actor in the audit log (default: the OS user). |

## Files wrench writes

All under the data directory unless noted.

| file | what it is |
|---|---|
| `wrench.db` | SQLite: samples, baselines, drift, patrols, actions, fleet nodes and keys |
| `audit.jsonl`, `audit.head` | the hash-chained audit log and its sealed head |
| `notifications.jsonl` | the notification inbox (last 2000) |
| `reports/` | standalone HTML patrol reports |
| `blueprint_backups/` | pre-change copies of every file a blueprint touched |
| `web_token` | a generated dashboard token, if one was needed |
| `logs/` | output of scheduled runs (macOS) |
| `config.toml`, `*_consent.json` | in the **config** directory: settings and recorded consent |
