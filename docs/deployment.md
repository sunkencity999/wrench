# Deploying wrench

From one laptop to a fleet. Each section is self-contained; start with the one
that matches what you have.

- [One machine](#one-machine)
- [A server](#a-server)
- [A fleet](#a-fleet)
- [Rolling out with MDM or configuration management](#rolling-out-with-mdm-or-configuration-management)
- [Putting the hub or dashboard on a network](#putting-the-hub-or-dashboard-on-a-network)
- [Air-gapped and offline networks](#air-gapped-and-offline-networks)
- [Wiring into monitoring and SIEM](#wiring-into-monitoring-and-siem)
- [Upgrading](#upgrading)
- [Operating it](#operating-it)
- [Troubleshooting](#troubleshooting)

## One machine

```bash
pipx install git+https://github.com/sunkencity999/wrench
wrench patrol            # first measurements — works with no model
wrench                   # where the machine stands, and the next step
wrench install-service   # start the heartbeat: patrol every 15 minutes + scheduled jobs
wrench jobs              # what is scheduled; approve the morning brief if you want it
wrench web               # http://127.0.0.1:8787
```

The dashboard opens with a five-step guide; each step is one command and
ticks itself off when done. Add a model whenever you like with `wrench init`.

**What "done" looks like:** `wrench doctor` is green, `wrench score` shows a
grade (not "provisional"), and the dashboard's guide has disappeared.

## A server

Servers usually run headless, without a model, as a dedicated account.

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin wrench
sudo -u wrench pipx install git+https://github.com/sunkencity999/wrench
sudo loginctl enable-linger wrench          # keep the user's systemd timer running after logout
sudo -u wrench XDG_RUNTIME_DIR=/run/user/$(id -u wrench) wrench install-service
```

Things to decide:

| question | guidance |
|---|---|
| Run as root? | No. As an ordinary account wrench reports the checks that need root as *skipped* — never as passing. To cover them, grant read access to what it needs (`adm` group for logs) rather than running the whole agent as root. |
| A model? | Optional. Without one, patrols are deterministic and cost nothing. With a local model on the same network, set `[provider] name = "custom"` and a private `base_url`. |
| Alerts? | Set `[notify] syslog_address` or `webhook_url`. Desktop notifications are skipped automatically on a headless box. |
| Changes? | Leave `[policy] tier = "suggest"` (the default) and nothing on the box can be changed by wrench. Add `[maintenance] windows` before raising it. |

## A fleet

One machine is the **hub**. Every other machine is a **node** that pushes a
small signed report after each patrol. Nodes need outbound access to the hub;
the hub never connects to nodes.

**1. Stand up the hub**

```bash
wrench fleet enroll --label "prod web" --hub-url https://wrench.corp.example:8788
wrench fleet serve --host 0.0.0.0 \
    --tls-cert /etc/wrench/tls/fullchain.pem --tls-key /etc/wrench/tls/privkey.pem
```

`enroll` prints a `wrench fleet join …` line containing a key. It is shown
once. `serve` prints the console address and, because it is bound beyond
loopback, an access token for the console.

**2. Join each machine**

```bash
wrench fleet join https://wrench.corp.example:8788 wfl_… --tags prod,web
wrench install-service
```

`join` sends a test report first. If the hub refuses it, nothing is saved and
the reason is shown.

**3. Keep it tidy**

| task | command |
|---|---|
| See every machine | `wrench fleet status` or the console at `/fleet` |
| List keys and who uses them | `wrench fleet keys` |
| Cut a key off | `wrench fleet revoke <key id>` |
| Retire a machine | `wrench fleet forget <node>` |
| Export inventory | console → **Export CSV**, or `GET /api/fleet/export.csv` |

**Key strategy.** One key per group you might want to revoke together — a
site, an environment, a team — is usually right. Use `--single-node` for a
machine that must have its own. A key can enroll up to 5000 machines.

**Sizing.** A report is about 2 KB. The hub keeps the latest state of each
node plus its last 200 reports in SQLite; a thousand nodes reporting every 15
minutes is a few megabytes and well within one small VM.

**Run the hub as a service** (systemd example):

```ini
# /etc/systemd/system/wrench-hub.service
[Unit]
Description=wrench fleet hub
After=network-online.target
Wants=network-online.target

[Service]
User=wrench
ExecStart=/home/wrench/.local/bin/wrench fleet serve --host 0.0.0.0 --port 8788
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/wrench/.local/share/wrench /home/wrench/.config/wrench

[Install]
WantedBy=multi-user.target
```

## Rolling out with MDM or configuration management

The join line is the whole enrollment, so any tool that can run a command can
build the fleet.

**Shell (Jamf, Intune for macOS/Linux, a golden image's first-boot script)**

```bash
#!/bin/sh
set -eu
command -v wrench >/dev/null || pipx install git+https://github.com/sunkencity999/wrench
wrench fleet join "https://wrench.corp.example:8788" "$WRENCH_FLEET_KEY" --tags "$(hostname -s | cut -d- -f1)"
wrench install-service
```

**Ansible**

```yaml
- name: Install wrench
  community.general.pipx:
    name: wrench-agent
    source: git+https://github.com/sunkencity999/wrench

- name: Join the fleet
  ansible.builtin.command: >
    wrench fleet join https://wrench.corp.example:8788 {{ wrench_fleet_key }}
    --tags {{ group_names | join(',') }}
  args:
    creates: "{{ ansible_env.HOME }}/.config/wrench/config.toml"
  no_log: true

- name: Schedule patrols
  ansible.builtin.command: wrench install-service
```

**PowerShell (Intune, GPO startup script)**

```powershell
if (-not (Get-Command wrench -ErrorAction SilentlyContinue)) {
  pipx install git+https://github.com/sunkencity999/wrench
}
wrench fleet join https://wrench.corp.example:8788 $env:WRENCH_FLEET_KEY --tags windows
wrench install-service
```

Treat the fleet key like any deployment secret: inject it from your tool's
secret store, and revoke and re-issue it if a script leaks. Windows support
has not had a native hands-on pass yet — see [PLATFORMS.md](../PLATFORMS.md).

## Putting the hub or dashboard on a network

Bound to `127.0.0.1` there is no sign-in. The moment you bind anywhere else,
every page and API call requires a token.

- **Give people their own access level.** Set `[web] auth_token` for operators
  and `viewer_token` for read-only use (a wall display, a manager's bookmark).
- **Use TLS.** Either pass `--tls-cert`/`--tls-key`, or terminate TLS at a
  reverse proxy and add the public name to `[web] allowed_hosts`.

```nginx
server {
    listen 443 ssl;
    server_name wrench.corp.example;
    ssl_certificate     /etc/letsencrypt/live/wrench.corp.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wrench.corp.example/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8788;
        proxy_set_header Host $host;
        proxy_read_timeout 300s;        # chat requests can take a while
    }
}
```

With the proxy on the same host, keep the hub bound to `127.0.0.1`, set a
token explicitly (loopback would otherwise need none), and add
`allowed_hosts = ["wrench.corp.example"]`.

## Air-gapped and offline networks

```toml
[general]
offline = true

[provider]
name = "custom"

[custom]
base_url = "http://10.0.0.9:8000/v1"   # a model server on the same enclave, or use name = "none"
model    = "your-served-model"
```

- `wrench doctor` lists what offline mode disables and confirms the model
  endpoint is private.
- A fleet hub on a private address keeps working; a public one is refused.
- To move evidence out: `wrench bundle --out /mnt/usb/box.tar.gz`. It contains
  the latest patrol, status, drift, security, compliance, backups, forecast and
  the audit chain — and no secrets.
- Install without internet access by building wheels on a connected machine
  (`pip wheel git+https://github.com/sunkencity999/wrench -w wheels/`), carrying
  the `wheels/` directory across, and running
  `pip install --no-index --find-links wheels/ wrench-agent`.

## Wiring into monitoring and SIEM

| you run | use |
|---|---|
| Prometheus / Grafana | `GET /metrics` on the dashboard or hub, or `wrench metrics serve`. Send a bearer token when access control is on. |
| A SIEM | `[notify] syslog_address` (RFC 5424) or `http_jsonl_url` (Splunk HEC / ELK style). |
| Cron, CI, scripts | `--json` on every command, with meaningful exit codes. |
| Chat | `[notify] webhook_url` (ntfy, Slack and Discord style). |

Useful alerts:

```promql
wrench_health_score < 70                   # a machine's posture has dropped
wrench_fleet_nodes_silent > 0              # something stopped reporting
time() - wrench_patrol_last_ok_timestamp_seconds > 3600
```

Schemas and every metric: [json-output.md](json-output.md).

## Upgrading

```bash
pipx upgrade wrench-agent      # or: pipx install --force git+https://github.com/sunkencity999/wrench
wrench doctor
```

- The database migrates itself in place on first run.
- **From 3.0 or 2.x: re-run `wrench install-service` once.** The old timer ran
  `wrench patrol` directly; the new one runs `wrench heartbeat`, which runs the
  patrol and every other scheduled job. The unit, agent and task names are the
  same, so the reinstall replaces the old timer in place. Until you do, patrols
  continue exactly as before but no other job fires.
- **From 2.x:** existing fleet nodes keep reporting with their shared tokens.
  Move them to enrollment keys at your own pace with `enroll` + `join`.
- **From 2.x:** a dashboard bound beyond loopback now requires a token. If you
  scrape `/metrics` remotely, add a bearer token to the scrape config.
- **From 2.x:** a `[maintenance]` window that does not parse now blocks changes
  instead of being ignored. `wrench doctor` shows the loaded config.

## Operating it

| question | answer |
|---|---|
| Is it healthy? | `wrench doctor` |
| Is it actually patrolling? | `wrench doctor` (patrol freshness), or the **Patrol** pillar |
| What did it do? | `wrench audit`, or **Trust & activity** on the dashboard |
| Has the record been altered? | `wrench audit verify` |
| How big will it get? | Telemetry is pruned to `retention_days`; a typical box settles at tens of megabytes |
| Back it up? | Copy the data directory. The config directory holds settings and consent |
| Remove it | `wrench install-service --uninstall`, then delete the data and config directories |

## Troubleshooting

**`wrench doctor` says "deterministic mode".** No model is configured or its
key is missing. That is a supported way to run; `wrench init` adds a brain.

**The score says "provisional".** Fewer than half of the pillars' weight has
been measured. Run `wrench patrol` once.

**Many compliance checks are "skipped".** They need root to read their target.
Skipped checks are excluded from the score rather than counted as passing.

**`install-service` failed on a server over SSH.** There is no user session
bus. Run `sudo loginctl enable-linger <user>` and try again.

**A node shows as silent.** It has not reported for twice its patrol
interval. On the node: `wrench fleet report` shows the hub's exact answer.
`HTTP 401 … clock` means the clocks differ by more than five minutes.
`HTTP 403 … revoked` means its key was revoked — join again with a new one.
`HTTP 409 … different credential` means another machine already uses that
node id; pass `--node-id`.

**The dashboard returns "unrecognized Host header".** You reached a
loopback-bound server through another name. Add it to `[web] allowed_hosts`,
or bind to the address you are using.

**"database is locked".** Should not happen from 3.0 (the store uses WAL and
waits). If it does, check that the data directory is on local disk, not a
network share.

**macOS: no listening ports from other users' processes.** Without root, macOS
only reveals this user's sockets. The census says so; run a patrol as root for
the full view.
