# wrench — build progress

## 2026-11-11 — guided fleet setup

`wrench/fleetsetup.py` is one engine with three front ends: agent tools
`fleet_setup_status` / `fleet_setup`, the `wrench fleet setup` wizard, and the
plain commands each step names. Mutating steps go through `confirm_fn` with a
`setup: ` label and are refused without one; passwords come from
`confirm_fn.ask_secret` (the CLI's hidden prompt), never from tool arguments.
`hub_start` spawns `python -m wrench fleet serve` detached with a pid file and
log in the data dir; `hub_stop` checks the pid is still a hub before signalling
it. `fleet join` / `connect` now share `fleetsetup.attach_node`. Tests:
`tests/test_fleet_setup.py` (a scripted model drives the agent; a real detached
hub is started and stopped). The detached start/stop on Windows and the
systemd / Task Scheduler step are covered only by CI and mocks.

## 2026-11-11 — fleet connect and the machine picker

`wrench fleet connect <hub>` posts the hub's admin password to
`POST /api/fleet/connect` and gets back a single-node enrollment key
(`fleet.connect_grant`); `fleet join` and `connect` share `_fleet_attach`.
The node probes `/healthz` first (https, then http for a bare address), will
not send the password over plain HTTP to another machine without
`--allow-http`, and stops on an untrusted certificate. The console API adds
the hub's own machine as a `local` row (`fleet.local_state`, never stored),
and `base.js` `fillMachines` drives a picker on both pages. Tests:
`tests/test_fleet_connect.py`. Verified live between two scratch installs on
one Mac, over loopback HTTP and over HTTPS with a self-signed certificate;
not exercised across two real machines.

## 2026-11-11 — dashboard password

`wrench password` and a step in `wrench init` put a password on the web
surfaces. `webauth.py` hashes with stdlib scrypt (PBKDF2 where OpenSSL lacks
it) into `<data dir>/web_password`; `AuthConfig` re-reads the file when it
changes and mixes the hash into the session key, so a change needs no restart
and signs everyone out. A network bind with no credentials left locks rather
than opens. Tests: `tests/test_web_password.py`. Verified live on macOS
against a scratch install; the interactive prompt was exercised only through
the test runner.

## 2026-11-10 — command catalog

The agent's reach was ~60 diagnostics and 7 fixes. Now `wrench/commands.py`
holds 243 diagnostic entries and 106 fix entries in 19 packs
(Linux, macOS, Windows), each with examples that tests run through the policy
check, plus ~380 commands that must stay refused, about 150 of them from an
independent review of the first draft (`tests/test_commands.py`).

- `policy.py` reads the catalog; fixes marked `ask` need a yes at every tier.
- `[policy] sudo / disabled_packs / allow_diag / allow_fix`.
- `wrench commands` (+ `--check`), agent tool `list_commands`, dashboard panel,
  `docs/commands.md` (generated; a test fails if it is stale).
- Not verified: almost none of the new commands were executed for real — the
  tests prove what is allowed and refused, not that each tool behaves on each
  OS. Linux and Windows forms were written from documentation.

## 2026-11-10 — v3.1.0: MEMORY + HEARTBEAT

wrench could watch and act but not learn or take initiative. Now:

- `wrench/memory.py` — memories (user / agent / learned), deterministic
  retrieval, review queue for unattended agent notes, habit counters
  (approvals, routine commands), export/import. Injected into every agent
  system prompt.
- `wrench/heartbeat.py` — schedule parser (plain language + cron), jobs with a
  closed action registry, `tick` (lock, timeouts, coalesced catch-up,
  fail-streak pause), pulse, `reflect` (routine → proposed job), the brief.
- Agent tools `remember`, `recall`, `schedule_task`, `list_tasks`; CLI
  `remember`, `memory`, `jobs`, `heartbeat`; dashboard Memory + Schedule
  panels; `install-service` now installs the heartbeat timer.
- Not verified: the OS timers themselves (install-service was not run), an
  `ask` job against a real model, Windows beyond CI.

## 2026-11-09 — v3.0.0: ENTERPRISE PASS (branch `enterprise-v3`)

Goal: a tool an IT infrastructure team would install on every machine. Full
detail in CHANGELOG.md; the short version:

- **First native macOS pass** (Apple Silicon, macOS 27). Running every command
  for real exposed, and this pass fixed: a patrol crash, phantom APFS volumes,
  an empty listener inventory, invisible user accounts, Linux-only compliance
  packs, no Time Machine awareness, `du --max-depth`, Darwin-as-Linux-kernel.
- **Two code reviews** (mutating paths; cross-platform sensing) → ~60 verified
  findings, the security-relevant ones all fixed: diagnostic allowlist that
  permitted log deletion / file truncation, repair allowlist that could power
  off the box, agent fixes ignoring maintenance windows, blueprint path
  bypasses, approval reuse, audit truncation, apt hangs under sudo, cert
  renewal targeting every lineage.
- **New**: `wrench score` (deterministic health score), brain-optional
  deterministic patrols, dashboard access control (token/session, roles, Host
  + CSRF checks, CSP, TLS), fleet v2 (enroll/join/keys/revoke/forget, replay
  protection, node binding), fleet console, redesigned dashboard,
  `macos-baseline` + `windows-baseline` packs on a closed probe registry,
  CI on three OSes.
- **Tests: 780 pass on macOS** (was 667 pass / 5 fail on this platform).

### Honest status
- Linux was NOT re-run on real hardware in this pass (macOS box only); the
  Linux suite runs in CI.
- Windows: implemented + unit-tested + CI green and gating (2026-11-10). No native pass.
- Not run natively on macOS: `install-service` (it would schedule patrols
  against the operator's real data), `fixxer` apply, any LLM provider.
- Known gaps left open: no macOS/Windows auth-log reader (reported as "not
  watched"), `net user` parsing on localized Windows, Windows toast AppID,
  Task Scheduler battery/visibility defaults, blueprint approvals are bound to
  the intent text rather than the drafted diff, interactive TTY runs skip the
  out-of-band approval gate by design.

## 2026-11-04 ~12:00 — v1.0.0: WEB INTEL + LIVE CHAT + BEAUTY (final pass)

Christopher's 1.0 directive, three workstreams, all shipped + live-tested:

### 1. Web intelligence (0261a63)
- `wrench/webintel.py`: OSV.dev (querybatch + capped per-vuln detail) over a
  sensible inventory — pip + npm globals + curated distro watchlist (openssl,
  openssh, sudo, systemd… ~20 source pkgs) — plus endoflife.date for
  os/kernel/python/node. 8s timeouts, sqlite TTL cache (24h, `[webintel]`
  enable/cadence_hours knobs), offline → stale cache marked offline. Patrol
  context gets a summary line; **patrol can never fail from network loss**.
- `wrench cve`: severity-colored tables + first-person threat briefing;
  exit 1 on findings. fixxer gains `cve_upgrade` catalog action (targeted
  `apt-get install --only-upgrade` of exactly the CVE-affected binaries,
  moderate tier) + EOL advisory panel (flagged, never auto). New agent tool
  `security_intel` (cached, instant).
- **LIVE**: 261 packages checked on Devbox2 — real findings: aiohttp 3.13.3
  15 advisories (fix 3.14.4), kernel 7.0 EOL 2026-06-27. Briefing triaged
  correctly (transcript: /tmp/wrench_cve_transcript.txt, 3.2k tok).

### 2. Live chat in the dashboard (ecbdb0b)
- 🔧 FAB → chat panel: POST /api/chat runs the same Agent loop as `wrench
  chat` (tool calls included), session conversation memory, typing dots,
  model/tokens/tool-call meta per reply. Greeting: "I'm wrench. I live here."
- Security: still binds 127.0.0.1; chat enforces localhost-origin + 16KB cap;
  503 without cfg. Shortcuts: ? overlay, c chat, r refresh, t theme (new
  dark/light toggle, persisted), Esc. New security-intel feed panel.
- **LIVE**: curl chat → 23.8k tok, 4 tool calls, CVE triage cross-referencing
  live listeners; browser chat → RAM question answered (9.7k tok, 3 tools).
  Screenshot: ~/.openclaw/workspace/reports/state/wrench_dashboard_chat_live.png

### 3. Beauty pass (8fc4c63)
- Site: scroll-reveal (reduced-motion safe), hero entrance + counter-rotating
  gear rings, card hover lift, simulated chat replay FAB ("on your machine,
  this chat is real"), tutorial step 6 `wrench web` pops it as the finale,
  ? shortcuts overlay (parity with dashboard), 'Watch the horizon' CVE card.
  Verified in a real browser. Screenshot:
  ~/.openclaw/workspace/reports/state/wrench_site_chat_teaser.png
- Dashboard polish rode along with #2 (theme, hover, panels).
- CLI: `wrench cve` tables are the new-formatting showcase; existing rich
  output untouched (already aligned/colored/spinnered).

### Verification
- **Tests: 165 pass** (138 → +20 webintel +7 webchat).
- Token burn this pass: cve 3.2k + web-chat 33.5k; cumulative **2.27M / 398
  calls** (reports/state/wrench_hackathon_tokens.md).
- v1.0.0 tagged. pipx reinstall + wrench status + patrol timer + Pages
  checked below (final verify sweep).

Cut for deadline: GitHub-releases watchlist checker (optional extra),
deeper CLI reformat (already rich), macOS/Windows native smokes (unchanged).


## 2026-11-04 ~11:45 — FIXXER + PERSONALITY (v0.3.0, final pre-deadline pass)

Christopher's final feature directive, all shipped and live-tested:

- **`wrench fixxer`** (55e37c6): scans for programmatically correctable issues
  (pending updates incl. security, orphans/old kernels, fat journald, bloated
  package caches, stale /tmp, failed services) → numbered risk-labeled menu
  (safe/moderate/risky) → first-person muse briefing → all/none/pick →
  applies with sudo where needed → **verifies each fix by re-measuring**.
  SAFETY LINE: every command is a hand-written parameterized catalog entry in
  wrench/fixxer.py — the LLM explains/recommends, never authors shell. apt
  fully implemented; dnf/pacman/brew/winget best-effort behind the same
  abstraction.
- **Auto mode**: `--setup-auto` interactive consent ceremony (recorded to
  fixxer_consent.json), effective scope = consent ∩ config auto_tiers
  (default safe-only — widening moderate takes two locks), `--dry-run`
  preview, `--revoke-auto`, JSONL audit log with rollback hints +
  `--audit` viewer, `install-service --with-auto-fixxer` daily scheduled
  run (systemd/launchd/schtasks; consent-gated; uninstall removes both).
- **Personality pass** (9a2d542): wrench speaks first person — init greeting
  ("I'm wrench — your systems administrator. I live here now."), status/patrol
  voice lines (one line, then data), README top quote + fixxer section with
  loud auto-mode warnings, site hero/feature card/leash copy (d028164).
  All claims true: fixes only with permission or recorded consent.
- **Tests: 138 pass** (106 + 32 new: catalog detect/plan/apply(mock)/verify
  per action, tier gating incl. consent∩config intersection, consent
  roundtrip/corruption, audit, scheduler plans for all 3 OSes).
- **LIVE test on Devbox2 (meta provider)**: interactive fixxer found 4 real
  issues; muse-spark briefed first-person (1,901 tok), human picked the two
  safe ones → journald 4096→439 MB, apt cache 2015→0 MB, both verified,
  rescan showed them gone. Consent ceremony → dry-run (consent ∩ config =
  safe, correctly empty scope) → audit table → revoke, all live. nvidia*/GPU/
  docker/llama services untouched; auto mode NOT left enabled on this box.
- Token totals after pass: muse-spark 2,045,458/352 + muse-wonder 129,258/27
  = **2.17M tokens / 379 calls** (reports/state/wrench_hackathon_tokens.md).
- v0.3.0. pipx reinstall verified; wrench-patrol.timer still active; Pages
  200 with fixxer tutorial finale (step 5) + Fix feature card deployed.

## 2026-11-04 ~02:30 — PROVIDER MENU + OLLAMA GUIDED LOCAL SETUP (shipped)

Christopher's explicit ask from the v0.2.0 pass, now done end-to-end:

- **`wrench init` provider menu** (TTY): meta (enter = default) / openai /
  anthropic / ollama (guided) / lmstudio / litellm. No TTY/CI → meta + note.
  Scripting: `--provider/--model/--yes`. Install scripts offer `wrench init`
  at the end when a real terminal exists (install.sh reads /dev/tty).
- **Ollama guided setup**: detects RAM (psutil) + NVIDIA VRAM (nvidia-smi) +
  Apple Silicon unified memory; recommends a tool-calling tier —
  qwen2.5 1.5b/3b/7b/14b (non-thinking, CPU-sane) and qwen3:30b MoE for
  24GB+ GPUs (tags + tools capability verified on ollama.com 2026-11-04);
  consented install (official installer per OS) + `ollama pull`; finishes with
  a REAL tool-calling smoke test through the agent loop (≥1 tool dispatch
  required) and reports pass/fail honestly in the init panel.
- **Hardening found by live CPU testing on this box** (qwen2.5-3b-cpu variant,
  num_gpu 0 — GPU tenants untouched, verified via nvidia-smi before/after):
  1. 180s HTTP timeout killed thinking models mid-reasoning → 600s for
     ollama/lmstudio.
  2. qwen3-family on CPU burns its whole 4k budget thinking (~7 min/turn,
     measured 10 t/s) → thinking families route via ollama native /api/chat
     with think:false; CPU tiers recommend non-thinking qwen2.5.
  3. Smoke probe must be unanswerable from context (model cheated off the
     system prompt's OS line) → probe = quote `date +%s` output.
  4. qwen2.5:3b emits `{"action":"run_diag"}` (tool name in action field) →
     agent normalizes the shape. **Final live smoke: PASS in 6.6s** (menu →
     config → baseline → 1 real tool call → answer), 100% CPU, 0 GPU.
- **Tests: 106 pass** (70 existing + 36 new: recommendation table with mocked
  RAM/VRAM/Apple, detection failure paths, per-OS installer commands, smoke
  gating, menu flow with mocked TTY, protocol normalization).
- Docs: README menu walkthrough + hardware→model table + local-mode story;
  site tabnote + tutorial init now plays the menu. Meta stays the default
  everywhere (hackathon).
- ⚠ Two sessions edited this repo concurrently tonight (this one + the
  hackathon-compliance pass, 395060f). Reconciled: compliance commit kept,
  its in-flight localsetup draft superseded by this implementation; its
  tutorial.js menu frames + README blockquote folded into the docs commit.
- No Meta tokens burned this pass (all live testing on local Ollama).

## 2026-11-04 ~02:00 — MAJOR UPGRADE PASS (v0.2.0)

Three workstreams, all pushed to main and verified live:

### 1. Cross-platform (Linux / macOS / Windows)
- New `wrench/platforms.py` abstraction: OS identity, per-OS config/data dirs
  (XDG / `~/Library/Application Support` / `%APPDATA%`+`%LOCALAPPDATA%`),
  capability detection (service manager, log backend).
- New `wrench/scheduler.py`: `install-service` targets systemd / launchd plist /
  schtasks per OS, plus `--uninstall`. Plan/apply split for testability.
- driftscan, tools, sensors, policy all platform-dispatched: psutil-first core,
  OS-native tools as graceful enrichers (unified log, wevtutil, launchctl,
  sc/schtasks/tasklist, brew/pacman/apk, pure-Python du fallback).
- `tests/`: **70 unit tests**, all platform branches covered with mocks. All pass.
- `scripts/install.sh` (curl|bash) + `scripts/install.ps1` (irm|iex).
- **PLATFORMS.md** support matrix. HONESTY: Linux = tested end-to-end;
  macOS/Windows = implemented + unit-tested, **need native smoke tests**.
  Do not claim mac/win tested anywhere public.

### 2. README rewrite (first principles)
- Sells the problem to a stranger (silent degradation, no change memory);
  no references to predecessor tools as known things.
- sense/remember/explain/patrol framing, per-OS quickstart, full CLI tour with
  real sanitized outputs in <details>, patrol anatomy + failing-disk incident
  story, provider setup, mermaid architecture diagram (renders on GitHub), FAQ.
- 2 new real GIFs (asciinema+agg, casts sanitized pre-render):
  docs/assets/status.gif (25K), docs/assets/ask.gif (171K).

### 3. Site rewrite (docs/ → Pages)
- First-principles hero + problem cards + feature cards + case study +
  OS-tabbed install snippets.
- **Interactive tutorial**: simulated terminal in vanilla JS (docs/tutorial.js),
  plays init→status→ask→patrol with typing animation + real canned output.
  Verified in a real browser locally AND on the live Pages deploy: 0 console
  errors, all steps play.

### Verified after push (2026-11-04 ~01:55 PST)
- Pages 200 + new content live; tutorial.js 200; GIFs/raw installers 200.
- GitHub README renders (mermaid container present, GIFs embedded).
- Fresh venv `pip install git+.../wrench` → wrench 0.2.0, drift works.
- Local pipx reinstall → `wrench status` clean; wrench-patrol.timer still active.

### Pending
- [ ] Native macOS smoke test (install, doctor, status, drift, install-service)
- [ ] Native Windows smoke test (same)
- [x] Ollama provider live test — DONE 2026-11-04 (guided setup + real tool-calling smoke, CPU-pinned model, GPUs untouched)


Deadline: 2026-11-04 ~14:00 PST. Builder notes for the orchestrator.

## 2026-11-03 ~20:20 — ALL PHASES FUNCTIONALLY COMPLETE

**Repo:** https://github.com/sunkencity999/wrench (main, pushed)
**Pages:** https://sunkencity999.github.io/wrench/ → **200** (landing + dashboard.png + demo.gif all serve)

### Verified working on Devbox2
- `pipx install -e .` ✔ · `wrench version/status/doctor/drift/ask/chat/explain/patrol/web/init/install-service/report` all exercised live ✔
- Meta provider live: muse-spark-1.3 (patrols/asks), muse-wonder-1.0 (--deep). Both reasoning
  models — max_tokens 6144 default. Key = full pipe-delimited string, read via api_key_file.
- 3 real patrols stored (2 spark, 1 wonder-deep). Deep patrol found: /dev/sda pending sectors,
  PCIe AER errors, broken smartd mail, blocked sudo probes. Genuinely useful output.
- `wrench install-service` → wrench-patrol.timer every 30min; first scheduled run exit 0,
  46.7k tokens. Timer left ENABLED to keep feeding the dashboard until the deadline.
- `wrench web` dashboard verified in a real browser: vitals gauges, 4 SVG timelines, patrol
  feed, drift feed, action log, token-spend widget. Screenshot (host=devbox) in docs/assets/.
- 2 sanitized HTML patrol reports in examples/ (sanitizer with leak-check: scripts/sanitize_report.py).
- Agent-loop hardening from live testing: (1) nudge on malformed protocol JSON, (2) nudge on
  premature prose intent ("I'll check...") with 0 tool calls — both verified fixed.
- Token burn so far: **~354k tokens / 69 calls** (see reports/state/wrench_hackathon_tokens.md).

### In flight
- scripts/demo_batch.sh running: 12 varied ask/explain calls (spark + wonder) → transcripts
  in .wrench-dev/demo_transcripts/ (will sanitize 2-3 into examples/).
- wrench-patrol.timer keeps patrolling every 30min.

### Final verify sweep — 2026-11-03 20:30 PST — ALL GREEN
- [x] 12-item demo batch complete; 3 sanitized transcripts + index committed to examples/
- [x] Fresh venv install from public GitHub URL → `wrench version` + `wrench status` clean
- [x] Pages 200 with hero copy; repo 200; README renders
- [x] Token log updated: **746k tokens / 145 calls** (spark 617k/118, wonder 129k/27)
- [ ] Ollama provider live test — DEFERRED while GPUs are pinned by the P-H3 trial
      (ollama would want VRAM). Code-complete; same OpenAI-compat path as the proven meta
      adapter; graceful-error path verified. Test if GPUs free up before deadline.
- wrench-patrol.timer left ENABLED (30min cadence) — keeps the dashboard + token widget
  live and burns credits as instructed. Disable after judging with:
  `systemctl --user disable --now wrench-patrol.timer`

### Known notes
- Port 8787 is taken on Devbox2 by an unrelated service → use `wrench web --port 8790` here.
  (Default stays 8787 for the public tool; config web_port handles it.)
- muse models: ~300-500 reasoning tokens before any content; never set max_tokens < 2000.

## v1.0.1 — Azure OpenAI / AI Foundry provider — 2026-11-04

### Shipped
- New `azure` provider in the adapter layer (providers.py `_azure`): Azure OpenAI
  deployment-path URLs (`/openai/deployments/<dep>/chat/completions?api-version=...`)
  AND AI Foundry serverless (`https://<name>.<region>.models.ai.azure.com` — model in body).
  Auth modes: `api-key` (Azure-native header), `bearer`, or `auto` (api-key first,
  one Bearer retry on 401). Native `tools` passthrough added to chat() for all
  OpenAI-shaped adapters (wrench's agent keeps its provider-agnostic JSON protocol).
- Config: `[azure]` section (endpoint, model=deployment, api_version default 2024-10-21,
  auth), env support AZURE_OPENAI_API_KEY / AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_VERSION.
  Config written with a key inside gets chmod 600.
- `wrench init`: menu entry #4 "Azure OpenAI / AI Foundry — enterprise" with guided
  prompts (endpoint, deployment, api-version, hidden key prompt, enter-to-skip for env).
  Headless: `--provider azure --azure-endpoint ... --azure-deployment ...
  [--azure-api-version ...] [--api-key ...] --yes`.
- Tests: 16 new mocked-HTTP unit tests (URL construction for all 3 endpoint shapes,
  api-key vs Bearer vs auto-401-fallback, api-version query param, tools passthrough,
  429 + key redaction, token-usage logging, env + toml config loading, chmod 600).
  183 total, all green (was 165 + 2 renumbered menu cases).
- Docs: README provider example + Azure details block + architecture diagram;
  site tabnote mentions Azure.

### Honest status
- Adapter implemented + fully unit-tested against mocked HTTP. **No live Azure smoke
  test** — no wrench-usable Azure key on this box (OpenClaw's own Azure creds are
  off-limits for wrench testing by policy). First user with a real deployment:
  `wrench init -p azure ...` then `wrench doctor`.
- No Meta API calls made for this work — token log unchanged.
- wrench-patrol.timer untouched and active throughout.
