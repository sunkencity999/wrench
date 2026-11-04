# WRENCH — Meta Hackathon Build Spec (deadline: 2026-11-04 afternoon)

**One-liner:** An intentional local sysadmin agent. Mechanic's senses + Drift's memory + a Muse-powered brain. Installable CLI that genuinely *administers* a machine: watches, diagnoses, explains, and (with permission) fixes.

## Heritage (what we're combining — concepts, not code copies)
- **Mechanic** (~/.local/bin/mechanic concept): periodic sensor sampling (os/docker/ollama) → sqlite time-series, EWMA baselines, anomaly z-scores. 30s grain, 30d retention.
- **Drift** (~/.local/bin/drift concept): periodic snapshots of ports/services/packages/users/cron → plain-English diffs ("what changed on this box").

## Product requirements (from Christopher)
1. **CLI tool**, pip/pipx installable, clean UX. Name: `wrench`. Package: `wrench-agent`.
2. **Model-agnostic agent brain**: accepts **Meta Model API** (default — hackathon), **OpenAI, Anthropic, Ollama, LM Studio, LiteLLM** as providers. Config file + env vars.
   - Meta: base `https://api.meta.ai/v1` (OpenAI-compatible chat/completions), models `muse-spark-1.3` (default, agentic) and `muse-wonder-1.0` (deep reasoning). VERIFIED WORKING. Key: env `META_API_KEY`; for local testing read `~/.openclaw/credentials/meta_llama_api_key.txt` (pipe-delimited key, NEVER commit, NEVER echo into logs/repo).
3. **Simple CLI commands to communicate with the agent**: `wrench ask "..."`, `wrench chat`, `wrench explain <service|port|pid>`.
4. **Regular, beautifully styled reporting**: rich terminal output (tables/sparklines/panels) + scheduled patrol reports.
5. **Web interface**: `wrench web` — local dashboard reporting its regular work: health timeline, drift events, patrol reports, agent action log. Self-contained static HTML + small server (stdlib or FastAPI). Dark, gorgeous, at-a-glance.
6. **At-a-glance + deep hooks**: `wrench status` (one-screen health), plus deep diagnostics (journalctl/systemctl/ss/df/ps/smart hooks).
7. **GitHub repo** on sunkencity999 (public), **cheeky+fun extensive README**, **GitHub Pages site** from same repo (docs/ folder) — demonstrative and intriguing landing page.
8. **Burn the $150 credits**: use Meta API liberally — real patrols, demo transcripts, README/site copy drafted *by* muse models, stress/eval runs. Log token usage.

## Architecture
```
wrench/
  cli.py          # typer app: status, ask, chat, patrol, watch, drift, report, web, init, install-service, explain, doctor
  providers.py    # unified LLM client: meta|openai|anthropic|ollama|lmstudio|litellm (openai-compat first, native fallbacks)
  sensors.py      # os/docker/gpu/net samplers -> sqlite (wrench.db), EWMA baselines + z-score anomalies
  driftscan.py    # snapshot ports/services/packages/users/cron/suid -> diff engine, plain-English change narration (LLM-assisted)
  agent.py        # the intentional loop: observe (sensors+drift) -> orient (LLM w/ tool calls) -> act (policy-gated) -> report
  tools.py        # agent tools: run_diag (allowlisted read-only cmds), read_logs, service_status, disk_tree, net_listeners, fix_action (gated)
  policy.py       # action tiers: observe (always) / suggest (default) / repair (allowlist+confirm) / autonomous (explicit opt-in)
  report.py       # rich terminal rendering + HTML report generation (self-contained, inline CSS/JS charts)
  webapp.py       # wrench web: serves dashboard + JSON API from wrench.db
  store.py        # sqlite schema: samples, snapshots, diffs, patrols, actions, tokens_spent
```
- Config: `~/.config/wrench/config.toml` (`wrench init` wizard). Data: `~/.local/share/wrench/`.
- Patrol scheduling: `wrench install-service` writes user systemd service+timer (15min default).
- Safety defaults: read-only. Mutating actions require policy tier + explicit confirm; every action logged to actions table and shown in web UI.

## Deliverables checklist
- [ ] Working CLI (all commands above) on Python 3.10+
- [ ] Providers verified: meta (live), ollama (live on this box :11434), others code-complete w/ graceful errors
- [ ] Patrol produces: terminal report + HTML report + sqlite rows; anomalies narrated in plain English by muse
- [ ] Web dashboard: timeline charts (cpu/mem/disk/net), drift feed, patrol feed, action log, token spend widget
- [ ] Repo: github.com/sunkencity999/wrench (public), MIT license, cheeky README (badges, demo GIF via asciinema+agg, quickstart, architecture diagram)
- [ ] GitHub Pages: docs/ landing page — intriguing, demonstrative (fake-live demo panel ok), link to repo
- [ ] Real demo artifacts committed: sample patrol reports from Devbox2 (sanitize hostnames/paths if sensitive)
- [ ] Token-burn log: reports/state/wrench_hackathon_tokens.md

## Ground rules
- Build dir: ~/.openclaw/workspace/projects/wrench/ (this dir). Push early, push often.
- Never commit secrets; .gitignore the key paths. Sanitize anything private from demo data (no credentials, no family names, no internal IPs beyond 127.0.0.1).
- Don't disturb running services (flash-next, comfy, gateway). Read-only against this box.
- nice -n 10 for heavy local work. The P-H3 image trial is running concurrently — don't touch the GPUs.
- Test with: META_API_KEY from the credentials file; muse-spark-1.3 for agent turns, muse-wonder-1.0 for the showcase "deep diagnosis" demo.
