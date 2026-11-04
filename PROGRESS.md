# wrench — build progress

Deadline: 2026-11-04 ~14:00 PST. Builder notes for the orchestrator.

## 2026-11-03 ~20:00 — Phases A–C complete + pushed
- Repo live: https://github.com/sunkencity999/wrench (main)
- Meta API verified live. Gotcha discovered: muse-spark-1.3 / muse-wonder-1.0 are
  reasoning models — ~350+ hidden reasoning tokens even on trivial prompts, so
  max_tokens must be generous (default 6144) or content comes back null.
  Key = the FULL pipe-delimited string from the credentials file.
- All modules written: config, store (sqlite: samples/baselines/anomalies/snapshots/
  diffs/patrols/actions/tokens), providers (meta/openai/anthropic native/ollama/
  lmstudio/litellm), sensors (os/docker/gpu + EWMA z-score anomalies), driftscan
  (ports/services/packages/users/cron), policy (4 tiers + allowlists + forbidden
  patterns, no shell chaining), tools (7 agent tools, no-shell exec), agent
  (JSON-protocol tool loop, works on any provider), report (rich terminal + HTML),
  webapp (stdlib server + dark dashboard), cli (all 12 commands).
- Verified on Devbox2: pipx install -e ✔, status ✔, doctor ✔ (meta ping pong ✔),
  drift baseline ✔, **first real patrol ✔** — muse-spark-1.3, 8 tool calls, 57k
  tokens, 120s, status=attention with genuinely useful findings.
- `wrench web` serves; all 6 /api/* endpoints return real data.

## Remaining
- [x] Phase D polish (dashboard verified via curl; screenshot for README)
- [ ] Phase E: README (muse-wonder drafted), docs/ Pages site, demo GIF (asciinema+agg),
      2-3 sanitized sample patrol reports, token-burn log
- [ ] install-service test, more live patrols/asks (burn credits), final verify pass
