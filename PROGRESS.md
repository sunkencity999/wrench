# wrench — build progress

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
