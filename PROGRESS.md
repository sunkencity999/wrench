# wrench — build progress

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
- [ ] Ollama provider live test (GPUs still pinned)


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
