/* wrench interactive tutorial — a simulated terminal, pure vanilla JS, no backend.
   Click a step (or press Enter / the Run button) and watch a scripted wrench
   session play out with canned-but-real (sanitized) output. The tour walks the
   five arcs — SEE · PREDICT · PROVE · FIX · SCALE — then peeks at air-gap mode. */
(function () {
  "use strict";

  // ---- the script -------------------------------------------------------
  // cls maps to the c-* color classes in the page CSS.
  var STEPS = [
    {
      id: "init",
      label: "1 · init",
      cmd: "wrench init",
      out: [
        { t: "🔧 bring your own mind — choose a model provider", cls: "c-acc" },
        { t: "  1  ollama (recommended for this box)   local & private — guided, no API key", cls: "" },
        { t: "  2  lmstudio   local — LM Studio server", cls: "c-dim" },
        { t: "  3  openai      API · 4  anthropic  API · 5  meta  API", cls: "c-dim" },
        { t: "  6  azure       API · 7  litellm    API proxy", cls: "c-dim" },
        { t: "  8  custom      any OpenAI-compatible endpoint (vLLM, llama.cpp, TGI, your own server)", cls: "c-dim" },
        { t: "detected 64 GB RAM · 24 GB NVIDIA VRAM — a local model will run well here", cls: "c-dim" },
        { t: "provider [1-8 or name]: ⏎   → ollama", cls: "c-cyan" },
        { t: "recommended model: qwen3:30b (~19 GB) — pulled with consent, tool-calling smoke test ✓", cls: "c-cyan" },
        { t: "wrote ~/.config/wrench/config.toml", cls: "c-ok" },
        { t: "recording first sensor sample + drift baseline...", cls: "c-dim" },
        { t: "╭──────────────────── 🔧 wrench initialized ────────────────────╮", cls: "c-ok" },
        { t: "│ I'm wrench — the sysadmin's right hand. I live here now.     │", cls: "c-ok" },
        { t: "│ provider: ollama · model: qwen3:30b · policy: suggest         │", cls: "c-ok" },
        { t: "│ data: ~/.local/share/wrench/wrench.db                         │", cls: "c-ok" },
        { t: "│ put me to work: doctor · status · patrol · fixxer · web        │", cls: "c-ok" },
        { t: "╰────────────────────────────────────────────────────────────────╯", cls: "c-ok" },
        { t: "Entry 8, custom, points wrench at any OpenAI-compatible endpoint. Every brain — fully local (Ollama, LM Studio) or any API (OpenAI, Anthropic, Meta, Azure, LiteLLM) — drives the exact same agent loop. No favorites, and nothing left the box.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "status",
      label: "2 · status · SEE",
      cmd: "wrench status",
      out: [
        { t: "╭──────────────────────── 🔧 wrench status ─────────────────────╮", cls: "c-acc" },
        { t: "│    CPU  █░░░░░░░░░░░░░░░░░   5.8%   ▅▆▄▅▁▂▂▆▂▁▂▄▁▁▁▂          │", cls: "" },
        { t: "│    MEM  ████░░░░░░░░░░░░░░  24.5%   ▂▄▂▁▇▇▇▇█▁▁▂▂▁▁▁          │", cls: "" },
        { t: "│   SWAP  █████░░░░░░░░░░░░░  33.2%                             │", cls: "" },
        { t: "│ disk /  ███████░░░░░░░░░░░  43.7%                             │", cls: "" },
        { t: "│ disk /mnt/tank  █████████░░░░░░░  52.8%                       │", cls: "" },
        { t: "│                                                               │", cls: "" },
        { t: "│ load 0.63 / 0.77 / 1.26   procs 683   net ↓179 ↑72 KB/s       │", cls: "c-dim" },
        { t: "│ gpu NVIDIA RTX PRO 6000: 0% util, 96375/97887 MB, 33°C        │", cls: "c-dim" },
        { t: "│ docker: 5/8 containers running                                │", cls: "c-warn" },
        { t: "│ no anomalies in 24h — baselines quiet                         │", cls: "c-ok" },
        { t: "╰──────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "SEE — one screen, every vital, with 24h sparklines and anomalies flagged against learned baselines (z-score, not arbitrary thresholds). No doomscrolling through top/df/htop.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "score",
      label: "3 · score · SEE",
      cmd: "wrench score",
      out: [
        { t: "╭──────────── 🔧 wrench score ────────────╮", cls: "c-acc" },
        { t: "│ 80 / 100   grade B                      │", cls: "c-ok" },
        { t: "│ 8 of 8 pillars measured                 │", cls: "c-dim" },
        { t: "╰──────────────────────────────────────────╯", cls: "c-acc" },
        { t: " Capacity          61  ██████░░░░  fullest disk /var at 88%, memory 64%", cls: "c-warn" },
        { t: " Security          90  █████████░  0 critical, 1 warning finding(s)", cls: "c-ok" },
        { t: " Vulnerabilities   70  ███████░░░  1 known CVE in 1 package · 1 end-of-life product", cls: "c-warn" },
        { t: " Compliance        88  █████████░  88% of checks pass · 5 failing", cls: "c-ok" },
        { t: " Backups          100  ██████████  2 job(s), all fresh", cls: "c-ok" },
        { t: " Certificates      85  ████████░░  1 tracked · next expiry in 23d", cls: "c-ok" },
        { t: " Forecast          80  ████████░░  1 projected incident · disk /var in ~6d", cls: "c-ok" },
        { t: " Patrol            70  ███████░░░  last patrol attention, 7m ago", cls: "c-warn" },
        { t: "next steps", cls: "c-acc" },
        { t: "  • Capacity: fullest disk /var at 88%  → wrench status", cls: "c-dim" },
        { t: "  • Vulnerabilities: 1 known CVE         → wrench cve", cls: "c-dim" },
        { t: "SEE — one number for \"how is this box, really?\". It is arithmetic over what each subsystem measured — the model is never asked. A pillar with no data is shown as unmeasured and left out, never counted as healthy; one critical pillar caps the total so it can't hide in a good average. The same score rides in every fleet report.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "forecast",
      label: "4 · forecast · PREDICT",
      cmd: "wrench forecast",
      out: [
        { t: "  ⚙ trend engine — least-squares over 3,125 samples / 1.9d", cls: "c-cyan" },
        { t: "╭──────────────── 🔮 wrench forecast — future incidents ────────────────╮", cls: "c-acc" },
        { t: "│ sev     resource        ETA     current   rate/day   confidence      │", cls: "c-dim" },
        { t: "│ → info  🔁 swap        10.8d     26.5%     +6.37%     medium          │", cls: "c-warn" },
        { t: "│ · none  💾 /mnt/nvme   181.1d    52.0%     +0.24%     high            │", cls: "" },
        { t: "│ · none  💾 /home       194.0d    59.2%     +0.18%     medium          │", cls: "" },
        { t: "│ · none  🧠 memory         —      43.3%      flat       medium          │", cls: "" },
        { t: "╰────────────────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "╭──────────────────────────── 🔧 wrench ────────────────────────╮", cls: "c-acc" },
        { t: "│ Zero critical/warning incidents. First to break: swap at      │", cls: "" },
        { t: "│ 26.5%, climbing ~6.4%/day → 95% in ~11 days. Only medium      │", cls: "" },
        { t: "│ confidence (3,125 samples / 1.9d), so: watch, don't panic.    │", cls: "" },
        { t: "│ Line up a mitigation before the window closes.                │", cls: "" },
        { t: "╰──────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "PREDICT — the trend math is CODE; the model is never asked when your disk fills. Certificate expiry joins the same unified feed, so 'disk full Tuesday' and 'cert dead Friday' page through one lead-time ladder (≤14d info → ≤7d warning → ≤3d critical).", cls: "c-dim", note: true }
      ]
    },
    {
      id: "comply",
      label: "5 · comply · PROVE",
      cmd: "wrench comply",
      out: [
        { t: "╭──── 📋 Ubuntu hardening essentials (inspired by CIS L1) — score 56.8% ────╮", cls: "c-acc" },
        { t: "│ ✖ fail   high     sshd.permitrootlogin   PermitRootLogin → want 'no'       │", cls: "c-crit" },
        { t: "│ ✖ fail   high     sshd.passwordauth      PasswordAuthentication must be no  │", cls: "c-crit" },
        { t: "│ ✖ fail   medium   login.umask            default UMASK 027 or stricter      │", cls: "c-warn" },
        { t: "│ ✔ pass   critical perm.sudoers           /etc/sudoers is 0440               │", cls: "c-ok" },
        { t: "│ · skip   critical auth.noemptypw         (needs root to read /etc/shadow)   │", cls: "c-dim" },
        { t: "╰───────────────────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "40 checks in cis-ubuntu-essentials · 15 in wrench-baseline · deterministic · offline", cls: "c-dim" },
        { t: "PROVE — packs are DATA, not code: every rule maps to a read-only check primitive, verdicts are deterministic (never a model's opinion), and it all runs fully offline. A skip is a counted skip, never a fake pass. `comply accept` blesses known debt by consent (audit-sealed); patrols then alarm only on NEW failures.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "audit",
      label: "6 · audit + bundle · PROVE",
      cmd: "wrench audit verify && wrench bundle",
      out: [
        { t: "╭────────────────────── 🧾 audit verify ──────────────────────╮", cls: "c-ok" },
        { t: "│ ✔ INTACT — 7 event(s), every link verified.                 │", cls: "c-ok" },
        { t: "╰──────────────────────────────────────────────────────────────╯", cls: "c-ok" },
        { t: "  (flip one byte anywhere and verify names the exact first broken link, exit 1)", cls: "c-dim" },
        { t: "╭──────────────────────── 📦 wrench bundle ─────────────────────╮", cls: "c-acc" },
        { t: "│ wrote ./wrench-bundle-homelab-2026-11-05.tar.gz               │", cls: "c-acc" },
        { t: "│ 24 KB · 13 files · no secrets (config redacted)               │", cls: "c-ok" },
        { t: "│ carry it on a USB stick; unpack: tar xzf wrench-bundle-…      │", cls: "c-dim" },
        { t: "╰──────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "PROVE — every consequential act is sealed into a hash-chained, append-only log (each record folds in the previous hash). `bundle` packs the whole box — patrol, status, drift, security, comply, backups, forecast, the tamper-evident audit chain + its verdict — into one reproducible tar.gz. The air-gap answer to 'email me the state of the box.'", cls: "c-dim", note: true }
      ]
    },
    {
      id: "fixxer",
      label: "7 · fixxer · FIX",
      cmd: "wrench fixxer",
      out: [
        { t: "I'm going through the box looking for things I can fix myself...", cls: "c-dim" },
        { t: "                 🔧 correctable issues I found", cls: "c-acc" },
        { t: " #   risk      fix                        evidence", cls: "c-dim" },
        { t: " 1   safe      Shrink journald logs       journald uses 4096 MB — vacuum to 500M", cls: "c-ok" },
        { t: " 2   safe      Clear package cache        apt archives hold 2015 MB of old .debs", cls: "c-ok" },
        { t: " 3   moderate  Apply pending updates      242 packages upgradable (3 security)", cls: "c-warn" },
        { t: " 4   moderate  Remove orphaned packages   3 removable, incl. 1 old kernel", cls: "c-warn" },
        { t: "╭──────────────────────────── 🔧 wrench ────────────────────────────╮", cls: "c-acc" },
        { t: "│ I'd start with 1 and 2 — safe-tier housekeeping: 6 GB back,   │", cls: "" },
        { t: "│ nothing changes behavior. 3 is worth doing soon (3 security   │", cls: "" },
        { t: "│ patches) but it's moderate. Your call; nothing happens yet.   │", cls: "" },
        { t: "╰────────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "apply which? [a]ll / [n]one / numbers e.g. 1,3 ▸ 1,2", cls: "c-cyan" },
        { t: "  ✓ Shrink journald logs — fixed + verified · journald now uses 488 MB", cls: "c-ok" },
        { t: "  ✓ Clear package cache — fixed + verified · apt cache now 0 MB", cls: "c-ok" },
        { t: "  2 fixed + verified · every action in fixxer_audit.jsonl", cls: "c-ok" },
        { t: "FIX — the fixes are real; the authorship is the point. Every command comes from a hand-written, risk-tiered catalog — detection is code, the command is code, verification is code. The model only explains and recommends; it never writes the shell. (`wrench blueprint` extends the same ceremony to config files, LLM-drafted as a diff, validated by the daemon's own checker, auto-rolled-back on failure.)", cls: "c-dim", note: true }
      ]
    },
    {
      id: "learn",
      label: "8 · memory + heartbeat",
      cmd: "wrench remember \"the 02:00 load spike is the nightly pg_dump — expected\"",
      out: [
        { t: "✔ remembered #3  [fact] the 02:00 load spike is the nightly pg_dump — expected", cls: "c-ok" },
        { t: "$ wrench jobs add pg-growth \"every 6h\" ask -p \"is /var/lib/postgresql growing faster than its 30-day trend?\"", cls: "c-cyan" },
        { t: "✔ scheduled pg-growth  every 6h → ask · first run in 6h", cls: "c-ok" },
        { t: "$ wrench jobs", cls: "c-cyan" },
        { t: "  job             state      schedule         does                         next     last", cls: "c-dim" },
        { t: "  auto-security   proposed   daily 08:45      security                     —        never", cls: "c-acc" },
        { t: "  patrol          active     every 15m        patrol                       in 11m   attention 4m ago", cls: "c-warn" },
        { t: "  pg-growth       active     every 6h         ask: is /var/lib/postgresql… in 6h    never", cls: "" },
        { t: "  morning-brief   active     weekdays 08:30   brief                        in 14h   ok 9h ago", cls: "c-ok" },
        { t: "proposed  auto-security — You run `wrench security` around 09:00 most days (7 times over 6 days).", cls: "c-acc" },
        { t: "          I can have it done beforehand and tell you only what needs attention.", cls: "c-acc" },
        { t: "          approve: wrench jobs approve auto-security   ·   decline: wrench jobs rm auto-security", cls: "c-dim" },
        { t: "heartbeat alive · last beat 2m ago", cls: "c-dim" },
        { t: "$ wrench memory review", cls: "c-cyan" },
        { t: "╭─ 🧠 note #12 ─────────────────────────────────────────────────╮", cls: "c-acc" },
        { t: "│ reports.service is restarted by deploys on Tuesdays; a stop   │", cls: "" },
        { t: "│ outside Tuesday is unusual.                                   │", cls: "" },
        { t: "│ observation · noted 1h ago · during patrol                    │", cls: "c-dim" },
        { t: "╰────────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "keep it? [y]es / [n]o / [s]kip ▸ y", cls: "c-cyan" },
        { t: "LEARN — tell it once and every patrol and answer starts with it. It also learns from what you do (the checks you run by hand each morning become a proposal) and keeps notes of its own. Two rules keep that safe: a note written while nobody was watching is shown to no model until you approve it — so a log line cannot plant a standing instruction — and a job wrench proposes does nothing until you say yes. Scheduled questions are read-only by default.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "fleet",
      label: "9 · fleet · SCALE",
      cmd: "wrench fleet connect hub.example --tags prod,web",
      out: [
        { t: "password for the hub at https://hub.example:8788: ••••••••••••", cls: "c-cyan" },
        { t: "╭──────────────────── 🔧 wrench fleet connect ──────────────────╮", cls: "c-ok" },
        { t: "│ connected to https://hub.example:8788 as web-01               │", cls: "c-ok" },
        { t: "│ (tags: prod, web) · every patrol now reports                  │", cls: "c-dim" },
        { t: "╰────────────────────────────────────────────────────────────────╯", cls: "c-ok" },
        { t: "$ wrench fleet status                                                          # on the hub", cls: "c-cyan" },
        { t: "  fleet — 10 node(s): 5 ok / 3 attn / 1 crit / 1 SILENT", cls: "c-acc" },
        { t: "  db-01        critical   41 F   disk /var/lib/postgresql is 96% full", cls: "c-crit" },
        { t: "  web-02       attention  72 C   certificate shop.example.com expires in 9d", cls: "c-warn" },
        { t: "  web-01       ok         94 A   all clear", cls: "c-ok" },
        { t: "  dc-edge-07   SILENT     —      no report for 12m — expected every 5m", cls: "c-crit" },
        { t: "SCALE — start a hub, then connect each machine with the hub's address and password. The password is used once, to get that machine a key of its own; it is never stored on the machine. Every report is signed over a timestamp + body: the hub rejects replays, stale clocks, revoked keys, and a name claimed by a different key. A machine that misses its deadline turns SILENT and raises a critical alert. The step-by-step version is the \"Many machines\" walkthrough further up this page.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "offline",
      label: "10 · offline mode",
      cmd: "WRENCH_OFFLINE=1 wrench cve",
      chatFinale: true,
      out: [
        { t: "  config: offline = true   (or export WRENCH_OFFLINE=1)", cls: "c-dim" },
        { t: "╭──────────── ⏳ end-of-life status (endoflife.date) ───────────╮", cls: "c-acc" },
        { t: "│ os            24.04   supported until 2029-05-31              │", cls: "c-ok" },
        { t: "│ linux-kernel  7.0     REACHED EOL 2026-06-27                  │", cls: "c-crit" },
        { t: "│ python        3.12    supported until 2028-10-31              │", cls: "c-ok" },
        { t: "╰──────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "checked 261 packages · OFFLINE — cached data", cls: "c-dim" },
        { t: "⚠ briefing unavailable (provider 'meta': skipped — wrench is in offline", cls: "c-warn" },
        { t: "  mode and api.meta.ai is not a local/private address) — the tables stand", cls: "c-warn" },
        { t: "  on their own", cls: "c-warn" },
        { t: "Air-gap mode is a DECLARED, enforced zero-egress guarantee — for classified, OT, shipboard, and air-gapped boxes. OSV/CVE, endoflife.date, update checks, and any public provider call are refused with a clear message; the cached scan still serves and every local check keeps working. A central guard (ipaddress stdlib) decides local-vs-public. wrench runs on boxes that have never seen the internet.", cls: "c-dim", note: true },
        { t: "…and the 🔧 bubble in YOUR corner right now? On your machine that chat is a live agent loop — watch.", cls: "c-dim", note: true }
      ]
    }
  ];

  // ---- the many-machines walkthrough ------------------------------------
  // Each step names the machine it runs on; the prompt shows it.
  var FLEET_STEPS = [
    {
      id: "ask",
      label: "★ or just ask",
      host: "hub",
      cmd: "wrench chat",
      out: [
        { t: "you ▸ I want to watch my servers from one place. Set this machine up as the hub.", cls: "c-cyan" },
        { t: "  ⚙ fleet_setup_status {\"role\": \"hub\"}", cls: "c-dim" },
        { t: "🔧 Happy to. A hub is the machine every other machine reports to, and whose", cls: "" },
        { t: "   dashboard you open. Five steps; the first is a dashboard password. Shall I?", cls: "" },
        { t: "you ▸ yes", cls: "c-cyan" },
        { t: "  ⚙ fleet_setup {\"action\": \"set_password\"}", cls: "c-dim" },
        { t: "╭─ 🧭 setup step — set the dashboard password ─────────────────────────────────╮", cls: "c-acc" },
        { t: "│ Set the dashboard password on this machine. You will type it privately; it   │", cls: "" },
        { t: "│ is not shown to the model.                                                   │", cls: "" },
        { t: "╰──────────────────────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "do it? [y/N]: y", cls: "c-cyan" },
        { t: "new dashboard password: ••••••••••••••••      again, to confirm: ••••••••••••••••", cls: "c-cyan" },
        { t: "🔧 Done — only a salted hash is stored. Next: let other machines reach this one.", cls: "" },
        { t: "   I'll have the hub listen on every interface, port 8788. OK?", cls: "" },
        { t: "you ▸ go ahead, and start it", cls: "c-cyan" },
        { t: "  ⚙ fleet_setup {\"action\": \"hub_listen\"}   ⚙ fleet_setup {\"action\": \"hub_start\"}", cls: "c-dim" },
        { t: "🔧 The hub is running. On each other machine, run:", cls: "c-ok" },
        { t: "     wrench fleet connect 192.168.1.10", cls: "c-ok" },
        { t: "   (or `wrench chat` there and say \"connect this machine to the hub at 192.168.1.10\").", cls: "c-dim" },
        { t: "   If this machine runs a firewall, open TCP 8788: sudo ufw allow 8788/tcp", cls: "c-dim" },
        { t: "The agent can do the whole setup with you: it checks where the machine stands, explains a step, does it when you say yes, and moves on. Every change waits for your yes, and passwords are typed at a hidden prompt — they never pass through the model. No model configured? `wrench fleet setup` asks the same questions. The steps that follow are what it is doing underneath.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "hub-password",
      label: "1 · hub: set a password",
      host: "hub",
      cmd: "wrench password",
      out: [
        { t: "new dashboard password: ••••••••••••••••", cls: "c-cyan" },
        { t: "again, to confirm: ••••••••••••••••", cls: "c-cyan" },
        { t: "✔ dashboard password set", cls: "c-ok" },
        { t: "a running dashboard picks it up now · sign in at the address `wrench web` prints", cls: "c-dim" },
        { t: "One password, two jobs: it signs you in to the dashboard, and it is what each machine presents — once — to connect. Only a salted hash is stored on the hub. Pick the machine that stays on to be the hub; a small VM is plenty.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "hub-serve",
      label: "2 · hub: start it",
      host: "hub",
      cmd: "wrench fleet serve --host 0.0.0.0 --tls-cert hub-cert.pem --tls-key hub-key.pem",
      out: [
        { t: "╭─────────────────────────── 🔧 wrench fleet serve ────────────────────────────╮", cls: "c-acc" },
        { t: "│ fleet console: https://hub.example:8788/fleet                                │", cls: "" },
        { t: "│ nodes report to: https://hub.example:8788/api/fleet/report                   │", cls: "" },
        { t: "│ 0 enrollment key(s) · silent-node sweep every 30s · Ctrl-C to stop           │", cls: "c-dim" },
        { t: "│ add a machine — run on it: wrench fleet connect hub.example                  │", cls: "c-ok" },
        { t: "│ (asks for the dashboard password)                                            │", cls: "c-dim" },
        { t: "│ access control: on — sign in with the dashboard password                     │", cls: "c-dim" },
        { t: "╰──────────────────────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "--host 0.0.0.0 lets other machines reach the hub (open TCP 8788 in its firewall). The certificate keeps the password off the wire in clear; a self-signed one is fine — you will hand its public half to each machine. The banner prints the exact line to run on the others. Machines call the hub; the hub never calls them.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "connect",
      label: "3 · web-01: connect",
      host: "web-01",
      cmd: "wrench fleet connect hub.example --tags prod,web",
      out: [
        { t: "password for the hub at https://hub.example:8788: ••••••••••••••••", cls: "c-cyan" },
        { t: "╭────────────────────────── 🔧 wrench fleet connect ───────────────────────────╮", cls: "c-ok" },
        { t: "│ connected to https://hub.example:8788 as web-01 (tags: prod, web)            │", cls: "c-ok" },
        { t: "│ saved to ~/.config/wrench/config.toml (owner-only) · every patrol now        │", cls: "c-dim" },
        { t: "│ reports · schedule them with wrench install-service                          │", cls: "c-dim" },
        { t: "╰──────────────────────────────────────────────────────────────────────────────╯", cls: "c-ok" },
        { t: "web-01$ wrench install-service", cls: "c-cyan" },
        { t: "installed + started the heartbeat via systemd (beats every 5min · patrol every 15min)", cls: "c-ok" },
        { t: "connect finds the hub (HTTPS first), trades the password for a key that belongs to web-01 alone, sends one test report, and only then saves anything. The password is not written on this machine. install-service starts the schedule: a patrol every 15 minutes, and a report to the hub after each.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "selfsigned",
      label: "4 · db-01: private certificate",
      host: "db-01",
      cmd: "wrench fleet connect 192.168.1.10",
      out: [
        { t: "╭────────────────────────── 🔧 wrench fleet connect ───────────────────────────╮", cls: "c-crit" },
        { t: "│ https://192.168.1.10:8788 answered, but its certificate is not trusted —     │", cls: "c-crit" },
        { t: "│ self-signed certificate                                                      │", cls: "c-crit" },
        { t: "│ if the hub uses a private or self-signed certificate, pass --ca-file <its CA │", cls: "c-dim" },
        { t: "│ or certificate .pem>                                                         │", cls: "c-dim" },
        { t: "╰──────────────────────────────────────────────────────────────────────────────╯", cls: "c-crit" },
        { t: "db-01$ wrench fleet connect 192.168.1.10 --ca-file hub-cert.pem --tags prod,db", cls: "c-cyan" },
        { t: "password for the hub at https://192.168.1.10:8788: ••••••••••••••••", cls: "c-cyan" },
        { t: "╭────────────────────────── 🔧 wrench fleet connect ───────────────────────────╮", cls: "c-ok" },
        { t: "│ connected to https://192.168.1.10:8788 as db-01 (tags: prod, db)             │", cls: "c-ok" },
        { t: "╰──────────────────────────────────────────────────────────────────────────────╯", cls: "c-ok" },
        { t: "An IP works as well as a name. When the certificate cannot be verified, connect stops before the password is asked for — it never quietly falls back to plain HTTP. If the hub has no TLS at all, it tells you the password would cross the network unencrypted and asks first (scripts must pass --allow-http).", cls: "c-dim", note: true }
      ]
    },
    {
      id: "scripted",
      label: "5 · win-03: scripted",
      host: "win-03 PS>",
      cmd: "$pw | wrench fleet connect hub.example --password-stdin --tags windows,ci",
      out: [
        { t: "╭────────────────────────── 🔧 wrench fleet connect ───────────────────────────╮", cls: "c-ok" },
        { t: "│ connected to https://hub.example:8788 as win-03 (tags: windows, ci)          │", cls: "c-ok" },
        { t: "╰──────────────────────────────────────────────────────────────────────────────╯", cls: "c-ok" },
        { t: "win-03 PS> wrench install-service", cls: "c-cyan" },
        { t: "installed + started the heartbeat via schtasks (beats every 5min · patrol every 15min)", cls: "c-ok" },
        { t: "Same command on Windows, macOS and Linux. For a few machines, pipe the password from your secret store (or set WRENCH_HUB_PASSWORD). For a rollout through MDM or Ansible, use `wrench fleet enroll` on the hub instead: it prints a join line with a key, so the admin password never sits in your tooling.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "see",
      label: "6 · hub: see every machine",
      host: "hub",
      cmd: "wrench fleet status",
      out: [
        { t: "  🔧 fleet — 3 node(s): 1 ok / 1 attn / 1 crit / 0 silent", cls: "c-acc" },
        { t: "  node     host                  status      last seen   worst finding", cls: "c-dim" },
        { t: "  db-01    db-01.corp.example    critical    12s ago     disk /var/lib/postgresql is 96% full", cls: "c-crit" },
        { t: "  win-03   win-03.corp.example   attention   40s ago     compliance: SMBv1 server protocol is enabled", cls: "c-warn" },
        { t: "  web-01   web-01.corp.example   ok          1m ago      all clear", cls: "c-ok" },
        { t: "", cls: "" },
        { t: "  in the browser → https://hub.example:8788", cls: "c-acc" },
        { t: "  ┌ machine ▾ ─────────────┐", cls: "c-dim" },
        { t: "  │ This machine           │   the hub's own full dashboard", cls: "" },
        { t: "  │ All machines (4)       │   the console: filter, search, sort, export CSV", cls: "" },
        { t: "  │ db-01 — critical       │   one machine: score and trend, volumes, findings", cls: "c-crit" },
        { t: "  │ web-01 — healthy       │", cls: "c-ok" },
        { t: "  │ win-03 — attention     │", cls: "c-warn" },
        { t: "  └────────────────────────┘", cls: "c-dim" },
        { t: "The console lists every machine, the hub included, and the picker in the top bar switches between this machine, all machines, and any one of them. A link like /fleet?node=db-01 opens one machine directly. `wrench fleet status` exits non-zero when anything is critical or silent, so it drops into a script or a check.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "silent",
      label: "7 · a machine goes quiet",
      host: "hub",
      cmd: "wrench fleet status",
      out: [
        { t: "  🔧 fleet — 3 node(s): 1 ok / 1 attn / 0 crit / 1 SILENT", cls: "c-acc" },
        { t: "  db-01    db-01.corp.example    SILENT      31m ago     no report for 31m — expected every 15m", cls: "c-crit" },
        { t: "  win-03   win-03.corp.example   attention   2m ago      compliance: SMBv1 server protocol is enabled", cls: "c-warn" },
        { t: "  web-01   web-01.corp.example   ok          4m ago      all clear", cls: "c-ok" },
        { t: "🔔 critical · fleet: node db-01 is SILENT — no report for ~31m (cadence 900s)", cls: "c-crit" },
        { t: "Nothing to configure. The hub knows each machine's interval, and when a report is overdue by twice that, the machine turns SILENT and the hub raises a critical alert through your notification sinks — desktop, webhook, syslog. A machine that cannot report is exactly the one you need to hear about. To hear sooner: `wrench install-service --interval 5` on the machines that matter.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "revoke",
      label: "8 · revoke and reconnect",
      host: "hub",
      cmd: "wrench fleet keys",
      out: [
        { t: "  key id             label              state    last used          nodes", cls: "c-dim" },
        { t: "  2f5cb8f71c9347e4   connect: web-01    active   2026-11-11 19:22   web-01", cls: "" },
        { t: "  9d04e1a7b3c6f218   connect: db-01     active   2026-11-11 19:21   db-01", cls: "" },
        { t: "  c81b77e02a5d4f96   connect: win-03    active   2026-11-11 19:20   win-03", cls: "" },
        { t: "hub$ wrench fleet revoke 2f5cb8f71c9347e4", cls: "c-cyan" },
        { t: "revoked 2f5cb8f71c9347e4 — 1 node(s) will go silent until re-joined: web-01", cls: "c-warn" },
        { t: "web-01$ wrench fleet report", cls: "c-cyan" },
        { t: "  the hub refused this report — HTTP 403: enrollment key revoked", cls: "c-crit" },
        { t: "web-01$ wrench fleet connect hub.example", cls: "c-cyan" },
        { t: "password for the hub at https://hub.example:8788: ••••••••••••••••", cls: "c-cyan" },
        { t: "web-01 was already known to the hub — it keeps its history and its previous key was retired", cls: "c-dim" },
        { t: "  connected to https://hub.example:8788 as web-01", cls: "c-ok" },
        { t: "Every connected machine has a key of its own, so you can cut one off without touching the rest — a stolen laptop, a decommissioned server. A rebuilt machine just connects again and keeps its name and history. Changing the hub password signs browsers out but does not disturb connected machines: they hold keys, not the password. That's the whole setup.", cls: "c-dim", note: true }
      ]
    }
  ];

  // ---- terminal engine --------------------------------------------------
  function mount(opts) {
    var STEPS = opts.steps;
    var pre = document.getElementById(opts.screen);
    var chipsBox = document.getElementById(opts.chips);
    var runBtn = document.getElementById(opts.run);
    var section = document.getElementById(opts.section);
    if (!pre || !chipsBox || !runBtn) return;

    var next = 0;          // next step index
    var busy = false;
    var timers = [];

    function later(fn, ms) { timers.push(setTimeout(fn, ms)); }
    function clearTimers() { timers.forEach(clearTimeout); timers = []; }

    function span(text, cls) {
      var s = document.createElement("span");
      if (cls) s.className = cls;
      s.textContent = text;
      return s;
    }

    function line(text, cls) {
      pre.appendChild(span(text + "\n", cls));
      pre.scrollTop = pre.scrollHeight;
    }

    function promptOf(step) {
      if (!step.host) return "$ ";
      return /[>$]$/.test(step.host) ? step.host + " " : step.host + "$ ";
    }

    function typeCmd(step, done) {
      pre.appendChild(span(promptOf(step), "c-dim"));
      var target = span("", "c-acc");
      pre.appendChild(target);
      var cmd = step.cmd, i = 0;
      (function tick() {
        if (i < cmd.length) {
          target.textContent += cmd.charAt(i++);
          pre.scrollTop = pre.scrollHeight;
          later(tick, 18 + Math.random() * 40);
        } else {
          pre.appendChild(span("\n"));
          later(done, 220);
        }
      })();
    }

    function playOutput(rows, i, done) {
      if (i >= rows.length) { done(); return; }
      var r = rows[i];
      if (r.note) {
        pre.appendChild(span("\n→ " + r.t + "\n\n", "tut-note"));
        pre.scrollTop = pre.scrollHeight;
        later(function () { playOutput(rows, i + 1, done); }, 120);
        return;
      }
      line(r.t, r.cls);
      later(function () { playOutput(rows, i + 1, done); }, 26 + Math.random() * 60);
    }

    function setBusy(b) {
      busy = b;
      runBtn.disabled = b;
      runBtn.textContent = b ? "running…"
        : (next < STEPS.length ? "▶ run: " + promptOf(STEPS[next]).replace(/^\$ $/, "") + STEPS[next].cmd
                               : opts.restart);
    }

    function markChips() {
      Array.prototype.forEach.call(chipsBox.children, function (chip, idx) {
        chip.classList.toggle("done", idx < next);
        chip.classList.toggle("current", idx === next);
      });
    }

    function banner() {
      opts.banner.forEach(function (t, i) {
        line(t + (i === opts.banner.length - 1 ? "\n" : ""), "c-dim");
      });
    }

    function runStep(idx) {
      if (busy) return;
      if (idx >= STEPS.length) { // restart
        pre.textContent = "";
        next = 0;
        banner();
        setBusy(false); markChips();
        return;
      }
      // jumping backwards/forwards: replay from a clean screen for coherence
      if (idx !== next) { pre.textContent = ""; next = idx; }
      var step = STEPS[idx];
      setBusy(true);
      clearTimers();
      typeCmd(step, function () {
        playOutput(step.out, 0, function () {
          next = idx + 1;
          setBusy(false);
          markChips();
          // finale: pop the simulated chat — "on your machine, this chat is real"
          if (step.chatFinale && typeof window.wrenchChatDemo === "function") {
            later(window.wrenchChatDemo, 600);
          }
        });
      });
    }

    STEPS.forEach(function (s, idx) {
      var chip = document.createElement("button");
      chip.className = "tut-chip";
      chip.type = "button";
      chip.textContent = s.label;
      chip.addEventListener("click", function () { runStep(idx); });
      chipsBox.appendChild(chip);
    });

    runBtn.addEventListener("click", function () { runStep(next); });
    // Enter runs the next step of whichever walkthrough is in the middle of the screen
    document.addEventListener("keydown", function (e) {
      if (e.key !== "Enter" || busy || !section) return;
      var r = section.getBoundingClientRect(), mid = window.innerHeight / 2;
      if (r.top > mid || r.bottom < mid) return;
      var tag = (document.activeElement && document.activeElement.tagName) || "";
      if (tag !== "INPUT" && tag !== "TEXTAREA" && tag !== "BUTTON" && tag !== "SUMMARY") runStep(next);
    });

    banner();
    setBusy(false);
    markChips();
  }

  mount({
    steps: STEPS, screen: "tut-screen", chips: "tut-chips", run: "tut-run", section: "tutorial",
    restart: "↺ restart the tour",
    banner: ["wrench interactive tour — nothing here touches your machine.",
             "the five arcs: see · predict · prove · fix · scale — click a step, or hit ▶ / Enter."]
  });
  mount({
    steps: FLEET_STEPS, screen: "fleet-screen", chips: "fleet-chips", run: "fleet-run", section: "multi",
    restart: "↺ start over",
    banner: ["one hub, three machines — a simulated session; nothing here touches your machine.",
             "the prompt shows which machine each command runs on. Click a step, or hit ▶ / Enter."]
  });
})();
