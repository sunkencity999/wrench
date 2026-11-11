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
      cmd: "wrench fleet enroll --label \"web tier\"",
      out: [
        { t: "╭──────────────────── 🔧 wrench fleet enroll ───────────────────╮", cls: "c-acc" },
        { t: "│ run this on each machine that should report to this hub:      │", cls: "c-dim" },
        { t: "│ wrench fleet join https://hub.example:8788 wfl_9bbe…0d7b      │", cls: "c-ok" },
        { t: "│ key id 44c9d382ce376f27 · reusable · shown once               │", cls: "c-dim" },
        { t: "╰────────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "$ wrench fleet join https://hub.example:8788 wfl_9bbe…0d7b --tags prod,web     # on web-01", cls: "c-cyan" },
        { t: "✔ joined https://hub.example:8788 as web-01 (tags: prod, web)", cls: "c-ok" },
        { t: "$ wrench fleet status                                                          # on the hub", cls: "c-cyan" },
        { t: "  fleet — 10 node(s): 5 ok / 3 attn / 1 crit / 1 SILENT", cls: "c-acc" },
        { t: "  db-01        critical   41 F   disk /var/lib/postgresql is 96% full", cls: "c-crit" },
        { t: "  web-02       attention  72 C   certificate shop.example.com expires in 9d", cls: "c-warn" },
        { t: "  web-01       ok         94 A   all clear", cls: "c-ok" },
        { t: "  dc-edge-07   SILENT     —      no report for 12m — expected every 5m", cls: "c-crit" },
        { t: "SCALE — one command on the hub, one line on each machine (drop it in your MDM or Ansible). Every report is signed over a timestamp + body: the hub rejects replays, stale clocks, revoked keys, and a node id claimed by another key — and it stores only a derived key, never the token. The hub itself checks every 30 seconds for machines that have gone quiet, because a silent box is the one you most need to hear about.", cls: "c-dim", note: true }
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

  // ---- terminal engine --------------------------------------------------
  var pre = document.getElementById("tut-screen");
  var chipsBox = document.getElementById("tut-chips");
  var runBtn = document.getElementById("tut-run");
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

  function promptLine() {
    pre.appendChild(span("$ ", "c-dim"));
  }

  function typeCmd(cmd, done) {
    promptLine();
    var target = span("", "c-acc");
    pre.appendChild(target);
    var i = 0;
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
    runBtn.textContent = b ? "running…" : (next < STEPS.length ? "▶ run: " + STEPS[next].cmd : "↺ restart the tour");
  }

  function markChips() {
    Array.prototype.forEach.call(chipsBox.children, function (chip, idx) {
      chip.classList.toggle("done", idx < next);
      chip.classList.toggle("current", idx === next);
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
    typeCmd(step.cmd, function () {
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

  function banner() {
    line("wrench interactive tour — nothing here touches your machine.", "c-dim");
    line("the five arcs: see · predict · prove · fix · scale — click a step, or hit ▶ / Enter.\n", "c-dim");
  }

  // ---- wire up ----------------------------------------------------------
  STEPS.forEach(function (s, idx) {
    var chip = document.createElement("button");
    chip.className = "tut-chip";
    chip.type = "button";
    chip.textContent = s.label;
    chip.addEventListener("click", function () { runStep(idx); });
    chipsBox.appendChild(chip);
  });

  runBtn.addEventListener("click", function () { runStep(next); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && !busy &&
        document.getElementById("tutorial").getBoundingClientRect().top < window.innerHeight) {
      var tag = (document.activeElement && document.activeElement.tagName) || "";
      if (tag !== "INPUT" && tag !== "TEXTAREA") runStep(next);
    }
  });

  banner();
  setBusy(false);
  markChips();
})();
