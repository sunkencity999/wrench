/* wrench interactive tutorial — a simulated terminal, pure vanilla JS, no backend.
   Click a step (or press Enter / the Run button) and watch a scripted wrench
   session play out with canned-but-real (sanitized) output. */
(function () {
  "use strict";

  // ---- the script -------------------------------------------------------
  // cls maps to the c-* color classes in the page CSS.
  var STEPS = [
    {
      id: "init",
      label: "1 · wrench init",
      cmd: "wrench init",
      out: [
        { t: "🔧 choose your model provider", cls: "c-acc" },
        { t: "  1  meta (default)   Meta muse models — hosted", cls: "" },
        { t: "  2  openai           OpenAI", cls: "c-dim" },
        { t: "  3  anthropic        Anthropic Claude", cls: "c-dim" },
        { t: "  4  ollama           local — private + free, guided setup", cls: "" },
        { t: "  5  lmstudio         LM Studio · 6  litellm  LiteLLM proxy", cls: "c-dim" },
        { t: "provider [1-6 or name]: ⏎   → meta", cls: "c-cyan" },
        { t: "wrote ~/.config/wrench/config.toml", cls: "c-ok" },
        { t: "recording first sensor sample + drift baseline...", cls: "c-dim" },
        { t: "╭──────────────────── 🔧 wrench initialized ────────────────────╮", cls: "c-ok" },
        { t: "│ provider: meta · model: muse-spark-1.3 · policy: suggest      │", cls: "c-ok" },
        { t: "│ data: ~/.local/share/wrench/wrench.db                         │", cls: "c-ok" },
        { t: "│ next: wrench doctor · wrench patrol · wrench web              │", cls: "c-ok" },
        { t: "╰────────────────────────────────────────────────────────────────╯", cls: "c-ok" },
        { t: "wrench now knows what \"normal\" looks like. (Option 4 runs a guided local setup: it detects your RAM/GPU, recommends a tool-calling model, pulls it with consent, and smoke-tests the loop.)", cls: "c-dim", note: true }
      ]
    },
    {
      id: "status",
      label: "2 · wrench status",
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
        { t: "│ docker: 5/8 containers running                                │", cls: "c-warn" },
        { t: "│ no anomalies in 24h — baselines quiet                         │", cls: "c-ok" },
        { t: "╰──────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "One screen, every vital, with sparklines of the last 24h. No doomscrolling through top/df/htop.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "ask",
      label: "3 · wrench ask",
      cmd: "wrench ask \"why is my disk filling up?\"",
      out: [
        { t: "  ⚙ run_diag {\"command\": \"df -h\"}", cls: "c-cyan" },
        { t: "  ⚙ disk_tree {\"path\": \"/home/user/storage\", \"depth\": 1}", cls: "c-cyan" },
        { t: "  ⚙ disk_tree {\"path\": \"/\", \"depth\": 1}", cls: "c-cyan" },
        { t: "╭──────────────────────────── 🔧 wrench ────────────────────────╮", cls: "c-acc" },
        { t: "│ Most at risk: /home/user/storage — 59% used, only 722G free,  │", cls: "" },
        { t: "│ the smallest headroom of your four mounts.                    │", cls: "" },
        { t: "│                                                               │", cls: "" },
        { t: "│ But du only accounts for 42G of the 1019G used. The gap hides │", cls: "" },
        { t: "│ in root-owned dirs: 'backups/borg-system: Permission denied'. │", cls: "c-warn" },
        { t: "│ Your hog is almost certainly the backup archive, not you.     │", cls: "" },
        { t: "│                                                               │", cls: "" },
        { t: "│ To confirm (I'm suggest-tier — run as human):                 │", cls: "c-dim" },
        { t: "│   sudo du -xhd1 /home/user/storage | sort -hr                 │", cls: "c-mag" },
        { t: "╰──────────────────────────────────────────────────────────────╯", cls: "c-acc" },
        { t: "It ran its own diagnostics, noticed du and df disagree, and named the suspect — then handed the privileged command to you instead of running it.", cls: "c-dim", note: true }
      ]
    },
    {
      id: "patrol",
      label: "4 · wrench patrol",
      cmd: "wrench patrol",
      out: [
        { t: "patrolling with muse-spark-1.3 (tier: suggest)...", cls: "c-dim" },
        { t: "  ⚙ run_diag {\"command\": \"systemctl --user list-units --state=failed\"}", cls: "c-cyan" },
        { t: "  ⚙ read_logs {\"unit\": \"smartd\", \"lines\": 60}", cls: "c-cyan" },
        { t: "  ⚙ run_diag {\"command\": \"smartctl -H /dev/sda\"}", cls: "c-cyan" },
        { t: "╭──────────────────────── 🔧 wrench patrol ─────────────────────╮", cls: "c-warn" },
        { t: "│ ⚠ ATTENTION  Box healthy overall, but /dev/sda reports 7      │", cls: "c-warn" },
        { t: "│ pending sectors — and the SMART email alerts are broken.      │", cls: "c-warn" },
        { t: "│                                                               │", cls: "" },
        { t: "│ [high] smartd: 7 unreadable (pending) sectors on /dev/sda —   │", cls: "c-crit" },
        { t: "│        warned every 30 min all day; 2.8T of data at risk      │", cls: "c-crit" },
        { t: "│ [low]  smartd-runner fails: /usr/bin/mail missing — those     │", cls: "" },
        { t: "│        warnings were never delivered to a human               │", cls: "" },
        { t: "│                                                               │", cls: "" },
        { t: "│ recommendations:                                              │", cls: "c-dim" },
        { t: "│   back up /mnt/tank NOW, then plan disk replacement           │", cls: "c-mag" },
        { t: "│   sudo smartctl -a /dev/sda · sudo apt install mailutils      │", cls: "c-mag" },
        { t: "╰──────────────────────────────────────────────────────────────╯", cls: "c-warn" },
        { t: "This is a real finding from wrench's first day: a dying disk whose alert pipeline was ALSO broken. Nobody would have known. wrench install-service makes this run every 15 minutes, forever.", cls: "c-dim", note: true }
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
      });
    });
  }

  function banner() {
    line("wrench interactive tour — nothing here touches your machine.", "c-dim");
    line("click a step below, or just hit ▶ / Enter.\n", "c-dim");
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
