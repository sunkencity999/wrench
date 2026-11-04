"""The intentional loop: observe → orient → act → report.

Provider-agnostic tool calling via a strict JSON protocol (works on every
backend, no function-calling API required). The model gets the tool menu and
must reply with exactly one JSON object per turn:

  {"action": "tool", "tool": "run_diag", "args": {"command": "df -h"}}
  {"action": "final", "answer": "...markdown..."}

Patrols additionally return structured findings for the report/dashboard.
"""

from __future__ import annotations

import json
import platform
import time

from . import driftscan, sensors, tools
from .config import Config
from .providers import LLMClient, ProviderError, extract_json

MAX_STEPS = 8


def _normalize_action(obj: dict) -> dict:
    """Tolerate common small-model protocol flubs instead of burning a nudge.

    Seen in the wild (qwen2.5:3b): {"action": "run_diag", "args": {...}} —
    the tool name lands in "action". Normalize any shape that unambiguously
    names a known tool into {"action": "tool", "tool": <name>, "args": {...}}.
    """
    action = obj.get("action")
    if action in ("tool", "final"):
        return obj
    known = {spec["name"] for spec in tools.TOOL_SPECS}
    name = obj.get("tool") or (action if action in known else None)
    if name in known:
        return {"action": "tool", "tool": name, "args": obj.get("args", {}) or {}}
    return obj

SYSTEM_PERSONA = """\
You are wrench, a careful and competent staff sysadmin agent running ON the machine you administer.
Hostname: {host} ({os_info}). Policy tier: {tier}.

Rules of engagement:
- You diagnose with evidence, not vibes. Use tools to look before you conclude.
- Be precise: name the unit, the port, the mount, the number.
- Tier observe/suggest: you NEVER mutate. Propose fixes as exact commands for the human.
- Tier repair/autonomous: you may call fix_action for ALLOWLISTED commands only.
- Plain English, dry wit allowed, zero filler. Humans read your reports over coffee.
"""

TOOL_PROTOCOL = """\
You have these tools:
{tool_menu}

STRICT protocol — reply with EXACTLY ONE JSON object and nothing else (no prose
before or after it; put any commentary INSIDE the JSON):
  To use a tool:   {{"action": "tool", "tool": "<name>", "args": {{...}}}}
  To finish:       {{"action": "final", "answer": "<your full answer, markdown ok>"}}
You have at most {max_steps} tool calls. Spend them wisely; then give the final answer.
"""


def _tool_menu() -> str:
    lines = []
    for spec in tools.TOOL_SPECS:
        args = ", ".join(f"{k}: {v}" for k, v in spec["args"].items()) or "none"
        lines.append(f"- {spec['name']}({args}) — {spec['desc']}")
    return "\n".join(lines)


def _system_prompt(cfg: Config) -> str:
    return SYSTEM_PERSONA.format(
        host=platform.node() or "localhost",
        os_info=f"{platform.system()} {platform.release()}",
        tier=cfg.policy_tier,
    ) + "\n" + TOOL_PROTOCOL.format(tool_menu=_tool_menu(), max_steps=MAX_STEPS)


class Agent:
    def __init__(self, cfg: Config, store, client: LLMClient | None = None,
                 confirm_fn=None, on_step=None):
        self.cfg = cfg
        self.store = store
        self.client = client or LLMClient(cfg, store)
        self.confirm_fn = confirm_fn
        self.on_step = on_step  # callback(kind, detail) for live terminal UX

    # ---------------- core loop ----------------
    def run(self, user_goal: str, context: str = "", model: str | None = None,
            purpose: str = "ask", max_steps: int = MAX_STEPS) -> dict:
        """Run the observe→orient→act loop. Returns {answer, steps, tokens}."""
        def _user(content: str) -> dict:
            return {"role": "user", "content": content}

        messages = [{"role": "system", "content": _system_prompt(self.cfg)}]
        if context:
            messages.append({"role": "system", "content": f"Current telemetry context:\n{context}"})
        messages.append(_user(user_goal))

        steps: list[dict] = []
        tokens = 0
        nudged_prose = False
        for step_i in range(max_steps + 1):
            force_final = step_i == max_steps
            if force_final:
                messages.append(_user(
                    'Tool budget exhausted. Reply now with {"action":"final","answer":"..."}.'))
            try:
                raw = self.client.chat(messages, model=model, purpose=purpose)
            except ProviderError as e:
                return {"answer": f"(provider error: {e})", "steps": steps, "tokens": tokens,
                        "error": str(e)}
            tokens += self.client.last_usage.get("total_tokens", 0)
            obj = extract_json(raw)
            if obj is not None:
                obj = _normalize_action(obj)
            if obj is None or "action" not in obj:
                # Looks like it meant to follow the protocol but flubbed it — nudge.
                looks_jsonish = '"action"' in raw or raw.lstrip().startswith("{")
                # Prose with zero investigation is usually stated *intent*, not an
                # answer ("I'll check your disk..."). One nudge back to the rails.
                premature_prose = not steps and not nudged_prose and len(raw) < 400
                if (looks_jsonish or premature_prose) and not force_final:
                    nudged_prose = nudged_prose or premature_prose
                    messages.append({"role": "assistant", "content": raw})
                    messages.append(_user(
                        "Protocol reminder: reply with exactly ONE valid JSON "
                        'object — {"action":"tool",...} to gather data, or '
                        '{"action":"final","answer":"..."} with your complete '
                        "answer. No other text."))
                    continue
                # Plain prose answer — accept as final.
                return {"answer": raw, "steps": steps, "tokens": tokens}
            if obj["action"] == "final":
                return {"answer": str(obj.get("answer", "")).strip(), "steps": steps,
                        "tokens": tokens}
            if obj["action"] == "tool":
                name = str(obj.get("tool", ""))
                args = obj.get("args", {}) or {}
                if self.on_step:
                    self.on_step("tool", f"{name} {json.dumps(args)[:120]}")
                result = tools.dispatch(name, args, self.store, self.cfg.policy_tier,
                                        self.confirm_fn)
                steps.append({"tool": name, "args": args, "result": result[:2000]})
                messages.append({"role": "assistant", "content": raw})
                messages.append(_user(f"TOOL RESULT for {name}:\n{result}"))
                continue
            # unknown action — nudge once
            messages.append({"role": "assistant", "content": raw})
            messages.append(_user('Invalid action. Use "tool" or "final" exactly.'))
        return {"answer": "(no final answer produced)", "steps": steps, "tokens": tokens}

    # ---------------- patrol ----------------
    def gather_context(self) -> tuple[str, dict]:
        """Observe: sample sensors, run driftscan, summarize for the model."""
        data = sensors.sample_all(self.store)
        drift_changes = driftscan.scan(self.store)
        anomalies = self.store.recent_anomalies(3600 * 6)

        osd = data["os"]
        lines = [
            f"cpu {osd['cpu_pct']}% | mem {osd['mem_pct']}% ({osd['mem_used_gb']}/{osd['mem_total_gb']} GB) "
            f"| swap {osd['swap_pct']}% | load {osd['load_1m']}/{osd['load_5m']}/{osd['load_15m']} "
            f"| procs {osd['n_procs']} | uptime {osd['uptime_s'] // 3600}h",
            "disks: " + ", ".join(f"{m} {p}%" for m, p in sorted(osd["disk_pct"].items())),
            "top cpu: " + ", ".join(f"{p['name']} {p['cpu_pct']}%" for p in osd["top_cpu"]),
            "top mem: " + ", ".join(f"{p['name']} {p['mem_pct']}%" for p in osd["top_mem"]),
        ]
        if "docker" in data:
            d = data["docker"]
            not_running = [c["name"] for c in d["containers"] if c["state"] != "running"]
            lines.append(
                f"docker: {d['n_running']}/{d['n_total']} running"
                + (f"; not running: {', '.join(not_running[:8])}" if not_running else "")
            )
        if "gpu" in data:
            lines.append(
                "gpu: " + "; ".join(
                    f"{g['name']}: {g['util_pct']}% util, "
                    f"{g['mem_used_mb']:.0f}/{g['mem_total_mb']:.0f} MB, {g['temp_c']:.0f}C"
                    for g in data["gpu"]["gpus"]
                )
            )
        if anomalies:
            lines.append("anomalies (6h): " + "; ".join(
                f"{a['metric']}={a['value']} (z={a['zscore']})" for a in anomalies[:10]
            ))
        else:
            lines.append("anomalies (6h): none")
        if drift_changes:
            for d in drift_changes:
                lines.append(f"drift [{d['kind']}]: " + "; ".join(d["changes"][:10]))
        else:
            lines.append("drift: no changes since last scan")
        return "\n".join(lines), {"sensor": data, "drift": drift_changes, "anomalies": anomalies}


PATROL_GOAL = """\
Patrol this machine. You've been given fresh telemetry context. Investigate anything that
looks off (use tools — check failed units, error logs, disk pressure, suspicious drift).
If all is well, say so briefly and confidently.

End with a final answer as JSON INSIDE the "answer" field — format the answer itself as:
STATUS: ok|attention|critical
SUMMARY: <one sentence>
FINDINGS:
- [severity] finding one (evidence)
- [severity] finding two (evidence)
RECOMMENDATIONS:
- exact command or action, one per line (or 'none')
"""


def parse_patrol_answer(answer: str) -> tuple[str, str, list[dict]]:
    """Extract (status, summary, findings[]) from the patrol answer text."""
    status, summary = "ok", ""
    findings: list[dict] = []
    section = ""
    for line in answer.splitlines():
        s = line.strip()
        low = s.lower()
        if low.startswith("status:"):
            val = s.split(":", 1)[1].strip().lower()
            if val in ("ok", "attention", "critical"):
                status = val
        elif low.startswith("summary:"):
            summary = s.split(":", 1)[1].strip()
        elif low.startswith("findings"):
            section = "findings"
        elif low.startswith("recommendations"):
            section = "recs"
        elif s.startswith("-") and section == "findings":
            item = s.lstrip("- ").strip()
            sev = "info"
            for cand in ("critical", "warning", "attention", "info", "ok"):
                if item.lower().startswith(f"[{cand}]"):
                    sev = cand
                    item = item[len(cand) + 2 :].strip()
                    break
            findings.append({"severity": sev, "text": item})
        elif s.startswith("-") and section == "recs":
            findings.append({"severity": "recommendation", "text": s.lstrip("- ").strip()})
    if not summary:
        summary = answer.strip().splitlines()[0][:200] if answer.strip() else "(empty)"
    return status, summary, findings


def run_patrol(cfg: Config, store, client: LLMClient | None = None, on_step=None,
               deep: bool = False) -> dict:
    """Full patrol: observe, let the agent investigate, store + return the report."""
    agent = Agent(cfg, store, client=client, on_step=on_step)
    t0 = time.time()
    context, raw_data = agent.gather_context()
    model = cfg.deep_model if deep else cfg.model
    result = agent.run(PATROL_GOAL, context=context, model=model, purpose="patrol")
    status, summary, findings = parse_patrol_answer(result["answer"])
    if result.get("error"):
        status, summary = "error", f"patrol failed: {result['error'][:200]}"
    store.add_patrol(model, status, summary, findings, result["answer"], result["tokens"])
    return {
        "status": status,
        "summary": summary,
        "findings": findings,
        "answer": result["answer"],
        "steps": result["steps"],
        "tokens": result["tokens"],
        "context": context,
        "raw_data": raw_data,
        "duration_s": round(time.time() - t0, 1),
        "model": model,
    }
