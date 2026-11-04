"""Rendering: rich terminal panels + self-contained HTML reports."""

from __future__ import annotations

import html
import time
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

SPARK_CHARS = "▁▂▃▄▅▆▇█"

STATUS_STYLE = {
    "ok": ("green", "✔"),
    "attention": ("yellow", "▲"),
    "critical": ("red", "✖"),
    "error": ("red", "✖"),
}
SEV_STYLE = {
    "critical": "bold red",
    "warning": "yellow",
    "attention": "yellow",
    "info": "cyan",
    "ok": "green",
    "recommendation": "magenta",
}


def sparkline(values: list[float], width: int = 24) -> str:
    if not values:
        return "·" * width
    vals = values[-width:]
    lo, hi = min(vals), max(vals)
    rng = (hi - lo) or 1.0
    return "".join(SPARK_CHARS[int((v - lo) / rng * (len(SPARK_CHARS) - 1))] for v in vals)


def pct_bar(pct: float, width: int = 18) -> Text:
    filled = int(pct / 100 * width)
    color = "green" if pct < 70 else "yellow" if pct < 90 else "red"
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="grey35")
    bar.append(f" {pct:5.1f}%", style=color)
    return bar


def _ago(ts: float) -> str:
    d = time.time() - ts
    if d < 90:
        return f"{int(d)}s ago"
    if d < 5400:
        return f"{int(d / 60)}m ago"
    if d < 172800:
        return f"{d / 3600:.1f}h ago"
    return f"{d / 86400:.1f}d ago"


# ---------------- wrench status ----------------

def render_status(console: Console, data: dict, history: list[tuple[float, dict]],
                  cfg=None) -> None:
    osd = data["os"]

    # headline gauges
    gauges = Table.grid(padding=(0, 2))
    gauges.add_column(justify="right", style="bold")
    gauges.add_column()
    cpu_hist = [h[1].get("cpu_pct", 0) for h in history]
    mem_hist = [h[1].get("mem_pct", 0) for h in history]
    gauges.add_row("CPU", Text.assemble(pct_bar(osd["cpu_pct"]), "  ",
                                        Text(sparkline(cpu_hist), style="cyan")))
    gauges.add_row("MEM", Text.assemble(pct_bar(osd["mem_pct"]), "  ",
                                        Text(sparkline(mem_hist), style="cyan")))
    gauges.add_row("SWAP", pct_bar(osd["swap_pct"]))
    for mount, pct in sorted(osd["disk_pct"].items()):
        gauges.add_row(f"disk {mount}", pct_bar(pct))
    load_line = Text(
        f"load {osd['load_1m']:.2f} / {osd['load_5m']:.2f} / {osd['load_15m']:.2f}"
        f"   procs {osd['n_procs']}   up {osd['uptime_s'] // 3600}h"
        f"   net ↓{osd.get('net_recv_rate_kbs', 0):.0f} ↑{osd.get('net_sent_rate_kbs', 0):.0f} KB/s",
        style="dim",
    )

    parts: list = [gauges, Text(""), load_line]

    if "gpu" in data:
        for g in data["gpu"]["gpus"]:
            parts.append(Text(
                f"gpu {g['name']}: {g['util_pct']:.0f}% util, "
                f"{g['mem_used_mb']:.0f}/{g['mem_total_mb']:.0f} MB, {g['temp_c']:.0f}°C",
                style="dim cyan"))
    if "docker" in data:
        d = data["docker"]
        style = "green" if d["n_running"] == d["n_total"] else "yellow"
        parts.append(Text(f"docker: {d['n_running']}/{d['n_total']} containers running",
                          style=style))

    anoms = data.get("anomalies_24h", [])
    if anoms:
        t = Table(box=box.SIMPLE, title="anomalies (24h)", title_style="bold yellow",
                  show_header=True, header_style="dim")
        t.add_column("when")
        t.add_column("metric")
        t.add_column("value", justify="right")
        t.add_column("z", justify="right")
        for a in anoms[:8]:
            t.add_row(_ago(a["ts"]), a["metric"], f"{a['value']:.1f}",
                      Text(f"{a['zscore']:+.1f}", style="yellow"))
        parts.append(t)
    else:
        parts.append(Text("no anomalies in 24h — baselines quiet", style="green"))

    console.print(Panel(Group(*parts), title="[bold]🔧 wrench status[/bold]",
                        subtitle=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        border_style="bright_blue", padding=(1, 2)))


# ---------------- patrol rendering ----------------

def render_patrol(console: Console, patrol: dict) -> None:
    color, icon = STATUS_STYLE.get(patrol["status"], ("white", "?"))
    header = Text.assemble(
        (f" {icon} {patrol['status'].upper()} ", f"bold {color} reverse"),
        ("  ", ""),
        (patrol["summary"], "bold"),
    )
    body: list = [header, Text("")]

    findings = [f for f in patrol["findings"] if f["severity"] != "recommendation"]
    recs = [f for f in patrol["findings"] if f["severity"] == "recommendation"]
    if findings:
        for f in findings:
            style = SEV_STYLE.get(f["severity"], "white")
            body.append(Text.assemble((f"  [{f['severity']}] ", style), (f["text"], "")))
    if recs:
        body.append(Text(""))
        body.append(Text("recommendations:", style="bold magenta"))
        for r in recs:
            body.append(Text(f"  $ {r['text']}", style="magenta"))
    if patrol.get("steps"):
        body.append(Text(""))
        body.append(Text(
            f"investigated with {len(patrol['steps'])} tool call(s): "
            + ", ".join(s["tool"] for s in patrol["steps"]), style="dim"))
    body.append(Text(
        f"model {patrol.get('model', '?')} · {patrol['tokens']} tokens · "
        f"{patrol.get('duration_s', '?')}s", style="dim"))

    console.print(Panel(Group(*body), title="[bold]🔧 wrench patrol[/bold]",
                        subtitle=datetime.now().strftime("%Y-%m-%d %H:%M"),
                        border_style=color, padding=(1, 2)))


def render_answer(console: Console, answer: str, meta: str = "") -> None:
    group: list = [Markdown(answer)]
    if meta:
        group += [Text(""), Text(meta, style="dim")]
    console.print(Panel(Group(*group), title="[bold]🔧 wrench[/bold]",
                        border_style="bright_blue", padding=(1, 2)))


# ---------------- HTML report ----------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wrench patrol — {date}</title>
<style>
:root {{ --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3; --dim:#8b949e;
  --ok:#3fb950; --warn:#d29922; --crit:#f85149; --accent:#58a6ff; --mag:#bc8cff; }}
* {{ box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--fg); font:15px/1.6 'SF Mono',ui-monospace,Menlo,Consolas,monospace;
  max-width:880px; margin:2rem auto; padding:0 1rem; }}
.panel {{ background:var(--panel); border:1px solid var(--border); border-radius:10px;
  padding:1.2rem 1.5rem; margin-bottom:1rem; }}
h1 {{ font-size:1.3rem; margin:0 0 .2rem; }} h2 {{ font-size:1rem; color:var(--accent); margin:1rem 0 .4rem; }}
.status {{ display:inline-block; padding:.15rem .7rem; border-radius:6px; font-weight:bold; }}
.status.ok {{ background:#1a3a24; color:var(--ok); }} .status.attention {{ background:#3a2e14; color:var(--warn); }}
.status.critical,.status.error {{ background:#3d1a1a; color:var(--crit); }}
.dim {{ color:var(--dim); font-size:.85rem; }}
.finding {{ margin:.3rem 0; padding-left:1rem; border-left:3px solid var(--border); }}
.finding.critical {{ border-color:var(--crit); }} .finding.warning,.finding.attention {{ border-color:var(--warn); }}
.finding.info {{ border-color:var(--accent); }} .finding.recommendation {{ border-color:var(--mag); color:var(--mag); }}
pre {{ background:#0a0d12; border:1px solid var(--border); border-radius:8px; padding:1rem;
  overflow-x:auto; white-space:pre-wrap; font-size:.82rem; }}
.meter {{ display:flex; align-items:center; gap:.6rem; margin:.25rem 0; }}
.meter .label {{ width:110px; text-align:right; color:var(--dim); font-size:.85rem; }}
.meter .bar {{ flex:1; height:10px; background:#21262d; border-radius:5px; overflow:hidden; }}
.meter .fill {{ height:100%; border-radius:5px; }}
.meter .val {{ width:60px; font-size:.85rem; }}
footer {{ color:var(--dim); font-size:.8rem; text-align:center; margin:2rem 0 1rem; }}
a {{ color:var(--accent); }}
</style></head><body>
<div class="panel">
  <h1>🔧 wrench patrol report</h1>
  <div class="dim">{date} · host: {host} · model: {model} · {tokens} tokens · {duration}s</div>
  <p><span class="status {status}">{status_upper}</span> &nbsp; {summary}</p>
</div>
<div class="panel"><h2>system vitals</h2>{meters}</div>
<div class="panel"><h2>findings</h2>{findings_html}</div>
<div class="panel"><h2>telemetry context given to the agent</h2><pre>{context}</pre></div>
<div class="panel"><h2>full agent report</h2><pre>{answer}</pre></div>
<footer>generated by <a href="https://github.com/sunkencity999/wrench">wrench</a> — an intentional local sysadmin agent</footer>
</body></html>
"""


def _meter(label: str, pct: float) -> str:
    color = "#3fb950" if pct < 70 else "#d29922" if pct < 90 else "#f85149"
    return (
        f'<div class="meter"><div class="label">{html.escape(label)}</div>'
        f'<div class="bar"><div class="fill" style="width:{min(pct, 100):.1f}%;background:{color}"></div></div>'
        f'<div class="val">{pct:.1f}%</div></div>'
    )


def html_report(patrol: dict, host: str = "localhost", out_dir: Path | None = None) -> Path:
    osd = patrol["raw_data"]["sensor"]["os"]
    meters = [_meter("cpu", osd["cpu_pct"]), _meter("mem", osd["mem_pct"]),
              _meter("swap", osd["swap_pct"])]
    for mount, pct in sorted(osd["disk_pct"].items()):
        meters.append(_meter(f"disk {mount}", pct))

    findings_html = []
    for f in patrol["findings"]:
        findings_html.append(
            f'<div class="finding {f["severity"]}">[{f["severity"]}] {html.escape(f["text"])}</div>'
        )
    if not findings_html:
        findings_html.append('<div class="finding info">no findings — all quiet</div>')

    page = HTML_TEMPLATE.format(
        date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        host=html.escape(host),
        model=html.escape(str(patrol.get("model", "?"))),
        tokens=patrol.get("tokens", 0),
        duration=patrol.get("duration_s", "?"),
        status=html.escape(patrol["status"]),
        status_upper=html.escape(patrol["status"].upper()),
        summary=html.escape(patrol["summary"]),
        meters="\n".join(meters),
        findings_html="\n".join(findings_html),
        context=html.escape(patrol.get("context", "")),
        answer=html.escape(patrol.get("answer", "")),
    )
    out_dir = out_dir or (Path.home() / ".local/share/wrench/reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"patrol-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
    out.write_text(page)
    return out
