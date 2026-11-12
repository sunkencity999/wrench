"""wrench CLI — typer app."""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import (__version__, agent as agent_mod, driftscan, jsonout, platforms,
               report, sensors)
from .config import CONFIG_PATH, load_config, write_default_config
from .providers import LLMClient
from .store import Store

app = typer.Typer(
    help="🔧 wrench — I'm the sysadmin's right hand on your machine. I watch, remember, "
    "explain, and — with your permission — fix.",
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode="rich",
)


def _never_crash_on_encoding() -> None:
    """A piped or redirected stream on Windows uses the ANSI code page, which
    cannot encode the glyphs wrench prints — and a UnicodeEncodeError there
    kills the command (`wrench comply > report.txt`, a scheduled task's log).
    Keep the stream's encoding; substitute what it cannot represent."""
    for stream in (sys.stdout, sys.stderr):
        try:
            enc = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
            if enc not in ("utf8", "utf8sig"):
                stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


_never_crash_on_encoding()
console = Console()

# `wrench --help` groups commands by the five arcs instead of one long list.
ARC_SEE, ARC_PREDICT, ARC_PROVE, ARC_FIX, ARC_SCALE, ARC_SETUP = (
    "SEE — watch the machine (read-only)", "PREDICT — see it coming",
    "PROVE — evidence, not vibes", "FIX — with your permission",
    "SCALE — many machines, your stack", "Setup & housekeeping")
ARC_LEARN = "LEARN — remembers you, works on a schedule"
_HELP_PANELS = {
    "status": ARC_SEE, "score": ARC_SEE, "patrol": ARC_SEE, "ask": ARC_SEE, "chat": ARC_SEE,
    "explain": ARC_SEE, "drift": ARC_SEE, "security": ARC_SEE, "watch": ARC_SEE,
    "report": ARC_SEE, "notifications": ARC_SEE,
    "forecast": ARC_PREDICT, "certs": ARC_PREDICT, "cve": ARC_PREDICT,
    "audit": ARC_PROVE, "backups": ARC_PROVE, "comply": ARC_PROVE, "bundle": ARC_PROVE,
    "fixxer": ARC_FIX, "blueprint": ARC_FIX, "approve": ARC_FIX, "approvals": ARC_FIX,
    "policy": ARC_FIX, "commands": ARC_FIX,
    "remember": ARC_LEARN, "memory": ARC_LEARN, "jobs": ARC_LEARN, "heartbeat": ARC_LEARN,
    "fleet": ARC_SCALE, "web": ARC_SCALE, "password": ARC_SCALE, "metrics": ARC_SCALE,
    "init": ARC_SETUP, "doctor": ARC_SETUP, "install-service": ARC_SETUP, "version": ARC_SETUP,
}


def _apply_help_panels() -> None:
    for c in app.registered_commands:
        name = c.name or (c.callback.__name__.replace("_", "-") if c.callback else "")
        c.rich_help_panel = _HELP_PANELS.get(name, ARC_SETUP)
    for g in app.registered_groups:
        g.rich_help_panel = _HELP_PANELS.get(g.name or "", ARC_SETUP)
    # panels appear in the order their first command does: SEE first, setup last
    order = [ARC_SEE, ARC_PREDICT, ARC_PROVE, ARC_FIX, ARC_LEARN, ARC_SCALE, ARC_SETUP]
    app.registered_commands.sort(key=lambda c: order.index(c.rich_help_panel))


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        _home()
    else:
        _note_routine(ctx.invoked_subcommand)


def _note_routine(command: str) -> None:
    """Remember that a person ran this read-only command, and when — so the
    heartbeat can offer to do it for them. Interactive terminals only (a
    script or a scheduled run is not a habit). Never fatal."""
    try:
        from . import heartbeat as _hb, memory as _mem
        if command not in _hb.ROUTINE_COMMANDS or not (sys.stdin.isatty() and sys.stdout.isatty()):
            return
        cfg, store = _ctx()
        try:
            if _mem.settings(cfg)["enabled"] and _mem.settings(cfg)["learn_habits"]:
                _mem.note_command(store, command)
        finally:
            store.close()
    except Exception:  # noqa: BLE001
        pass


def _home() -> None:
    """`wrench` with no arguments: where this machine stands and what to do next.

    Reads cached state only — it is instant and never touches the machine.
    """
    from . import posture
    cfg, store = _ctx()
    try:
        pos = posture.compute(cfg, store)
        steps = posture.checklist(cfg, store)
        patrols = store.recent_patrols(1)
        learn = _learn_brief(store)
    finally:
        store.close()
    head = Text()
    head.append(platform.node() or "this machine", style="bold")
    head.append(f"  ·  {platforms.os_label()}  ·  wrench {__version__}\n", style="dim")
    style = {"ok": "green", "attention": "yellow", "critical": "bold red"}.get(pos["state"], "dim")
    if pos["score"] is None:
        head.append("not measured yet", style="dim")
    elif pos.get("provisional"):
        head.append(f"health {pos['score']:.0f}/100", style="dim")
        head.append("  provisional — most pillars are not measured yet", style="yellow")
    else:
        head.append(f"health {pos['score']:.0f}/100", style=f"bold {style}")
        head.append(f"  grade {pos['grade']}", style=style)
        cov = pos["coverage"]
        head.append(f"  ·  {cov['measured']} of {cov['total']} pillars measured", style="dim")
    if patrols:
        age = time.time() - patrols[0]["ts"]
        when = f"{age / 60:.0f}m ago" if age < 5400 else f"{age / 3600:.1f}h ago" \
            if age < 172800 else f"{age / 86400:.0f}d ago"
        head.append(f"\nlast patrol {patrols[0]['status']}, {when}: ", style="dim")
        head.append((patrols[0].get("summary") or "")[:110])
    console.print(Panel(head, border_style="bright_blue", title="🔧 wrench", title_align="left"))

    todo = [s for s in steps if not s["done"]]
    if todo:
        console.print(Text.assemble(("next  ", "bold bright_blue"), (todo[0]["command"], "bold"),
                                    (f"   {todo[0]['why']}", "dim")))
        if len(todo) > 1:
            console.print(Text("then  " + "  ·  ".join(s["command"] for s in todo[1:4]), style="dim"))
    elif pos.get("top_issues"):
        i = pos["top_issues"][0]
        console.print(Text.assemble(("next  ", "bold bright_blue"), (i["command"], "bold"),
                                    (f"   {i['label']}: {i['detail']}", "dim")))
    else:
        console.print(Text("all set — nothing needs attention", style="green"))
    for label, body, hint in learn:
        console.print(Text.assemble((f"{label}  ", "bold bright_blue"), (body, ""),
                                    (f"   {hint}" if hint else "", "dim")))
    t = Table.grid(padding=(0, 2))
    t.add_column(style="bold bright_blue", no_wrap=True)
    t.add_column()
    for arc, cmds in (
        ("see", "status · score · patrol · ask \"…\" · drift · security"),
        ("predict", "forecast · certs · cve"),
        ("prove", "audit verify · backups · comply · bundle"),
        ("fix", "policy <tier> · commands · fixxer · blueprint \"…\""),
        ("learn", "remember \"…\" · memory · jobs · heartbeat"),
        ("scale", "web · fleet enroll / join / serve · metrics"),
        ("setup", "init · doctor · install-service"),
    ):
        t.add_row(arc, Text(cmds, style="dim"))
    console.print()
    console.print(t)
    console.print(Text("\nwrench <command> --help for details  ·  wrench --help for everything",
                       style="dim"))


def _rel(ts: float | None, now: float | None = None) -> str:
    """'in 12m' / '3h ago' / '—'."""
    if not ts:
        return "—"
    d = ts - (now if now is not None else time.time())
    a = abs(d)
    span = f"{a:.0f}s" if a < 90 else f"{a / 60:.0f}m" if a < 5400 else \
        f"{a / 3600:.0f}h" if a < 172800 else f"{a / 86400:.0f}d"
    return f"in {span}" if d > 0 else f"{span} ago"


def _learn_brief(store) -> list[tuple[str, str, str]]:
    """Home-screen lines about memory and the heartbeat. Cached reads only."""
    out: list[tuple[str, str, str]] = []
    try:
        from . import heartbeat as _hb, memory as _mem
        mc = _mem.counts(store)
        pu = _hb.pulse(store)
        waiting = []
        if mc["pending"]:
            waiting.append((f"{mc['pending']} note{'s' if mc['pending'] != 1 else ''} to review",
                            "wrench memory review"))
        if pu["jobs"]["proposed"]:
            n = pu["jobs"]["proposed"]
            waiting.append((f"{n} proposed job{'s' if n != 1 else ''}", "wrench jobs"))
        if waiting:
            out.append(("waiting", " · ".join(w[0] for w in waiting),
                        " · ".join(w[1] for w in waiting)))
        if pu["alive"] is None:
            out.append(("heartbeat", "not running", "wrench install-service"))
        else:
            nxt = f" · next: {pu['next']['name']} {_rel(pu['next']['at'])}" if pu["next"] else ""
            out.append(("heartbeat",
                        ("alive" if pu["alive"] else "SILENT") + f", last beat "
                        f"{_rel(pu['last_tick'])}{nxt}",
                        "" if pu["alive"] else "wrench install-service"))
        if mc["active"]:
            out.append(("memory", f"{mc['active']} thing{'s' if mc['active'] != 1 else ''} "
                        "remembered", "wrench memory"))
    except Exception:  # noqa: BLE001
        pass
    return out


def _ctx(provider: str | None = None, model: str | None = None):
    cfg = load_config(provider_override=provider, model_override=model)
    store = Store(cfg.db_path)
    return cfg, store


def _notify_banner(cfg) -> None:
    """One-line heads-up when unread patrol notifications exist. Never fatal."""
    try:
        from . import notifications
        rows = notifications.unread(cfg.data_dir)
        n = len(rows)
        if n:
            worst = max(rows, key=lambda r: notifications.severity_rank(r.get("severity", "")))
            console.print(
                f"[bold yellow]\U0001f514 {n} unread notification{'s' if n != 1 else ''}"
                f"[/bold yellow] [dim]\u2014 worst: {worst.get('severity', '?')} "
                f"({worst.get('kind', 'patrol')}) \u00b7 run `wrench notifications`[/dim]")
    except Exception:  # noqa: BLE001
        pass


def _confirm(command: str, label: str) -> bool:
    if label.startswith(("memory:", "schedule:")):
        what, _, ask = label.partition(": ")
        console.print(Panel(Text(command, style="bold white"), border_style="bright_blue",
                            title="🧠 remember?" if what == "memory" else "⏱ schedule?",
                            title_align="left"))
        # default No, like a fix: a bare Enter must not make a model's note stick
        return typer.confirm(ask + "?", default=False)
    console.print(Panel(
        Text.assemble(("about to execute: ", "bold yellow"), (command, "bold white"),
                      (f"\n({label})", "dim")),
        border_style="yellow", title="confirmation required"))
    return typer.confirm("run it?", default=False)


def _enforce_window(cfg, operation: str, override_window: bool, has_consent: bool) -> None:
    """Block an executing state-change outside the maintenance window.

    No windows configured → no-op (home-user default). Outside a window,
    --override-window WITH consent proceeds and is audit-logged; without consent
    (or without the flag) it exits cleanly with a clear message.
    """
    from . import windows as _win, audit as _amod
    dec = _win.gate(cfg, operation, override=override_window, has_consent=has_consent)
    if not dec.allowed:
        console.print(Panel(dec.reason, border_style="yellow",
                            title="⏳ maintenance window"))
        raise typer.Exit(2)
    if dec.overridden:
        _amod.log_event(cfg, "window.override",
                        {"operation": operation, "reason": dec.reason})
        console.print(f"[yellow]⏳ {dec.reason}[/yellow]")


def _approval_gate(cfg, store, action: str, detail: str) -> None:
    """Out-of-band approval for a consent-gated action in a non-TTY context.

    - approvals not configured → no-op (default; behavior unchanged);
    - interactive TTY → no-op (the normal consent ceremony runs);
    - an approval already granted out-of-band → claim it and proceed;
    - otherwise → mint a single-use token, POST it to the approval webhook,
      tell the operator how to approve, and EXIT CLEANLY (never hang).
    """
    from . import approvals, audit as _amod
    st = approvals.settings_from(cfg)
    if not st.enabled or sys.stdin.isatty():
        return
    # the approval is bound to THIS request (action + a digest of its detail)
    key = approvals.bound_action(action, detail)
    if approvals.claim_approval(store, key):
        _amod.log_event(cfg, "approval.claimed", {"action": action, "key": key})
        console.print("[green]✔ approved out-of-band — proceeding[/green]")
        return
    token, posted = approvals.create_and_notify(cfg, store, key, detail)
    _amod.log_event(cfg, "approval.requested",
                    {"action": action, "key": key, "posted": posted})
    # The token is the approver's credential. It goes to the approval channel
    # only — printing it here would put it in the requesting job's own log
    # (cron mail, CI output) and let the requester approve itself.
    if posted:
        body = ("[yellow]pending approval[/yellow] — this action needs out-of-band "
                "approval before it runs.\n"
                "the approval token was sent to the approval webhook; the approver "
                "runs [bold]wrench approve <token>[/bold], then re-run this command.")
    else:
        body = ("[red]approval could not be requested[/red] — the webhook POST failed, "
                "so nobody holds a token for this action.\n"
                "check [bold][approvals] approval_webhook_url[/bold] and re-run.")
    console.print(Panel(body, border_style="yellow", title="⏸ pending approval"))
    raise typer.Exit(0 if posted else 1)


PROVIDER_OPT = typer.Option(None, "--provider", "-p",
                            help="ollama|lmstudio|openai|anthropic|meta|azure|litellm|custom")
MODEL_OPT = typer.Option(None, "--model", "-m", help="model override")
JSON_OPT = typer.Option(False, "--json",
                        help="machine-readable JSON to stdout (no rich formatting)")


# ---------------- commands ----------------

@app.command()
def version(json_out: bool = JSON_OPT):
    """Print version."""
    if json_out:
        jsonout.emit("version", {})
        return
    console.print(f"wrench {__version__}")


@app.command()
def status(json_out: bool = JSON_OPT):
    """One-screen health: gauges, sparklines, anomalies."""
    cfg, store = _ctx()
    if json_out:
        data = sensors.status_snapshot(store)
        jsonout.emit("status", {
            "os": data.get("os", {}),
            "docker": data.get("docker"),
            "gpu": data.get("gpu"),
            "anomalies_24h": data.get("anomalies_24h", []),
            "unread_notifications": _unread_count(cfg),
            "posture": _posture_brief(cfg, store),
        })
        return
    _notify_banner(cfg)
    with console.status("[cyan]sampling sensors..."):
        data = sensors.status_snapshot(store)
        history = store.recent_samples("os", 86400)
    report.render_status(console, data, history, cfg)
    pb = _posture_brief(cfg, store)
    if pb.get("score") is not None:
        style = {"ok": "green", "attention": "yellow", "critical": "bold red"}.get(pb["state"], "dim")
        console.print(Text.assemble(
            ("health ", "dim"), (f"{pb['score']:.0f}/100", style),
            (" (provisional)" if pb.get("provisional") else f" (grade {pb['grade']})", style),
            (f" · {pb['measured']} of {pb['total']} pillars measured · ", "dim"),
            ("wrench score", "bold"), (" for the breakdown", "dim")))


def _posture_brief(cfg, store) -> dict:
    try:
        from . import posture
        p = posture.compute(cfg, store)
        return {"score": p["score"], "grade": p["grade"], "state": p["state"],
                "provisional": p.get("provisional", False),
                "measured": p["coverage"]["measured"], "total": p["coverage"]["total"]}
    except Exception:  # noqa: BLE001
        return {}


def _unread_count(cfg) -> int:
    try:
        from . import notifications
        return len(notifications.unread(cfg.data_dir))
    except Exception:  # noqa: BLE001
        return 0


@app.command()
def ask(
    question: list[str] = typer.Argument(..., help="your question for the agent"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
    deep: bool = typer.Option(False, "--deep", help="use the deep-reasoning model"),
):
    """Ask the agent one question. It may run read-only diagnostics to answer."""
    cfg, store = _ctx(provider, model)
    _notify_banner(cfg)
    q = " ".join(question)
    use_model = cfg.deep_model if deep else None
    a = agent_mod.Agent(cfg, store, confirm_fn=_confirm,
                        on_step=lambda k, d: console.print(f"  [dim cyan]⚙ {d}[/dim cyan]"))
    with console.status(f"[cyan]thinking ({use_model or cfg.model})..."):
        res = a.run(q, model=use_model, purpose="ask")
    meta = f"{use_model or cfg.model} · {res['tokens']} tokens · {len(res['steps'])} tool call(s)"
    report.render_answer(console, res["answer"], meta)


@app.command()
def chat(provider: str = PROVIDER_OPT, model: str = MODEL_OPT):
    """Interactive conversation with wrench. Ctrl-D or 'exit' to leave."""
    cfg, store = _ctx(provider, model)
    _notify_banner(cfg)
    a = agent_mod.Agent(cfg, store, confirm_fn=_confirm,
                        on_step=lambda k, d: console.print(f"  [dim cyan]⚙ {d}[/dim cyan]"))
    console.print(Panel(
        f"chatting with [bold]{cfg.model}[/bold] ({cfg.provider}) · policy tier: "
        f"[bold]{cfg.policy_tier}[/bold]\ntype [bold]exit[/bold] to leave",
        border_style="bright_blue", title="🔧 wrench chat"))
    history: list[dict] = []
    while True:
        try:
            q = console.input("[bold bright_blue]you ▸ [/bold bright_blue]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]bye[/dim]")
            return
        if not q or q.lower() in ("exit", "quit", "q"):
            console.print("[dim]bye[/dim]")
            return
        convo = "\n".join(f"{m['role']}: {m['content'][:500]}" for m in history[-6:])
        goal = (f"Conversation so far:\n{convo}\n\nHuman's new message: {q}") if history else q
        with console.status("[cyan]thinking..."):
            res = a.run(goal, purpose="chat")
        report.render_answer(console, res["answer"],
                             f"{res['tokens']} tokens · {len(res['steps'])} tool call(s)")
        history.append({"role": "user", "content": q})
        history.append({"role": "assistant", "content": res["answer"]})


@app.command()
def patrol(
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
    deep: bool = typer.Option(False, "--deep", help="deep patrol with the reasoning model"),
    html: bool = typer.Option(True, "--html/--no-html", help="also write an HTML report"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="only print if attention/critical"),
    no_llm: bool = typer.Option(False, "--no-llm",
                                help="deterministic patrol: every code check, no model call"),
    json_out: bool = JSON_OPT,
):
    """Run one patrol: observe → investigate → report. The heart of wrench.

    Without a configured brain (or with --no-llm) the patrol still runs every
    deterministic check — sensors, drift, certs, security, backups, compliance,
    forecast — and files a report."""
    cfg, store = _ctx(provider, model)
    steps_seen: list[str] = []

    def on_step(kind, detail):
        steps_seen.append(detail)
        if not quiet:
            console.print(f"  [dim cyan]⚙ {detail}[/dim cyan]")

    quiet = quiet or json_out
    usable, why = agent_mod.brain_status(cfg)
    if not quiet:
        brain = (cfg.deep_model if deep else cfg.model) if (usable and not no_llm) \
            else "deterministic mode"
        console.print(f"[dim italic]I'm on patrol — sweeping sensors, drift, and logs "
                      f"({brain}, tier: {cfg.policy_tier})...[/dim italic]")
    p = agent_mod.run_patrol(cfg, store, on_step=on_step, deep=deep, use_llm=not no_llm)
    if json_out:
        jsonout.emit("patrol", {
            "status": p["status"], "summary": p["summary"], "findings": p["findings"],
            "model": p["model"], "deterministic": p["deterministic"],
            "tokens": p["tokens"], "duration_s": p["duration_s"], "ts": p["ts"]})
        raise typer.Exit({"ok": 0, "attention": 1}.get(p["status"], 2))
    if quiet and p["status"] == "ok":
        return
    report.render_patrol(console, p)
    if html:
        out = report.html_report(p, host=platform.node() or "localhost")
        console.print(f"[dim]html report: {out}[/dim]")


@app.command()
def watch(
    interval: int = typer.Option(900, "--interval", "-i", help="seconds between patrols"),
    provider: str = PROVIDER_OPT,
):
    """Patrol forever at an interval (foreground; see install-service for systemd)."""
    cfg, store = _ctx(provider)
    console.print(f"[bold]wrench watch[/bold] — patrol every {interval}s. Ctrl-C to stop.")
    while True:
        try:
            p = agent_mod.run_patrol(cfg, store)
            report.render_patrol(console, p)
            if p.get("notification"):
                n = p["notification"]
                console.print(f"[bold yellow]\U0001f514 notification "
                              f"[{n['severity']}][/bold yellow] {n['summary']}")
            report.html_report(p, host=platform.node() or "localhost")
            store.prune(cfg.retention_days)
            time.sleep(interval)
        except KeyboardInterrupt:
            console.print("\n[dim]watch stopped[/dim]")
            return


@app.command()
def drift(
    narrate: bool = typer.Option(False, "--narrate", help="let the model narrate significance"),
    provider: str = PROVIDER_OPT,
    json_out: bool = JSON_OPT,
):
    """Scan for drift: what changed on this box since last scan?"""
    cfg, store = _ctx(provider)
    first = not driftscan.baseline_exists(store)
    if json_out:
        changes = driftscan.scan(store)
        jsonout.emit("drift", {
            "baseline_recorded": first,
            "change_count": sum(len(c.get("changes", [])) for c in changes),
            "changes": changes,
        })
        return
    with console.status("[cyan]snapshotting ports/services/packages/users/cron..."):
        changes = driftscan.scan(store)
    if first:
        console.print(Panel("[green]baseline recorded[/green] — run [bold]wrench drift[/bold] "
                            "again later to see what changed", border_style="green",
                            title="🔧 wrench drift"))
        return
    if not changes:
        console.print(Panel("[green]no drift[/green] — this box is exactly as you left it",
                            border_style="green", title="🔧 wrench drift"))
        return
    body = []
    for c in changes:
        body.append(Text(c["kind"], style="bold cyan"))
        for line in c["changes"]:
            body.append(Text(f"  • {line}"))
    from rich.console import Group
    console.print(Panel(Group(*body), border_style="yellow", title="🔧 wrench drift"))
    if narrate:
        client = LLMClient(cfg, store)
        flat = "\n".join(f"[{c['kind']}] " + "; ".join(c["changes"]) for c in changes)
        with console.status("[cyan]narrating..."):
            try:
                text = client.chat(
                    [{"role": "system",
                      "content": "You are wrench, a sysadmin agent. Briefly assess these system "
                                 "changes: likely cause, risk level, anything deserving a look. "
                                 "3-6 sentences, plain English."},
                     {"role": "user", "content": flat}],
                    purpose="drift-narrate")
                report.render_answer(console, text, f"{cfg.model}")
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]narration failed:[/red] {e}")


@app.command("report")
def report_cmd(
    last: int = typer.Option(10, "--last", "-n", help="how many patrols to list"),
    open_html: bool = typer.Option(False, "--open", help="regenerate+print latest HTML path"),
    json_out: bool = JSON_OPT,
):
    """Show recent patrol reports. Viewing them marks notifications read."""
    cfg, store = _ctx()
    if json_out:
        patrols = store.recent_patrols(last)
        jsonout.emit("report", {
            "count": len(patrols),
            "patrols": [{
                "ts": p["ts"], "status": p["status"], "summary": p["summary"],
                "model": p.get("model"), "tokens": p.get("tokens"),
                "findings": p.get("findings", []),
            } for p in patrols],
        })
        return
    _notify_banner(cfg)
    patrols = store.recent_patrols(last)
    if not patrols:
        console.print("[dim]no patrols yet — run [bold]wrench patrol[/bold][/dim]")
        return
    t = Table(title="🔧 recent patrols", border_style="bright_blue")
    t.add_column("when")
    t.add_column("status")
    t.add_column("summary", max_width=70)
    t.add_column("tokens", justify="right")
    for p in patrols:
        color, icon = report.STATUS_STYLE.get(p["status"], ("white", "?"))
        t.add_row(
            time.strftime("%m-%d %H:%M", time.localtime(p["ts"])),
            Text(f"{icon} {p['status']}", style=color),
            p["summary"], str(p["tokens"]),
        )
    console.print(t)
    reports_dir = cfg.data_dir / "reports"
    if open_html and reports_dir.exists():
        files = sorted(reports_dir.glob("patrol-*.html"))
        if files:
            console.print(f"[bold]latest html:[/bold] {files[-1]}")
    try:
        from . import notifications
        if notifications.mark_read(cfg.data_dir):
            console.print("[dim]\U0001f514 notifications marked read[/dim]")
    except Exception:  # noqa: BLE001
        pass


def is_loopback_hint(bind: str) -> bool:
    from . import webauth
    return webauth.is_loopback_bind(bind)


def _serve_banner(httpd, bind: str, port: int, title: str, lines: list[str]) -> None:
    """Print where the server is and how to get in (token shown once if minted)."""
    auth = httpd.auth
    host = "localhost" if bind in ("127.0.0.1", "::1") else bind
    if bind in ("0.0.0.0", "::"):
        host = platform.node() or "this-host"
    url = f"{httpd.scheme}://{host}:{port}"
    body = [f"{ln}".replace("{url}", url) for ln in lines]
    if auth.required:
        if auth.generated:
            body.append(
                f"[yellow]access token[/yellow] (generated, stored owner-only in the data dir):\n"
                f"[bold bright_green]{auth.admin_token}[/bold bright_green]")
        elif auth.has_password:
            body.append("[dim]access control: on — sign in with the dashboard password "
                        "(change it: [bold]wrench password[/bold])"
                        + (", or an access token" if auth.admin_token else "") + "[/dim]")
        elif auth.admin_token or auth.viewer_token:
            body.append("[dim]access control: on — sign in with the token from "
                        "[bold][web] auth_token[/bold] / WRENCH_WEB_TOKEN[/dim]")
        else:
            body.append("[yellow]access control: on, but nothing can sign in[/yellow] — "
                        "set a password with [bold]wrench password[/bold]")
        if auth.viewer_token:
            body.append("[dim]a read-only viewer token is also configured[/dim]")
    else:
        body.append("[dim]access: this machine only (loopback), no sign-in. "
                    "[bold]wrench password[/bold] puts a password on it; binding wider "
                    "turns sign-in on automatically.[/dim]")
    if not auth.loopback and httpd.scheme == "http":
        body.append("[yellow]serving plain HTTP on a network address[/yellow] — add "
                    "[bold]--tls-cert/--tls-key[/bold] (or a TLS reverse proxy) so tokens "
                    "and telemetry are not sent in the clear")
    console.print(Panel("\n".join(body), border_style="bright_blue", title=title))


@app.command()
def web(
    port: int = typer.Option(None, "--port", help="port (default from config, 8787)"),
    bind: str = typer.Option(None, "--bind", help="bind address (default 127.0.0.1)"),
    no_sample: bool = typer.Option(False, "--no-sample", help="don't sample in the background"),
    tls_cert: str = typer.Option(None, "--tls-cert", help="serve HTTPS with this certificate (PEM)"),
    tls_key: str = typer.Option(None, "--tls-key", help="private key for --tls-cert (PEM)"),
):
    """Serve the dashboard: health score, posture, vitals, patrols — and the
    fleet console when this box is a hub.

    With a password set (`wrench password`) every visit signs in. Without
    one, loopback needs no sign-in and any wider bind requires a token (one
    is generated if you have not set [web] auth_token)."""
    from .webapp import serve

    cfg, store = _ctx()
    store.close()
    web_cfg = (cfg.raw or {}).get("web", {}) if isinstance((cfg.raw or {}).get("web"), dict) else {}
    port = port or cfg.web_port
    bind = bind or str(web_cfg.get("bind", "127.0.0.1"))
    tls_cert = tls_cert or str(web_cfg.get("tls_cert", "") or "")
    tls_key = tls_key or str(web_cfg.get("tls_key", "") or "")
    try:
        from . import config as _config
        httpd = serve(cfg.db_path, port=port, host_label=platform.node() or "localhost",
                      bind=bind, sample_thread=not no_sample, cfg=cfg,
                      tls_cert=tls_cert, tls_key=tls_key,
                      tier_io=(lambda: load_config().policy_tier, _config.set_policy_tier))
    except OSError as e:
        console.print(f"[red]could not start the dashboard on {bind}:{port} — {e}[/red]\n"
                      "[dim]is another wrench (or something else) using that port? "
                      "try --port[/dim]")
        raise typer.Exit(1) from None
    _serve_banner(httpd, bind, port, "🔧 wrench web", [
        "dashboard: [bold bright_blue]{url}[/bold bright_blue]",
        "[dim]sampling every 30s · press ? in the page for shortcuts · Ctrl-C to stop[/dim]"])
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]dashboard stopped[/dim]")


@app.command()
def score(json_out: bool = JSON_OPT):
    """One number for this box: a 0–100 health score with the reasons behind it.

    Deterministic arithmetic over what each subsystem last measured (capacity,
    security, vulnerabilities, compliance, backups, certificates, forecast,
    patrol). Unmeasured pillars are shown as such and left out of the score."""
    from . import posture
    cfg, store = _ctx()
    if store.last_sample("os") is None:
        sensors.sample_all(store)
    p = posture.compute(cfg, store)
    store.close()
    if json_out:
        jsonout.emit("score", p)
        raise typer.Exit(0 if p["state"] in ("ok", "unknown") else 1 if p["state"] == "attention" else 2)
    style = {"ok": "green", "attention": "yellow", "critical": "bold red"}.get(p["state"], "dim")
    head = Text()
    if p["score"] is None:
        head.append("no data yet", style="dim")
    else:
        head.append(f"{p['score']:.0f}", style=f"bold {style}")
        head.append(" / 100", style="dim")
        if p.get("provisional"):
            head.append("   provisional — too little measured for a grade yet", style="yellow")
        else:
            head.append(f"   grade {p['grade']}", style=style)
    cov = p["coverage"]
    head.append(f"\n{cov['measured']} of {cov['total']} pillars measured", style="dim")
    t = Table(border_style="bright_blue", show_edge=False, pad_edge=False)
    t.add_column("pillar", style="bold")
    t.add_column("score", justify="right")
    t.add_column("", width=12)
    t.add_column("why")
    for x in p["pillars"]:
        st = {"ok": "green", "attention": "yellow", "critical": "bold red"}.get(x["state"], "dim")
        if x["score"] is None:
            t.add_row(x["label"], Text("—", style="dim"), Text("not measured", style="dim"),
                      Text(f"{x['detail']} — run `{x['command']}`", style="dim"))
        else:
            filled = round(x["score"] / 10)
            t.add_row(x["label"], Text(f"{x['score']:.0f}", style=st),
                      Text("█" * filled + "░" * (10 - filled), style=st), x["detail"])
    console.print(Panel(head, border_style="bright_blue", title="🔧 wrench score"))
    console.print(t)
    if p["top_issues"]:
        console.print("\n[bold]next steps[/bold]")
        for i in p["top_issues"]:
            console.print(f"  • {i['label']}: {i['detail']}  [dim]→ {i['command']}[/dim]")


@app.command()
def explain(
    target: str = typer.Argument(..., help="a service name, :port, PID, or path"),
    provider: str = PROVIDER_OPT,
):
    """Explain a service, port, pid, or path: what is it, is it healthy, should it be there?"""
    cfg, store = _ctx(provider)
    a = agent_mod.Agent(cfg, store, confirm_fn=_confirm,
                        on_step=lambda k, d: console.print(f"  [dim cyan]⚙ {d}[/dim cyan]"))
    if target.startswith(":") and target[1:].isdigit():
        goal = (f"Explain what is listening on port {target[1:]} on this machine. Use "
                "net_listeners and run_diag to identify the process, then explain what it is, "
                "whether it looks healthy, and whether it should be exposed.")
    elif target.isdigit():
        goal = (f"Explain PID {target} on this machine: what process is it, what's it doing, "
                "resource usage, parent, should I worry? Use proc_top and run_diag with "
                "platform-appropriate read-only commands.")
    elif "/" in target:
        goal = (f"Explain the path {target}: what is it, how big, what writes to it? "
                "Use run_diag (ls, stat, du) and disk_tree.")
    else:
        goal = (f"Explain the service '{target}' on this machine: what it does, current state, "
                "recent log activity, resource footprint, and any problems. Use service_status "
                "and read_logs.")
    with console.status(f"[cyan]investigating {target}..."):
        res = a.run(goal, purpose="explain")
    report.render_answer(console, res["answer"],
                         f"{cfg.model} · {res['tokens']} tokens · {len(res['steps'])} tool call(s)")


PROVIDER_MENU = [
    ("ollama", "local & private — guided setup, no API key needed"),
    ("lmstudio", "local — LM Studio server"),
    ("openai", "API — OpenAI"),
    ("anthropic", "API — Anthropic Claude"),
    ("meta", "API — Meta muse models"),
    ("azure", "API — Azure OpenAI / AI Foundry"),
    ("litellm", "API — anything behind a LiteLLM proxy"),
    ("custom", "any OpenAI-compatible endpoint (vLLM, llama.cpp, TGI, your own server)"),
]


def _isatty() -> bool:
    import sys
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _local_hardware_hint() -> str | None:
    """Best-effort: describe the local hardware if it can comfortably run a
    local model. Returns None when detection fails or hardware is minimal."""
    try:
        from . import localsetup
        res = localsetup.detect_resources()
        if res.ram_gb >= 8 or (res.vram_gb or 0) >= 8 or res.apple_silicon:
            hw = f"{res.ram_gb:.0f} GB RAM"
            if res.vram_gb:
                hw += f" · {res.vram_gb:.0f} GB NVIDIA VRAM"
            if res.apple_silicon:
                hw += " · Apple Silicon"
            return hw
    except Exception:
        pass
    return None


def _choose_provider() -> str:
    """Interactive provider menu — bring your own mind. Local brains first,
    API brains after; no brand is favored. Enter = the first row (ollama),
    flagged as recommended when the hardware can carry a local model."""
    hw = _local_hardware_hint()
    t = Table(title="🔧 bring your own mind — choose a model provider",
              border_style="bright_blue", show_header=False, pad_edge=True)
    t.add_column(justify="right", style="bold cyan")
    t.add_column(style="bold")
    t.add_column(style="dim")
    for i, (name, blurb) in enumerate(PROVIDER_MENU, 1):
        tag = " (recommended for this box)" if name == "ollama" and hw else ""
        t.add_row(str(i), name + tag, blurb)
    console.print(t)
    if hw:
        console.print(f"[dim]detected {hw} — a local model will run well here; "
                      "nothing would ever leave the box.[/dim]")
    raw = typer.prompt(f"provider [1-{len(PROVIDER_MENU)} or name]",
                       default="1", show_default=False).strip().lower()
    names = [n for n, _ in PROVIDER_MENU]
    if raw.isdigit() and 1 <= int(raw) <= len(names):
        return names[int(raw) - 1]
    if raw in names:
        return raw
    console.print(f"[yellow]unknown choice {raw!r} — using ollama (local)[/yellow]")
    return "ollama"


def _ollama_guided_setup(interactive: bool, assume_yes: bool,
                         model_override: str | None) -> str:
    """Detect resources, recommend a tool-calling model, ensure ollama + model
    exist (with consent), and return the model tag to write into config."""
    from . import localsetup

    res = localsetup.detect_resources()
    rec_tag, rec_gb, reason = localsetup.recommend(res)
    hw = f"{res.ram_gb:.0f} GB RAM"
    if res.vram_gb:
        hw += f" · {res.vram_gb:.0f} GB NVIDIA VRAM"
    if res.apple_silicon:
        hw += " · Apple Silicon unified memory"
    console.print(Panel(
        f"detected: [bold]{hw}[/bold]\n"
        f"recommended model: [bold green]{rec_tag}[/bold green] (~{rec_gb:g} GB download)\n"
        f"[dim]{reason}[/dim]\n\n"
        "[dim]all suggestions are tool-calling-capable — wrench needs that.\n"
        "other sizes: " + ", ".join(t for t, _, _ in localsetup.TIERS) + "[/dim]",
        border_style="cyan", title="🧠 local model recommendation"))

    model = model_override or rec_tag
    if interactive and not assume_yes and not model_override:
        model = typer.prompt("model to use", default=rec_tag).strip() or rec_tag

    # 1. binary
    if not localsetup.ollama_binary():
        cmds = localsetup.install_commands()
        console.print(Panel(
            "[yellow]ollama is not installed.[/yellow]\n"
            "I can run the official installer:\n  " + "\n  ".join(cmds),
            border_style="yellow", title="ollama missing"))
        do_install = assume_yes or (interactive and typer.confirm("install ollama now?",
                                                                  default=True))
        if not do_install:
            console.print("[yellow]skipped — install ollama yourself, then re-run "
                          "`wrench init -p ollama --force`[/yellow]")
            return model
        with console.status("[cyan]installing ollama..."):
            ok = localsetup.run_install()
        if not ok or not localsetup.ollama_binary():
            console.print("[red]ollama install did not complete — finish it manually "
                          "(https://ollama.com/download) and re-run wrench init[/red]")
            return model
        console.print("[green]ollama installed[/green]")

    # 2. server
    if not localsetup.server_alive():
        console.print("[yellow]ollama server not responding at 127.0.0.1:11434 — "
                      "start it with `ollama serve` (or your service manager) "
                      "and re-run `wrench doctor`[/yellow]")
        return model

    # 3. model present?
    have = localsetup.installed_models()
    if not any(m == model or m.startswith(model + ":") or model == m.split(":")[0]
               for m in have):
        console.print(f"[yellow]{model} is not pulled yet "
                      f"(download ≈ {rec_gb:g} GB for {rec_tag}).[/yellow]")
        do_pull = assume_yes or (interactive and typer.confirm(f"pull {model} now?",
                                                               default=True))
        if do_pull:
            console.print(f"[cyan]pulling {model}... (this can take a while)[/cyan]")
            if not localsetup.pull_model(model):
                console.print(f"[red]pull failed — run `ollama pull {model}` manually[/red]")
                return model
        else:
            console.print(f"[yellow]skipped — run `ollama pull {model}` before first use[/yellow]")
            return model
    return model


def _openai_local_guided_setup(provider: str, interactive: bool,
                               model: str | None) -> tuple[str, str | None, bool]:
    """Guided setup for OpenAI-compatible local servers (LM Studio, LiteLLM).

    Probes the server, lists its models, lets the user pick. Returns
    (base_url, model, complete). complete=False means no model was verified —
    the caller must NOT print the success greeting."""
    from . import localsetup
    from .config import PROVIDER_DEFAULTS
    label = "LM Studio" if provider == "lmstudio" else "LiteLLM"
    default_base = PROVIDER_DEFAULTS[provider]["base_url"]
    base_url = default_base
    if interactive:
        base_url = typer.prompt(f"{label} server URL",
                                default=default_base).strip().rstrip("/")
    if not localsetup.openai_server_alive(base_url):
        hint = ("open LM Studio → Developer tab → [bold]Start Server[/bold] "
                "(default port 1234)"
                if provider == "lmstudio"
                else "start your LiteLLM proxy (e.g. `litellm --port 4000`)")
        console.print(Panel(
            f"[yellow]{label} isn't answering at {base_url}.[/yellow]\n"
            f"{hint}, then re-run:  [bold]wrench init -p {provider} --force[/bold]",
            border_style="yellow", title=f"⚠ {label} not running"))
        return base_url, model, False
    models = localsetup.openai_models(base_url)
    if not models:
        detail = ("the server is up but no model is loaded — load one in "
                  "LM Studio (or `lms load <model>`)"
                  if provider == "lmstudio"
                  else "the proxy is up but lists no models — check its config")
        console.print(Panel(
            f"[yellow]{detail}, then re-run:  "
            f"[bold]wrench init -p {provider} --force[/bold][/yellow]",
            border_style="yellow", title=f"⚠ {label}: no models available"))
        return base_url, model, False
    if model and model not in models:
        console.print(f"[yellow]{model!r} isn't served — pick from what "
                      f"{label} offers:[/yellow]")
        model = None
    if not model:
        if interactive and len(models) > 1:
            t = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
            for i, mid in enumerate(models, 1):
                t.add_row(f"[bold]{i}[/bold]", mid)
            console.print(t)
            idx = typer.prompt(f"model [1-{len(models)}]", default="1").strip()
            try:
                model = models[max(1, min(len(models), int(idx))) - 1]
            except ValueError:
                model = next((m for m in models if m == idx), models[0])
        else:
            model = models[0]
    console.print(f"[green]✔ {label} answering at {base_url}[/green] — "
                  f"model: [bold]{model}[/bold]")
    return base_url, model, True


def _custom_guided_setup(interactive: bool,
                         model: str | None) -> tuple[str | None, str | None, bool]:
    """Guided setup for the `custom` provider: any OpenAI-compatible endpoint
    (vLLM, llama.cpp, TGI, a FastAPI shim, your own server).

    There is NO default base_url — the user must give one. When reachable, we
    probe GET <base>/models and let them pick a live model, same as the
    LM Studio / LiteLLM path. Returns (base_url, model, complete). complete=False
    means the caller must NOT print the success greeting. In non-TTY mode with
    no URL supplied, returns (None, model, False) — never hangs."""
    from . import localsetup
    base_url = (os.environ.get("WRENCH_BASE_URL") or "").strip().rstrip("/")
    if interactive and not base_url:
        console.print(Panel(
            "Point wrench at any server that speaks the OpenAI chat-completions\n"
            "API: a local [bold]vLLM[/bold] / [bold]llama.cpp[/bold] / [bold]TGI[/bold] server, a\n"
            "FastAPI shim, or your own endpoint. Example: http://127.0.0.1:8000/v1\n"
            "[dim]An API key is optional — set CUSTOM_API_KEY only if your server needs one.[/dim]",
            border_style="cyan", title="🔌 custom — OpenAI-compatible endpoint"))
        base_url = typer.prompt("base URL (e.g. http://127.0.0.1:8000/v1)").strip().rstrip("/")
    if not base_url:
        console.print(Panel(
            "[yellow]no base URL given — the custom provider needs one.[/yellow]\n"
            "Re-run with a URL:  [bold]WRENCH_BASE_URL=http://host:port/v1 "
            "wrench init -p custom --force[/bold]\n"
            "[dim]or run `wrench init -p custom --force` in a terminal for the prompt.[/dim]",
            border_style="yellow", title="⚠ custom: no endpoint"))
        return None, model, False
    if not localsetup.openai_server_alive(base_url):
        console.print(Panel(
            f"[yellow]nothing answering at {base_url}.[/yellow]\n"
            "Start your server (vLLM / llama.cpp / TGI / …) so it serves\n"
            f"GET {base_url}/models, then re-run:  "
            f"[bold]wrench init -p custom --force[/bold]",
            border_style="yellow", title="⚠ custom: endpoint unreachable"))
        return base_url, model, False
    models = localsetup.openai_models(base_url)
    if not models:
        console.print(Panel(
            f"[yellow]the server at {base_url} is up but lists no models.[/yellow]\n"
            "Load/serve a model, then re-run:  "
            "[bold]wrench init -p custom --force[/bold]",
            border_style="yellow", title="⚠ custom: no models available"))
        return base_url, model, False
    if model and model not in models:
        console.print(f"[yellow]{model!r} isn't served — pick from what the "
                      "endpoint offers:[/yellow]")
        model = None
    if not model:
        if interactive and len(models) > 1:
            t = Table(show_header=False, box=box.ROUNDED, border_style="cyan")
            for i, mid in enumerate(models, 1):
                t.add_row(f"[bold]{i}[/bold]", mid)
            console.print(t)
            idx = typer.prompt(f"model [1-{len(models)}]", default="1").strip()
            try:
                model = models[max(1, min(len(models), int(idx))) - 1]
            except ValueError:
                model = next((m for m in models if m == idx), models[0])
        else:
            model = models[0]
    console.print(f"[green]✔ custom endpoint answering at {base_url}[/green] — "
                  f"model: [bold]{model}[/bold]")
    return base_url, model, True


def _azure_guided_setup(interactive: bool,
                        endpoint: str | None,
                        api_version: str | None,
                        api_key: str | None,
                        model: str | None) -> tuple[str, str, str | None, str | None]:
    """Collect the Azure specifics (endpoint, api-version, optional key).
    Returns (endpoint, api_version, api_key, model). Never echoes the key."""
    import os
    console.print(Panel(
        "Two endpoint styles are accepted:\n"
        "  [bold]Azure OpenAI[/bold]        https://<resource>.openai.azure.com\n"
        "  [bold]AI Foundry serverless[/bold]  https://<name>.<region>.models.ai.azure.com\n"
        "[dim]The model name below is your DEPLOYMENT name on Azure OpenAI.\n"
        "Auth: the native api-key header is tried first; Bearer on 401 (auto).[/dim]",
        border_style="cyan", title="☁ Azure OpenAI / AI Foundry"))
    if not endpoint:
        env_ep = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        if interactive:
            endpoint = typer.prompt("endpoint URL", default=env_ep or None).strip()
        else:
            endpoint = env_ep
    if not endpoint:
        console.print("[red]azure needs an endpoint — pass --azure-endpoint or set "
                      "AZURE_OPENAI_ENDPOINT[/red]")
        raise typer.Exit(1)
    if interactive and not model:
        model = typer.prompt("deployment / model name", default="gpt-4o-mini").strip()
    if not api_version:
        api_version = (typer.prompt("api-version", default="2024-10-21").strip()
                       if interactive else "2024-10-21")
    if not api_key and interactive and not os.environ.get("AZURE_OPENAI_API_KEY"):
        entered = typer.prompt("API key (enter to skip — use AZURE_OPENAI_API_KEY env)",
                               default="", show_default=False, hide_input=True).strip()
        api_key = entered or None
    return endpoint.rstrip("/"), api_version, api_key, model


def _read_new_password() -> str | None:
    """Ask twice for a new dashboard password. None when the operator gives up."""
    from . import webauth
    for _ in range(3):
        pw = typer.prompt("new dashboard password", hide_input=True, default="",
                          show_default=False)
        problem = webauth.password_problem(pw)
        if problem:
            console.print(f"[yellow]{problem}[/yellow]")
            continue
        if typer.prompt("again, to confirm", hide_input=True, default="",
                        show_default=False) != pw:
            console.print("[yellow]those did not match[/yellow]")
            continue
        return pw
    return None


def _store_web_password(cfg, password: str, source: str) -> bool:
    """Hash and store the dashboard password, and seal the change in the audit
    chain. The password itself is never written, logged or printed."""
    from . import audit, webauth
    changed = webauth.password_is_set(cfg.data_dir)
    try:
        webauth.set_password(cfg.data_dir, password)
    except ValueError as e:
        console.print(f"[red]password not set — {e}[/red]")
        return False
    except OSError as e:
        console.print(f"[red]password not set — could not write to {cfg.data_dir}: {e}[/red]")
        return False
    audit.append(cfg.data_dir, "web.password.changed" if changed else "web.password.set",
                 {"source": source}, actor="cli")
    return True


def _init_web_password(cfg, interactive: bool) -> str:
    """The dashboard-password step of `wrench init`. Returns one line for the
    closing panel."""
    from . import webauth
    if webauth.password_is_set(cfg.data_dir):
        return "password set ✔ (change it: wrench password)"
    env_pw = os.environ.get("WRENCH_WEB_PASSWORD", "")
    if env_pw:
        if _store_web_password(cfg, env_pw, "init-env"):
            console.print("[green]✔ dashboard password set[/green] from WRENCH_WEB_PASSWORD "
                          "[dim]— only a salted hash is stored; unset the variable now[/dim]")
            return "password set ✔ (change it: wrench password)"
        return "[yellow]no password — WRENCH_WEB_PASSWORD was not usable[/yellow]"
    if interactive:
        try:
            pw = _read_new_password() if typer.confirm(
                "Put a password on the web dashboard? (recommended if anyone else can "
                "reach this machine)", default=True) else None
        except (typer.Abort, EOFError):
            pw = None          # Ctrl-C here skips the question, it does not undo the setup
            console.print()
        if pw and _store_web_password(cfg, pw, "init"):
            console.print("[green]✔ dashboard password set[/green] "
                          "[dim]— only a salted hash is stored[/dim]")
            return "password set ✔ (change it: wrench password)"
    return "no password — open on this machine only (set one: wrench password)"


@app.command("password")
def password_cmd(
    clear: bool = typer.Option(False, "--clear", help="remove the password"),
    status: bool = typer.Option(False, "--status", help="only say whether one is set"),
    stdin: bool = typer.Option(False, "--stdin",
                               help="read the new password from standard input (for scripts)"),
    json_out: bool = JSON_OPT,
):
    """Set, change or remove the password on the web dashboard.

    \b
    wrench password             set one, or change it (asks twice, never echoes)
    wrench password --status    is one set?
    wrench password --clear     remove it
    wrench password --stdin     read it from a pipe, for config management

    With a password set, every visit to the dashboard or the fleet console
    signs in — on this machine too. Changing or removing it takes effect on a
    running server straight away and signs out every browser. Only a salted
    scrypt hash is kept, owner-only, in the data dir.

    Forgot it? Just run this again: being able to run wrench as its owner on
    this machine is the proof of who you are."""
    from . import audit, webauth
    cfg = load_config()
    was_set = webauth.password_is_set(cfg.data_dir)

    def done(state: str, changed: bool) -> None:
        if json_out:
            jsonout.emit("password", {"set": state == "set", "changed": changed})

    if status:
        if json_out:
            done("set" if was_set else "none", False)
        elif was_set:
            console.print("[green]✔[/green] the dashboard has a password "
                          f"[dim]({webauth.password_path(cfg.data_dir)})[/dim]")
        else:
            console.print("the dashboard has [bold]no password[/bold] "
                          "[dim]— set one: wrench password[/dim]")
        raise typer.Exit(0 if was_set else 1)

    if clear:
        if stdin:
            console.print("[red]--clear and --stdin do not go together[/red]")
            raise typer.Exit(2)
        if webauth.clear_password(cfg.data_dir):
            audit.append(cfg.data_dir, "web.password.cleared", {}, actor="cli")
        done("none", was_set)
        if not json_out:
            console.print("[green]✔[/green] dashboard password removed"
                          if was_set else "there was no dashboard password")
            console.print(Text("on this machine the dashboard is open again; on a network "
                               "address it needs an access token ([web] auth_token).",
                               style="dim"))
        return

    if stdin:
        pw = sys.stdin.readline().rstrip("\r\n")
    elif _isatty():
        pw = _read_new_password()
        if pw is None:
            console.print("[red]password not changed[/red]")
            raise typer.Exit(1)
    else:
        console.print("[red]no terminal to ask in[/red] — pipe the password in: "
                      "[bold]wrench password --stdin[/bold]")
        raise typer.Exit(2)
    if not _store_web_password(cfg, pw, "stdin" if stdin else "cli"):
        raise typer.Exit(1)
    done("set", True)
    if not json_out:
        console.print(f"[green]✔[/green] dashboard password {'changed' if was_set else 'set'}")
        console.print(Text("a running dashboard picks it up now"
                           + (" and every browser is signed out" if was_set else "")
                           + " · sign in at the address `wrench web` prints", style="dim"))


@app.command()
def init(
    provider: str = typer.Option(None, "--provider", "-p",
                                 help="ollama|lmstudio|openai|anthropic|meta|azure|litellm|custom "
                                      "(omit for interactive menu)"),
    model: str = typer.Option(None, "--model", "-m", help="model tag override"),
    azure_endpoint: str = typer.Option(None, "--azure-endpoint",
                                       help="Azure endpoint URL (or AZURE_OPENAI_ENDPOINT)"),
    azure_deployment: str = typer.Option(None, "--azure-deployment",
                                         help="Azure deployment name (alias for --model)"),
    azure_api_version: str = typer.Option(None, "--azure-api-version",
                                          help="Azure api-version (default 2024-10-21)"),
    api_key: str = typer.Option(None, "--api-key",
                                help="write the API key into config.toml (chmod 600); "
                                     "prefer the provider's env var"),
    yes: bool = typer.Option(False, "--yes", "-y",
                             help="non-interactive: accept defaults/recommendations "
                                  "(consents to ollama install + model pull)"),
    force: bool = typer.Option(False, "--force", help="overwrite existing config"),
):
    """Set up wrench: pick a provider (interactive menu), write config, record baselines.

    In a terminal it also offers to put a password on the web dashboard. For
    an unattended install, export WRENCH_WEB_PASSWORD before running it."""
    interactive = _isatty() and not yes
    model = model or azure_deployment
    if provider is None:
        if interactive:
            provider = _choose_provider()
        else:
            provider = "meta"
            console.print("[dim]no TTY — using the hosted 'meta' provider as a functional "
                          "fallback. Any brain works: re-run `wrench init --force` in a "
                          "terminal for the menu, or script it with `wrench init -p "
                          "<provider>` (e.g. `-p ollama` for fully local).[/dim]")
    provider = provider.lower()
    from .config import PROVIDER_DEFAULTS
    if provider not in PROVIDER_DEFAULTS:
        console.print(f"[red]unknown provider {provider!r} — choose from: "
                      f"{', '.join(PROVIDER_DEFAULTS)}[/red]")
        raise typer.Exit(1)

    setup_complete = True
    incomplete_reason = ""
    if CONFIG_PATH.exists() and not force:
        console.print(f"[yellow]config already exists:[/yellow] {CONFIG_PATH} (use --force)")
    else:
        local_base_url = None
        if provider == "ollama":
            model = _ollama_guided_setup(interactive, yes, model)
        elif provider in ("lmstudio", "litellm"):
            local_base_url, model, setup_complete = _openai_local_guided_setup(
                provider, interactive, model)
            if not setup_complete:
                incomplete_reason = ("no model verified — start the server, "
                                     f"then re-run `wrench init -p {provider} --force`")
        elif provider == "custom":
            local_base_url, model, setup_complete = _custom_guided_setup(
                interactive, model)
            if not setup_complete:
                incomplete_reason = (
                    "no live OpenAI-compatible endpoint verified — give a base URL "
                    "(WRENCH_BASE_URL=http://host:port/v1) and make sure it serves "
                    "GET /models, then re-run `wrench init -p custom --force`")
        if provider == "azure":
            azure_endpoint, azure_api_version, api_key, model = _azure_guided_setup(
                interactive, azure_endpoint, azure_api_version, api_key, model)
            p = write_default_config(provider, model=model,
                                     azure_endpoint=azure_endpoint,
                                     azure_api_version=azure_api_version,
                                     api_key=api_key)
        else:
            p = write_default_config(provider, model=model, base_url=local_base_url)
        console.print(f"[green]wrote[/green] {p}")
    cfg, store = _ctx()
    with console.status("[cyan]recording first sensor sample + drift baseline..."):
        sensors.sample_all(store)
        driftscan.scan(store)

    web_note = _init_web_password(cfg, interactive)

    if not setup_complete:
        console.print(Panel(
            f"[yellow]⚠ setup is NOT complete:[/yellow] {incomplete_reason}\n"
            f"[dim]config written to {CONFIG_PATH} — your provider choice is saved;\n"
            "baseline sensors + drift snapshot were still recorded.[/dim]",
            border_style="yellow", title="⚠ wrench init: unfinished"))
        return

    smoke_note = ""
    from . import localsetup
    if cfg.provider == "ollama":
        if localsetup.server_alive():
            with console.status(f"[cyan]smoke test: one tool-calling round-trip on {cfg.model}..."):
                ok, detail = localsetup.smoke_test(cfg, store)
            if ok:
                console.print(f"[green]✔ local smoke test passed[/green] — {detail}")
                smoke_note = "\nlocal smoke test: ✔ tool-calling verified"
            else:
                console.print(f"[red]✖ local smoke test failed[/red] — {detail}")
                smoke_note = "\nlocal smoke test: ✖ FAILED — fix before relying on patrols"
        else:
            smoke_note = "\nlocal smoke test: skipped (ollama server not running)"
    elif cfg.provider in ("lmstudio", "litellm", "custom") and cfg.base_url \
            and localsetup.openai_server_alive(cfg.base_url):
        with console.status(f"[cyan]smoke test: one tool-calling round-trip on {cfg.model}..."):
            ok, detail = localsetup.smoke_test(cfg, store)
        if ok:
            console.print(f"[green]✔ local smoke test passed[/green] — {detail}")
            smoke_note = "\nlocal smoke test: ✔ tool-calling verified"
        else:
            console.print(f"[red]✖ local smoke test failed[/red] — {detail}")
            smoke_note = "\nlocal smoke test: ✖ FAILED — fix before relying on patrols"
    console.print(Panel(
        "[bold]I'm wrench — your right hand on this machine. I live here now.[/bold]\n"
        "I read the logs so you don't have to, I remember what changes on this box,\n"
        "and with your permission I fix problems before you ever see them.\n"
        "I just took my first look around (sensor baseline + drift snapshot recorded).\n\n"
        f"provider: [bold]{cfg.provider}[/bold] · model: [bold]{cfg.model}[/bold] · "
        f"policy: [bold]{cfg.policy_tier}[/bold]\n"
        f"data: {cfg.db_path}{smoke_note}\n"
        f"dashboard: {web_note}\n"
        + ("api key: none needed — it's your hardware\n"
           if cfg.provider in ("ollama", "lmstudio", "litellm")
           else "api key: configured ✔\n" if cfg.api_key
           else "api key: none (optional for a custom endpoint — set "
                "CUSTOM_API_KEY if yours needs one)\n" if cfg.provider == "custom"
           else f"api key: [yellow]missing[/yellow] — "
                f"export {_key_env(cfg.provider)}=... (or set api_key_file in config)\n")
        +
        "\nput me to work — every line below is a command you can type:\n"
        "  wrench doctor    — verify everything\n"
        "  wrench patrol    — I'll sweep the box and report\n"
        "  wrench fixxer    — I'll find what I can fix, and ask\n"
        "  wrench web       — live dashboard\n\n"
        + ("[yellow]⚠ setup finished but the smoke test failed — run `wrench doctor` "
           "and check that your model supports tool calling[/yellow]"
           if "FAILED" in smoke_note
           else "[green]✅ setup complete — start with: wrench doctor[/green]"),
        border_style="green", title="🔧 wrench initialized"))


RISK_STYLE = {"safe": "green", "moderate": "yellow", "risky": "red"}
SEV_STYLE = {"critical": "bold red", "high": "red", "moderate": "yellow",
             "medium": "yellow", "low": "green"}


def _sev_text(sev: str) -> Text:
    s = (sev or "?").strip()
    return Text(s or "?", style=SEV_STYLE.get(s.lower().split(":")[0], "white"))


@app.command()
def cve(
    refresh: bool = typer.Option(False, "--refresh", help="force a fresh scan (ignore cache)"),
    no_llm: bool = typer.Option(False, "--no-llm", help="skip the model briefing"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
):
    """Check installed packages against OSV.dev and the OS/runtimes against endoflife.date."""
    from . import webintel

    cfg, store = _ctx(provider, model)
    with console.status("[cyan]asking OSV.dev + endoflife.date about this box..."):
        res = webintel.scan(cfg, store, force=refresh,
                            on_step=lambda k, d: None)
    vulns = res.get("vulns", [])
    age_min = (time.time() - res.get("ts", time.time())) / 60
    src_note = (f"checked {res.get('packages_checked', 0)} packages "
                f"(pip + npm + distro watchlist) · "
                + (f"cached {age_min:.0f}m ago" if age_min > 2 else "fresh scan")
                + (" · [red]OFFLINE — cached data[/red]" if not res.get("online", True) else ""))

    if vulns:
        t = Table(title="\U0001f6a8 known vulnerabilities (OSV.dev)", border_style="red")
        t.add_column("package", style="bold")
        t.add_column("installed")
        t.add_column("src", style="dim")
        t.add_column("CVE / id")
        t.add_column("severity", justify="center")
        t.add_column("fixed in", style="green")
        t.add_column("what", max_width=46, style="dim")
        for v in vulns[:40]:
            ids = ", ".join(v.get("aliases") or [v.get("vuln_id", "?")])
            t.add_row(v["package"], v["version"], v["source"], ids,
                      _sev_text(v.get("severity", "")), v.get("fixed", "") or "—",
                      v.get("summary", ""))
        console.print(t)
    else:
        console.print(Panel("[green]no known vulnerabilities[/green] in the packages I checked",
                            border_style="green", title="\U0001f6e1 OSV.dev"))

    eol = res.get("eol", [])
    if eol:
        t = Table(title="\u23f3 end-of-life status (endoflife.date)", border_style="bright_blue")
        t.add_column("product", style="bold")
        t.add_column("cycle")
        t.add_column("status")
        for e in eol:
            style = "red bold" if e["is_eol"] else "green"
            t.add_row(e["product"], e["cycle"], Text(e["label"].split(": ", 1)[-1], style=style))
        console.print(t)
    console.print(f"[dim]{src_note}[/dim]")
    for err in res.get("errors", []):
        console.print(f"[yellow]⚠ {err}[/yellow]")

    if not no_llm and (vulns or any(e["is_eol"] for e in eol)) \
            and (cfg.api_key or cfg.provider in ("ollama", "lmstudio")):
        lines = [f"- {v['package']} {v['version']} ({v['source']}): "
                 + ",".join(v.get('aliases') or [v['vuln_id']])
                 + (f" fixed in {v['fixed']}" if v.get("fixed") else " (no fixed version listed)")
                 + f" — {v.get('summary', '')[:150]}" for v in vulns[:20]]
        lines += [f"- EOL: {e['label']}" for e in eol if e["is_eol"]]
        client = LLMClient(cfg, store)
        try:
            with console.status("[cyan]thinking about what this means for this box..."):
                text = client.chat(
                    [{"role": "system",
                      "content": "You are wrench, a sysadmin agent speaking in the first person "
                                 "about YOUR machine. You are shown known vulnerabilities in "
                                 "installed packages and any end-of-life products. In 4-8 "
                                 "sentences: triage honestly (which matter on a typical box, "
                                 "which are noise), name the most urgent action, and mention "
                                 "that `wrench fixxer` can apply targeted security updates if "
                                 "fixed builds exist. No markdown headers, no filler."},
                     {"role": "user", "content": "\n".join(lines)}],
                    purpose="cve")
            report.render_answer(console, text, f"{cfg.model} · threat briefing")
        except Exception as e:  # noqa: BLE001
            console.print(f"[dim]briefing unavailable ({e}) — the tables stand on their own[/dim]")
    raise typer.Exit(1 if vulns else 0)


def _render_findings(findings) -> Table:
    t = Table(title="\U0001f527 correctable issues I found", border_style="bright_blue")
    t.add_column("#", justify="right", style="bold cyan")
    t.add_column("risk", justify="center")
    t.add_column("fix")
    t.add_column("evidence", max_width=58)
    t.add_column("sudo", justify="center", style="dim")
    for i, f in enumerate(findings, 1):
        t.add_row(str(i), Text(f.risk, style=RISK_STYLE.get(f.risk, "white")),
                  f.title, f.detail, "\u2713" if f.needs_sudo else "")
    return t


def _fixxer_llm_brief(cfg, store, findings, anomalies) -> None:
    """One model call: wrench explains, in first person, what it found and what
    it recommends. The model only ever talks ABOUT the catalog \u2014 selection and
    execution stay in code."""
    if not (cfg.api_key or cfg.provider in ("ollama", "lmstudio")):
        return
    lines = [f"{i}. [{f.risk}] {f.title} \u2014 {f.detail} (command: "
             + " && ".join(" ".join(c) for c in f.commands) + ")"
             for i, f in enumerate(findings, 1)]
    if anomalies:
        lines.append("Recent sensor anomalies (context only, not directly fixable): "
                     + "; ".join(f"{a['metric']}={a['value']} (z={a['zscore']})"
                                 for a in anomalies[:6]))
    client = LLMClient(cfg, store)
    try:
        with console.status("[cyan]thinking about what I found..."):
            text = client.chat(
                [{"role": "system",
                  "content": "You are wrench, a sysadmin agent speaking in the first person "
                             "about YOUR machine. You are shown a numbered list of fixes you "
                             "can apply from your vetted catalog. Briefly (4-8 sentences) "
                             "explain what you found, which numbers you'd apply first and "
                             "why, and anything the human should know before saying yes "
                             "(e.g. what 'moderate' risk means here). Refer to fixes by "
                             "their list numbers. No markdown headers, no filler."},
                 {"role": "user", "content": "\n".join(lines)}],
                purpose="fixxer")
        report.render_answer(console, text, f"{cfg.model} \u00b7 fixxer briefing")
    except Exception as e:  # noqa: BLE001 \u2014 the briefing is optional sugar
        console.print(f"[dim]briefing unavailable ({e}) \u2014 the findings above stand on their own[/dim]")


def _consent_ceremony(cfg) -> bool:
    from . import fixxer as fx
    console.print(Panel(
        "[bold]You are about to let me fix things WITHOUT asking.[/bold]\n\n"
        "What auto mode may do, by risk tier:\n"
        "  [green]safe[/green]     \u2014 refresh package metadata, vacuum journald logs,\n"
        "             clear package caches, reset stale failed-unit markers\n"
        "  [yellow]moderate[/yellow] \u2014 apply pending package updates, remove orphaned\n"
        "             packages, delete stale /tmp files, restart failed services\n"
        "  [red]risky[/red]    \u2014 (reserved \u2014 nothing in the catalog today)\n\n"
        "The rules I hold myself to:\n"
        "  \u2022 I only run hand-written catalog commands \u2014 the model never invents shell.\n"
        "  \u2022 Default auto scope is [green]safe[/green] only. Widening to moderate requires BOTH\n"
        "    your consent here AND auto_tiers in config.toml \u2014 two locks.\n"
        "  \u2022 Every action is appended to the audit log with a rollback hint:\n"
        f"    {fx.audit_path(cfg)}\n"
        "  \u2022 Revoke any time: [bold]wrench fixxer --revoke-auto[/bold]",
        border_style="red", title="\u26a0 consent \u2014 autonomous fixing"))
    if not typer.confirm("do you consent to autonomous fixing on this machine?", default=False):
        console.print("[dim]no consent \u2014 auto mode stays off. I'll keep asking first.[/dim]")
        return False
    raw = typer.prompt("which tiers? [safe / safe,moderate]", default="safe").strip().lower()
    tiers = [t.strip() for t in raw.split(",") if t.strip() in fx.RISK_TIERS]
    if not tiers:
        tiers = ["safe"]
    p = fx.write_consent(cfg, tiers)
    from . import audit as _amod
    _amod.log_event(cfg, "consent.grant", {"subsystem": "fixxer", "tiers": tiers})
    console.print(f"[green]consent recorded[/green] for tiers: [bold]{', '.join(tiers)}[/bold]\n"
                  f"[dim]{p}[/dim]")
    if "moderate" in tiers:
        console.print("[yellow]note:[/yellow] moderate also needs "
                      "[bold]auto_tiers = [\"safe\", \"moderate\"][/bold] under [fixxer] "
                      f"in {CONFIG_PATH} before auto mode will touch it.")
    return True


@app.command()
def fixxer(
    auto: bool = typer.Option(False, "--auto", help="apply consented-tier fixes WITHOUT asking "
                                                    "(requires the one-time consent ceremony)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="show what --auto would do, touch nothing"),
    setup_auto: bool = typer.Option(False, "--setup-auto", help="run the auto-mode consent ceremony"),
    revoke_auto: bool = typer.Option(False, "--revoke-auto", help="revoke auto-mode consent"),
    no_llm: bool = typer.Option(False, "--no-llm", help="skip the model briefing (findings only)"),
    audit: bool = typer.Option(False, "--audit", help="show the last 20 audit-log entries and exit"),
    override_window: bool = typer.Option(False, "--override-window",
                                         help="execute outside the maintenance window "
                                              "(requires recorded auto consent; audit-logged)"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
):
    """Find what I can fix \u2014 updates, bloat, failed services \u2014 and fix it with your OK."""
    from . import fixxer as fx

    cfg, store = _ctx(provider, model)

    if revoke_auto:
        if fx.revoke_consent(cfg):
            from . import audit as _amod
            _amod.log_event(cfg, "consent.revoke", {"subsystem": "fixxer"})
            console.print("[green]auto-mode consent revoked.[/green] I'm back to always asking first.")
        else:
            console.print("[dim]no consent was recorded \u2014 nothing to revoke[/dim]")
        return
    if setup_auto:
        _consent_ceremony(cfg)
        return
    if audit:
        rows = fx.audit_tail(cfg, 20)
        if not rows:
            console.print(f"[dim]audit log is empty ({fx.audit_path(cfg)})[/dim]")
            return
        t = Table(title="\U0001f527 fixxer audit log (last 20)", border_style="bright_blue")
        t.add_column("when")
        t.add_column("mode")
        t.add_column("action")
        t.add_column("risk")
        t.add_column("ok", justify="center")
        t.add_column("verified", justify="center")
        for r in rows:
            t.add_row(r.get("iso", "")[:16], r.get("mode", ""), r.get("action", ""),
                      r.get("risk", ""), "\u2713" if r.get("ok") else "\u2717",
                      "\u2713" if r.get("verified") else "\u2717")
        console.print(t)
        console.print(f"[dim]{fx.audit_path(cfg)}[/dim]")
        return

    console.print("[dim]I'm going through the box looking for things I can fix myself...[/dim]")
    with console.status("[cyan]scanning (package state, journals, caches, services, /tmp)..."):
        findings, ctx = fx.scan(cfg)
        anomalies = store.recent_anomalies(3600 * 6)

    if not findings:
        console.print(Panel(
            "[green]nothing to fix.[/green] I checked pending updates, orphaned packages, "
            "journal size, package caches, failed services, and stale /tmp files \u2014 "
            "this box is clean. I'll keep patrolling.",
            border_style="green", title="\U0001f527 wrench fixxer"))
        return

    console.print(_render_findings(findings))

    # EOL advisories from cached web intel — flagged, risk-tiered, NEVER auto-fixed
    try:
        from . import webintel
        advisories = webintel.eol_advisories(
            store.cache_get("webintel_scan", float("inf")) or {})
        if advisories:
            console.print(Panel(
                "\n".join(f"[red]⚠ {a}[/red]" for a in advisories)
                + "\n[dim]EOL products need a human decision (major upgrade/migration) — "
                  "I flag them, I never auto-fix them.[/dim]",
                border_style="red", title="⏳ end-of-life advisories"))
    except Exception:  # noqa: BLE001
        pass

    if not no_llm:
        _fixxer_llm_brief(cfg, store, findings, anomalies)

    # ---- dry-run: what WOULD auto do ----
    if dry_run:
        scope = fx.auto_scope(cfg, findings)
        consent = fx.load_consent(cfg)
        tiers = fx.effective_auto_tiers(cfg)
        consent_str = ("\u2713 " + ", ".join(consent["tiers"])) if consent \
            else "\u2717 none \u2014 run wrench fixxer --setup-auto"
        tiers_str = ", ".join(tiers) if tiers else "(none)"
        lines = [f"consent: {consent_str}",
                 f"effective auto tiers (consent \u2229 config): {tiers_str}", ""]
        if scope:
            lines.append("auto mode would apply:")
            lines += [f"  \u2022 ({f.risk}) {f.title} \u2014 " + " && ".join(" ".join(c) for c in f.commands)
                      for f in scope]
        else:
            lines.append("auto mode would apply: nothing (no findings inside the consented tiers)")
        skipped = [f for f in findings if f not in scope]
        if skipped:
            lines.append("left for you (outside auto scope): "
                         + ", ".join(f"{f.title} ({f.risk})" for f in skipped))
        console.print(Panel("\n".join(lines), border_style="cyan", title="\U0001f527 fixxer --dry-run"))
        return

    if not auto:
        _approval_gate(cfg, store, "fixxer apply",
                       f"{len(findings)} finding(s) pending")

    # ---- auto: consented tiers, no questions ----
    if auto:
        consent = fx.load_consent(cfg)
        if not consent:
            console.print(Panel(
                "[red]auto mode is OFF \u2014 no consent recorded.[/red]\n"
                "I don't touch this machine unattended until you've explicitly told me I may.\n"
                "Run [bold]wrench fixxer --setup-auto[/bold] (interactive, one time).",
                border_style="red", title="\u26a0 consent required"))
            raise typer.Exit(2)
        chosen = fx.auto_scope(cfg, findings)
        if not chosen:
            console.print("[dim]nothing inside my consented auto tiers "
                          f"({', '.join(fx.effective_auto_tiers(cfg)) or 'none'}) \u2014 "
                          "the rest waits for you. See wrench fixxer --dry-run.[/dim]")
            return
    # ---- interactive: the human picks ----
    else:
        raw = typer.prompt("apply which? [a]ll / [n]one / numbers e.g. 1,3", default="n").strip().lower()
        if raw in ("n", "none", ""):
            console.print("[dim]nothing applied. I'll be here when you're ready.[/dim]")
            return
        if raw in ("a", "all"):
            chosen = list(findings)
        else:
            idx = set()
            for tok in raw.replace(" ", "").split(","):
                if tok.isdigit() and 1 <= int(tok) <= len(findings):
                    idx.add(int(tok))
            chosen = [findings[i - 1] for i in sorted(idx)]
        if not chosen:
            console.print("[yellow]didn't catch any valid numbers \u2014 nothing applied.[/yellow]")
            return
        for f in [f for f in chosen if f.risk == "risky"]:
            if not typer.confirm(f"'{f.title}' is RISKY \u2014 really apply?", default=False):
                chosen.remove(f)

    _enforce_window(cfg, "fixxer apply", override_window, bool(fx.load_consent(cfg)))

    mode = "auto" if auto else "interactive"
    results = []
    for f in chosen:
        console.print(f"[bold cyan]\u2699 {f.title}[/bold cyan] [dim]({f.risk})[/dim]")
        res = fx.apply_finding(cfg, store, ctx, f, mode, non_interactive=auto,
                               on_step=lambda k, d: console.print(f"  [dim]$ {d}[/dim]"))
        results.append(res)
        style = "green" if res.ok and res.verified else ("yellow" if res.ok else "red")
        mark = "\u2713 fixed + verified" if res.ok and res.verified else (
            "\u2713 applied (verify: " + res.verify_note + ")" if res.ok else "\u2717 failed")
        console.print(f"  [{style}]{mark}[/{style}] [dim]{res.duration_s}s \u00b7 {res.verify_note}[/dim]")

    done = sum(1 for r in results if r.ok and r.verified)
    partial = sum(1 for r in results if r.ok and not r.verified)
    failed = sum(1 for r in results if not r.ok)
    summary = f"[green]{done} fixed + verified[/green]"
    if partial:
        summary += f" \u00b7 [yellow]{partial} applied, verification inconclusive[/yellow]"
    if failed:
        summary += f" \u00b7 [red]{failed} failed[/red]"
    console.print(Panel(
        summary + f"\n[dim]every action is in the audit log: {fx.audit_path(cfg)} "
                  "(wrench fixxer --audit)[/dim]",
        border_style="green" if not failed else "red", title="\U0001f527 fixxer report"))
    if failed:
        for r in results:
            if not r.ok:
                console.print(Panel(r.output[-1200:], border_style="red",
                                    title=f"\u2717 {r.finding.title}"))
        raise typer.Exit(1)


# ---------------- certs (certwrench) ----------------

CERT_SEV_STYLE = {"critical": "bold red", "warning": "yellow", "info": "cyan",
                  "ok": "green"}


def _days_cell(days) -> Text:
    if days is None:
        return Text("—", style="dim")
    if days < 0:
        return Text(f"EXPIRED {-days}d ago", style="bold red")
    style = "bold red" if days <= 7 else "yellow" if days <= 30 else "green"
    return Text(f"{days}d", style=style)


def _render_cert_table(cert_list) -> Table:
    t = Table(title="\U0001f510 certificate inventory", border_style="bright_blue")
    t.add_column("name", style="bold", max_width=28)
    t.add_column("expires in", justify="right")
    t.add_column("issuer", max_width=24, style="dim")
    t.add_column("key")
    t.add_column("flags")
    t.add_column("source", max_width=30, style="dim")
    for c in cert_list:
        if c.error:
            t.add_row(Text(Path(c.path).name, style="dim"),
                      Text("parse error", style="red"), "—", "—",
                      Text(c.error[:20], style="red"), c.source or c.path)
            continue
        flags = []
        if c.self_signed:
            flags.append(Text("self-signed", style="yellow"))
        if c.is_ca:
            flags.append(Text("CA", style="dim"))
        if c.weak_key:
            flags.append(Text("weak-key", style="bold red"))
        if c.chain_complete is False:
            flags.append(Text("broken-chain", style="red"))
        flag_text = Text(" ").join(flags) if flags else Text("ok", style="green")
        issuer_cn = ""
        import re as _re
        m = _re.search(r"CN\s*=\s*([^,/]+)", c.issuer or "")
        issuer_cn = m.group(1).strip() if m else (c.issuer or "")[:24]
        key_str = f"{c.key_type}-{c.key_bits}" if c.key_bits else (c.key_type or "?")
        t.add_row(c.common_name, _days_cell(c.days_left), issuer_cn, key_str,
                  flag_text, (c.source or "").split(":", 1)[-1])
    return t


def _render_weaknesses(weaknesses) -> Panel | None:
    if not weaknesses:
        return None
    from rich.console import Group
    rows = []
    for w in weaknesses:
        style = CERT_SEV_STYLE.get(w.severity, "white")
        rows.append(Text.assemble((f"[{w.severity}] ", style), (w.detail, "white")))
    return Panel(Group(*rows), border_style="yellow",
                title="\u26a0 weak TLS configuration")


certs_app = typer.Typer(
    help="\U0001f510 SSL/TLS certificate lifecycle: inventory, renew, audit.",
    no_args_is_help=False, invoke_without_command=True)


@certs_app.callback(invoke_without_command=True)
def certs_main(
    ctx: typer.Context,
    probe: bool = typer.Option(False, "--probe",
                               help="also live-probe local HTTPS listeners (read-only)"),
    verify_chain: bool = typer.Option(True, "--verify-chain/--no-verify-chain",
                                      help="run openssl chain verification per cert"),
    json_out: bool = JSON_OPT,
):
    """Inventory certificates: scan configs + well-known stores, parse, persist, report."""
    if ctx.invoked_subcommand is not None:
        return
    from . import certs as cmod
    cfg, store = _ctx()
    if json_out:
        cert_list, weaknesses = cmod.inventory()
        if verify_chain:
            for c in cert_list:
                if c.ok and not c.self_signed and c.chain_complete is None:
                    complete, _note = cmod.verify_chain(c.path)
                    c.chain_complete = complete
        for c in cert_list:
            store.upsert_cert(c.to_row())
        attention = [c for c in cert_list if c.ok and c.expiry_severity()]
        jsonout.emit("certs", {
            "count": len(cert_list),
            "needing_attention": len(attention),
            "certs": [{**c.to_row(), "common_name": c.common_name,
                       "weak_key": c.weak_key,
                       "expiry_severity": c.expiry_severity()} for c in cert_list],
            "weaknesses": weaknesses,
        })
        return
    _notify_banner(cfg)
    with console.status("[cyan]scanning configs + well-known stores for certificates..."):
        cert_list, weaknesses = cmod.inventory()
        if verify_chain:
            for c in cert_list:
                if c.ok and not c.self_signed and c.chain_complete is None:
                    complete, _note = cmod.verify_chain(c.path)
                    c.chain_complete = complete
        for c in cert_list:
            store.upsert_cert(c.to_row())
    if not cert_list:
        console.print(Panel(
            "[green]no certificates found[/green] in web-server configs or the "
            "well-known stores (/etc/letsencrypt/live, /etc/ssl, /etc/pki).\n"
            "[dim]nothing to track yet \u2014 install a TLS service and re-run.[/dim]",
            border_style="green", title="\U0001f510 wrench certs"))
        return
    console.print(_render_cert_table(cert_list))
    wp = _render_weaknesses(weaknesses)
    if wp is not None:
        console.print(wp)
    if probe:
        _probe_local_listeners(cfg, store, cmod)
    # expiry headline
    soon = [c for c in cert_list if c.ok and c.expiry_severity()]
    if soon:
        worst = min((c.days_left for c in soon if c.days_left is not None), default=None)
        console.print(f"[dim]tracked {len(cert_list)} certs \u2014 "
                      f"[bold yellow]{len(soon)}[/bold yellow] need attention "
                      f"(soonest expiry: {worst}d)[/dim]")
    else:
        console.print(f"[dim]tracked {len(cert_list)} certs \u2014 none expiring within 30 days[/dim]")


def _probe_local_listeners(cfg, store, cmod) -> None:
    """Live-probe HTTPS on common local ports (read-only handshake)."""
    rows = []
    for port in (443, 8443):
        res = cmod.probe_tls("127.0.0.1", port, timeout=3.0)
        if res["ok"]:
            weak = cmod.protocol_is_weak(res["protocol"])
            rows.append(Text.assemble(
                (f":{port} ", "bold"),
                (f"{res['protocol']} ", "red" if weak else "green"),
                (f"{res['cipher']} ", "dim"),
                (f"(cert {res['days_left']}d)" if res["days_left"] is not None else "", "dim")))
    if rows:
        from rich.console import Group
        console.print(Panel(Group(*rows), border_style="bright_blue",
                            title="\U0001f4e1 live TLS probe (localhost)"))


def _render_renew_result(res) -> None:
    from rich.console import Group
    rows = []
    for s in res.steps:
        mark = "\u2713" if s.ok else "\u2717"
        style = "green" if s.ok else "red"
        rows.append(Text.assemble((f"{mark} {s.name}", style),
                                  (f"  {s.detail[:90]}", "dim")))
    border = "green" if res.ok else ("yellow" if res.rolled_back else "red")
    title = ("\U0001f501 dry-run" if res.dry_run else "\U0001f501 renewal") \
        + f" \u2014 {Path(res.cert_path).name}"
    rows.append(Text(res.message, style="bold " + border))
    console.print(Panel(Group(*rows), border_style=border, title=title))


def _renew_consent_ceremony(cfg) -> bool:
    from . import certs as cmod
    console.print(Panel(
        "[bold]You are about to let me RENEW certificates and RELOAD services.[/bold]\n\n"
        "What a real renewal does, in order:\n"
        "  \u2022 dry-run the ACME client first (certbot --dry-run / acme.sh --info)\n"
        "  \u2022 renew via the allowlisted client only (no model-authored commands)\n"
        "  \u2022 validate the new chain with openssl before trusting it\n"
        "  \u2022 test the service config (nginx -t, etc.) BEFORE reloading\n"
        "  \u2022 reload the consuming service; never against an unvalidated cert\n\n"
        "If any step fails I stop and tell you \u2014 the old cert stays in place and\n"
        "the service is left running on its known-good config.",
        border_style="red", title="\u26a0 consent \u2014 certificate renewal"))
    if not typer.confirm("do you consent to automated renewal on this machine?", default=False):
        console.print("[dim]no consent \u2014 renewal stays dry-run only.[/dim]")
        return False
    p = cmod.write_renew_consent(cfg)
    from . import audit as _amod
    _amod.log_event(cfg, "consent.grant", {"subsystem": "certs"})
    console.print(f"[green]renewal consent recorded[/green] [dim]{p}[/dim]")
    return True


@certs_app.command("renew")
def certs_renew(
    name: str = typer.Argument(None, help="cert name/CN/path substring to renew"),
    all_: bool = typer.Option(False, "--all", help="renew every discovered cert"),
    dry_run: bool = typer.Option(True, "--dry-run/--execute",
                                 help="dry-run first (default); --execute renews for real"),
    tool: str = typer.Option(None, "--tool", help="certbot|acme.sh (auto-detected)"),
    reload_service: str = typer.Option(None, "--reload-service",
                                       help="nginx|apache2|httpd|caddy|haproxy to reload after renew"),
    probe_host: str = typer.Option(None, "--probe-host",
                                   help="host to live-probe after a real renewal"),
    setup_consent: bool = typer.Option(False, "--setup-consent",
                                       help="record consent for real (non-dry-run) renewals"),
    revoke_consent: bool = typer.Option(False, "--revoke-consent",
                                        help="revoke renewal consent"),
    override_window: bool = typer.Option(False, "--override-window",
                                         help="renew outside the maintenance window "
                                              "(requires consent; audit-logged)"),
):
    """Renew certificates: dry-run first, validate the chain, reload the service."""
    from . import certs as cmod
    cfg, store = _ctx()

    if revoke_consent:
        _revoked = cmod.revoke_renew_consent(cfg)
        if _revoked:
            from . import audit as _amod
            _amod.log_event(cfg, "consent.revoke", {"subsystem": "certs"})
        console.print("[green]renewal consent revoked.[/green]" if _revoked
                      else "[dim]no renewal consent was recorded.[/dim]")
        return
    if setup_consent:
        _renew_consent_ceremony(cfg)
        return

    tool = tool or cmod.detect_renewer()
    if not tool:
        console.print(Panel(
            "[yellow]no ACME client found[/yellow] \u2014 install [bold]certbot[/bold] or "
            "[bold]acme.sh[/bold] to renew certificates. Inventory + audit still work.",
            border_style="yellow", title="\U0001f501 wrench certs renew"))
        raise typer.Exit(1)

    rows = store.recent_certs()
    if not rows:
        with console.status("[cyan]no cached inventory \u2014 scanning now..."):
            cert_list, _ = cmod.inventory()
            for c in cert_list:
                store.upsert_cert(c.to_row())
        rows = store.recent_certs()
    targets = _select_renew_targets(rows, name, all_)
    if not targets:
        console.print("[yellow]no matching certificate to renew.[/yellow] "
                      "Run [bold]wrench certs[/bold] to see what's tracked, or pass --all.")
        raise typer.Exit(1)

    if not dry_run:
        allowed, reason = cmod.renewal_permitted(cfg)
        if not allowed:
            console.print(f"[yellow]{reason}[/yellow]")
            if not _renew_consent_ceremony(cfg):
                raise typer.Exit(2)
        _approval_gate(cfg, store, "certs renew --execute",
                       f"{len(targets)} cert(s) via {tool}")
        _enforce_window(cfg, "certs renew --execute", override_window, True)

    console.print(f"[dim]tool: [bold]{tool}[/bold] \u00b7 mode: "
                  f"[bold]{'dry-run' if dry_run else 'EXECUTE'}[/bold] \u00b7 "
                  f"{len(targets)} cert(s)[/dim]")
    any_fail = False
    for row in targets:
        cert = cmod._cert_from_cache(row)
        res = cmod.orchestrate_renew(cert, tool, dry_run=dry_run,
                                     reload_service=reload_service, probe_host=probe_host)
        _render_renew_result(res)
        store.add_action(cfg.policy_tier, f"certs:renew:{'dry' if dry_run else 'exec'}",
                         f"{tool} {cert.common_name}", res.ok, res.message[:400])
        if not dry_run:
            from . import notifications
            notifications.emit_event(
                cfg, "certs.renew",
                "attention" if res.ok else ("error" if res.rolled_back else "critical"),
                f"cert renewal {cert.common_name} via {tool}: {res.message[:200]}")
        any_fail = any_fail or not res.ok
    if any_fail:
        raise typer.Exit(1)


def _select_renew_targets(rows: list[dict], name: str | None, all_: bool) -> list[dict]:
    # skip CA certs and parse errors \u2014 only renewable leaf certs
    leaf = [r for r in rows if not r.get("error") and not r.get("is_ca")]
    if all_:
        return leaf
    if not name:
        return []
    nl = name.lower()
    out = []
    import re as _re
    for r in leaf:
        m = _re.search(r"CN\s*=\s*([^,/]+)", r.get("subject") or "")
        cn = m.group(1).strip().lower() if m else ""
        sans = " ".join(r.get("sans") or []).lower()
        if nl in cn or nl in (r.get("path") or "").lower() or nl in sans:
            out.append(r)
    return out


@certs_app.command("audit")
def certs_audit(
    no_probe: bool = typer.Option(False, "--no-probe",
                                  help="skip the live localhost TLS handshake probes"),
    no_llm: bool = typer.Option(False, "--no-llm", help="skip the brain-narrated summary"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
    json_out: bool = JSON_OPT,
):
    """Weak-TLS audit: protocols/ciphers/HSTS/OCSP from configs + live probe, narrated."""
    from . import certs as cmod
    cfg, store = _ctx(provider, model)
    if json_out:
        rep = cmod.audit_report(do_probe=not no_probe)
        for c in rep["certs"]:
            store.upsert_cert(c.to_row())
        jsonout.emit("certs.audit", {
            "certs": [{**c.to_row(), "common_name": c.common_name,
                       "weak_key": c.weak_key,
                       "expiry_severity": c.expiry_severity()} for c in rep["certs"]],
            "weaknesses": rep["weaknesses"],
            "probes": rep["probes"],
        })
        return
    with console.status("[cyan]auditing TLS posture (configs + live probe)..."):
        rep = cmod.audit_report(do_probe=not no_probe)
        for c in rep["certs"]:
            store.upsert_cert(c.to_row())
    cert_list = rep["certs"]
    if cert_list:
        console.print(_render_cert_table(cert_list))
    wp = _render_weaknesses(rep["weaknesses"])
    if wp is not None:
        console.print(wp)
    else:
        console.print("[green]no weak TLS configuration detected in scanned configs.[/green]")
    if rep["probes"]:
        from rich.console import Group
        rows = []
        for p in rep["probes"]:
            weak = p.get("weak_protocol")
            rows.append(Text.assemble(
                (f":{p['port']} ", "bold"),
                (f"{p.get('protocol','?')} ", "red" if weak else "green"),
                (f"{p.get('cipher','?')} ", "dim"),
                ("\u26a0 below TLS 1.2" if weak else "ok",
                 "bold red" if weak else "green")))
        console.print(Panel(Group(*rows), border_style="bright_blue",
                            title="\U0001f4e1 live TLS probe (localhost)"))

    if no_llm or not (cfg.api_key or cfg.provider in ("ollama", "lmstudio")):
        return
    lines = cmod.audit_lines(rep)
    if not lines:
        return
    from .providers import LLMClient
    client = LLMClient(cfg, store)
    try:
        with console.status("[cyan]narrating the audit..."):
            text = client.chat(
                [{"role": "system",
                  "content": "You are wrench, a sysadmin agent speaking in the first person "
                             "about YOUR machine's TLS posture. You are shown an inventory of "
                             "certificates, weak-configuration findings, and live-probe "
                             "results. In 4-8 sentences: triage what actually matters "
                             "(expiring certs, weak keys, protocols below TLS 1.2, missing "
                             "HSTS/OCSP stapling), name the single most urgent action, and "
                             "note that `wrench certs renew` can rotate a cert under the "
                             "consent ceremony. No markdown headers, no filler."},
                 {"role": "user", "content": "\n".join(lines)}],
                purpose="certs-audit")
        report.render_answer(console, text, f"{cfg.model} \u00b7 TLS audit")
    except Exception as e:  # noqa: BLE001
        console.print(f"[dim]narration unavailable ({e}) \u2014 the findings stand on their own[/dim]")


app.add_typer(certs_app, name="certs")


# ---------------- blueprint (declarative config automation) ----------------

blueprint_app = typer.Typer(
    help="\U0001f4d0 declarative config automation: the brain drafts a diff, "
         "code validates, applies, and rolls back.",
    no_args_is_help=False, invoke_without_command=True)


def _render_bp_steps(steps) -> None:
    t = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    t.add_column("step")
    t.add_column("ok", justify="center")
    t.add_column("detail", overflow="fold")
    for s in steps:
        t.add_row(s.name, "[green]\u2713[/green]" if s.ok else "[red]\u2717[/red]",
                  s.detail[:200])
    console.print(t)


def _render_diff(diff_text: str) -> None:
    from rich.syntax import Syntax
    console.print(Panel(Syntax(diff_text, "diff", theme="ansi_dark", word_wrap=True),
                        border_style="cyan", title="\U0001f4d0 proposed blueprint (diff)"))


def _bp_consent_ceremony(cfg) -> bool:
    from . import blueprint as bp
    console.print(Panel(
        "[bold]blueprint apply consent[/bold]\n\n"
        "You are authorizing wrench to apply reviewed config diffs:\n"
        "  \u2022 targets restricted to the allowlist (default /etc), never "
        "passwd/shadow/sudoers-direct\n"
        "  \u2022 timestamped backup of every file BEFORE any write\n"
        "  \u2022 validation with the daemon's own checker (nginx -t, sshd -t, "
        "visudo -c, \u2026)\n"
        "  \u2022 service reload only via allowlisted systemctl verbs\n"
        "  \u2022 automatic rollback from backup on any failure\n"
        "  \u2022 every application audited + recorded as a drift snapshot",
        border_style="yellow", title="consent ceremony"))
    if not typer.confirm("record this consent?", default=False):
        console.print("[dim]no consent recorded.[/dim]")
        return False
    p = bp.write_consent(cfg)
    from . import audit as _amod
    _amod.log_event(cfg, "consent.grant", {"subsystem": "blueprint"})
    console.print(f"[green]consent recorded[/green] [dim]\u2192 {p}[/dim]")
    return True


@blueprint_app.callback(invoke_without_command=True)
def blueprint_main(
    ctx: typer.Context,
    intent: str = typer.Argument(None, help="what to change, in plain English "
                                            "(e.g. 'harden sshd: disable root login')"),
    target: list[str] = typer.Option(None, "--target", "-t",
                                     help="target file(s); omit to let the brain choose"),
    execute: bool = typer.Option(False, "--execute",
                                 help="apply for real (default is dry-run preview)"),
    yes: bool = typer.Option(False, "--yes", "-y",
                             help="skip the interactive diff confirmation (execute mode)"),
    override_window: bool = typer.Option(False, "--override-window",
                                         help="apply outside the maintenance window "
                                              "(requires consent; audit-logged)"),
    show_history: bool = typer.Option(False, "--history",
                                      help="list past blueprint applications and exit"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
    json_out: bool = JSON_OPT,
):
    """Draft a config change as a reviewed diff and (with consent) apply it."""
    if ctx.invoked_subcommand is not None:
        return
    from . import blueprint as bp
    cfg, store = _ctx(provider, model)
    # `wrench blueprint history` — the INTENT argument would otherwise swallow
    # the word "history" and send it to the drafting brain; treat it as --history.
    if show_history or (intent or "").strip().lower() == "history":
        if json_out:
            _bp_history_json(cfg)
        else:
            _bp_history(cfg)
        return
    if not intent:
        console.print("[yellow]tell me what to change:[/yellow] "
                      "wrench blueprint \"harden sshd: disable password auth\"")
        raise typer.Exit(1)
    _notify_banner(cfg)

    # 1. draft
    try:
        with console.status("[cyan]drafting blueprint (the brain writes a diff, "
                            "never commands)..."):
            plan = bp.draft(cfg, store, intent, targets=list(target) if target else None)
    except bp.BlueprintError as e:
        console.print(f"[red]draft failed:[/red] {e}")
        raise typer.Exit(1) from None

    # 2. preview
    _render_diff(plan.diff_text)
    checkers = bp.plan_checkers(plan)
    for path, spec in checkers.items():
        if spec is None:
            console.print(f"[yellow]\u26a0 {path}: no validator known — syntax "
                          "validation will be skipped[/yellow]")
        else:
            note = f" [dim]({spec.note})[/dim]" if spec.note else ""
            console.print(f"[dim]validator for {path}: [bold]{spec.id}[/bold]{note}[/dim]")

    # 3. gate + ceremony
    if not execute:
        res = bp.apply_plan(cfg, store, plan, execute=False)
        _render_bp_steps(res.steps)
        color = "green" if res.ok else "red"
        console.print(Panel(f"[{color}]{res.message}[/{color}]",
                            border_style=color, title="dry-run"))
        raise typer.Exit(0 if res.ok else 1)

    allowed, reason = bp.apply_permitted(cfg)
    if not allowed:
        console.print(f"[yellow]{reason}[/yellow]")
        if not _bp_consent_ceremony(cfg):
            raise typer.Exit(2)
    _approval_gate(cfg, store, "blueprint --execute", plan.intent[:120])
    _enforce_window(cfg, "blueprint --execute", override_window, True)
    if not yes and not typer.confirm(
            f"apply this blueprint to {', '.join(plan.files)}?", default=False):
        console.print("[dim]not applied.[/dim]")
        raise typer.Exit(0)

    res = bp.apply_plan(cfg, store, plan, execute=True)
    _render_bp_steps(res.steps)
    if res.ok:
        console.print(Panel(f"[green]{res.message}[/green]",
                            border_style="green", title="\u2713 blueprint applied"))
    else:
        console.print(Panel(
            f"[red]{res.message}[/red]"
            + (f"\n[dim]backup: {res.backup_dir}[/dim]" if res.backup_dir else ""),
            border_style="red",
            title="\u21a9 rolled back" if res.rolled_back else "\u2717 blueprint failed"))
        raise typer.Exit(1)


def _bp_history(cfg) -> None:
    from . import blueprint as bp
    rows = bp.history(cfg, n=30)
    if not rows:
        console.print("[dim]no blueprints have been applied yet.[/dim]")
        return
    t = Table(title="\U0001f4d0 blueprint history", show_header=True,
              header_style="bold")
    t.add_column("when")
    t.add_column("intent", overflow="fold", max_width=48)
    t.add_column("files", overflow="fold", max_width=40)
    t.add_column("outcome")
    for r in rows:
        outcome = ("[green]applied[/green]" if r.get("ok")
                   else "[yellow]rolled back[/yellow]" if r.get("rolled_back")
                   else "[red]failed[/red]")
        t.add_row(r.get("iso", "")[:19], r.get("intent", "")[:120],
                  ", ".join(r.get("files", [])), outcome)
    console.print(t)


def _bp_history_json(cfg) -> None:
    from . import blueprint as bp
    rows = bp.history(cfg, n=100)
    jsonout.emit("blueprint.history", {"count": len(rows), "history": rows})


@blueprint_app.command("history")
def blueprint_history(json_out: bool = JSON_OPT):
    """List past blueprint applications with outcomes."""
    cfg, _store = _ctx()
    if json_out:
        _bp_history_json(cfg)
    else:
        _bp_history(cfg)


@blueprint_app.command("consent")
def blueprint_consent(
    revoke: bool = typer.Option(False, "--revoke", help="revoke blueprint consent"),
):
    """Record (or revoke) consent for real blueprint applications."""
    from . import blueprint as bp
    cfg, _store = _ctx()
    if revoke:
        _revoked = bp.revoke_consent(cfg)
        if _revoked:
            from . import audit as _amod
            _amod.log_event(cfg, "consent.revoke", {"subsystem": "blueprint"})
        console.print("[green]blueprint consent revoked.[/green]"
                      if _revoked
                      else "[dim]no blueprint consent was recorded.[/dim]")
        return
    _bp_consent_ceremony(cfg)


app.add_typer(blueprint_app, name="blueprint")


# ---------------- security (watch the doors) ----------------

security_app = typer.Typer(
    help="🛡️ security watch: auth anomalies, privilege drift, listener "
         "ownership, CVE matching — read-only, baseline by consent.",
    no_args_is_help=False, invoke_without_command=True)

_SEC_SEV_STYLE = {"critical": ("bold red", "✖"), "warning": ("yellow", "⚠"),
                  "info": ("dim", "·")}


def _render_security_findings(findings: list[dict]):
    from rich.table import Table as _T
    t = _T(title="🛡️ security findings", border_style="bright_blue",
           show_lines=False)
    t.add_column("sev", width=9)
    t.add_column("area", width=9, style="cyan")
    t.add_column("finding")
    t.add_column("detail", style="dim", max_width=60)
    order = {"critical": 0, "warning": 1, "info": 2}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
        style, icon = _SEC_SEV_STYLE.get(f["severity"], ("white", "?"))
        t.add_row(Text(f"{icon} {f['severity']}", style=style),
                  f["category"], f["title"], f.get("detail", ""))
    return t


def _render_listener_table(rows: list[dict]):
    from rich.table import Table as _T
    t = _T(title="📡 listening sockets", border_style="bright_blue")
    t.add_column("socket", style="bold")
    t.add_column("addr", style="dim")
    t.add_column("process")
    t.add_column("unit", style="dim")
    for r in rows:
        proc = r.get("process") or "[red]— ownerless —[/red]"
        t.add_row(r["key"], r.get("addr") or "*", proc, r.get("unit") or "")
    return t


def _security_json(report: dict) -> None:
    jsonout.emit("security", {
        "worst": report["worst"],
        "counts": report["counts"],
        "baseline_exists": report["baseline_exists"],
        "baseline_accepted_at": report["baseline_accepted_at"],
        "findings": report["findings"],
        "components": report["components"],
    })


@security_app.callback(invoke_without_command=True)
def security_main(
    ctx: typer.Context,
    no_cve: bool = typer.Option(False, "--no-cve",
                                help="skip the OSV CVE scan (faster, offline-safe)"),
    refresh_cve: bool = typer.Option(False, "--refresh-cve",
                                     help="bypass the CVE cache TTL"),
    no_llm: bool = typer.Option(False, "--no-llm",
                                help="skip the brain-narrated briefing"),
    notify: bool = typer.Option(True, "--notify/--no-notify",
                                help="emit a notification when findings clear the ladder"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
    json_out: bool = JSON_OPT,
):
    """Full security scan: auth log + access drift + listeners + CVEs."""
    if ctx.invoked_subcommand is not None:
        return
    from . import security as sec
    cfg, store = _ctx(provider, model)
    if json_out:
        report = sec.scan(cfg, store, include_cve=not no_cve, force_cve=refresh_cve)
        if notify:
            sec.notify_scan(cfg, report)
        _security_json(report)
        raise typer.Exit(1 if report["worst"] == "critical" else 0)

    def on_step(kind, detail):
        console.print(f"  [dim cyan]⚙ {detail}[/dim cyan]")

    console.print("[dim italic]watching the doors — auth log, privilege drift, "
                  "listeners" + (", CVEs" if not no_cve else "") + "...[/dim italic]")
    report = sec.scan(cfg, store, include_cve=not no_cve, force_cve=refresh_cve,
                      on_step=on_step)
    if notify:
        sec.notify_scan(cfg, report)
    rows = report["components"].get("listeners", {}).get("rows", [])
    if rows:
        console.print(_render_listener_table(rows))
    if report["findings"]:
        console.print(_render_security_findings(report["findings"]))
    else:
        console.print("[green]no security findings — the doors are locked and "
                      "accounted for.[/green]")
    if not report["baseline_exists"]:
        console.print(Panel(
            "[yellow]no accepted baseline yet[/yellow] — deltas (new IPs, new "
            "listeners, sudoers changes) only alarm once you bless the current "
            "state:\n  [bold]wrench security accept[/bold]",
            border_style="yellow", title="baseline"))
    cve = report["components"].get("cve", {})
    if cve.get("error"):
        console.print(f"[dim]{cve['error']}[/dim]")

    if no_llm or not (cfg.api_key or cfg.provider in ("ollama", "lmstudio")):
        raise typer.Exit(1 if report["worst"] == "critical" else 0)
    lines = sec.narration_lines(report)
    client = LLMClient(cfg, store)
    try:
        with console.status("[cyan]briefing..."):
            text = client.chat(
                [{"role": "system",
                  "content": "You are wrench, a sysadmin agent speaking in the first "
                             "person about YOUR machine's security posture. You are "
                             "shown a security scan: auth-log anomalies, privilege "
                             "drift, listening sockets, and CVE matches. In 4-8 "
                             "sentences: triage what actually matters, name the single "
                             "most urgent action, and say plainly if the box looks "
                             "clean. You only analyze — you never execute anything. "
                             "No markdown headers, no filler."},
                 {"role": "user", "content": "\n".join(lines)}],
                purpose="security-brief")
        from . import report as _report
        _report.render_answer(console, text, f"{cfg.model} · security brief")
    except Exception as e:  # noqa: BLE001
        console.print(f"[dim]briefing unavailable ({e}) — the findings stand on "
                      f"their own[/dim]")
    raise typer.Exit(1 if report["worst"] == "critical" else 0)


@security_app.command("baseline")
def security_baseline(json_out: bool = JSON_OPT):
    """Show the accepted baseline (what deltas are measured against)."""
    from . import security as sec
    _cfg, store = _ctx()
    base = sec.baseline_get(store)
    if json_out:
        jsonout.emit("security.baseline", {"baseline": base})
        return
    if not base:
        console.print("[yellow]no baseline accepted yet[/yellow] — run "
                      "[bold]wrench security accept[/bold] to bless the current state")
        return
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(base.get("accepted_at", 0)))
    body = [Text(f"accepted {when}", style="dim")]
    auth = base.get("auth", {})
    body.append(Text(f"known source IPs: {len(auth.get('known_ips', []))} — "
                     + ", ".join(auth.get("known_ips", [])[:8])))
    body.append(Text(f"sudo users: {', '.join(auth.get('sudo_users', [])) or '(none)'}"))
    acc = base.get("access", {})
    body.append(Text(f"sudoers files tracked: {len(acc.get('sudoers', {}))}"))
    body.append(Text(f"authorized_keys users: "
                     f"{', '.join(sorted(acc.get('authorized_keys', {}))) or '(none)'}"))
    body.append(Text(f"UID-0 accounts: {', '.join(acc.get('uid0', [])) or 'root'}"))
    body.append(Text(f"listeners: {len(base.get('listeners', {}))} — "
                     + ", ".join(sorted(base.get("listeners", {}))[:12])))
    from rich.console import Group
    console.print(Panel(Group(*body), border_style="bright_blue",
                        title="🛡️ security baseline"))


@security_app.command("accept")
def security_accept(
    yes: bool = typer.Option(False, "--yes", "-y",
                             help="skip the confirmation prompt (CI use)"),
):
    """Bless the CURRENT observed state as the baseline (consent ceremony)."""
    from . import security as sec
    cfg, store = _ctx()
    with console.status("[cyan]observing current state..."):
        observed = sec.collect_observed(cfg)
    auth = observed.get("auth", {})
    acc = observed.get("access", {})
    summary = (
        f"known IPs: {len(auth.get('known_ips', []))} · "
        f"sudo users: {len(auth.get('sudo_users', []))} · "
        f"sudoers files: {len(acc.get('sudoers', {}))} · "
        f"authorized_keys users: {len(acc.get('authorized_keys', {}))} · "
        f"UID-0: {', '.join(acc.get('uid0', [])) or 'root'} · "
        f"listeners: {len(observed.get('listeners', {}))}")
    console.print(Panel(
        Text.assemble(("about to bless the current state as the security baseline\n",
                       "bold yellow"),
                      (summary + "\n", "white"),
                      ("future scans alarm on anything that DIFFERS from this.", "dim")),
        border_style="yellow", title="consent required"))
    if not yes and not typer.confirm("accept this baseline?", default=False):
        console.print("[dim]baseline unchanged.[/dim]")
        raise typer.Exit(0)
    sec.baseline_accept(store, observed)
    from . import audit as _amod
    _amod.log_event(cfg, "security.baseline.accept", {
        "known_ips": len(auth.get("known_ips", [])),
        "sudo_users": len(auth.get("sudo_users", [])),
        "listeners": len(observed.get("listeners", {}))})
    console.print("[green]baseline accepted[/green] — deltas now alarm against it.")


app.add_typer(security_app, name="security")


# ---------------- backups (trust your backups) ----------------

backups_app = typer.Typer(
    help="\U0001f9f0 backup verification: find every backup job, prove it ran, "
         "prove the repository is sane \u2014 read-only by default.",
    no_args_is_help=False, invoke_without_command=True)

_BK_FRESH_STYLE = {"fresh": "green", "stale": "bold red", "unknown": "yellow"}
_BK_INTEG_STYLE = {"ok": "green", "failed": "bold red", "locked": "yellow",
                   "unknown": "yellow", "skipped": "dim"}


def _render_backup_table(report: dict):
    from rich.table import Table as _T
    t = _T(title="\U0001f9f0 backup jobs", border_style="bright_blue")
    t.add_column("job", style="bold")
    t.add_column("origin", style="dim", max_width=44)
    t.add_column("schedule", style="dim", max_width=20)
    t.add_column("last run")
    t.add_column("freshness")
    t.add_column("integrity")
    t.add_column("note", style="dim", max_width=40)
    for j in report["jobs"]:
        age = j.get("age_s")
        if age is None:
            last = Text("never seen", style="yellow")
        elif age < 3600 * 48:
            last = Text(f"{age / 3600:.1f}h ago")
        else:
            last = Text(f"{age / 86400:.1f}d ago")
        t.add_row(j["name"], j["origin"], j["schedule"] or "?", last,
                  Text(j["freshness"], style=_BK_FRESH_STYLE.get(j["freshness"], "white")),
                  Text(j["integrity"], style=_BK_INTEG_STYLE.get(j["integrity"], "white")),
                  j.get("integrity_note", ""))
    return t


@backups_app.callback(invoke_without_command=True)
def backups_main(
    ctx: typer.Context,
    restore_test: bool = typer.Option(False, "--restore-test",
                                      help="L3: consent-gated sample restore proof "
                                           "(borg dry-run extract / restic check)"),
    yes: bool = typer.Option(False, "--yes", "-y",
                             help="skip the restore-test consent prompt (CI)"),
    no_llm: bool = typer.Option(False, "--no-llm",
                                help="skip the brain-narrated briefing"),
    notify: bool = typer.Option(True, "--notify/--no-notify",
                                help="emit a notification when findings clear the ladder"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
    json_out: bool = JSON_OPT,
):
    """Detect every backup job and climb the verification ladder."""
    if ctx.invoked_subcommand is not None:
        return
    from . import backups as bmod
    cfg, store = _ctx(provider, model)

    def on_step(detail):
        if not json_out:
            console.print(f"  [dim cyan]\u2699 {detail}[/dim cyan]")

    if not json_out:
        console.print("[dim italic]untested backups don't exist \u2014 detecting "
                      "and verifying...[/dim italic]")
    report = bmod.scan(cfg, store, on_step=on_step)
    if notify:
        bmod.notify_scan(cfg, report, store)

    # L3 — consent-gated restore proof
    if restore_test and report["jobs"]:
        jobs = bmod.detect_jobs()
        if not yes and not json_out:
            ok = typer.confirm(
                f"run sample restore proofs against {len(jobs)} repositories "
                f"(read-only: borg --dry-run extract / restic check)?")
            if not ok:
                console.print("[dim]restore test skipped.[/dim]")
                jobs = []
        for j in jobs:
            on_step(f"restore-testing {j.name}...")
            bmod.check_freshness(j)
            bmod.check_integrity(j)
            bmod.restore_test(j)
        if jobs:
            report = {**report, "jobs": [j.as_dict() for j in jobs]}
            store.add_snapshot(bmod.BACKUPS_KIND, report)
            store.add_action(cfg.policy_tier, "backups:restore-test",
                             f"{len(jobs)} jobs", True, "completed")

    if json_out:
        jsonout.emit("backups", {
            "count": report["count"],
            "worst": report["worst"],
            "no_jobs": report["no_jobs"],
            "severity_counts": report["severity_counts"],
            "jobs": report["jobs"],
        })
        raise typer.Exit(1 if report["worst"] == "critical" else 0)

    if report["no_jobs"]:
        console.print(Panel(
            "[bold yellow]no backup jobs detected on this box.[/bold yellow]\n"
            "Nothing in crontabs or systemd timers invokes borg/restic/rsync/"
            "pg_dump/mysqldump \u2014 if this data matters, that's the finding.",
            border_style="yellow", title="\U0001f9f0 wrench backups"))
        raise typer.Exit(0)

    console.print(_render_backup_table(report))
    worst = report.get("worst", "none")
    if worst == "none":
        console.print("[green]every detected backup job is fresh and its "
                      "repository answers \u2014 nice.[/green]")

    if no_llm or not (cfg.api_key or cfg.provider in ("ollama", "lmstudio")):
        raise typer.Exit(1 if worst == "critical" else 0)
    lines = bmod.narration_lines(report)
    client = LLMClient(cfg, store)
    try:
        with console.status("[cyan]briefing..."):
            text = client.chat(
                [{"role": "system",
                  "content": "You are wrench, a sysadmin agent speaking in the first "
                             "person about YOUR machine's backups. You are shown every "
                             "detected backup job with freshness and integrity "
                             "verdicts. In 3-6 sentences: say plainly whether this box "
                             "could be restored today, name the weakest link, and the "
                             "single most urgent action. Remember: an untested backup "
                             "does not exist. You only analyze \u2014 you never execute "
                             "anything. No markdown headers, no filler."},
                 {"role": "user", "content": "\n".join(lines)}],
                purpose="backups-brief")
        from . import report as _report
        _report.render_answer(console, text, f"{cfg.model} \u00b7 backups brief")
    except Exception as e:  # noqa: BLE001
        console.print(f"[dim]briefing unavailable ({e}) \u2014 the verdicts stand "
                      f"on their own[/dim]")
    raise typer.Exit(1 if worst == "critical" else 0)


app.add_typer(backups_app, name="backups")


# ---------------- audit (tamper-evident hash-chained log) ----------------

audit_app = typer.Typer(
    help="🧾 tamper-evident audit log: every consent, apply, rollback, "
         "renewal and override sealed into a hash chain you can `verify`.",
    no_args_is_help=False,
)


def _render_audit_table(records: list[dict]) -> Table:
    t = Table(title="🧾 audit log — recent events", border_style="bright_blue")
    t.add_column("time", style="dim", no_wrap=True)
    t.add_column("actor", style="cyan")
    t.add_column("kind", style="bold")
    t.add_column("detail", overflow="fold")
    t.add_column("hash", style="dim", no_wrap=True)
    for r in records:
        detail = r.get("detail")
        if isinstance(detail, dict):
            dtxt = ", ".join(f"{k}={v}" for k, v in detail.items())
        else:
            dtxt = str(detail)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("ts", 0)))
        t.add_row(ts, str(r.get("actor", "?")), str(r.get("kind", "?")),
                  dtxt[:80], str(r.get("hash", ""))[:12])
    return t


@audit_app.callback(invoke_without_command=True)
def audit_main(
    ctx: typer.Context,
    limit: int = typer.Option(20, "--limit", "-n", help="how many recent events to show"),
    json_out: bool = JSON_OPT,
):
    """List recent audit events. Run `wrench audit verify` to check the chain."""
    if ctx.invoked_subcommand is not None:
        return
    from . import audit as amod
    cfg, _store = _ctx()
    records = amod.recent(cfg.data_dir, limit=limit)
    chain = amod.verify(cfg.data_dir)
    if json_out:
        jsonout.emit("audit", {
            "entries": records,
            "count": chain["count"],
            "shown": len(records),
            "intact": chain["intact"],
        })
        return
    if not records:
        console.print(Panel(
            "[dim]no audit events yet.[/dim] The chain seeds itself the first time "
            "wrench does something consequential — a consent grant, a fixxer "
            "apply, a cert renewal, a blueprint apply.",
            border_style="bright_blue", title="🧾 wrench audit"))
        return
    console.print(_render_audit_table(records))
    status = ("[green]✔ chain INTACT[/green]" if chain["intact"]
              else f"[bold red]✗ chain BROKEN at #{chain['broken_index']}[/bold red]")
    console.print(f"{status} [dim]· {chain['count']} total event(s) · "
                  f"`wrench audit verify` for the full walk[/dim]")


@audit_app.command("verify")
def audit_verify(json_out: bool = JSON_OPT):
    """Re-walk the hash chain. Reports INTACT or the exact first broken link."""
    from . import audit as amod
    cfg, _store = _ctx()
    chain = amod.verify(cfg.data_dir)
    if json_out:
        jsonout.emit("audit.verify", chain)
        raise typer.Exit(0 if chain["intact"] else 1)
    if chain["intact"]:
        console.print(Panel(
            f"[bold green]✔ INTACT[/bold green] — {chain['count']} event(s), "
            f"every link verified.",
            border_style="green", title="🧾 audit verify"))
        raise typer.Exit(0)
    console.print(Panel(
        f"[bold red]✗ TAMPER DETECTED[/bold red]\n"
        f"first broken link: record #{chain['broken_index']} of {chain['count']}\n"
        f"reason: {chain['reason']}",
        border_style="red", title="🧾 audit verify"))
    raise typer.Exit(1)


app.add_typer(audit_app, name="audit")


# ---------------- command catalog ----------------

@app.command("commands")
def commands_cmd(
    pack: str = typer.Argument(None, help="a pack name (e.g. network, packages) to list in full"),
    check: str = typer.Option(None, "--check", "-c", metavar="COMMAND",
                              help="would the agent be allowed to run this exact command?"),
    all_os: bool = typer.Option(False, "--all", help="every OS, not just this machine's"),
    fixes: bool = typer.Option(False, "--fixes", help="only the commands that change things"),
    markdown: bool = typer.Option(False, "--markdown", hidden=True),
    json_out: bool = JSON_OPT,
):
    """Every command the agent may run — and a way to test one.

    wrench commands                     the packs, and how many commands in each
    wrench commands network             one pack in full, with examples
    wrench commands --fixes             only the commands that change the machine
    wrench commands --check "df -h"     would this exact command be allowed?
    """
    from . import commands as _cmds, platforms as _plat, policy as _pol
    if markdown:
        sys.stdout.write(_cmds.markdown() + "\n")
        return
    cfg, store = _ctx()
    store.close()
    tier = cfg.policy_tier if cfg.policy_tier in _pol.TIERS else "suggest"
    st = _pol.settings(cfg)
    plat = "all" if all_os else _plat.current_platform()

    if check is not None:
        look = _pol.check_diag(check, cfg)
        fix = _pol.check_repair(check, tier, cfg)
        fix_any = _pol.check_repair(check, "autonomous", cfg)
        if look.allowed:
            verdict, detail = "look", f"read-only · {look.label} · runs at every tier"
        elif fix_any.allowed:
            how = ("asks you every time, at any tier" if fix_any.always_ask
                   else "asks you first at repair, runs unattended at autonomous")
            verdict = "fix"
            detail = f"changes the machine · {fix_any.label} · {how}"
            if not fix.allowed:
                detail += f"\nnot at the current tier ({tier}) — wrench policy repair"
        else:
            verdict = "refused"
            if fix_any.label or look.label or "Allowed forms" not in (look.reason + fix_any.reason):
                detail = fix_any.reason if fix_any.label else look.reason
                if detail.startswith("not on the "):
                    detail = "not in the command catalog — the agent cannot run it"
            else:
                forms = list(dict.fromkeys(_cmds.hints(check, "diag") + _cmds.hints(check, "fix")))
                detail = ("not in the command catalog in this form. Allowed forms of this tool: "
                          + " · ".join(forms))
        if json_out:
            jsonout.emit("commands.check", {
                "command": check, "verdict": verdict, "tier": tier,
                "allowed_now": bool(look.allowed or fix.allowed),
                "needs_confirm": bool(not look.allowed and fix.allowed and fix.needs_confirm),
                "label": look.label or fix_any.label, "pack": look.pack or fix_any.pack,
                "reason": detail})
        else:
            mark = {"look": "[green]✔ allowed[/green]", "fix": "[yellow]✔ allowed as a fix[/yellow]",
                    "refused": "[red]✖ refused[/red]"}[verdict]
            console.print(f"{mark}  [bold]{escape(check)}[/bold]")
            console.print(Text(detail, style="dim"))
        if verdict == "refused":
            raise typer.Exit(1)
        return

    if pack is not None:
        pack = pack.strip().lower()
        if pack not in _cmds.PACKS:
            console.print(f"[red]✖ unknown pack '{escape(pack)}'[/red] — one of: "
                          + ", ".join(_cmds.PACKS))
            raise typer.Exit(2)
    rows = [c for c in _cmds.entries(None, plat, pack) if not fixes or c.kind == "fix"]
    if json_out:
        jsonout.emit("commands", {
            "os": plat, "tier": tier, "counts": _cmds.counts(plat),
            "disabled_packs": sorted(st["disabled_packs"]), "sudo": st["sudo"],
            "allow_diag": st["allow_diag"], "allow_fix": st["allow_fix"],
            "packs": _cmds.summary(plat, st["disabled_packs"]),
            "commands": [_cmds.as_dict(c) for c in rows] if (pack or fixes) else []})
        return
    if pack or fixes:
        t = Table(box=box.SIMPLE_HEAD, title_justify="left",
                  title=f"🔧 {_cmds.PACKS[pack] if pack else 'fixes'} — what the agent may run"
                        + ("" if all_os else f" on {plat}"))
        t.add_column("")
        if not pack:
            t.add_column("pack", style="dim")
        t.add_column("what")
        t.add_column("examples", overflow="fold")
        for c in rows:
            kind = ("[green]look[/green]" if c.kind == "diag"
                    else "[yellow]fix · asks[/yellow]" if c.ask else "[yellow]fix[/yellow]")
            cells = [kind] + ([c.pack] if not pack else []) + [
                c.label, Text("\n".join(c.examples), style="bold" if c.kind == "fix" else "")]
            t.add_row(*cells)
        console.print(t)
        if pack and pack in st["disabled_packs"]:
            console.print(Text("this pack is switched off ([policy] disabled_packs)",
                               style="yellow"))
        console.print(Text("examples only — each entry allows a fixed set of flags. Test one: "
                           'wrench commands --check "<command>"', style="dim"))
        return
    n = _cmds.counts(plat)
    t = Table(box=box.SIMPLE_HEAD, title_justify="left",
              title=f"🔧 what the agent may run{'' if all_os else ' on ' + plat} — "
                    f"{n['diag']} kinds of look, {n['fix']} kinds of fix")
    t.add_column("pack")
    t.add_column("look", justify="right")
    t.add_column("fix", justify="right")
    t.add_column("tools", overflow="fold")
    for r in _cmds.summary(plat, st["disabled_packs"]):
        tools_ = list(dict.fromkeys(r["diag_tools"] + r["fix_tools"]))
        shown = ", ".join(tools_[:12]) + (f", +{len(tools_) - 12}" if len(tools_) > 12 else "")
        t.add_row(r["pack"], str(r["diag"] or ""), str(r["fix"] or ""),
                  shown if r["enabled"] else "[yellow]switched off[/yellow]",
                  style="" if r["enabled"] else "dim")
    console.print(t)
    extra = len(st["allow_diag"]) + len(st["allow_fix"])
    if extra:
        console.print(Text(f"plus {extra} of your own ([policy] allow_diag / allow_fix)"))
    can = {"observe": "looks only", "suggest": "looks only, and proposes fixes for you to run",
           "repair": "looks freely; runs a fix after you say yes",
           "autonomous": "looks freely; runs routine fixes itself, asks for the rest"}[tier]
    console.print(Text.assemble(("tier ", "dim"), (tier, "bold"), (f" — {can}", "dim")))
    console.print(Text('one pack: wrench commands <pack>   ·   test one: wrench commands '
                       '--check "<command>"   ·   change the tier: wrench policy', style="dim"))


# ---------------- policy tier ----------------

@app.command("policy")
def policy_cmd(
    tier: str = typer.Argument(None, help="observe | suggest | repair | autonomous "
                                          "(omit to see the current tier)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="skip the confirmation (for scripts)"),
    json_out: bool = JSON_OPT,
):
    """Show or change how much wrench may do on its own — observer to actor.

    wrench policy               where the leash is now, and what each tier allows
    wrench policy repair        let it run allowlisted fixes, asking you each time
    wrench policy autonomous    let it run them unattended
    wrench policy suggest       back to advice only
    """
    from . import audit as _amod, config as _config, policy as _pol
    cfg, store = _ctx()
    store.close()
    forced = _config.policy_env_override()
    current = cfg.policy_tier if cfg.policy_tier in _pol.TIERS else "suggest"
    if tier is None:
        if json_out:
            jsonout.emit("policy", {
                "tier": current, "env_override": bool(forced),
                "tiers": [{"tier": t, "name": _pol.TIER_INFO[t][0], "allows": _pol.TIER_INFO[t][1],
                           "current": t == current} for t in _pol.TIERS]})
            return
        t = Table(box=box.SIMPLE_HEAD, title="🔧 policy tier — how much wrench may do on its own",
                  title_justify="left")
        t.add_column("")
        t.add_column("tier")
        t.add_column("role")
        t.add_column("what it may do", overflow="fold")
        for name in _pol.TIERS:
            here = name == current
            t.add_row("[bold green]▶[/]" if here else "", f"[bold]{name}[/]" if here else name,
                      _pol.TIER_INFO[name][0], _pol.TIER_INFO[name][1],
                      style="" if here else "dim")
        console.print(t)
        if forced:
            console.print(f"[yellow]WRENCH_POLICY={forced} is set in the environment and "
                          "overrides the config file.[/yellow]")
        console.print(Text.assemble(("change it:  ", "dim"), ("wrench policy <tier>", "bold"),
                                    ("   e.g. wrench policy repair", "dim")))
        return
    tier = tier.strip().lower()
    if tier not in _pol.TIERS:
        console.print(f"[red]✖ unknown tier '{tier}'[/red] — one of: {', '.join(_pol.TIERS)}")
        raise typer.Exit(2)
    if forced:
        console.print(f"[red]✖ WRENCH_POLICY={forced} is set in the environment and overrides "
                      "the config file.[/red] Unset it (or change it there) first.")
        raise typer.Exit(2)
    if tier == current:
        if json_out:
            jsonout.emit("policy", {"tier": current, "changed": False})
        else:
            console.print(f"already at [bold]{current}[/bold] — {_pol.TIER_INFO[current][1]}")
        return
    raising = _pol.tier_rank(tier) > _pol.tier_rank(current)
    if raising and tier in ("repair", "autonomous") and not yes:
        if not sys.stdin.isatty():
            console.print("[red]✖ raising the tier needs a person at a terminal, or --yes[/red]")
            raise typer.Exit(2)
        body = Text.assemble(
            (f"{current} → {tier}\n\n", "bold"), (_pol.TIER_INFO[tier][1], ""),
            ("\n\nIt can only ever run commands from its catalog (wrench commands) — never a "
             "command it wrote itself. Higher-impact fixes, such as installing updates or "
             "killing a process, ask you every time at any tier. Every action is logged "
             "(wrench audit).", "dim"))
        console.print(Panel(body, border_style="yellow", title="⚠ give wrench hands",
                            title_align="left"))
        if tier == "autonomous":
            typed = typer.prompt("type 'autonomous' to let it act with nobody watching",
                                 default="", show_default=False)
            if typed.strip().lower() != "autonomous":
                console.print("[dim]unchanged[/dim]")
                raise typer.Exit(1)
        elif not typer.confirm(f"switch to {tier}?", default=False):
            console.print("[dim]unchanged[/dim]")
            raise typer.Exit(1)
    path = _config.set_policy_tier(tier)
    _amod.log_event(cfg, "policy.tier_change", {"from": current, "to": tier, "via": "cli"})
    if json_out:
        jsonout.emit("policy", {"tier": tier, "changed": True, "from": current})
        return
    console.print(Text.assemble(("✔ ", "green"), ("policy tier ", ""), (current, "dim"),
                                (" → ", "dim"), (tier, "bold"),
                                (f"  {_pol.TIER_INFO[tier][0]}", "dim")))
    console.print(Text(f"{_pol.TIER_INFO[tier][1]}\nsaved to {path} · a running dashboard picks "
                       "it up on its next refresh", style="dim"))
    if tier == "repair":
        console.print(Text("scheduled patrols have nobody to ask, so they still only suggest; "
                           "`wrench chat` and `wrench ask` will offer fixes and wait for your OK.",
                           style="dim"))



@app.command("approve")
def approve_cmd(token: str = typer.Argument(..., help="approval token from the pending-approval webhook")):
    """Approve a pending action (the second channel in an async approval flow)."""
    from . import approvals, audit as _amod
    cfg, store = _ctx()
    res = approvals.approve(store, token)
    status = res["status"]
    if status == "approved":
        _amod.log_event(cfg, "approval.granted", {"action": res["action"]})
        console.print(Panel(
            f"[green]✔ approved[/green] — action [bold]{res['action']}[/bold] "
            "may now proceed on its next run.",
            border_style="green", title="✅ wrench approve"))
        return
    msgs = {
        "not_found": "[red]unknown token[/red] — no pending approval matches it.",
        "expired": "[yellow]token expired[/yellow] — request a fresh approval.",
        "already_used": "[yellow]already used[/yellow] — this token was already approved (single-use).",
    }
    console.print(Panel(msgs.get(status, f"[red]{status}[/red]"),
                        border_style="red", title="✅ wrench approve"))
    raise typer.Exit(1)


@app.command("approvals")
def approvals_cmd(json_out: bool = JSON_OPT):
    """List recent approval tokens and their state (hashes only; never plaintext)."""
    cfg, store = _ctx()
    rows = store.recent_approvals(50)
    now = time.time()
    def _state(r):
        if r["claimed"]:
            return "claimed"
        if r["approved"]:
            return "approved"
        if now > r["expires"]:
            return "expired"
        return "pending"
    if json_out:
        jsonout.emit("approvals", {
            "count": len(rows),
            "approvals": [{"action": r["action"], "detail": r["detail"],
                           "created": r["created"], "expires": r["expires"],
                           "state": _state(r)} for r in rows],
        })
        return
    if not rows:
        console.print(Panel(
            "[dim]no approval tokens yet.[/dim] Configure [bold]approval_webhook_url[/bold] "
            "under [approvals] to require out-of-band approval for consent-gated changes.",
            border_style="bright_blue", title="✅ wrench approvals"))
        return
    t = Table(title="✅ approval tokens", border_style="bright_blue")
    t.add_column("when", style="dim", no_wrap=True)
    t.add_column("action", style="bold")
    t.add_column("detail", overflow="fold")
    t.add_column("state")
    _style = {"pending": "yellow", "approved": "green", "claimed": "cyan",
              "expired": "dim"}
    for r in rows:
        stt = _state(r)
        t.add_row(time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created"])),
                  r["action"], str(r["detail"])[:60],
                  Text(stt, style=_style.get(stt, "white")))
    console.print(t)


# ---------------- forecast (capacity forecasting) ----------------

_FC_SEV_STYLE = {"critical": ("bold red", "\u2191"), "warning": ("yellow", "\u2197"),
                 "info": ("cyan", "\u2192"), "none": ("dim", "\u00b7")}
_FC_KIND_ICON = {"disk": "\U0001f4be", "inode": "\U0001f5c3", "memory": "\U0001f9e0",
                 "swap": "\U0001f501", "log": "\U0001f4dc", "cert": "\U0001f510"}


def _render_forecast_table(incidents: list[dict]) -> Table:
    t = Table(title="\U0001f52e future incidents \u2014 capacity forecast",
              border_style="bright_blue")
    t.add_column("sev", width=9)
    t.add_column("resource", style="bold", max_width=26)
    t.add_column("ETA", justify="right")
    t.add_column("date", style="dim")
    t.add_column("current", justify="right")
    t.add_column("rate/day", justify="right")
    t.add_column("confidence", style="dim")
    order = {"critical": 0, "warning": 1, "info": 2, "none": 3}
    for i in sorted(incidents, key=lambda x: (order.get(x["severity"], 9),
                                              x.get("eta_days") if x.get("eta_days")
                                              is not None else 1e9)):
        style, arrow = _FC_SEV_STYLE.get(i["severity"], ("white", "?"))
        icon = _FC_KIND_ICON.get(i["kind"], "\u2022")
        eta = i.get("eta_days")
        eta_txt = Text("\u2014", style="dim") if eta is None else Text(
            f"{eta:.1f}d", style=style)
        if i["unit"] == "%":
            cur = f"{i['current']:.1f}%"
            rate = f"+{i['growth_per_day']:.2f}%"
        elif i["unit"] == "bytes":
            cur = f"{i['current'] / 2**30:.2f}G"
            rate = f"+{i['growth_per_day'] / 2**20:.1f}M"
        else:  # days (cert)
            cur = f"{int(i['current'])}d left"
            rate = "\u2014"
        t.add_row(Text(f"{arrow} {i['severity']}", style=style),
                  f"{icon} {i['resource']}", eta_txt, i.get("eta_date") or "\u2014",
                  cur, rate, i.get("confidence", ""))
    return t


@app.command()
def forecast(
    window: int = typer.Option(30, "--window", help="days of sensor history to fit"),
    no_certs: bool = typer.Option(False, "--no-certs",
                                  help="capacity only; omit TLS expiry from the feed"),
    no_llm: bool = typer.Option(False, "--no-llm",
                                help="skip the brain-narrated briefing"),
    notify: bool = typer.Option(False, "--notify/--no-notify",
                                help="emit a notification for the soonest projection"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
    json_out: bool = JSON_OPT,
):
    """See it coming: project disk/inode/memory/swap/log growth + cert expiry
    into a future-incidents feed with ETAs and confidence."""
    from . import forecast as fc
    cfg, store = _ctx(provider, model)
    report = fc.feed_report(cfg, store, include_certs=not no_certs,
                            now=None, persist=True)
    report["window_days"] = window
    if notify:
        fc.notify_feed(cfg, report)
    if json_out:
        jsonout.emit("forecast", {
            "worst": report["worst"],
            "counts": report["counts"],
            "soonest": report["soonest"],
            "thresholds": report["thresholds"],
            "window_days": window,
            "incidents": report["incidents"],
        })
        raise typer.Exit(1 if report["worst"] == "critical" else 0)
    incidents = report["incidents"]
    if not incidents:
        console.print("[dim]no sensor history to forecast yet \u2014 let patrols run "
                      "for a few hours and try again.[/dim]")
        raise typer.Exit(0)
    actionable = [i for i in incidents
                  if i["severity"] in ("critical", "warning", "info")]
    console.print(_render_forecast_table(incidents))
    if not actionable:
        console.print("[green]nothing is trending toward exhaustion within the "
                      "lead-time window \u2014 you're flying level.[/green]")
    if no_llm or not (cfg.api_key or cfg.provider in ("ollama", "lmstudio")):
        raise typer.Exit(1 if report["worst"] == "critical" else 0)
    lines = fc.narration_lines(report)
    client = LLMClient(cfg, store)
    try:
        with console.status("[cyan]reading the trend lines..."):
            text = client.chat(
                [{"role": "system",
                  "content": "You are wrench, a sysadmin agent speaking in the first "
                             "person about YOUR machine's capacity outlook. You are "
                             "shown a future-incidents feed: projected disk/inode/"
                             "memory/swap exhaustion and certificate expiry, each with "
                             "an ETA and confidence. In 3-6 sentences: say what will "
                             "break first and roughly when, call out anything low-"
                             "confidence as a watch-not-panic, and name the one thing "
                             "to do now. You only analyze \u2014 never execute. No "
                             "markdown headers, no filler."},
                 {"role": "user", "content": "\n".join(lines)}],
                purpose="forecast-brief")
        from . import report as _report
        _report.render_answer(console, text, f"{cfg.model} \u00b7 capacity outlook")
    except Exception as e:  # noqa: BLE001
        console.print(f"[dim]briefing unavailable ({e}) \u2014 the projections stand "
                      f"on their own[/dim]")
    raise typer.Exit(1 if report["worst"] == "critical" else 0)


# ---------------- metrics (Prometheus exporter) ----------------

metrics_app = typer.Typer(
    help="📈 Prometheus metrics: print one scrape or serve /metrics.",
    no_args_is_help=False, invoke_without_command=True)


@metrics_app.callback(invoke_without_command=True)
def metrics_main(ctx: typer.Context):
    """Print one Prometheus scrape to stdout (textfile-collector friendly)."""
    if ctx.invoked_subcommand is not None:
        return
    from . import metrics
    cfg, store = _ctx()
    print(metrics.render(store, cfg.data_dir), end="")


@metrics_app.command("serve")
def metrics_serve(
    port: int = typer.Option(9465, "--port", help="port for the exporter"),
    bind: str = typer.Option("127.0.0.1", "--bind", help="bind address"),
):
    """Serve a bare /metrics endpoint (no dashboard). The dashboard
    (`wrench web`) also exposes /metrics on its own port."""
    from . import metrics
    cfg, store = _ctx()
    store.close()
    httpd = metrics.serve(cfg.db_path, port=port, bind=bind)
    console.print(f"[bold]wrench metrics[/bold] — Prometheus exposition at "
                  f"[bright_blue]http://{bind}:{port}/metrics[/bright_blue] · Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]exporter stopped[/dim]")


app.add_typer(metrics_app, name="metrics")


# ---------------- fleet (hub + node reporting + dead-man's switch) ----------------

fleet_app = typer.Typer(
    help="\U0001f527 fleet mode \u2014 many nodes, one view: run a hub, report from "
         "nodes, watch for silent boxes. Default OFF (no [fleet] config = no-op).",
    no_args_is_help=True,
)

_FLEET_COLOR_STYLE = {"green": "green", "yellow": "yellow", "red": "bold red",
                     "silent": "bold magenta"}


@fleet_app.command("enroll")
def fleet_enroll(
    label: str = typer.Option("", "--label", "-l", help="what this key is for (a host, a site, a team)"),
    single_node: bool = typer.Option(False, "--single-node",
                                     help="bind the key to the first node that uses it"),
    hub_url: str = typer.Option(None, "--hub-url",
                                help="the address nodes will reach this hub at (for the join command)"),
    json_out: bool = JSON_OPT,
):
    """HUB: mint an enrollment key and print the one-line command that joins a node.

    The key is shown once. The hub stores only a derived signing key under a
    short id, so it can be listed and revoked (`wrench fleet keys` / `revoke`)
    without ever being shown again. One key can enroll many machines — put it
    in your MDM / config-management script — unless you pass --single-node."""
    from . import fleet as fmod, audit as _amod
    cfg, store = _ctx()
    st = fmod.settings_from(cfg)
    res = fmod.enroll(store, label=label, single_node=single_node)
    store.close()
    _amod.log_event(cfg, "fleet.enroll", {"key_id": res["key_id"], "label": label,
                                          "single_node": single_node})
    scheme = "https" if st.tls_cert else "http"
    host = platform.node() or "HUB-HOST"
    url = hub_url or f"{scheme}://{host}:{st.listen_port}"
    join = f"wrench fleet join {url} {res['token']}"
    if json_out:
        jsonout.emit("fleet.enroll", {"key_id": res["key_id"], "token": res["token"],
                                      "label": label, "single_node": single_node,
                                      "join_command": join})
        return
    console.print(Panel(
        Text.assemble(
            ("run this on each machine that should report to this hub:\n\n", "dim"),
            (join, "bold bright_green"),
            (f"\n\nkey id {res['key_id']}", "dim"),
            (f" · label: {label or '(none)'}", "dim"),
            (" · single node" if single_node else " · reusable", "dim"),
            ("\nthe key is shown once — the hub keeps only a derived signing key", "dim")),
        border_style="bright_green", title="\U0001f527 wrench fleet enroll"))
    console.print("[dim]then start the hub if it is not running: [bold]wrench fleet serve "
                  "--host 0.0.0.0[/bold]  ·  check the URL above is how nodes reach "
                  "this box (override with --hub-url)[/dim]")


@fleet_app.command("join")
def fleet_join(
    hub_url: str = typer.Argument(..., help="the hub address, e.g. https://hub.example:8788"),
    token: str = typer.Argument(..., help="the enrollment key from `wrench fleet enroll`"),
    node_id: str = typer.Option(None, "--node-id", help="name for this node (default: hostname)"),
    tags: str = typer.Option("", "--tags", help="comma-separated labels, e.g. prod,web,eu"),
    ca_file: str = typer.Option(None, "--ca-file", help="CA bundle for a hub with a private certificate"),
    no_verify: bool = typer.Option(False, "--no-test", help="write the config without a test report"),
):
    """NODE: point this machine at a hub with an enrollment key. Tests the
    connection, then saves the [fleet] settings so every patrol reports from
    now on. (No key to hand? `wrench fleet connect` uses the hub's password.)"""
    hub_url = hub_url.rstrip("/")
    if not hub_url.lower().startswith(("http://", "https://")):
        console.print("[red]the hub address must start with http:// or https://[/red]")
        raise typer.Exit(2)
    _fleet_attach(hub_url, token.strip(), node_id, tags, ca_file, no_verify,
                  title="\U0001f527 wrench fleet join", event="fleet.join")


def _fleet_attach(hub_url: str, token: str, node_id: str | None, tags: str,
                  ca_file: str | None, no_verify: bool, title: str, event: str) -> None:
    """Shared tail of `fleet join` and `fleet connect`: send a test report
    with the key, then save the [fleet] settings."""
    from . import fleet as fmod, audit as _amod
    from .config import set_section_values, CONFIG_PATH as _CP
    cfg, store = _ctx()
    st = fmod.settings_from(cfg)
    st.hub_url, st.token = hub_url, token
    if node_id:
        st.node_id = node_id
    if tags:
        st.tags = fmod._clean_tags(tags)  # noqa: SLF001
    if ca_file:
        st.ca_file = ca_file
    if not no_verify:
        if store.last_sample("os") is None:
            sensors.sample_all(store)
        ok, detail = fmod.push_once(st, fmod.build_report(cfg, store, st))
        if not ok:
            store.close()
            console.print(Panel(
                f"[red]the hub did not accept a test report[/red] — {detail}\n"
                "[dim]nothing was saved. Check the address, that the hub is running "
                "(`wrench fleet serve`), and that the key was copied whole.[/dim]",
                border_style="red", title=title))
            raise typer.Exit(1)
    store.close()
    values: dict = {"hub_url": hub_url, "token": st.token}
    if node_id:
        values["node_id"] = node_id
    if st.tags:
        values["tags"] = st.tags
    if ca_file:
        values["ca_file"] = ca_file
    try:
        set_section_values("fleet", values)
    except (ValueError, OSError) as e:
        console.print(Panel(
            f"[red]the hub accepted this machine, but the config could not be saved[/red] — {e}\n"
            "[dim]add these lines under [bold][fleet][/bold] yourself:[/dim]\n"
            + "\n".join(f"{k} = {json.dumps(v)}" for k, v in values.items() if k != "token")
            + "\ntoken = \"<the enrollment key you just used>\"",
            border_style="red", title=title))
        raise typer.Exit(1) from None
    _amod.log_event(cfg, event, {"hub_url": hub_url, "node_id": st.node_id,
                                 "key_id": fmod.key_id_of(st.token)})
    console.print(Panel(
        f"[green]{'connected to' if event == 'fleet.connect' else 'joined'}[/green] "
        f"{hub_url} as [bold]{st.node_id}[/bold]"
        + (f" [dim](tags: {', '.join(st.tags)})[/dim]" if st.tags else "") + "\n"
        f"[dim]saved to {_CP} (owner-only) · every patrol now reports · "
        "schedule them with [bold]wrench install-service[/bold][/dim]",
        border_style="green", title=title))


@fleet_app.command("connect")
def fleet_connect(
    hub: str = typer.Argument(..., help="the hub's address: an IP or name (192.168.1.10), "
                                        "or a full URL (https://hub.example:8788)"),
    port: int = typer.Option(None, "--port", help="hub port when the address has none (default 8788)"),
    node_id: str = typer.Option(None, "--node-id", help="name for this machine (default: hostname)"),
    tags: str = typer.Option("", "--tags", help="comma-separated labels, e.g. prod,web,eu"),
    ca_file: str = typer.Option(None, "--ca-file", help="CA bundle for a hub with a private certificate"),
    password_stdin: bool = typer.Option(False, "--password-stdin",
                                        help="read the hub password from standard input"),
    allow_http: bool = typer.Option(False, "--allow-http",
                                    help="send the password to a hub that has no TLS "
                                         "(anyone on the network path can read it)"),
):
    """NODE: connect this machine to a hub with the hub's dashboard password.

    \b
    wrench fleet connect 192.168.1.10            asks for the hub password
    wrench fleet connect https://hub.example:8788 --tags prod,web
    echo "$PW" | wrench fleet connect hub.lan --password-stdin

    The password is sent once, to get this machine a key of its own; it is
    never written here. From then on every patrol reports to the hub, signed
    with that key, and the hub can revoke this machine alone
    (`wrench fleet keys` / `revoke`). Connecting again later keeps the
    machine's name and history.

    On the hub: `wrench password`, then `wrench fleet serve --host 0.0.0.0`."""
    from . import audit as _amod, fleet as fmod, offline as _offline
    title = "\U0001f527 wrench fleet connect"

    def fail(msg: str, hint: str = "", code: int = 1):
        console.print(Panel(f"[red]{msg}[/red]" + (f"\n[dim]{hint}[/dim]" if hint else ""),
                            border_style="red", title=title))
        raise typer.Exit(code)

    cfg = load_config()
    candidates = fmod.hub_candidates(hub, port)
    if not candidates:
        fail(f"{hub!r} is not an address I can use",
             "give an IP or host name (192.168.1.10), optionally with :port, or a full "
             "http(s):// URL", 2)
    if _offline.is_offline(cfg) and not _offline.egress_allowed(cfg, candidates[0]):
        fail("offline mode is on and that hub is not a local or private address",
             "set offline = false, or connect to a hub on your own network", 2)

    # find the hub without sending anything secret; never step down from a
    # TLS endpoint whose certificate we could not verify
    hub_url, problems = "", []
    with console.status("[cyan]looking for the hub..."):
        for url in candidates:
            verdict, detail = fmod.probe_hub(url, ca_file or "")
            if verdict == "ok":
                hub_url = url
                break
            if verdict == "cert":
                fail(f"{url} answered, but its certificate is not trusted — {detail}",
                     "if the hub uses a private or self-signed certificate, pass "
                     "--ca-file <its CA or certificate .pem>")
            problems.append(f"{url} — {detail}")
    if not hub_url:
        fail("no wrench hub answered at " + ", ".join(candidates),
             "\n".join(problems) + "\ncheck the address and port, that the hub is "
             "running (`wrench fleet serve --host 0.0.0.0`), and that a firewall is not "
             "in the way")

    if hub_url.lower().startswith("http://") and not fmod.is_local_url(hub_url) \
            and not allow_http:
        warn = (f"{hub_url} has no TLS: the hub password would cross the network "
                "unencrypted, readable by anyone on the path.")
        if _isatty() and not password_stdin:
            console.print(f"[yellow]{warn}[/yellow]")
            if not typer.confirm("Send it anyway?", default=False):
                fail("not connected — nothing was sent",
                     "give the hub a certificate (`wrench fleet serve --tls-cert … "
                     "--tls-key …`), or use an enrollment key instead: `wrench fleet "
                     "enroll` on the hub")
        else:
            fail(warn, "re-run with --allow-http to accept that, or give the hub a "
                       "certificate (`wrench fleet serve --tls-cert … --tls-key …`)", 2)

    if password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    elif os.environ.get("WRENCH_HUB_PASSWORD"):
        password = os.environ["WRENCH_HUB_PASSWORD"]
    elif _isatty():
        password = typer.prompt(f"password for the hub at {hub_url}", hide_input=True,
                                default="", show_default=False)
    else:
        fail("no terminal to ask for the hub password in",
             "pipe it in with --password-stdin, or set WRENCH_HUB_PASSWORD", 2)
    if not password:
        fail("no password given — nothing was sent", code=2)

    name = fmod.clean_node_id(node_id) or fmod.settings_from(cfg).node_id
    with console.status("[cyan]asking the hub for this machine's key..."):
        res = fmod.connect_request(hub_url, password, name, ca_file or "")
    del password
    if not res["ok"]:
        _amod.log_event(cfg, "fleet.connect.failed", {"hub_url": hub_url, "node_id": name,
                                                      "code": res["code"]})
        hint = {401: "that is the password set with `wrench password` on the hub",
                429: "too many wrong passwords from this address — wait a minute",
                }.get(res["code"], "")
        fail(f"the hub did not connect this machine — {res['detail']}", hint)
    if res.get("reconnected"):
        console.print(f"[dim]{name} was already known to the hub — it keeps its history "
                      "and its previous key was retired[/dim]")
    _fleet_attach(hub_url, res["token"], node_id, tags, ca_file, False,
                  title=title, event="fleet.connect")


@fleet_app.command("keys")
def fleet_keys(json_out: bool = JSON_OPT):
    """HUB: list enrollment keys — id, label, state, nodes using each."""
    cfg, store = _ctx()
    rows = []
    for k in store.fleet_keys():
        rows.append({"key_id": k["key_id"], "label": k["label"], "created": k["created"],
                     "revoked": k["revoked"], "single_node": k["single_node"],
                     "last_used": k["last_used"],
                     "nodes": store.fleet_nodes_for_key(k["key_id"])})
    store.close()
    if json_out:
        jsonout.emit("fleet.keys", {"keys": rows})
        return
    if not rows:
        console.print("[dim]no enrollment keys yet — create one with [bold]wrench fleet enroll[/bold][/dim]")
        return
    t = Table(title="\U0001f527 fleet enrollment keys", border_style="bright_blue")
    for col in ("key id", "label", "state", "created", "last used", "nodes"):
        t.add_column(col)
    for r in rows:
        fmt = lambda ts: time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "never"  # noqa: E731
        t.add_row(r["key_id"], r["label"] or "", Text("revoked", style="red") if r["revoked"]
                  else Text("active", style="green"), fmt(r["created"]), fmt(r["last_used"]),
                  ", ".join(r["nodes"][:6]) + (f" +{len(r['nodes']) - 6}" if len(r["nodes"]) > 6 else ""))
    console.print(t)


@fleet_app.command("revoke")
def fleet_revoke(key_id: str = typer.Argument(..., help="key id from `wrench fleet keys`")):
    """HUB: revoke an enrollment key. Nodes using it are refused from the next report."""
    from . import audit as _amod
    cfg, store = _ctx()
    ok = store.revoke_fleet_key(key_id, time.time())
    nodes = store.fleet_nodes_for_key(key_id)
    store.close()
    if not ok:
        console.print(f"[red]no active key with id {key_id}[/red]")
        raise typer.Exit(1)
    _amod.log_event(cfg, "fleet.revoke", {"key_id": key_id, "nodes": nodes})
    console.print(f"[green]revoked[/green] {key_id}"
                  + (f" — {len(nodes)} node(s) will go silent until re-joined: "
                     f"{', '.join(nodes[:8])}" if nodes else ""))


@fleet_app.command("forget")
def fleet_forget(node_id: str = typer.Argument(..., help="node to retire from the hub")):
    """HUB: remove a decommissioned node and its history."""
    from . import audit as _amod
    cfg, store = _ctx()
    ok = store.delete_fleet_node(node_id)
    store.close()
    if not ok:
        console.print(f"[red]no node named {node_id}[/red]")
        raise typer.Exit(1)
    _amod.log_event(cfg, "fleet.forget", {"node_id": node_id})
    console.print(f"[green]forgot[/green] {node_id} [dim](it will reappear if it reports again)[/dim]")


@fleet_app.command("token", hidden=True)
def fleet_token(
    label: str = typer.Option("", "--label", help="a human label for this node token"),
    register: bool = typer.Option(True, "--register/--no-register",
                                  help="record the token FINGERPRINT in this hub's db"),
):
    """(legacy, 2.x) Generate a shared token for [fleet] authorized_tokens.
    New deployments: use `wrench fleet enroll` + `wrench fleet join`."""
    from . import fleet as fmod
    cfg, store = _ctx()
    tok = fmod.generate_token()
    fp = fmod.token_fingerprint(tok)
    if register:
        store.add_fleet_token(fp, label, time.time())
    store.close()
    console.print(Panel(
        Text.assemble(
            ("legacy shared token (shown once \u2014 copy it now):\n\n", "dim"),
            (tok, "bold bright_green"),
            (f"\n\nfingerprint: {fp[:16]}\u2026  ", "dim"),
            (f"label: {label or '(none)'}", "dim"),
        ),
        border_style="bright_green", title="\U0001f527 wrench fleet token"))
    console.print(
        "[dim]Add it to the node's [bold][fleet] token[/bold] and to the hub's "
        "[bold][fleet] authorized_tokens[/bold]. Prefer [bold]wrench fleet enroll[/bold]: "
        "no config editing, and keys can be listed and revoked.[/dim]")


@fleet_app.command("report")
def fleet_report(
    hub: str = typer.Option(None, "--hub", help="override hub_url"),
    token: str = typer.Option(None, "--token", help="override the node token"),
    node_id: str = typer.Option(None, "--node-id", help="override this node's id"),
    dry_run: bool = typer.Option(False, "--dry-run", help="build the report, don't push"),
    json_out: bool = JSON_OPT,
):
    """Build this node's compact snapshot (from cached scans) and push it to the hub."""
    from . import fleet as fmod
    cfg, store = _ctx()
    st = fmod.settings_from(cfg)
    if hub:
        st.hub_url = hub.rstrip("/")
    if token:
        st.token = token
    if node_id:
        st.node_id = node_id
    report = fmod.build_report(cfg, store, st)
    if dry_run:
        store.close()
        if json_out:
            jsonout.emit("fleet.report", {"pushed": False, "report": report})
        else:
            console.print(Panel(json.dumps(report, indent=2),
                                border_style="bright_blue",
                                title="\U0001f527 fleet report (dry-run)"))
        return
    if not st.node_enabled:
        store.close()
        msg = "fleet node not configured \u2014 set [fleet] hub_url + token (or pass --hub/--token)"
        if json_out:
            jsonout.emit("fleet.report", {"pushed": False, "error": msg})
        else:
            console.print(Panel(msg, border_style="yellow", title="\U0001f527 wrench fleet"))
        raise typer.Exit(2)
    res = fmod.node_push(cfg, store, st)
    store.close()
    if json_out:
        jsonout.emit("fleet.report", {"pushed": res["ok"], "queued": res.get("queued"),
                                      "detail": res["detail"], "report": report})
        raise typer.Exit(0 if res["ok"] else 1)
    if res["ok"]:
        console.print(f"[green]\u2714 reported to {st.hub_url}[/green] "
                      f"[dim]({res['detail']}; status={report['status']}, "
                      f"worst={report['worst_severity']})[/dim]")
    else:
        console.print(Panel(
            f"[yellow]hub unreachable \u2014 report queued for retry[/yellow]\n"
            f"[dim]{res['detail']}[/dim]",
            border_style="yellow", title="\U0001f527 wrench fleet"))
        raise typer.Exit(1)


@fleet_app.command("serve")
def fleet_serve(
    host: str = typer.Option(None, "--host", help="bind address (default from config, 127.0.0.1)"),
    port: int = typer.Option(None, "--port", help="port (default from config, 8788)"),
    no_sample: bool = typer.Option(False, "--no-sample",
                                   help="don't sample this hub box in the background"),
    tls_cert: str = typer.Option(None, "--tls-cert", help="serve HTTPS with this certificate (PEM)"),
    tls_key: str = typer.Option(None, "--tls-key", help="private key for --tls-cert (PEM)"),
):
    """Run the fleet HUB: accept signed node reports, serve the fleet console,
    and watch for nodes that go silent."""
    from . import fleet as fmod
    from .webapp import serve
    cfg, store = _ctx()
    st = fmod.settings_from(cfg)
    n_keys = sum(1 for k in store.fleet_keys() if not k["revoked"])
    store.close()
    bind = host or st.listen_host
    port = port or st.listen_port
    try:
        httpd = serve(cfg.db_path, port=port, host_label=platform.node() or "localhost",
                      bind=bind, sample_thread=not no_sample, cfg=cfg, fleet_hub=True,
                      tls_cert=tls_cert or st.tls_cert, tls_key=tls_key or st.tls_key)
    except OSError as e:
        console.print(f"[red]could not start the hub on {bind}:{port} — {e}[/red]")
        raise typer.Exit(1) from None
    lines = ["fleet console: [bold bright_blue]{url}/fleet[/bold bright_blue]",
             "nodes report to: [bright_blue]{url}/api/fleet/report[/bright_blue]",
             f"[dim]{n_keys} enrollment key(s)"
             + (f" + {len(st.authorized_tokens)} legacy token(s)" if st.authorized_tokens else "")
             + " · silent-node sweep every 30s · Ctrl-C to stop[/dim]"]
    if not st.connect:
        if not n_keys and not st.authorized_tokens:
            lines.append("[yellow]no enrollment keys yet[/yellow] — in another terminal: "
                         "[bold]wrench fleet enroll[/bold]")
    elif httpd.auth.has_password:
        lines.append("add a machine — run on it: [bold]wrench fleet connect "
                     + (platform.node() or "<this hub's address>")
                     + (f" --port {port}" if port != fmod.DEFAULT_LISTEN_PORT else "")
                     + "[/bold] [dim](asks for the dashboard password)[/dim]")
    else:
        lines.append("[yellow]no dashboard password yet[/yellow] — set one with "
                     "[bold]wrench password[/bold] and machines can join with "
                     "[bold]wrench fleet connect <this hub's address>[/bold] "
                     "[dim](or mint keys: wrench fleet enroll)[/dim]")
    if is_loopback_hint(bind):
        lines.append("[dim]listening on this machine only — other machines cannot reach "
                     "it; use [bold]--host 0.0.0.0[/bold] to accept them[/dim]")
    _serve_banner(httpd, bind, port, "\U0001f527 wrench fleet serve", lines)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]fleet hub stopped[/dim]")


@fleet_app.command("status")
def fleet_status(json_out: bool = JSON_OPT):
    """Hub-side: show every known node \u2014 status, last-seen age, worst finding."""
    from . import fleet as fmod
    cfg, store = _ctx()
    st = fmod.settings_from(cfg)
    states = fmod.node_states(store, st)
    summary = fmod.fleet_summary(states)
    store.close()
    if json_out:
        jsonout.emit("fleet", {
            "summary": summary,
            "nodes": [{
                "node_id": n["node_id"], "hostname": n["hostname"],
                "status": n["status"], "color": n["color"], "silent": n["silent"],
                "last_seen": n["last_seen"], "age_s": n["age_s"],
                "worst_severity": n["worst_severity"], "summary": n["summary"],
                "cadence_s": n["cadence_s"], "wrench_version": n["wrench_version"],
                "report_count": n["report_count"],
                "findings": n["findings"], "gauges": n["gauges"],
                "meta": n.get("meta") or {},
            } for n in states],
        })
        raise typer.Exit(1 if summary.get("silent") or summary.get("red") else 0)
    if not states:
        console.print(Panel(
            "[dim]no nodes have reported yet.[/dim] Configure a node with "
            "[bold][fleet][/bold] hub_url + token and run [bold]wrench fleet report[/bold].",
            border_style="bright_blue", title="\U0001f527 wrench fleet status"))
        return
    t = Table(title=f"\U0001f527 fleet \u2014 {summary['total']} node(s): "
                    f"{summary['green']} ok / {summary['yellow']} attn / "
                    f"{summary['red']} crit / {summary['silent']} silent",
              border_style="bright_blue")
    t.add_column("node", style="bold")
    t.add_column("host", style="dim", max_width=24)
    t.add_column("status")
    t.add_column("last seen")
    t.add_column("worst finding", max_width=50)
    t.add_column("ver", style="dim")
    for n in states:
        age = n["age_s"]
        last = (f"{age:.0f}s ago" if age < 90 else f"{age/60:.0f}m ago"
                if age < 5400 else f"{age/3600:.1f}h ago")
        label = "silent" if n["silent"] else n["status"]
        worst = ""
        for f in n.get("findings", []):
            if (f.get("severity") or "").lower() in ("critical", "error", "warning"):
                worst = f.get("text", "")
                break
        if not worst:
            worst = n.get("summary", "")
        t.add_row(n["node_id"], n["hostname"] or "",
                  Text(label, style=_FLEET_COLOR_STYLE.get(n["color"], "white")),
                  last, worst, n.get("wrench_version") or "?")
    console.print(t)


app.add_typer(fleet_app, name="fleet")


# ---------------------------------------------------------------------------
# comply — compliance packs (deterministic, read-only, baseline by consent)
# ---------------------------------------------------------------------------

comply_app = typer.Typer(
    help="📋 compliance packs: audit the box against hardening baselines — "
         "deterministic code checks, read-only, offline.",
    no_args_is_help=False, invoke_without_command=True)

_COMPLY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow",
                 "low": "dim"}


def _render_comply_table(rep: dict):
    from rich.table import Table as _T
    score = "n/a (nothing could be graded)" if rep["score"] is None else f"{rep['score']}%"
    t = _T(title=f"📋 {rep['title']} — score {score}",
           border_style="bright_blue")
    t.add_column("status", width=7)
    t.add_column("sev", width=9)
    t.add_column("rule", style="cyan", no_wrap=True)
    t.add_column("title")
    t.add_column("detail", style="dim", max_width=48)
    icon = {"pass": ("[green]✔ pass[/green]"), "fail": ("[red]✖ fail[/red]"),
            "skip": ("[dim]· skip[/dim]")}
    order = {"fail": 0, "skip": 1, "pass": 2}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows = sorted(rep["results"],
                  key=lambda r: (order[r["status"]],
                                 sev_order.get(r["severity"], 9)))
    for r in rows:
        t.add_row(icon[r["status"]],
                  Text(r["severity"], style=_COMPLY_STYLE.get(r["severity"], "")),
                  r["id"], r["title"], r["detail"])
    return t


@comply_app.callback(invoke_without_command=True)
def comply_main(
    ctx: typer.Context,
    pack: str = typer.Option(None, "--pack", "-p",
                             help="run one pack (default: the packs written for this OS)"),
    brief: bool = typer.Option(False, "--brief",
                               help="ask the brain to triage failures "
                                    "(analysis only, never executes)"),
    json_out: bool = JSON_OPT,
):
    """Run compliance packs and show pass/fail/skip per rule with a score."""
    if ctx.invoked_subcommand is not None:
        return
    from . import comply as cm
    cfg, store = _ctx()
    try:
        report = cm.scan(store, packs=[pack] if pack else None)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from None
    if json_out:
        jsonout.emit("comply", {
            "packs": [{k: rep.get(k) for k in ("pack", "title", "score", "platforms",
                                               "counts", "severity_fails")}
                      for rep in report["packs"]],
            "critical_fails": report["critical_fails"],
            "results": [r for rep in report["packs"] for r in
                        [dict(x, pack=rep["pack"]) for x in rep["results"]]],
        })
        raise typer.Exit(1 if report["critical_fails"] else 0)
    if not report["packs"]:
        console.print(Panel(
            f"no compliance pack is written for this OS ({platforms.current_platform()}) yet.\n"
            "[dim]`wrench comply list` shows every shipped pack; "
            "`wrench comply --pack <name>` runs one anyway.[/dim]",
            border_style="yellow", title="📋 wrench comply"))
        return
    skips = 0
    for rep in report["packs"]:
        console.print(_render_comply_table(rep))
        skips += rep["counts"]["skip"]
    if skips:
        console.print(f"[dim]{skips} check(s) skipped — most need root to "
                      f"read their target; run with sudo for full coverage.[/dim]")
    base = cm.baseline_fail_ids(store)
    if base is None:
        console.print("[dim]no accepted baseline — patrols will treat every "
                      "failure as news. Bless the current state with "
                      "[bold]wrench comply accept[/bold].[/dim]")
    if brief:
        _comply_brief(cfg, store, report)
    if report["critical_fails"]:
        console.print(f"[bold red]✖ {report['critical_fails']} critical "
                      f"failure(s)[/bold red]")
        raise typer.Exit(1)


def _comply_brief(cfg, store, report: dict) -> None:
    from rich.markdown import Markdown as _Md

    from . import comply as cm
    try:
        client = LLMClient(cfg, store)
        ctxt = cm.narration_context(report)
        with console.status("[cyan]brain triaging failures..."):
            text = client.chat(
                [{"role": "system", "content":
                  "You are wrench, a pragmatic sysadmin agent triaging YOUR "
                  "machine's compliance scan. Group the failures, call out "
                  "what actually matters on a real box vs. checkbox noise, "
                  "and give the 3 highest-value fixes. Be concrete and "
                  "brief. Analysis only — never commands to run blindly."},
                 {"role": "user", "content": ctxt}],
                purpose="comply-brief")
        console.print(Panel(_Md(text), border_style="magenta",
                            title="🧠 brain briefing — analysis only"))
    except Exception as e:  # noqa: BLE001
        console.print(f"[dim]brain briefing unavailable: {e}[/dim]")


@comply_app.command("list")
def comply_list():
    """List shipped packs and their rule counts."""
    from . import comply as cm
    from rich.table import Table as _T
    t = _T(title="📋 shipped compliance packs", border_style="bright_blue")
    t.add_column("pack", style="bold cyan")
    t.add_column("rules", justify="right")
    t.add_column("description", style="dim")
    for p in cm.list_packs():
        t.add_row(p.name, str(len(p.rules)), p.description)
    console.print(t)


@comply_app.command("show")
def comply_show(rule_id: str = typer.Argument(..., help="rule id, e.g. sshd.permitrootlogin")):
    """Show one rule: title, severity, rationale, and its exact check."""
    from . import comply as cm
    hit = cm.find_rule(rule_id)
    if hit is None:
        console.print(f"[red]no rule named {rule_id!r}[/red] — "
                      f"try [bold]wrench comply list[/bold]")
        raise typer.Exit(2)
    pack, rule = hit
    res = cm.run_rule(rule)
    body = Text.assemble(
        (f"{rule.title}\n", "bold"),
        (f"pack {pack.name} · severity {rule.severity}\n\n", "dim"),
        ("why: ", "bold cyan"), (rule.rationale + "\n\n", ""),
        ("check: ", "bold cyan"),
        (json.dumps(rule.check, sort_keys=True) + "\n", "dim"),
        ("now: ", "bold cyan"),
        (f"{res.status} — {res.detail}",
         {"pass": "green", "fail": "red", "skip": "dim"}[res.status]))
    console.print(Panel(body, border_style="bright_blue",
                        title=f"📋 {rule.id}"))


@comply_app.command("accept")
def comply_accept(
    yes: bool = typer.Option(False, "--yes", "-y",
                             help="skip the confirmation prompt (CI use)"),
):
    """Bless the CURRENT failures as accepted debt (consent ceremony)."""
    from . import comply as cm
    cfg, store = _ctx()
    with console.status("[cyan]running packs..."):
        report = cm.scan(store)
    fails = report["fail_ids"]
    console.print(Panel(
        Text.assemble(("about to accept the current compliance failures as "
                       "baseline debt\n", "bold yellow"),
                      (f"{len(fails)} failing rule(s) across "
                       f"{len(report['packs'])} pack(s)\n", "white"),
                      ("patrols will only alarm on NEW failures after this.",
                       "dim")),
        border_style="yellow", title="consent required"))
    if not yes and not typer.confirm("accept this baseline?", default=False):
        console.print("[dim]baseline unchanged.[/dim]")
        raise typer.Exit(0)
    store.add_snapshot(cm.BASELINE_KIND, {"fail_ids": fails})
    from . import audit as _amod
    _amod.log_event(cfg, "comply.baseline.accept",
                    {"fail_count": len(fails),
                     "packs": [p["pack"] for p in report["packs"]]})
    console.print(f"[green]✔ baseline accepted[/green] — {len(fails)} "
                  f"failure(s) recorded as known debt (audit-sealed)")


app.add_typer(comply_app, name="comply")


def _key_env(provider: str) -> str:
    from .config import PROVIDER_DEFAULTS
    return PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["meta"])["key_env"]


def _own_executable() -> str | None:
    """Absolute path of THIS wrench install's entry point.

    The scheduler must run the same install the operator just configured — not
    whichever `wrench` happens to be first on PATH (or none, when the venv was
    never activated).
    """
    import shutil
    cands = [Path(sys.argv[0])]
    exe_dir = Path(sys.executable).parent
    cands += [exe_dir / "wrench", exe_dir / "wrench.exe", exe_dir / "Scripts" / "wrench.exe"]
    for c in cands:
        try:
            if c.name.lower().startswith("wrench") and c.is_file():
                return str(c.resolve())
        except OSError:
            continue
    return shutil.which("wrench")


# ---------------- memory ----------------

def _mem_table(rows: list[dict], title: str) -> Table:
    t = Table(title=title, title_justify="left", box=box.SIMPLE_HEAD, expand=False)
    t.add_column("#", justify="right", style="dim")
    t.add_column("kind")
    t.add_column("from", style="dim")
    t.add_column("memory", overflow="fold")
    t.add_column("used", justify="right", style="dim")
    tag = {"user": "you", "agent": "wrench", "learned": "learned"}
    for m in rows:
        t.add_row(str(m["id"]), ("📌 " if m["pinned"] else "") + m["kind"],
                  tag.get(m["source"], m["source"]), m["text"], str(m["uses"]))
    return t


@app.command("remember")
def remember_cmd(
    text: list[str] = typer.Argument(..., help="what wrench should remember"),
    kind: str = typer.Option("fact", "--kind", "-k",
                             help="preference | fact | procedure | lesson | observation"),
    pin: bool = typer.Option(False, "--pin", help="always bring this to the agent's attention"),
    json_out: bool = JSON_OPT,
):
    """Tell wrench something it should keep in mind from now on.

    wrench remember "nginx on this box is fronted by Cloudflare — 502s are usually upstream"
    wrench remember -k preference "never restart postgres without asking me first"
    """
    from . import memory as mem
    cfg, store = _ctx()
    try:
        m = mem.add(store, " ".join(text), kind, source="user", pinned=pin, cfg=cfg)
    except mem.MemoryError_ as e:
        if json_out:
            jsonout.emit("remember", {"ok": False, "error": str(e)})
        else:
            console.print(f"[red]✖ {e}[/red]")
        raise typer.Exit(2) from None
    finally:
        store.close()
    if json_out:
        jsonout.emit("remember", {"ok": True, "memory": m})
        return
    verb = "already knew that — refreshed" if m.get("duplicate") else "remembered"
    console.print(Text.assemble(("✔ ", "green"), (f"{verb} ", ""), (f"#{m['id']}", "bold"),
                                (f"  [{m['kind']}] {m['text']}", "dim")))


memory_app = typer.Typer(
    help="What wrench remembers: what you told it, what it noticed, what it learned.",
    invoke_without_command=True)


@memory_app.callback(invoke_without_command=True)
def memory_root(ctx: typer.Context,
                kind: str = typer.Option(None, "--kind", "-k", help="only this kind"),
                json_out: bool = JSON_OPT):
    """List what wrench remembers."""
    if ctx.invoked_subcommand is not None:
        return
    from . import memory as mem
    cfg, store = _ctx()
    try:
        rows = mem.list_memories(store, kind=kind)
        pending = mem.list_memories(store, status="pending")
    finally:
        store.close()
    if json_out:
        jsonout.emit("memory", {"memories": rows, "pending": pending,
                                "enabled": mem.settings(cfg)["enabled"]})
        return
    if not rows and not pending:
        console.print(Panel(
            "Nothing yet. Tell me how you want things done, or what is unusual about this "
            "machine:\n\n"
            "  [bold]wrench remember[/bold] \"the 02:00 load spike is the nightly backup — expected\"\n"
            "  [bold]wrench remember -k preference[/bold] \"never restart postgres without asking\"\n\n"
            "[dim]I also keep notes of my own (you approve them first) and learn from what "
            "you do.[/dim]", border_style="bright_blue", title="🧠 wrench memory",
            title_align="left"))
        return
    if rows:
        console.print(_mem_table(rows, f"🧠 {len(rows)} remembered"))
    if pending:
        console.print(Text.assemble(
            (f"{len(pending)} note{'s' if len(pending) != 1 else ''} waiting for your review  ",
             "yellow"), ("wrench memory review", "bold")))
    console.print(Text("forget: wrench memory forget <#>   ·   pin: wrench memory pin <#>   ·   "
                       "search: wrench memory search <words>", style="dim"))


@memory_app.command("search")
def memory_search(query: list[str] = typer.Argument(...), json_out: bool = JSON_OPT):
    """Find memories that mention these words."""
    from . import memory as mem
    cfg, store = _ctx()
    try:
        rows = mem.search(store, " ".join(query))
    finally:
        store.close()
    if json_out:
        jsonout.emit("memory.search", {"query": " ".join(query), "memories": rows})
        return
    if not rows:
        console.print("[dim]nothing in memory matches that[/dim]")
        return
    console.print(_mem_table(rows, f"🧠 {len(rows)} match{'es' if len(rows) != 1 else ''}"))


def _mem_set(mem_id: int, status: str, done: str) -> None:
    from . import memory as mem
    cfg, store = _ctx()
    try:
        m = mem.set_status(store, mem_id, status, cfg=cfg)
    finally:
        store.close()
    if m is None:
        console.print(f"[red]no memory #{mem_id}[/red]")
        raise typer.Exit(1)
    console.print(Text.assemble(("✔ ", "green"), (f"{done} #{mem_id}  ", ""), (m["text"], "dim")))


@memory_app.command("forget")
def memory_forget(mem_id: int = typer.Argument(..., help="memory number")):
    """Forget one memory (kept 30 days in case it was a slip, then deleted)."""
    _mem_set(mem_id, "forgotten", "forgot")


@memory_app.command("approve")
def memory_approve(mem_id: int = typer.Argument(..., help="pending note number")):
    """Approve one of wrench's own notes so it starts using it."""
    _mem_set(mem_id, "active", "approved")


@memory_app.command("reject")
def memory_reject(mem_id: int = typer.Argument(..., help="pending note number")):
    """Reject one of wrench's own notes."""
    _mem_set(mem_id, "rejected", "rejected")


@memory_app.command("pin")
def memory_pin(mem_id: int = typer.Argument(...),
               off: bool = typer.Option(False, "--off", help="unpin")):
    """Pin a memory: the agent sees it on every run, whatever the task."""
    from . import memory as mem
    cfg, store = _ctx()
    try:
        m = mem.set_pinned(store, mem_id, not off)
    finally:
        store.close()
    if m is None:
        console.print(f"[red]no memory #{mem_id}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]✔[/green] {'unpinned' if off else 'pinned'} #{mem_id}")


@memory_app.command("review")
def memory_review():
    """Go through the notes wrench wants to keep: approve, reject, or skip each."""
    from . import memory as mem
    cfg, store = _ctx()
    try:
        pending = mem.list_memories(store, status="pending")
        if not pending:
            console.print("[dim]nothing waiting for review[/dim]")
            return
        if not sys.stdin.isatty():
            console.print(_mem_table(pending, f"{len(pending)} pending"))
            console.print("[dim]approve: wrench memory approve <#>   ·   "
                          "reject: wrench memory reject <#>[/dim]")
            return
        kept = dropped = 0
        for m in pending:
            console.print(Panel(
                Text.assemble((m["text"], "bold white"),
                              (f"\n{m['kind']} · noted {_rel(m['ts'])}"
                               + (f" · during {m['origin']}" if m["origin"] else ""), "dim")),
                border_style="bright_blue", title=f"🧠 note #{m['id']}", title_align="left"))
            ans = typer.prompt("keep it? [y]es / [n]o / [s]kip", default="s").strip().lower()[:1]
            if ans == "y":
                mem.set_status(store, m["id"], "active", cfg=cfg)
                kept += 1
            elif ans == "n":
                mem.set_status(store, m["id"], "rejected", cfg=cfg)
                dropped += 1
        console.print(f"[green]✔[/green] kept {kept}, rejected {dropped}, "
                      f"left {len(pending) - kept - dropped} for later")
    finally:
        store.close()


@memory_app.command("export")
def memory_export():
    """Print every active memory as JSON (to carry to another machine)."""
    from . import memory as mem
    cfg, store = _ctx()
    try:
        print(json.dumps(mem.export(store), indent=2))
    finally:
        store.close()


@memory_app.command("import")
def memory_import(path: str = typer.Argument(..., help="a file written by `wrench memory export`")):
    """Load memories from an export. They become yours (you chose the file)."""
    from pathlib import Path as _P
    from . import memory as mem
    try:
        items = json.loads(_P(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        console.print(f"[red]cannot read {path}: {e}[/red]")
        raise typer.Exit(1) from None
    cfg, store = _ctx()
    try:
        res = mem.import_(store, items, cfg=cfg)
    finally:
        store.close()
    console.print(f"[green]✔[/green] imported {res['added']} · already known "
                  f"{res['duplicates']} · skipped {res['skipped']}")


app.add_typer(memory_app, name="memory")


# ---------------- jobs + heartbeat ----------------

_JOB_STYLE = {"ok": "green", "attention": "yellow", "critical": "bold red", "error": "red"}


def _jobs_table(jobs: list[dict]) -> Table:
    t = Table(title="⏱ scheduled jobs", title_justify="left", box=box.SIMPLE_HEAD)
    for col in ("job", "state", "schedule", "does", "next", "last"):
        t.add_column(col, overflow="fold")
    for j in jobs:
        state = {"active": "[green]active[/green]", "paused": "[yellow]paused[/yellow]",
                 "proposed": "[bright_blue]proposed[/bright_blue]",
                 "done": "[dim]done[/dim]"}.get(j["status"], j["status"])
        does = j["action"] + (f": {(j['args'].get('prompt') or j['args'].get('text') or '')[:48]}"
                              if j["action"] in ("ask", "remind") else "")
        last = "never" if not j["last_run"] else (
            f"[{_JOB_STYLE.get(j['last_status'], 'dim')}]{j['last_status']}[/] "
            f"{_rel(j['last_run'])}")
        t.add_row(j["name"], state, j["schedule"], does,
                  _rel(j["next_run"]) if j["status"] == "active" else "—", last)
    return t


jobs_app = typer.Typer(
    help="Scheduled work the heartbeat runs: patrols, scans, briefs, reminders, questions.",
    invoke_without_command=True)


@jobs_app.callback(invoke_without_command=True)
def jobs_root(ctx: typer.Context, json_out: bool = JSON_OPT):
    """List scheduled jobs."""
    if ctx.invoked_subcommand is not None:
        return
    from . import heartbeat as hb
    cfg, store = _ctx()
    try:
        jobs = hb.list_jobs(store)
        pu = hb.pulse(store)
    finally:
        store.close()
    if json_out:
        jsonout.emit("jobs", {"jobs": jobs, "heartbeat": pu})
        return
    live = [j for j in jobs if j["status"] != "done"]
    if not live:
        console.print(Panel(
            "No scheduled jobs yet.\n\n"
            "  [bold]wrench install-service[/bold]                      start the heartbeat + patrol\n"
            "  [bold]wrench jobs add brief \"weekdays 08:30\" brief[/bold]   a morning brief\n"
            "  [bold]wrench jobs add tls \"mon 09:00\" certs[/bold]          weekly certificate check\n"
            "  [bold]wrench jobs add growth \"every 6h\" ask -p \"is /var growing faster than "
            "usual?\"[/bold]", border_style="bright_blue", title="⏱ wrench jobs",
            title_align="left"))
        return
    console.print(_jobs_table(live))
    for j in live:
        if j["status"] == "proposed":
            console.print(Text.assemble(
                ("proposed  ", "bold bright_blue"), (j["name"], "bold"), (f" — {j['note']}", ""),
                # the whole text that would run — never a truncated preview
                (f"\n          would run: {j['action']}"
                 + (f": {j['args'].get('prompt') or j['args'].get('text')}"
                    if j["args"].get("prompt") or j["args"].get("text") else ""), ""),
                (f"\n          approve: wrench jobs approve {j['name']}   ·   "
                 f"decline: wrench jobs rm {j['name']}", "dim")))
    if pu["alive"] is None:
        console.print(Text.assemble(("heartbeat is not running — nothing will fire.  ", "yellow"),
                                    ("wrench install-service", "bold")))
    elif not pu["alive"]:
        console.print(Text.assemble((f"heartbeat has been silent since {_rel(pu['last_tick'])}.  ",
                                     "red"), ("wrench install-service", "bold")))
    else:
        console.print(Text(f"heartbeat alive · last beat {_rel(pu['last_tick'])}", style="dim"))


@jobs_app.command("add")
def jobs_add(
    name: str = typer.Argument(..., help="short name, e.g. morning-brief"),
    schedule: str = typer.Argument(..., help="'every 15m' · 'daily 08:30' · 'weekdays 9am' · "
                                             "'mon,thu 18:00' · 'in 2h' · cron"),
    action: str = typer.Argument(..., help="patrol | brief | score | security | comply | backups "
                                           "| cve | certs | drift | forecast | remind | ask"),
    prompt: str = typer.Option("", "--prompt", "-p",
                               help="for `ask`: the task; for `remind`: the reminder text"),
    notify: str = typer.Option("", "--notify", help="always | attention | never"),
):
    """Add a scheduled job.

    wrench jobs add morning-brief "weekdays 08:30" brief
    wrench jobs add tls-check "mon 09:00" certs
    wrench jobs add growth "every 6h" ask -p "is /var growing faster than usual?"
    wrench jobs add renew "at 2026-12-01 09:00" remind -p "renew the wildcard cert"
    """
    from . import heartbeat as hb
    cfg, store = _ctx()
    args: dict = {}
    if prompt:
        args["text" if action == "remind" else "prompt"] = prompt
    if notify:
        args["notify"] = notify
    try:
        job = hb.add_job(store, name, schedule, action, args, cfg=cfg)
        alive = hb.pulse(store)["alive"]
    except hb.HeartbeatError as e:
        console.print(f"[red]✖ {e}[/red]")
        raise typer.Exit(2) from None
    finally:
        store.close()
    console.print(Text.assemble(
        ("✔ ", "green"), ("scheduled ", ""), (job["name"], "bold"),
        (f"  {job['schedule']} → {job['action']} · first run {_rel(job['next_run'])}", "dim")))
    if not alive:
        console.print(Text.assemble(("the heartbeat is not running yet — start it with  ", "yellow"),
                                    ("wrench install-service", "bold")))


def _job_action(ref: str, fn, done: str) -> None:
    from . import heartbeat as hb
    cfg, store = _ctx()
    try:
        res = fn(hb, cfg, store)
    except hb.HeartbeatError as e:
        console.print(f"[red]✖ {e}[/red]")
        raise typer.Exit(2) from None
    finally:
        store.close()
    if not res:
        console.print(f"[red]no job '{ref}'[/red] — see: wrench jobs")
        raise typer.Exit(1)
    console.print(f"[green]✔[/green] {done} [bold]{ref}[/bold]")


@jobs_app.command("approve")
def jobs_approve(name: str = typer.Argument(...)):
    """Approve a job wrench proposed; it starts running on its schedule."""
    _job_action(name, lambda hb, c, s: hb.set_job_status(s, name, "active", cfg=c), "approved")


@jobs_app.command("resume")
def jobs_resume(name: str = typer.Argument(...)):
    """Resume a paused job."""
    _job_action(name, lambda hb, c, s: hb.set_job_status(s, name, "active", cfg=c), "resumed")


@jobs_app.command("pause")
def jobs_pause(name: str = typer.Argument(...)):
    """Pause a job without deleting it."""
    _job_action(name, lambda hb, c, s: hb.set_job_status(s, name, "paused", cfg=c), "paused")


@jobs_app.command("rm")
def jobs_rm(name: str = typer.Argument(...)):
    """Delete a job (or decline a proposal)."""
    _job_action(name, lambda hb, c, s: hb.remove_job(s, name, cfg=c), "removed")


@jobs_app.command("run")
def jobs_run(name: str = typer.Argument(...), json_out: bool = JSON_OPT):
    """Run one job right now, whatever its schedule."""
    from . import heartbeat as hb
    cfg, store = _ctx()
    try:
        job = hb.get_job(store, name)
        if job is None:
            console.print(f"[red]no job '{name}'[/red] — see: wrench jobs")
            raise typer.Exit(1)
        if json_out:
            res = hb.run_job(cfg, store, job)
        else:
            with console.status(f"[cyan]running {job['name']} ({job['action']})..."):
                res = hb.run_job(cfg, store, job)
    finally:
        store.close()
    if json_out:
        jsonout.emit("jobs.run", res)
    else:
        console.print(Panel(Text(res["summary"] or "(no output)"),
                            border_style=_JOB_STYLE.get(res["status"], "dim").replace("bold ", ""),
                            title=f"⏱ {res['name']} · {res['status']} · {res['duration_s']}s",
                            title_align="left"))
    raise typer.Exit(0 if res["status"] in ("ok", "attention") else 2)


@jobs_app.command("log")
def jobs_log(name: str = typer.Argument(None, help="one job (default: all)"),
             limit: int = typer.Option(20, "--limit", "-n"), json_out: bool = JSON_OPT):
    """What ran, when, and how it went."""
    from . import heartbeat as hb
    cfg, store = _ctx()
    try:
        runs = hb.job_runs(store, name, limit)
    finally:
        store.close()
    if json_out:
        jsonout.emit("jobs.log", {"runs": runs})
        return
    if not runs:
        console.print("[dim]no runs recorded yet[/dim]")
        return
    t = Table(box=box.SIMPLE_HEAD)
    for col in ("when", "job", "result", "took", "summary"):
        t.add_column(col, overflow="fold")
    for r in runs:
        t.add_row(_rel(r["ts"]), r["name"],
                  f"[{_JOB_STYLE.get(r['status'], 'dim')}]{r['status']}[/]",
                  f"{r['duration_s'] or 0:.1f}s", (r["summary"] or "").replace("\n", " ⏎ ")[:140])
    console.print(t)


app.add_typer(jobs_app, name="jobs")


@app.command("heartbeat")
def heartbeat_cmd(
    quiet: bool = typer.Option(False, "--quiet", "-q", help="print only when a job needs attention"),
    loop: bool = typer.Option(False, "--loop", help="keep beating in the foreground (no OS timer)"),
    status: bool = typer.Option(False, "--status", help="is the heartbeat alive? what is next?"),
    json_out: bool = JSON_OPT,
):
    """One beat: run every scheduled job that is due. `install-service` runs
    this on a timer; `--loop` keeps it going where there is no timer."""
    from . import heartbeat as hb
    if status:
        cfg, store = _ctx()
        try:
            pu = hb.pulse(store)
        finally:
            store.close()
        if json_out:
            jsonout.emit("heartbeat.status", pu)
        elif pu["alive"] is None:
            console.print("heartbeat has never run — start it with [bold]wrench install-service[/bold]")
        else:
            style = "green" if pu["alive"] else "red"
            console.print(Text.assemble(
                ("● ", style), ("alive" if pu["alive"] else "silent", f"bold {style}"),
                (f" · last beat {_rel(pu['last_tick'])} · {pu['ticks']} beats · "
                 f"{pu['jobs']['active']} active job(s)", ""),
                (f" · next: {pu['next']['name']} {_rel(pu['next']['at'])}" if pu["next"] else "",
                 "dim")))
        raise typer.Exit(0 if pu["alive"] else 1)

    def show(res: dict) -> None:
        if json_out:
            jsonout.emit("heartbeat", res)
            return
        if res["skipped"]:
            if not quiet:
                console.print(f"[dim]skipped — {res['skipped']}[/dim]")
            return
        for r in res["ran"]:
            if quiet and r["status"] == "ok":
                continue
            console.print(Text.assemble(
                ("⏱ ", "dim"), (r["name"], "bold"), (" ", ""),
                (r["status"], _JOB_STYLE.get(r["status"], "dim")),
                (f"  {(r['summary'] or '').splitlines()[0][:150] if r['summary'] else ''}", "dim")))
        for j in res["proposals"]:
            console.print(Text.assemble(("proposal  ", "bold bright_blue"), (j["note"], ""),
                                        (f"  wrench jobs approve {j['name']}", "dim")))
        if not res["ran"] and not res["proposals"] and not quiet:
            console.print("[dim]♥ beat — nothing due[/dim]")

    if loop:
        if not json_out:
            console.print("[bold]wrench heartbeat[/bold] — beating every 60s. Ctrl-C to stop.")
        try:
            hb.run_loop(lambda: _ctx(), on_tick=show)
        except KeyboardInterrupt:
            console.print("\n[dim]heartbeat stopped[/dim]")
        return
    cfg, store = _ctx()
    try:
        res = hb.tick(cfg, store)
    finally:
        store.close()
    show(res)



@app.command("install-service")
def install_service(
    interval: int = typer.Option(15, "--interval", help="minutes between patrols"),
    uninstall: bool = typer.Option(False, "--uninstall", help="remove the scheduled patrol"),
    with_auto_fixxer: bool = typer.Option(
        False, "--with-auto-fixxer",
        help="ALSO schedule a daily `wrench fixxer --auto` run (requires prior "
             "`wrench fixxer --setup-auto` consent; safe-tier only by default)"),
    fixxer_hour: int = typer.Option(4, "--fixxer-hour", help="hour of day for the auto-fixxer run"),
):
    """Start the heartbeat: one native timer (systemd, launchd, Task Scheduler)
    that runs the patrol and every other scheduled job."""

    from . import scheduler

    try:
        if uninstall:
            plan = scheduler.plan_uninstall()
            lines = scheduler.apply_plan(plan, uninstall=True)
            console.print(Panel("\n".join(["[green]removed the heartbeat timer[/green]", *lines]),
                                border_style="green", title="🔧 wrench install-service"))
            return
        wrench_bin = _own_executable()
        if not wrench_bin:
            console.print("[red]couldn't find the wrench executable for this install[/red]")
            raise typer.Exit(1)
        from . import heartbeat as _hb
        cfg, _store = _ctx()
        try:
            tick_min = max(1, min(_hb.settings(cfg)["tick_min"], interval))
            plan = scheduler.plan_install(wrench_bin, tick_min)
            scheduler.apply_plan(plan)
            _hb.ensure_defaults(cfg, _store, patrol_every_min=interval)
        finally:
            _store.close()
        fixxer_note = ""
        if with_auto_fixxer:
            from . import fixxer as fx
            cfg, _store = _ctx()
            if not fx.load_consent(cfg):
                console.print(Panel(
                    "[red]--with-auto-fixxer needs consent first.[/red]\n"
                    "Run [bold]wrench fixxer --setup-auto[/bold], then re-run this command.",
                    border_style="red", title="\u26a0 consent required"))
                raise typer.Exit(2)
            fplan = scheduler.plan_install_fixxer(wrench_bin, fixxer_hour)
            scheduler.apply_plan(fplan)
            fixxer_note = (f"\n[yellow]auto-fixxer scheduled daily @ {fixxer_hour:02d}:00[/yellow] "
                           f"({fplan.kind}) \u2014 tiers: "
                           f"{', '.join(fx.effective_auto_tiers(cfg)) or 'none (check consent/config)'}\n"
                           f"[dim]audit log: {fx.audit_path(cfg)} \u00b7 remove: wrench install-service --uninstall[/dim]")
    except scheduler.SchedulerError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None
    console.print(Panel(
        f"[green]installed + started[/green] the heartbeat via [bold]{plan.kind}[/bold] "
        f"(beats every {tick_min}min · patrol every {interval}min)\n"
        "[dim]jobs:      wrench jobs   (add, pause, or approve scheduled work)[/dim]\n"
        f"[dim]check:     {plan.check_hint}\n"
        f"uninstall: {plan.uninstall_hint}\n"
        "note: the service needs your provider API key; set\n"
        f"  api_key_file = \"/path/to/keyfile\" in {CONFIG_PATH}[/dim]"
        + fixxer_note,
        border_style="green", title="🔧 wrench install-service"))


@app.command("notifications")
def notifications_cmd(
    all_: bool = typer.Option(False, "--all", help="include already-read notifications"),
    last: int = typer.Option(50, "--last", "-n", help="max notifications to list"),
    mark_read: bool = typer.Option(False, "--mark-read", help="mark listed unread as read"),
    json_out: bool = JSON_OPT,
):
    """List patrol/subsystem notifications from the inbox."""
    from . import notifications as notif
    cfg, _store = _ctx()
    rows = notif.read_all(cfg.data_dir)
    unread = [r for r in rows if not r.get("read")]
    shown = (rows if all_ else unread)[-last:]
    if json_out:
        jsonout.emit("notifications", {
            "count": len(shown),
            "unread_count": len(unread),
            "notifications": shown,
        })
    elif not shown:
        console.print("[dim]no " + ("" if all_ else "unread ")
                      + "notifications — the box is quiet[/dim]")
    else:
        t = Table(title="🔔 notifications", border_style="bright_blue")
        t.add_column("when")
        t.add_column("severity")
        t.add_column("summary", max_width=70)
        t.add_column("read", justify="center")
        for r in shown:
            t.add_row(time.strftime("%m-%d %H:%M", time.localtime(r.get("ts", 0))),
                      _sev_text(r.get("severity", "")), r.get("summary", ""),
                      "✓" if r.get("read") else "")
        console.print(t)
    if mark_read and unread:
        n = notif.mark_read(cfg.data_dir, [r["id"] for r in shown if not r.get("read")])
        if not json_out:
            console.print(f"[dim]marked {n} read[/dim]")


@app.command("bundle")
def bundle_cmd(
    out: str = typer.Option(None, "--out", "-o",
                            help="output path (default ./wrench-bundle-<host>-<date>.tar.gz)"),
    json_out: bool = JSON_OPT,
):
    """Package everything wrench knows into one portable tar.gz for sneakernet.

    The air-gap answer to "email me the state of the box": latest patrol, status,
    drift, security, comply, backups, forecast, audit chain (+verify),
    notifications tail, versions — as JSON + a human-readable SUMMARY.md. No
    secrets (config key material is redacted).
    """
    from . import bundle as bmod
    cfg, store = _ctx()
    out_path, sections = bmod.build(cfg, store, out_path=out)
    size = out_path.stat().st_size
    if json_out:
        jsonout.emit("bundle", {
            "path": str(out_path),
            "bytes": size,
            "files": sorted(list(sections.keys()) + ["SUMMARY.md"]),
            "offline": sections.get("offline.json", {}).get("offline", False),
        })
        return
    console.print(Panel(
        Text.assemble(
            ("wrote ", ""), (str(out_path), "bold white"),
            (f"\n{size // 1024 or 1} KB · {len(sections) + 1} files · no secrets "
             "(config redacted)", "dim"),
            ("\n\ncarry it on a USB stick; unpack with: ", "dim"),
            (f"tar xzf {out_path.name}", "bold cyan"),
        ),
        border_style="green", title="📦 wrench bundle"))


def _doctor_facts(cfg, store) -> dict:
    """Environment facts shared by `doctor` and `doctor --json`."""
    import os as _os
    from . import audit as _audit, fleet as _fleet
    facts: dict = {"admin": platforms.is_admin(), "schema_version": store.schema_version}
    try:
        facts["data_dir_mode"] = (oct(cfg.data_dir.stat().st_mode & 0o777)
                                  if _os.name == "posix" else None)
    except OSError:
        facts["data_dir_mode"] = None
    v = _audit.verify(cfg.data_dir)
    facts["audit"] = {"intact": v["intact"], "count": v["count"], "reason": v["reason"],
                      "mac_checked": v.get("mac_checked", False)}
    patrols = store.recent_patrols(1)
    facts["last_patrol_age_s"] = (time.time() - patrols[0]["ts"]) if patrols else None
    st = _fleet.settings_from(cfg)
    roles = []
    if st.node_enabled:
        roles.append(f"node → {st.hub_url} (as {st.node_id})")
    if _fleet.hub_active(store, st):
        roles.append(f"hub ({len(store.fleet_nodes())} node(s) known)")
    facts["fleet"] = " · ".join(roles)
    return facts


@app.command()
def doctor(provider: str = PROVIDER_OPT, model: str = MODEL_OPT,
           json_out: bool = JSON_OPT):
    """Check config, data store, sensors, and provider connectivity."""
    cfg, store = _ctx(provider, model)
    if json_out:
        caps = platforms.capabilities()
        checks: dict = {
            "platform": caps["platform"],
            "scheduler": caps["service_manager"],
            "log_backend": caps["log_backend"],
            "config_path": str(CONFIG_PATH) if CONFIG_PATH.exists() else None,
            "provider": cfg.provider,
            "base_url": cfg.base_url,
            "model": cfg.model,
            "deep_model": cfg.deep_model,
            "policy_tier": cfg.policy_tier,
            "api_key_present": bool(cfg.api_key
                                    or cfg.provider in ("ollama", "lmstudio")),
            "db_path": str(cfg.db_path),
        }
        from . import offline as _offline
        checks["offline"] = _offline.status_summary(cfg)
        checks["offline"]["brain_is_local"] = _offline.url_is_private(cfg.base_url)
        try:
            s = sensors.sample_os()
            checks["sensor_os"] = {"ok": True, "cpu_pct": s["cpu_pct"],
                                   "mem_pct": s["mem_pct"]}
        except Exception as e:  # noqa: BLE001
            checks["sensor_os"] = {"ok": False, "error": str(e)}
        checks["sensor_docker"] = sensors.sample_docker() is not None
        checks["sensor_gpu"] = sensors.sample_gpu() is not None
        usable, why = agent_mod.brain_status(cfg)
        checks["brain"] = {"configured": usable, "reason": why}
        if usable:
            client = LLMClient(cfg, store)
            alive, detail = client.ping()
        else:
            # no brain is a supported mode (deterministic patrols), not a fault
            alive, detail = True, f"deterministic mode — {why}"
        checks["provider_ping"] = {"ok": alive, "detail": detail}
        checks.update(_doctor_facts(cfg, store))
        jsonout.emit("doctor", {"healthy": bool(alive) and checks["audit"]["intact"],
                                "checks": checks})
        if not alive or not checks["audit"]["intact"]:
            raise typer.Exit(1)
        return
    t = Table(title="🔧 wrench doctor", border_style="bright_blue", show_header=False)
    t.add_column(style="bold", justify="right")
    t.add_column()

    ok = Text("✔ ok", style="green")

    caps = platforms.capabilities()
    t.add_row("version", Text(__version__))
    t.add_row("platform", Text(f"{caps['platform']} ({platform.system()} {platform.release()})"))
    t.add_row("scheduler", Text(caps["service_manager"] or "— none (use `wrench watch`)",
                                style="green" if caps["service_manager"] else "yellow"))
    t.add_row("log reader", Text(caps["log_backend"] or "— none found",
                                 style="green" if caps["log_backend"] else "yellow"))
    t.add_row("config", Text(str(CONFIG_PATH) if CONFIG_PATH.exists()
                             else "(defaults — run wrench init)", style="dim"))
    t.add_row("provider", Text(f"{cfg.provider} @ {cfg.base_url}"))
    t.add_row("model", Text(f"{cfg.model} (deep: {cfg.deep_model})"))
    t.add_row("policy tier", Text(cfg.policy_tier,
                                  style="green" if cfg.policy_tier in ("observe", "suggest")
                                  else "yellow"))
    usable, why = agent_mod.brain_status(cfg)
    if usable:
        t.add_row("brain", Text("✔ configured", style="green"))
    else:
        t.add_row("brain", Text(f"— deterministic mode ({why}). Patrols, score, fleet and "
                                "every check still run; `wrench init` adds a model for "
                                "investigation and chat.", style="yellow"))
    # offline-awareness: on an air-gapped box, show what's disabled and verify
    # the brain endpoint is local/private (so doctor can still pass clean).
    from . import offline as _offline
    if _offline.is_offline(cfg):
        brain_local = _offline.url_is_private(cfg.base_url)
        t.add_row("offline mode", Text("✔ ON — zero egress enforced", style="green"))
        t.add_row("  disabled", Text("CVE/OSV · endoflife.date · webintel · "
                                     "update checks · public provider calls", style="dim"))
        t.add_row("  brain endpoint",
                  Text(f"✔ local/private ({cfg.base_url})", style="green") if brain_local
                  else Text(f"✖ {cfg.base_url} is NOT local/private — the brain is "
                            "unreachable in offline mode", style="red"))
    else:
        t.add_row("offline mode", Text("off (normal egress)", style="dim"))
    t.add_row("data store", Text(f"{cfg.db_path} "
                                 f"({cfg.db_path.stat().st_size // 1024} KB)"
                                 if cfg.db_path.exists() else "(will be created)", style="dim"))

    # sensors
    try:
        s = sensors.sample_os()
        t.add_row("sensor: os", Text(f"✔ cpu {s['cpu_pct']}% mem {s['mem_pct']}%", style="green"))
    except Exception as e:  # noqa: BLE001
        t.add_row("sensor: os", Text(f"✖ {e}", style="red"))
    t.add_row("sensor: docker", ok if sensors.sample_docker() is not None
              else Text("— not available", style="dim"))
    t.add_row("sensor: gpu", ok if sensors.sample_gpu() is not None
              else Text("— not available", style="dim"))

    facts = _doctor_facts(cfg, store)
    t.add_row("privileges", Text("administrator — full visibility", style="green")
              if facts["admin"] else
              Text("standard user — checks that need root are reported as skipped, "
                   "never as passing", style="dim"))
    perms = facts["data_dir_mode"]
    t.add_row("data privacy", Text(f"✔ data dir {perms} (owner-only)", style="green")
              if perms in ("0o700", None) else
              Text(f"⚠ data dir is {perms} — expected 0o700", style="yellow"))
    a = facts["audit"]
    t.add_row("audit chain", Text(f"✔ intact — {a['count']} event(s)"
                                  + (" · MAC verified" if a.get("mac_checked") else ""),
                                  style="green") if a["intact"]
              else Text(f"✖ {a['reason']}", style="bold red"))
    lp = facts["last_patrol_age_s"]
    if lp is None:
        t.add_row("patrols", Text("— none yet (run `wrench patrol`, then "
                                  "`wrench install-service`)", style="dim"))
    else:
        late = lp > max(cfg.patrol_interval_min * 60 * 4, 6 * 3600)
        t.add_row("patrols", Text(f"last ran {lp / 3600:.1f}h ago"
                                  + (" — not running on schedule? `wrench install-service`"
                                     if late else ""), style="yellow" if late else "green"))
    if facts["fleet"]:
        t.add_row("fleet", Text(facts["fleet"], style="dim"))
    t.add_row("schema", Text(f"v{facts['schema_version']}", style="dim"))

    # provider liveness (only when there is a brain to reach)
    alive = True
    if usable:
        with console.status(f"[cyan]pinging {cfg.provider}..."):
            client = LLMClient(cfg, store)
            alive, detail = client.ping()
        t.add_row("provider ping", Text(f"✔ {detail}", style="green") if alive
                  else Text(f"✖ {detail}", style="red"))

    console.print(t)
    if not alive or not a["intact"]:
        raise typer.Exit(1)


_apply_help_panels()

if __name__ == "__main__":
    app()
