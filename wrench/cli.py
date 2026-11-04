"""wrench CLI — typer app."""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, agent as agent_mod, driftscan, platforms, report, sensors
from .config import CONFIG_PATH, load_config, write_default_config
from .providers import LLMClient
from .store import Store

app = typer.Typer(
    help="🔧 wrench — an intentional local sysadmin agent. It watches, diagnoses, "
    "explains, and (with permission) fixes.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def _ctx(provider: str | None = None, model: str | None = None):
    cfg = load_config(provider_override=provider, model_override=model)
    store = Store(cfg.db_path)
    return cfg, store


def _confirm(command: str, label: str) -> bool:
    console.print(Panel(
        Text.assemble(("about to execute: ", "bold yellow"), (command, "bold white"),
                      (f"\n({label})", "dim")),
        border_style="yellow", title="confirmation required"))
    return typer.confirm("run it?", default=False)


PROVIDER_OPT = typer.Option(None, "--provider", "-p", help="meta|openai|anthropic|ollama|lmstudio|litellm")
MODEL_OPT = typer.Option(None, "--model", "-m", help="model override")


# ---------------- commands ----------------

@app.command()
def version():
    """Print version."""
    console.print(f"wrench {__version__}")


@app.command()
def status():
    """One-screen health: gauges, sparklines, anomalies."""
    cfg, store = _ctx()
    with console.status("[cyan]sampling sensors..."):
        data = sensors.status_snapshot(store)
        history = store.recent_samples("os", 86400)
    report.render_status(console, data, history, cfg)


@app.command()
def ask(
    question: list[str] = typer.Argument(..., help="your question for the agent"),
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
    deep: bool = typer.Option(False, "--deep", help="use the deep-reasoning model"),
):
    """Ask the agent one question. It may run read-only diagnostics to answer."""
    cfg, store = _ctx(provider, model)
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
    """Interactive conversation with your sysadmin. Ctrl-D or 'exit' to leave."""
    cfg, store = _ctx(provider, model)
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
):
    """Run one patrol: observe → investigate → report. The heart of wrench."""
    cfg, store = _ctx(provider, model)
    steps_seen: list[str] = []

    def on_step(kind, detail):
        steps_seen.append(detail)
        if not quiet:
            console.print(f"  [dim cyan]⚙ {detail}[/dim cyan]")

    if not quiet:
        console.print(f"[dim]patrolling with {cfg.deep_model if deep else cfg.model} "
                      f"(tier: {cfg.policy_tier})...[/dim]")
    p = agent_mod.run_patrol(cfg, store, on_step=on_step, deep=deep)
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
):
    """Scan for drift: what changed on this box since last scan?"""
    cfg, store = _ctx(provider)
    first = not driftscan.baseline_exists(store)
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
):
    """Show recent patrol reports."""
    cfg, store = _ctx()
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


@app.command()
def web(
    port: int = typer.Option(None, "--port", help="port (default from config, 8787)"),
    bind: str = typer.Option("127.0.0.1", "--bind", help="bind address"),
    no_sample: bool = typer.Option(False, "--no-sample", help="don't sample in the background"),
):
    """Serve the live dashboard (dark, gorgeous, auto-refreshing)."""
    from .webapp import serve

    cfg, store = _ctx()
    store.close()
    port = port or cfg.web_port
    httpd = serve(cfg.db_path, port=port, host_label=platform.node() or "localhost",
                  bind=bind, sample_thread=not no_sample)
    console.print(Panel(
        f"dashboard live at [bold bright_blue]http://{bind}:{port}[/bold bright_blue]\n"
        f"[dim]sampling every 30s in the background · Ctrl-C to stop[/dim]",
        border_style="bright_blue", title="🔧 wrench web"))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[dim]dashboard stopped[/dim]")


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
    ("meta", "Meta muse models — hosted, default"),
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic Claude"),
    ("ollama", "Ollama — local, private + free, guided setup"),
    ("lmstudio", "LM Studio — local server"),
    ("litellm", "LiteLLM — proxy to anything"),
]


def _isatty() -> bool:
    import sys
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _choose_provider() -> str:
    """Interactive provider menu. Enter = meta."""
    t = Table(title="🔧 choose your model provider", border_style="bright_blue",
              show_header=False, pad_edge=True)
    t.add_column(justify="right", style="bold cyan")
    t.add_column(style="bold")
    t.add_column(style="dim")
    for i, (name, blurb) in enumerate(PROVIDER_MENU, 1):
        t.add_row(str(i), name + (" (default)" if name == "meta" else ""), blurb)
    console.print(t)
    raw = typer.prompt("provider [1-6 or name]", default="1", show_default=False).strip().lower()
    names = [n for n, _ in PROVIDER_MENU]
    if raw.isdigit() and 1 <= int(raw) <= len(names):
        return names[int(raw) - 1]
    if raw in names:
        return raw
    console.print(f"[yellow]unknown choice {raw!r} — using meta[/yellow]")
    return "meta"


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


@app.command()
def init(
    provider: str = typer.Option(None, "--provider", "-p",
                                 help="meta|openai|anthropic|ollama|lmstudio|litellm "
                                      "(omit for interactive menu)"),
    model: str = typer.Option(None, "--model", "-m", help="model tag override"),
    yes: bool = typer.Option(False, "--yes", "-y",
                             help="non-interactive: accept defaults/recommendations "
                                  "(consents to ollama install + model pull)"),
    force: bool = typer.Option(False, "--force", help="overwrite existing config"),
):
    """Set up wrench: pick a provider (interactive menu), write config, record baselines."""
    interactive = _isatty() and not yes
    if provider is None:
        if interactive:
            provider = _choose_provider()
        else:
            provider = "meta"
            console.print("[dim]no TTY — defaulting to the meta provider. "
                          "Re-run `wrench init --force` in a terminal for the menu, or use "
                          "`wrench init -p <provider> --force`.[/dim]")
    provider = provider.lower()
    from .config import PROVIDER_DEFAULTS
    if provider not in PROVIDER_DEFAULTS:
        console.print(f"[red]unknown provider {provider!r} — choose from: "
                      f"{', '.join(PROVIDER_DEFAULTS)}[/red]")
        raise typer.Exit(1)

    if CONFIG_PATH.exists() and not force:
        console.print(f"[yellow]config already exists:[/yellow] {CONFIG_PATH} (use --force)")
    else:
        if provider == "ollama":
            model = _ollama_guided_setup(interactive, yes, model)
        p = write_default_config(provider, model=model)
        console.print(f"[green]wrote[/green] {p}")
    cfg, store = _ctx()
    with console.status("[cyan]recording first sensor sample + drift baseline..."):
        sensors.sample_all(store)
        driftscan.scan(store)

    smoke_note = ""
    if cfg.provider == "ollama":
        from . import localsetup
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
    console.print(Panel(
        f"provider: [bold]{cfg.provider}[/bold] · model: [bold]{cfg.model}[/bold] · "
        f"policy: [bold]{cfg.policy_tier}[/bold]\n"
        f"data: {cfg.db_path}{smoke_note}\n\n"
        "next steps:\n"
        + (""
           if cfg.provider in ("ollama", "lmstudio")
           else f"  1. export {_key_env(cfg.provider)}=...   (or set api_key_file in config)\n")
        + ("  1. (no API key needed — it's your hardware)\n"
           if cfg.provider in ("ollama", "lmstudio") else "")
        +
        "  2. wrench doctor      — verify everything\n"
        "  3. wrench patrol      — first patrol\n"
        "  4. wrench web         — dashboard",
        border_style="green", title="🔧 wrench initialized"))


RISK_STYLE = {"safe": "green", "moderate": "yellow", "risky": "red"}


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
    provider: str = PROVIDER_OPT,
    model: str = MODEL_OPT,
):
    """Find what I can fix \u2014 updates, bloat, failed services \u2014 and fix it with your OK."""
    from . import fixxer as fx

    cfg, store = _ctx(provider, model)

    if revoke_auto:
        if fx.revoke_consent(cfg):
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


def _key_env(provider: str) -> str:
    from .config import PROVIDER_DEFAULTS
    return PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["meta"])["key_env"]


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
    """Schedule patrols natively: systemd (Linux), launchd (macOS), or Task Scheduler (Windows)."""
    import shutil

    from . import scheduler

    try:
        if uninstall:
            plan = scheduler.plan_uninstall()
            lines = scheduler.apply_plan(plan, uninstall=True)
            console.print(Panel("\n".join(["[green]removed scheduled patrol[/green]", *lines]),
                                border_style="green", title="🔧 wrench install-service"))
            return
        wrench_bin = shutil.which("wrench")
        if not wrench_bin:
            console.print("[red]couldn't find the wrench binary on PATH[/red]")
            raise typer.Exit(1)
        plan = scheduler.plan_install(wrench_bin, interval)
        scheduler.apply_plan(plan)
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
        f"[green]installed + started[/green] scheduled patrol via [bold]{plan.kind}[/bold] "
        f"(every {interval}min)\n"
        f"[dim]check:     {plan.check_hint}\n"
        f"uninstall: {plan.uninstall_hint}\n"
        "note: the service needs your provider API key; set\n"
        f"  api_key_file = \"/path/to/keyfile\" in {CONFIG_PATH}[/dim]"
        + fixxer_note,
        border_style="green", title="🔧 wrench install-service"))


@app.command()
def doctor(provider: str = PROVIDER_OPT, model: str = MODEL_OPT):
    """Check config, data store, sensors, and provider connectivity."""
    cfg, store = _ctx(provider, model)
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
    t.add_row("api key", ok if cfg.api_key or cfg.provider in ("ollama", "lmstudio")
              else Text(f"✖ missing (set {_key_env(cfg.provider)})", style="red"))
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

    # provider liveness
    with console.status(f"[cyan]pinging {cfg.provider}..."):
        client = LLMClient(cfg, store)
        alive, detail = client.ping()
    t.add_row("provider ping", Text(f"✔ {detail}", style="green") if alive
              else Text(f"✖ {detail}", style="red"))

    console.print(t)
    if not alive:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
