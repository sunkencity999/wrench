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


def _key_env(provider: str) -> str:
    from .config import PROVIDER_DEFAULTS
    return PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["meta"])["key_env"]


@app.command("install-service")
def install_service(
    interval: int = typer.Option(15, "--interval", help="minutes between patrols"),
    uninstall: bool = typer.Option(False, "--uninstall", help="remove the scheduled patrol"),
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
    except scheduler.SchedulerError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None
    console.print(Panel(
        f"[green]installed + started[/green] scheduled patrol via [bold]{plan.kind}[/bold] "
        f"(every {interval}min)\n"
        f"[dim]check:     {plan.check_hint}\n"
        f"uninstall: {plan.uninstall_hint}\n"
        "note: the service needs your provider API key; set\n"
        f"  api_key_file = \"/path/to/keyfile\" in {CONFIG_PATH}[/dim]",
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
