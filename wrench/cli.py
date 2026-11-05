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
    help="🔧 wrench — I'm the sysadmin that lives on your machine. I watch, remember, "
    "explain, and — with your permission — fix.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()


def _ctx(provider: str | None = None, model: str | None = None):
    cfg = load_config(provider_override=provider, model_override=model)
    store = Store(cfg.db_path)
    return cfg, store


def _notify_banner(cfg) -> None:
    """One-line heads-up when unread patrol notifications exist. Never fatal."""
    try:
        from . import notifications
        n = len(notifications.unread(cfg.data_dir))
        if n:
            console.print(
                f"[bold yellow]\U0001f514 {n} new patrol finding{'s' if n != 1 else ''} "
                f"since you last looked[/bold yellow] [dim]\u2014 run `wrench report`[/dim]")
    except Exception:  # noqa: BLE001
        pass


def _confirm(command: str, label: str) -> bool:
    console.print(Panel(
        Text.assemble(("about to execute: ", "bold yellow"), (command, "bold white"),
                      (f"\n({label})", "dim")),
        border_style="yellow", title="confirmation required"))
    return typer.confirm("run it?", default=False)


PROVIDER_OPT = typer.Option(None, "--provider", "-p",
                            help="ollama|lmstudio|openai|anthropic|meta|azure|litellm")
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
    _notify_banner(cfg)
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
    """Interactive conversation with your sysadmin. Ctrl-D or 'exit' to leave."""
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
):
    """Run one patrol: observe → investigate → report. The heart of wrench."""
    cfg, store = _ctx(provider, model)
    steps_seen: list[str] = []

    def on_step(kind, detail):
        steps_seen.append(detail)
        if not quiet:
            console.print(f"  [dim cyan]⚙ {detail}[/dim cyan]")

    if not quiet:
        console.print(f"[dim italic]I'm on patrol — sweeping sensors, drift, and logs "
                      f"({cfg.deep_model if deep else cfg.model}, tier: {cfg.policy_tier})...[/dim italic]")
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
    """Show recent patrol reports. Viewing them marks notifications read."""
    cfg, store = _ctx()
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
                  bind=bind, sample_thread=not no_sample, cfg=cfg)
    console.print(Panel(
        f"dashboard live at [bold bright_blue]http://{bind}:{port}[/bold bright_blue]\n"
        f"[dim]sampling every 30s in the background · 🔧 chat bubble bottom-right · "
        f"press ? for shortcuts · Ctrl-C to stop[/dim]",
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
    ("ollama", "local & private — guided setup, no API key needed"),
    ("lmstudio", "local — LM Studio server"),
    ("openai", "API — OpenAI"),
    ("anthropic", "API — Anthropic Claude"),
    ("meta", "API — Meta muse models"),
    ("azure", "API — Azure OpenAI / AI Foundry"),
    ("litellm", "API — anything behind a LiteLLM proxy"),
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


@app.command()
def init(
    provider: str = typer.Option(None, "--provider", "-p",
                                 help="ollama|lmstudio|openai|anthropic|meta|azure|litellm "
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
    """Set up wrench: pick a provider (interactive menu), write config, record baselines."""
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
    elif cfg.provider in ("lmstudio", "litellm") and localsetup.openai_server_alive(cfg.base_url):
        with console.status(f"[cyan]smoke test: one tool-calling round-trip on {cfg.model}..."):
            ok, detail = localsetup.smoke_test(cfg, store)
        if ok:
            console.print(f"[green]✔ local smoke test passed[/green] — {detail}")
            smoke_note = "\nlocal smoke test: ✔ tool-calling verified"
        else:
            console.print(f"[red]✖ local smoke test failed[/red] — {detail}")
            smoke_note = "\nlocal smoke test: ✖ FAILED — fix before relying on patrols"
    console.print(Panel(
        "[bold]I'm wrench — your systems administrator. I live here now.[/bold]\n"
        "I read the logs so you don't have to, I remember what changes on this box,\n"
        "and with your permission I fix problems before you ever see them.\n"
        "I just took my first look around (sensor baseline + drift snapshot recorded).\n\n"
        f"provider: [bold]{cfg.provider}[/bold] · model: [bold]{cfg.model}[/bold] · "
        f"policy: [bold]{cfg.policy_tier}[/bold]\n"
        f"data: {cfg.db_path}{smoke_note}\n"
        + ("api key: none needed — it's your hardware\n"
           if cfg.provider in ("ollama", "lmstudio", "litellm")
           else "api key: configured ✔\n" if cfg.api_key
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
):
    """Inventory certificates: scan configs + well-known stores, parse, persist, report."""
    if ctx.invoked_subcommand is not None:
        return
    from . import certs as cmod
    cfg, store = _ctx()
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
    from . import tools
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
):
    """Renew certificates: dry-run first, validate the chain, reload the service."""
    from . import certs as cmod
    cfg, store = _ctx()

    if revoke_consent:
        console.print("[green]renewal consent revoked.[/green]" if cmod.revoke_renew_consent(cfg)
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


app.add_typer(certs_app, name="certs")


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
