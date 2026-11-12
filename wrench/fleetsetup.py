"""Guided fleet setup — turn this machine into a hub, or connect it to one.

One engine, three front ends:

* the **agent** (`wrench chat`): tools ``fleet_setup_status`` and
  ``fleet_setup`` let the model walk the operator through the steps and carry
  each one out;
* the **wizard** (`wrench fleet setup`): the same steps with no model at all;
* the plain commands the tutorial lists, which every step names so the
  operator can always do it by hand.

Rules the engine keeps, whoever is driving it:

* **Every change needs a yes.** A step that changes anything asks through the
  caller's confirmation channel and is refused when there is none (a patrol,
  a scheduled job, the web chat). The refusal names the command to run.
* **Passwords never pass through the model.** A step that needs one asks the
  operator directly, hidden, through the caller's secret channel. The text
  the model sees says only whether it worked.
* **Nothing here is free-form.** A step takes a few validated values (an
  address, a name, tags). There is no command string to inject into.

Stdlib only. Starting a hub in the background uses a pid file and a log in
the data dir; it does not survive a reboot (the deployment guide has a
systemd unit for that).
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from . import fleet, webauth

ROLES = ("hub", "node")
PID_FILE = "fleet_hub.pid"
LOG_FILE = "fleet_hub.log"
TLS_DIR = "tls"
START_WAIT_S = 12.0

ACTIONS = {
    # hub
    "set_password": "set (or change) the dashboard password — typed privately",
    "hub_listen": "make the hub reachable from other machines (args: host, port)",
    "hub_tls": "create a self-signed certificate for the hub and switch it on",
    "hub_start": "start the hub in the background",
    "hub_stop": "stop a hub started in the background",
    # node
    "node_connect": "connect this machine to a hub (args: hub, node_id, tags, ca_file, "
                    "allow_http) — the hub password is typed privately",
    "schedule": "start the heartbeat so patrols run, and report, on a schedule",
    "report_now": "send this machine's report to the hub now",
}


# ---------------------------------------------------------------- helpers
def _section(cfg) -> dict:
    sec = (getattr(cfg, "raw", None) or {}).get("fleet", {})
    return sec if isinstance(sec, dict) else {}


def local_addresses() -> list[str]:
    """Addresses other machines might reach this one at, best first: the
    address used for outbound traffic, then the host name. Opens no
    connection (a UDP socket is only *aimed*, nothing is sent)."""
    out: list[str] = []
    for family, target in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.connect((target, 9))
                ip = s.getsockname()[0]
            if ip and not ipaddress.ip_address(ip.split("%")[0]).is_loopback and ip not in out:
                out.append(ip)
        except (OSError, ValueError):
            pass
    name = platform.node()
    if name and name not in out:
        out.append(name)
    return out


def _probe_host(listen_host: str) -> str:
    h = (listen_host or "").strip().strip("[]")
    if h in ("", "0.0.0.0", "localhost"):
        return "127.0.0.1"
    if h == "::":
        return "[::1]"
    return f"[{h}]" if ":" in h else h


def hub_answers(listen_host: str, port: int, tls: bool, timeout: float = 2.0) -> bool:
    """Is a wrench server answering on this machine's hub port? A liveness
    probe of our own listener, so the certificate is not verified."""
    url = f"{'https' if tls else 'http'}://{_probe_host(listen_host)}:{port}/healthz"
    ctx = None
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as r:  # noqa: S310
            return json.loads(r.read(1024).decode("utf-8", "replace")).get("ok") is True
    except Exception:  # noqa: BLE001
        return False


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],  # noqa: S603,S607
                                 capture_output=True, text=True, timeout=10).stdout
            return str(pid) in out
        except (OSError, subprocess.SubprocessError):
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _read_pid(data_dir) -> int:
    try:
        return int((Path(data_dir) / PID_FILE).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 0


def _is_our_hub(pid: int) -> bool:
    """Before signalling a pid from a file: is it still a wrench hub? (A pid
    can be reused by an unrelated process after a reboot.)"""
    if os.name == "nt":
        return _pid_alive(pid)
    try:
        cmd = subprocess.run(["ps", "-p", str(pid), "-o", "command="],  # noqa: S603,S607
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "fleet" in cmd and "serve" in cmd


def own_executable() -> str:
    """This install's `wrench` entry point, for the scheduler ("" if not found)."""
    cands = [Path(sys.argv[0])]
    exe_dir = Path(sys.executable).parent
    cands += [exe_dir / "wrench", exe_dir / "wrench.exe", exe_dir / "Scripts" / "wrench.exe"]
    for c in cands:
        try:
            if c.name.lower().startswith("wrench") and c.is_file():
                return str(c.resolve())
        except OSError:
            continue
    return shutil.which("wrench") or ""


# ---------------------------------------------------------------- state
def state(cfg, store) -> dict:
    """Everything the steps are decided from. Reads only."""
    st = fleet.settings_from(cfg)
    sec = _section(cfg)
    tls = bool(st.tls_cert)
    pid = _read_pid(cfg.data_dir)
    running = hub_answers(st.listen_host, st.listen_port, tls)
    try:
        keys = [k for k in store.fleet_keys() if not k.get("revoked")]
        nodes = store.fleet_nodes()
    except Exception:  # noqa: BLE001
        keys, nodes = [], []
    beat = {}
    try:
        from . import heartbeat
        beat = heartbeat.pulse(store)
    except Exception:  # noqa: BLE001
        pass
    reachable = not webauth.is_loopback_bind(st.listen_host)
    addrs = local_addresses()
    scheme = "https" if tls else "http"
    return {
        "host": platform.node() or "this machine",
        "password_set": webauth.password_is_set(cfg.data_dir),
        "hub": {
            "listen_host": st.listen_host, "listen_port": st.listen_port,
            "reachable": reachable, "tls": tls, "tls_cert": st.tls_cert,
            "running": running, "pid": pid if (pid and _pid_alive(pid)) else 0,
            "opted_in": bool(sec.get("hub")) or bool(keys),
            "connect_enabled": st.connect, "keys": len(keys), "machines": len(nodes),
            "addresses": addrs,
            "url": f"{scheme}://{(addrs[0] if addrs and reachable else 'localhost')}"
                   f":{st.listen_port}",
            "openssl": bool(shutil.which("openssl")),
        },
        "node": {
            "connected": st.node_enabled, "hub_url": st.hub_url, "node_id": st.node_id,
            "tags": list(st.tags), "ca_file": st.ca_file,
        },
        "schedule": {"alive": bool(beat.get("alive")), "last_tick": beat.get("last_tick")},
    }


def _connect_line(s: dict) -> str:
    hub = s["hub"]
    addr = hub["addresses"][0] if hub["addresses"] else "<this hub's address>"
    line = f"wrench fleet connect {addr}"
    if hub["listen_port"] != fleet.DEFAULT_LISTEN_PORT:
        line += f" --port {hub['listen_port']}"
    if hub["tls"]:
        line += " --ca-file hub-cert.pem"
    return line


def firewall_hint(port: int) -> str:
    sysname = platform.system()
    if sysname == "Linux":
        return (f"if this machine runs a firewall, open TCP {port}: "
                f"`sudo ufw allow {port}/tcp` (Ubuntu/Debian) or `sudo firewall-cmd "
                f"--add-port={port}/tcp --permanent && sudo firewall-cmd --reload` (RHEL/Fedora)")
    if sysname == "Windows":
        return (f"open TCP {port} in an elevated PowerShell: `New-NetFirewallRule -DisplayName "
                f"\"wrench hub\" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow`")
    if sysname == "Darwin":
        return ("if macOS asks whether Python may accept incoming connections, answer Allow "
                "(System Settings → Network → Firewall)")
    return f"make sure TCP {port} is reachable from the other machines"


def steps(role: str, s: dict) -> list[dict]:
    """The ordered checklist for a role: {key, title, done, optional, detail,
    action (what fleet_setup would run), command (the same by hand)}."""
    hub, node = s["hub"], s["node"]
    if role == "hub":
        return [
            {"key": "password", "title": "Set the dashboard password",
             "done": s["password_set"], "optional": False, "action": "set_password",
             "command": "wrench password",
             "detail": "it signs people in to the dashboard, and each machine presents it "
                       "once to connect. Only a salted hash is stored."},
            {"key": "listen", "title": "Make the hub reachable from other machines",
             "done": hub["reachable"], "optional": False, "action": "hub_listen",
             "command": 'set listen_host = "0.0.0.0" and hub = true under [fleet]',
             "detail": (f"now listening on {hub['listen_host']}:{hub['listen_port']}"
                        + ("" if hub["reachable"] else " — this machine only") + ". "
                        + firewall_hint(hub["listen_port"]))},
            {"key": "tls", "title": "Give the hub a certificate",
             "done": hub["tls"], "optional": True, "action": "hub_tls",
             "command": "openssl req -x509 … (see the tutorial), then set tls_cert / tls_key "
                        "under [fleet]",
             "detail": ("serving HTTPS with " + hub["tls_cert"] if hub["tls"] else
                        "without one the password crosses the network unencrypted. "
                        + ("I can create a self-signed certificate here."
                           if hub["openssl"] else
                           "openssl is not installed here, so bring a certificate of your "
                           "own or skip this on a network you trust."))},
            {"key": "start", "title": "Start the hub",
             "done": hub["running"], "optional": False, "action": "hub_start",
             "command": "wrench fleet serve   (or: wrench fleet serve --detach)",
             "detail": (f"answering at {hub['url']}" if hub["running"] else
                        "not running. Started from here it runs in the background until "
                        "the next reboot; the deployment guide has a systemd unit to keep "
                        "it running.")},
            {"key": "machines", "title": "Connect the other machines",
             "done": hub["machines"] > 0, "optional": False, "action": None,
             "command": _connect_line(s),
             "detail": (f"{hub['machines']} machine(s) reporting. " if hub["machines"] else "")
                       + f"On each other machine run `{_connect_line(s)}` and enter the "
                         "dashboard password"
                       + (" (copy this hub's certificate to it first)" if hub["tls"] else "")
                       + f". Then open {hub['url']} in a browser."},
        ]
    if role == "node":
        return [
            {"key": "connect", "title": "Connect this machine to the hub",
             "done": node["connected"], "optional": False, "action": "node_connect",
             "command": "wrench fleet connect <hub-address>",
             "detail": (f"connected to {node['hub_url']} as {node['node_id']}"
                        if node["connected"] else
                        "needs the hub's address (an IP or name) and the hub's dashboard "
                        "password, which you type privately — it is used once to get this "
                        "machine its own key and is not stored here.")},
            {"key": "schedule", "title": "Patrol and report on a schedule",
             "done": s["schedule"]["alive"], "optional": False, "action": "schedule",
             "command": "wrench install-service",
             "detail": ("the heartbeat is running: a patrol every 15 minutes, and a report "
                        "to the hub after each" if s["schedule"]["alive"] else
                        "the heartbeat is not running, so this machine would report only "
                        "when you run a patrol by hand and then go silent on the hub.")},
            {"key": "report", "title": "Send a first report",
             "done": False, "optional": True, "action": "report_now",
             "command": "wrench patrol   (then: wrench fleet report)",
             "detail": "optional: shows up on the hub straight away instead of at the next "
                       "scheduled patrol."},
        ]
    raise ValueError("role must be 'hub' or 'node'")


def describe(role: str, s: dict) -> str:
    """The checklist as plain text — what the agent tool returns."""
    lines = [f"Fleet setup — this machine ({s['host']}) as a {role.upper()}:"]
    nxt = None
    for i, st in enumerate(steps(role, s), 1):
        mark = "done" if st["done"] else ("optional" if st["optional"] else "TO DO")
        lines.append(f"{i}. [{mark}] {st['title']} — {st['detail']}")
        how = f"   by hand: {st['command']}"
        if st["action"] and not st["done"]:
            how += f"   |   I can do it: fleet_setup(action=\"{st['action']}\")"
        lines.append(how)
        if nxt is None and not st["done"] and not st["optional"]:
            nxt = st
    lines.append("")
    if nxt is None:
        lines.append("Every required step is done.")
    elif nxt["action"]:
        lines.append(f"Next step: {nxt['title']} — fleet_setup(action=\"{nxt['action']}\").")
    else:
        lines.append(f"Next step: {nxt['title']} (the operator does this on the other machines).")
    other = "node" if role == "hub" else "hub"
    if role == "hub" and s["node"]["connected"]:
        lines.append(f"Note: this machine also reports to {s['node']['hub_url']} as a node.")
    if role == "node" and (s["hub"]["running"] or s["hub"]["opted_in"]):
        lines.append("Note: this machine is itself set up as a hub.")
    lines.append(f"(For the other role: fleet_setup_status(role=\"{other}\").)")
    return "\n".join(lines)


def overview(s: dict) -> str:
    """No role chosen yet: what this machine is today, and the two choices."""
    hub, node = s["hub"], s["node"]
    bits = [f"This machine ({s['host']}) today:"]
    bits.append("- hub: " + ("running at " + hub["url"] if hub["running"] else
                             "set up but not running" if hub["opted_in"] else "not a hub")
                + (f", {hub['machines']} machine(s) reporting" if hub["machines"] else ""))
    bits.append("- node: " + (f"connected to {node['hub_url']} as {node['node_id']}"
                              if node["connected"] else "not connected to a hub"))
    bits.append("- dashboard password: " + ("set" if s["password_set"] else "not set"))
    bits.append("")
    bits.append("A fleet has one HUB (the machine everyone's reports go to and whose dashboard "
                "you open) and any number of NODES (every other machine). Ask the operator "
                "which this machine should be, then call fleet_setup_status(role=\"hub\") or "
                "fleet_setup_status(role=\"node\").")
    return "\n".join(bits)


# ---------------------------------------------------------------- actions
class StepResult(dict):
    """{ok, message, …}. ``message`` is safe to show to a model."""

    @property
    def ok(self) -> bool:
        return bool(self.get("ok"))


def _res(ok: bool, message: str, **extra) -> StepResult:
    return StepResult(ok=ok, message=message, **extra)


def _audit(cfg, kind: str, detail: dict) -> None:
    try:
        from . import audit
        audit.log_event(cfg, kind, detail, actor="setup")
    except Exception:  # noqa: BLE001
        pass


def _save(values: dict) -> None:
    from .config import set_section_values
    set_section_values("fleet", values)


def valid_listen_host(host: str) -> bool:
    h = (host or "").strip().strip("[]")
    if h == "localhost":
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def set_password(cfg, password: str) -> StepResult:
    changed = webauth.password_is_set(cfg.data_dir)
    try:
        webauth.set_password(cfg.data_dir, password)
    except ValueError as e:
        return _res(False, f"password not set — {e}")
    except OSError as e:
        return _res(False, f"password not set — could not write to the data dir: {e}")
    _audit(cfg, "web.password.changed" if changed else "web.password.set", {"source": "setup"})
    return _res(True, "dashboard password " + ("changed" if changed else "set")
                + " (only a salted hash is stored)")


def hub_listen(cfg, host: str = "0.0.0.0", port: int | None = None) -> StepResult:  # noqa: S104
    host = (host or "0.0.0.0").strip()  # noqa: S104
    if not valid_listen_host(host):
        return _res(False, f"{host!r} is not an address to listen on — use 0.0.0.0 (every "
                           "interface), 127.0.0.1 (this machine only), or one of this "
                           "machine's own IPs")
    values: dict = {"listen_host": host, "hub": True}
    if port is not None:
        if not 0 < int(port) < 65536:
            return _res(False, "the port must be between 1 and 65535")
        values["listen_port"] = int(port)
    try:
        _save(values)
    except (ValueError, OSError) as e:
        return _res(False, f"could not save the config: {e}")
    _audit(cfg, "fleet.setup.listen", values)
    p = values.get("listen_port") or fleet.settings_from(cfg).listen_port
    return _res(True, f"saved: the hub will listen on {host}:{p}. "
                      "A hub that is already running must be restarted to pick this up. "
                      + firewall_hint(p), restart_needed=True)


def hub_tls(cfg, names: list[str] | None = None) -> StepResult:
    """Create a self-signed certificate for this hub with the openssl binary,
    in ``<config dir>/tls``, and point ``[fleet]`` at it."""
    openssl = shutil.which("openssl")
    if not openssl:
        return _res(False, "openssl is not installed on this machine — bring a certificate "
                           "of your own and set tls_cert / tls_key under [fleet], or skip TLS")
    from . import config as _config
    tdir = Path(_config.CONFIG_DIR) / TLS_DIR
    cert, key = tdir / "hub-cert.pem", tdir / "hub-key.pem"
    if cert.exists() and key.exists():
        try:
            _save({"tls_cert": str(cert), "tls_key": str(key)})
        except (ValueError, OSError) as e:
            return _res(False, f"could not save the config: {e}")
        return _res(True, f"using the existing certificate at {cert}", cert=str(cert),
                    restart_needed=True)
    alts: list[str] = []
    for n in (names or local_addresses()) + ["localhost", "127.0.0.1"]:
        n = n.strip()
        if not n or any(c in n for c in ",=\n\r /\\\"'") or len(n) > 253:
            continue
        try:
            ipaddress.ip_address(n)
            entry = f"IP:{n}"
        except ValueError:
            entry = f"DNS:{n}"
        if entry not in alts:
            alts.append(entry)
    cn = next((a.split(":", 1)[1] for a in alts if a.startswith("DNS:")), "wrench-hub")
    try:
        tdir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(tdir, 0o700)
        proc = subprocess.run(  # noqa: S603
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825",
             "-keyout", str(key), "-out", str(cert), "-subj", f"/CN={cn[:64]}",
             "-addext", "subjectAltName=" + ",".join(alts)],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return _res(False, f"openssl could not be run: {e}")
    if proc.returncode != 0 or not cert.exists() or not key.exists():
        return _res(False, "openssl failed: " + (proc.stderr or proc.stdout or "").strip()[-300:])
    if os.name == "posix":
        os.chmod(key, 0o600)
    try:
        _save({"tls_cert": str(cert), "tls_key": str(key)})
    except (ValueError, OSError) as e:
        return _res(False, f"the certificate was created at {cert} but the config could "
                           f"not be saved: {e}")
    _audit(cfg, "fleet.setup.tls", {"cert": str(cert), "names": alts})
    return _res(True,
                f"created a self-signed certificate valid for {', '.join(a.split(':', 1)[1] for a in alts)}. "
                f"Certificate: {cert} (copy THIS file to each machine and pass it as "
                f"--ca-file). Private key: {key} (never copy this). A running hub must be "
                "restarted to use it.", cert=str(cert), restart_needed=True)


def hub_start(cfg, wait_s: float = START_WAIT_S, argv: list[str] | None = None) -> StepResult:
    """Start `wrench fleet serve` detached from this process."""
    st = fleet.settings_from(cfg)
    tls = bool(st.tls_cert)
    if hub_answers(st.listen_host, st.listen_port, tls):
        return _res(True, f"the hub is already running on port {st.listen_port}", already=True)
    data_dir = Path(cfg.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    log = data_dir / LOG_FILE
    cmd = argv or [sys.executable, "-m", "wrench", "fleet", "serve"]
    kwargs: dict = {}
    if os.name == "nt":
        kwargs["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 0)
                                   | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    else:
        kwargs["start_new_session"] = True
    try:
        with open(log, "ab") as out:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=out,  # noqa: S603
                                    stderr=subprocess.STDOUT, close_fds=True, **kwargs)
    except OSError as e:
        return _res(False, f"could not start the hub: {e}")
    (data_dir / PID_FILE).write_text(f"{proc.pid}\n", encoding="utf-8")
    deadline = time.time() + wait_s
    while time.time() < deadline:
        if hub_answers(st.listen_host, st.listen_port, tls, timeout=1.0):
            _audit(cfg, "fleet.setup.hub_start", {"pid": proc.pid, "port": st.listen_port})
            where = "every interface" if st.listen_host in ("0.0.0.0", "::") else st.listen_host  # noqa: S104
            return _res(True, f"the hub is running in the background (pid {proc.pid}) on "
                              f"{where}, port {st.listen_port}, {'HTTPS' if tls else 'plain HTTP'}. "
                              f"Log: {log}. It runs until this machine reboots or you stop "
                              "it (`wrench fleet stop`).", pid=proc.pid)
        if proc.poll() is not None:
            break
        time.sleep(0.4)
    tail = ""
    try:
        tail = log.read_text(encoding="utf-8", errors="replace")[-400:].strip()
    except OSError:
        pass
    if proc.poll() is None:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        (data_dir / PID_FILE).unlink()
    except OSError:
        pass
    return _res(False, "the hub did not come up"
                + (f" — is something else using port {st.listen_port}?" if "in use" in tail.lower()
                   else "") + (f" Last output: {tail}" if tail else ""))


def hub_stop(cfg) -> StepResult:
    data_dir = Path(cfg.data_dir)
    pid = _read_pid(data_dir)
    if not pid or not _pid_alive(pid):
        try:
            (data_dir / PID_FILE).unlink()
        except OSError:
            pass
        return _res(False, "no hub started in the background from this install is running "
                           "(a hub in a terminal stops with Ctrl-C; a service with its "
                           "service manager)")
    if not _is_our_hub(pid):
        return _res(False, f"pid {pid} is no longer a wrench hub — not touching it")
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],  # noqa: S603,S607
                           capture_output=True, timeout=20)
        else:
            import signal
            os.kill(pid, signal.SIGTERM)
    except OSError as e:
        return _res(False, f"could not stop pid {pid}: {e}")
    for _ in range(25):
        if not _pid_alive(pid):
            break
        time.sleep(0.2)
    try:
        (data_dir / PID_FILE).unlink()
    except OSError:
        pass
    _audit(cfg, "fleet.setup.hub_stop", {"pid": pid})
    return _res(True, f"stopped the hub (pid {pid})")


def find_hub(hub: str, port: int | None = None, ca_file: str = "") -> StepResult:
    """Locate a hub without sending anything secret. ok → ``url``;
    otherwise ``reason`` is 'address' | 'cert' | 'unreachable'."""
    candidates = fleet.hub_candidates(hub, port)
    if not candidates:
        return _res(False, f"{hub!r} is not an address I can use — give an IP or host name "
                           "(192.168.1.10), optionally with :port, or a full http(s):// URL",
                    reason="address")
    problems = []
    for url in candidates:
        verdict, detail = fleet.probe_hub(url, ca_file or "")
        if verdict == "ok":
            return _res(True, f"found a wrench hub at {url}", url=url,
                        plain_http=url.lower().startswith("http://")
                        and not fleet.is_local_url(url))
        if verdict == "cert":
            return _res(False, f"{url} answered, but its certificate is not trusted ({detail}). "
                               "If the hub uses a private or self-signed certificate, the "
                               "operator must copy the hub's certificate file to this "
                               "machine and give its path as ca_file.", reason="cert", url=url)
        problems.append(f"{url} — {detail}")
    return _res(False, "no wrench hub answered at " + ", ".join(candidates) + ". Check the "
                       "address and port, that the hub is running and listening beyond "
                       "its own machine, and that a firewall is not in the way. ("
                       + "; ".join(problems) + ")", reason="unreachable")


def attach_node(cfg, store, hub_url: str, token: str, node_id: str = "", tags=None,
                ca_file: str = "", test: bool = True, event: str = "fleet.connect") -> StepResult:
    """Send a test report with the key, then save ``[fleet]``. Nothing is
    saved unless the hub accepts the report."""
    st = fleet.settings_from(cfg)
    st.hub_url, st.token = hub_url.rstrip("/"), token
    name = fleet.clean_node_id(node_id)
    if name:
        st.node_id = name
    clean_tags = fleet._clean_tags(tags) if tags else []  # noqa: SLF001
    if clean_tags:
        st.tags = clean_tags
    if ca_file:
        st.ca_file = ca_file
    if test:
        if store.last_sample("os") is None:
            try:
                from . import sensors
                sensors.sample_all(store)
            except Exception:  # noqa: BLE001
                pass
        ok, detail = fleet.push_once(st, fleet.build_report(cfg, store, st))
        if not ok:
            return _res(False, f"the hub did not accept a test report — {detail}. "
                               "Nothing was saved.", stage="test")
    values: dict = {"hub_url": st.hub_url, "token": st.token}
    if name:
        values["node_id"] = name
    if clean_tags:
        values["tags"] = clean_tags
    if ca_file:
        values["ca_file"] = ca_file
    try:
        _save(values)
    except (ValueError, OSError) as e:
        return _res(False, f"the hub accepted this machine, but the config could not be "
                           f"saved — {e}", stage="save", values=values)
    try:
        from . import audit
        audit.log_event(cfg, event, {"hub_url": st.hub_url, "node_id": st.node_id,
                                     "key_id": fleet.key_id_of(st.token)})
    except Exception:  # noqa: BLE001
        pass
    return _res(True, f"connected to {st.hub_url} as {st.node_id}"
                + (f" (tags: {', '.join(st.tags)})" if st.tags else "")
                + ". Every patrol now reports to the hub.", node_id=st.node_id,
                hub_url=st.hub_url, tags=list(st.tags))


def node_connect(cfg, store, hub_url: str, password: str, node_id: str = "", tags=None,
                 ca_file: str = "") -> StepResult:
    """Trade the hub password for this machine's key, then attach."""
    name = fleet.clean_node_id(node_id) or fleet.settings_from(cfg).node_id
    res = fleet.connect_request(hub_url, password, name, ca_file or "")
    if not res["ok"]:
        _audit(cfg, "fleet.connect.failed", {"hub_url": hub_url, "node_id": name,
                                             "code": res["code"]})
        hint = {401: " That is the password set with `wrench password` ON THE HUB.",
                429: " Too many wrong passwords from this address — wait a minute."
                }.get(res["code"], "")
        return _res(False, f"the hub did not connect this machine — {res['detail']}.{hint}",
                    code=res["code"])
    out = attach_node(cfg, store, hub_url, res["token"], node_id, tags, ca_file)
    if out.ok and res.get("reconnected"):
        out["message"] += (" (The hub already knew this name: it keeps its history and its "
                           "previous key was retired.)")
    return out


def schedule(cfg, store, wrench_bin: str, interval: int = 15) -> StepResult:
    """Install the heartbeat timer (what `wrench install-service` does)."""
    from . import heartbeat, scheduler
    if not wrench_bin:
        return _res(False, "could not find the wrench executable for this install — run "
                           "`wrench install-service` yourself")
    try:
        tick_min = max(1, min(heartbeat.settings(cfg)["tick_min"], interval))
        plan = scheduler.plan_install(wrench_bin, tick_min)
        scheduler.apply_plan(plan)
        heartbeat.ensure_defaults(cfg, store, patrol_every_min=interval)
    except scheduler.SchedulerError as e:
        return _res(False, f"the schedule could not be installed — {e}")
    _audit(cfg, "fleet.setup.schedule", {"kind": plan.kind, "interval": interval})
    return _res(True, f"installed and started the heartbeat via {plan.kind}: a patrol every "
                      f"{interval} minutes, and a report to the hub after each. "
                      "Remove it with `wrench install-service --uninstall`.")


def report_now(cfg, store) -> StepResult:
    st = fleet.settings_from(cfg)
    if not st.node_enabled:
        return _res(False, "this machine is not connected to a hub yet")
    res = fleet.node_push(cfg, store, st)
    if res["ok"]:
        return _res(True, f"reported to {st.hub_url} ({res['detail']})")
    if res.get("rejected"):
        return _res(False, f"the hub refused the report — {res['detail']}. If the key was "
                           "revoked, connect again.")
    return _res(False, f"the hub could not be reached — {res['detail']}"
                + (" (the report is queued and will be retried)" if res.get("queued") else ""))


# ---------------------------------------------------------------- agent tools
def _refresh(cfg):
    """A chat session loads its config once and can run for an hour; setup
    steps rewrite that config. Re-read ``[fleet]`` (and the rest of the file)
    before each step so one step sees what the previous one saved."""
    try:
        from . import config
        if isinstance(cfg, config.Config):
            raw = config._read_toml()  # noqa: SLF001
            if isinstance(raw, dict):
                cfg.raw = raw
    except Exception:  # noqa: BLE001
        pass
    return cfg


def tool_status(cfg, store, role: str = "") -> str:
    role = (role or "").strip().lower()
    s = state(_refresh(cfg), store)
    if role not in ROLES:
        return overview(s)
    return describe(role, s)


def _denied(action: str, command: str) -> str:
    return (f"DENIED: {action} changes this machine's setup and needs the operator's yes, "
            "but nobody can be asked here (unattended run or web chat). The operator can "
            f"do it in a terminal: {command}   — or run the guided `wrench fleet setup`.")


def tool_action(cfg, store, action: str, args: dict | None = None, confirm_fn=None,
                wrench_bin: str = "") -> str:
    """Carry out one setup step for the agent. Returns text for the model:
    never a password, a key, or anything else secret."""
    args = args or {}
    action = (action or "").strip().lower()
    cfg = _refresh(cfg)
    if action not in ACTIONS:
        return ("unknown action. Valid actions: "
                + "; ".join(f"{k} — {v}" for k, v in ACTIONS.items()))
    ask_secret = getattr(confirm_fn, "ask_secret", None) if confirm_fn else None
    st = fleet.settings_from(cfg)

    def confirm(what: str, label: str) -> bool:
        return bool(confirm_fn(what, "setup: " + label))

    if action == "set_password":
        if confirm_fn is None or ask_secret is None:
            return _denied(action, "wrench password")
        had = webauth.password_is_set(cfg.data_dir)
        if not confirm(("Change" if had else "Set") + " the dashboard password on this "
                       "machine. You will type it privately; it is not shown to the model.",
                       "set the dashboard password"):
            return "the operator declined; nothing was changed"
        pw = ask_secret("new dashboard password", confirm=True,
                        check=webauth.password_problem)
        if not pw:
            return "no password was entered; nothing was changed"
        return set_password(cfg, pw)["message"]

    if action == "hub_listen":
        host = str(args.get("host") or "0.0.0.0")  # noqa: S104
        port = args.get("port")
        try:
            port = int(port) if port not in (None, "") else None
        except (TypeError, ValueError):
            return "port must be a number"
        if not valid_listen_host(host):
            return hub_listen(cfg, host, port)["message"]
        if confirm_fn is None:
            return _denied(action, f'set listen_host = "{host}" and hub = true under [fleet]')
        where = "every network interface" if host in ("0.0.0.0", "::") else host  # noqa: S104
        if not confirm(f"Make this machine's hub listen on {where}, port "
                       f"{port or st.listen_port}, so other machines can reach it. "
                       "(Saved under [fleet] in the config.)", "make the hub reachable"):
            return "the operator declined; nothing was changed"
        return hub_listen(cfg, host, port)["message"]

    if action == "hub_tls":
        if confirm_fn is None:
            return _denied(action, "see the tutorial's certificate step")
        if not confirm("Create a self-signed certificate for this hub (valid for "
                       + ", ".join(local_addresses() or ["this machine"])
                       + ") and switch HTTPS on for it.", "give the hub a certificate"):
            return "the operator declined; nothing was changed"
        return hub_tls(cfg)["message"]

    if action == "hub_start":
        if confirm_fn is None:
            return _denied(action, "wrench fleet serve --detach")
        if not webauth.password_is_set(cfg.data_dir):
            return ("not started: set the dashboard password first "
                    "(fleet_setup(action=\"set_password\")). A hub without one cannot "
                    "accept `wrench fleet connect`.")
        where = ("every network interface" if st.listen_host in ("0.0.0.0", "::")  # noqa: S104
                 else st.listen_host)
        if not confirm(f"Start the fleet hub in the background, listening on {where}, port "
                       f"{st.listen_port} ({'HTTPS' if st.tls_cert else 'plain HTTP'}).",
                       "start the hub"):
            return "the operator declined; nothing was changed"
        res = hub_start(_refresh(cfg))
        msg = res["message"]
        if res.ok and webauth.is_loopback_bind(st.listen_host):
            msg += (" NOTE: it is listening on this machine only, so other machines cannot "
                    "connect yet — run hub_listen, then stop and start the hub.")
        if res.ok:
            msg += " Machines connect with: " + _connect_line(state(_refresh(cfg), store))
        return msg

    if action == "hub_stop":
        if confirm_fn is None:
            return _denied(action, "wrench fleet stop")
        if not confirm("Stop the fleet hub running in the background. Machines' reports "
                       "will queue until it is started again.", "stop the hub"):
            return "the operator declined; nothing was changed"
        return hub_stop(cfg)["message"]

    if action == "node_connect":
        hub = str(args.get("hub") or "").strip()
        if not hub:
            return ("I need the hub's address first — ask the operator for the IP or name "
                    "of the hub machine (for example 192.168.1.10 or hub.example).")
        ca_file = str(args.get("ca_file") or "").strip()
        if ca_file and not Path(ca_file).expanduser().is_file():
            return f"ca_file {ca_file!r} is not a file on this machine"
        ca_file = str(Path(ca_file).expanduser()) if ca_file else ""
        port = args.get("port")
        try:
            port = int(port) if port not in (None, "") else None
        except (TypeError, ValueError):
            return "port must be a number"
        found = find_hub(hub, port, ca_file)
        if not found.ok:
            return found["message"]
        if confirm_fn is None or ask_secret is None:
            return _denied(action, f"wrench fleet connect {hub}")
        url = found["url"]
        name = fleet.clean_node_id(args.get("node_id")) or st.node_id
        tags = fleet._clean_tags(args.get("tags"))  # noqa: SLF001
        warn = ""
        if found.get("plain_http"):
            warn = ("\nWARNING: this hub has no TLS. The hub password would cross the "
                    "network unencrypted, readable by anyone on the path.")
        if not confirm(f"Connect this machine to the hub at {url} as \"{name}\""
                       + (f" with tags {', '.join(tags)}" if tags else "")
                       + ". You will type the hub's password privately; it is used once "
                         "and not stored here." + warn,
                       "connect to the hub" + (" over plain HTTP" if warn else "")):
            return "the operator declined; nothing was sent or changed"
        pw = ask_secret(f"password for the hub at {url}")
        if not pw:
            return "no password was entered; nothing was sent or changed"
        res = node_connect(cfg, store, url, pw, name if args.get("node_id") else "", tags,
                           ca_file)
        del pw
        return res["message"]

    if action == "schedule":
        if confirm_fn is None:
            return _denied(action, "wrench install-service")
        if not confirm("Install the heartbeat timer on this machine (systemd, launchd or "
                       "Task Scheduler): a patrol every 15 minutes, and a report to the "
                       "hub after each.", "patrol and report on a schedule"):
            return "the operator declined; nothing was changed"
        return schedule(cfg, store, wrench_bin or own_executable())["message"]

    if action == "report_now":
        return report_now(cfg, store)["message"]

    return "unknown action"
