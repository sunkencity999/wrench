"""wrench web — the dashboard, the fleet console and their JSON API.

stdlib ``http.server`` only: no framework, no build step, no CDN. Pages live in
``wrench/web/`` and are served with a per-response CSP nonce.

Pages
  /                     this machine: health score, posture, vitals, patrols
  /fleet                fleet console (when this install is a hub)
  /login                password or token sign-in (only when access control is on)

API (JSON; every route needs a credential when access control is on)
  GET  /healthz                   liveness for load balancers (no auth, no data)
  GET  /api/overview              host, role, posture, latest sample, brain, audit
  GET  /api/timeline?hours=24     downsampled os samples (1h / 6h / 24h / 7d)
  GET  /api/patrols | /api/drift | /api/actions | /api/tokens | /api/webintel
  GET  /api/posture               the health score and its pillars
  GET  /api/pillar?key=           one pillar: what it measures and the evidence behind it
  GET  /api/notifications[?all=1] unread (or all) notifications
  POST /api/notifications/read    mark read                         [admin]
  POST /api/chat                  talk to the agent                 [admin]
  GET  /api/fleet/nodes           fleet summary + nodes
  GET  /api/fleet/node?id=        one node + report history
  GET  /api/fleet/export.csv      node inventory as CSV
  POST /api/fleet/forget          retire a node                     [admin]
  POST /api/fleet/report          node report ingest (HMAC-signed, no session)
  POST /api/fleet/connect         hub password -> that node's own key (no session)
  GET  /metrics                   Prometheus exposition

Access control, Host validation, CSRF and response headers: wrench/webauth.py.
"""

from __future__ import annotations

import csv
import io
import json
import platform
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, notifications, webauth
from .store import Store

WEB_DIR = Path(__file__).parent / "web"
MAX_BODY = 16 * 1024
MAX_CHAT_BODY = MAX_BODY          # kept for callers of the 2.x name
CHAT_HISTORY_MAX = 12
_RANGES = {1, 6, 24, 168}


def _load_pages() -> dict[str, str]:
    """Read the page templates once and inline the shared CSS/JS."""
    css = (WEB_DIR / "base.css").read_text(encoding="utf-8")
    js = (WEB_DIR / "base.js").read_text(encoding="utf-8")
    pages = {}
    for name in ("dashboard", "fleet", "login"):
        html = (WEB_DIR / f"{name}.html").read_text(encoding="utf-8")
        pages[name] = html.replace("__BASE_CSS__", css).replace("__BASE_JS__", js)
    return pages


def _downsample(samples: list[tuple[float, dict]], target: int = 240) -> list[dict]:
    if len(samples) <= target:
        rows = samples
    else:
        step = len(samples) / target
        rows = [samples[int(i * step)] for i in range(target)]
        if rows[-1] is not samples[-1]:
            rows.append(samples[-1])        # always include the newest point
    keys = ("cpu_pct", "mem_pct", "swap_pct", "load_1m", "net_recv_rate_kbs",
            "net_sent_rate_kbs", "disk_root_pct", "n_procs")
    return [{"ts": ts, **{k: p.get(k) for k in keys}} for ts, p in rows]


def _is_local_origin(value: str | None) -> bool:
    """True for a missing Origin or a loopback origin. (Kept for callers/tests;
    request handling uses ``webauth.AuthConfig.same_origin``.)"""
    if not value:
        return True
    host = urlparse(value).hostname or ""
    return host in ("127.0.0.1", "localhost", "::1")


def _catalog_summary(cfg) -> dict:
    """What the agent may run on this machine, by pack — for the tier panel."""
    from . import commands, platforms, policy
    plat = platforms.current_platform()
    st = policy.settings(cfg)
    packs = [{"pack": r["pack"], "title": r["title"], "look": r["diag"], "fix": r["fix"],
              "asks": r["asks"], "enabled": r["enabled"],
              "tools": list(dict.fromkeys(r["diag_tools"] + r["fix_tools"]))[:10]}
             for r in commands.summary(plat, st["disabled_packs"])]
    live = [p for p in packs if p["enabled"]]
    return {"look": sum(p["look"] for p in live), "fix": sum(p["fix"] for p in live),
            "custom": len(st["allow_diag"]) + len(st["allow_fix"]), "packs": packs}


def make_handler(db_path, host_label: str, cfg=None, auth: webauth.AuthConfig | None = None,
                 fleet_hub: bool = False, os_label: str | None = None, tier_io=None):
    auth = auth or webauth.AuthConfig()

    def tier_now() -> str:
        """The policy tier in force. With ``tier_io`` it is re-read from the
        config, so a change made in a terminal shows up here too."""
        from . import policy
        try:
            t = tier_io[0]() if tier_io else getattr(cfg, "policy_tier", "suggest")
        except Exception:  # noqa: BLE001
            t = getattr(cfg, "policy_tier", "suggest")
        return t if t in policy.TIERS else "suggest"

    def tier_raise_allowed() -> bool:
        web = (getattr(cfg, "raw", None) or {}).get("web", {})
        return bool(isinstance(web, dict) and web.get("allow_tier_raise", False))
    pages = _load_pages()
    limiter = webauth.RateLimiter()
    chat_lock = threading.Lock()
    chat_history: list[dict] = []          # session-scoped conversation memory
    data_dir = Path(db_path).parent        # inbox + audit chain live next to the db

    def hub_on(store) -> bool:
        if cfg is None:
            return False
        from . import fleet
        return fleet_hub or fleet.hub_active(store, fleet.settings_from(cfg))

    class Handler(BaseHTTPRequestHandler):
        server_version = "wrench"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = 30          # an idle or stalled client cannot pin a thread forever

        def setup(self):
            # TLS handshakes happen HERE, in the per-connection thread and under
            # the timeout — never in the accept loop, where one client that
            # connects and says nothing would stop the hub accepting anyone.
            if isinstance(self.request, ssl.SSLSocket):
                self.request.settimeout(self.timeout)
                self.request.do_handshake()
            super().setup()

        # ---------- plumbing ----------
        def log_message(self, *args):  # quiet: access logs are not wrench's job
            pass

        def _send(self, code: int, body: bytes, ctype: str, nonce: str = "",
                  extra: list[tuple[str, str]] | None = None) -> None:
            if self.command == "POST" and not getattr(self, "_body_read", False):
                # Replying without having read the request body would leave it
                # on a keep-alive connection to be parsed as the NEXT request
                # (request smuggling behind a proxy) — so that connection ends here.
                self.close_connection = True
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if self.close_connection:
                self.send_header("Connection", "close")
            for k, v in webauth.security_headers(nonce, auth.tls):
                self.send_header(k, v)
            for k, v in extra or []:
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, code: int = 200, extra=None):
            self._send(code, json.dumps(obj).encode(), "application/json", extra=extra)

        def _page(self, name: str, code: int = 200, **subs):
            nonce = secrets.token_urlsafe(16)
            html = pages[name].replace("__NONCE__", nonce)
            for key, val in subs.items():
                # JSON-encode into the script context; break up "</" so a value
                # can never close the <script> element
                html = html.replace(f"'__{key}__'", json.dumps(val).replace("</", "<\\/"))
            self._send(code, html.encode(), "text/html; charset=utf-8", nonce=nonce)

        def _redirect(self, where: str, extra=None):
            self._send(303, b"", "text/plain", extra=[("Location", where), *(extra or [])])

        def _client(self) -> str:
            return self.client_address[0] if self.client_address else "?"

        def _body(self, limit: int = MAX_BODY) -> bytes | None:
            """The request body, or None after replying 4xx (bad/oversize length)."""
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                length = -1
            if length < 0 or length > limit:
                self.close_connection = True      # don't read an unbounded body
                self._json({"error": "request too large"}, 413)
                return None
            data = self.rfile.read(length) if length else b""
            self._body_read = True
            return data

        def _json_body(self) -> dict | None:
            raw = self._body()
            if raw is None:
                return None
            if not raw:
                return {}
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._json({"error": "invalid JSON"}, 400)
                return None
            if not isinstance(obj, dict):
                self._json({"error": "expected a JSON object"}, 400)
                return None
            return obj

        def _gate(self, need: str = "viewer", api: bool = True) -> str | None:
            """Host check + authentication + role. Returns the role, or None
            after having replied (redirect to /login for pages, 401/403 for API)."""
            if not auth.host_allowed(self.headers.get("Host", "")):
                self._json({"error": "unrecognized Host header"}, 421)
                return None
            role = auth.role_for_request(self.headers)
            if role is None:
                if api:
                    self._json({"error": "authentication required"}, 401,
                               extra=[("WWW-Authenticate", 'Bearer realm="wrench"')])
                else:
                    self._redirect("/login?next=" + urlparse(self.path).path)
                return None
            if need == "admin" and role != "admin":
                self._json({"error": "this action needs the admin role"}, 403)
                return None
            return role

        # ---------- GET ----------
        def do_HEAD(self):  # noqa: N802
            self.do_GET()

        def do_GET(self):  # noqa: N802
            url = urlparse(self.path)
            path, query = url.path, parse_qs(url.query)
            if path == "/healthz":
                return self._json({"ok": True})
            if path == "/login":
                if not auth.host_allowed(self.headers.get("Host", "")):
                    return self._json({"error": "unrecognized Host header"}, 421)
                if not auth.required or auth.role_for_request(self.headers):
                    return self._redirect("/")
                return self._page("login", HOST=host_label)
            is_page = path in ("/", "/fleet")
            try:
                role = self._gate(api=not is_page)
            except Exception:  # noqa: BLE001 — a malformed credential is just "no"
                return self._json({"error": "authentication required"}, 401)
            if role is None:
                return None
            store = Store(db_path)  # per-request connection (sqlite + threads)
            try:
                return self._get(path, query, role, store)
            except BrokenPipeError:
                return None
            except Exception as e:  # noqa: BLE001 — never leak a traceback to a client
                return self._json({"error": f"internal error ({e.__class__.__name__})"}, 500)
            finally:
                store.close()

        def _get(self, path: str, query: dict, role: str, store: Store):
            if path == "/":
                return self._page("dashboard")
            if path == "/fleet":
                if not hub_on(store):
                    return self._redirect("/")
                return self._page("fleet")
            if path == "/metrics":
                from . import metrics
                return self._send(200, metrics.render(store, data_dir).encode(),
                                  metrics.CONTENT_TYPE)
            if path in ("/api/overview", "/api/summary"):
                return self._json(self._overview(store, role))
            if path == "/api/posture":
                from . import posture
                return self._json(posture.compute(cfg, store))
            if path == "/api/pillar":
                from . import posture
                ev = posture.evidence(cfg, store, (query.get("key") or [""])[0])
                if ev is None:
                    return self._json({"error": "unknown pillar"}, 404)
                return self._json(ev)
            if path == "/api/timeline":
                try:
                    hours = int((query.get("hours") or ["24"])[0])
                except ValueError:
                    hours = 24
                hours = hours if hours in _RANGES else 24
                return self._json(_downsample(store.recent_samples("os", hours * 3600)))
            if path == "/api/drift":
                return self._json(store.recent_diffs(86400 * 7)[:50])
            if path == "/api/patrols":
                return self._json(store.recent_patrols(20))
            if path == "/api/actions":
                return self._json(store.recent_actions(50))
            if path == "/api/tokens":
                return self._json(store.token_totals())
            if path == "/api/webintel":
                return self._json(store.cache_get("webintel_scan", float("inf")) or {})
            if path == "/api/notifications":
                rows = (notifications.read_all(data_dir)[-100:] if query.get("all")
                        else notifications.unread(data_dir))
                return self._json(rows)
            if path == "/api/memory":
                from . import memory
                return self._json({
                    "enabled": cfg is None or memory.settings(cfg)["enabled"],
                    "counts": memory.counts(store),
                    "memories": memory.list_memories(store, limit=200),
                    "pending": memory.list_memories(store, status="pending", limit=100)})
            if path == "/api/jobs":
                from . import heartbeat
                return self._json({
                    "heartbeat": heartbeat.pulse(store),
                    "jobs": [j for j in heartbeat.list_jobs(store) if j["status"] != "done"],
                    "runs": heartbeat.job_runs(store, limit=25),
                    "actions": {k: v[1] for k, v in heartbeat.ACTIONS.items()}})
            if path.startswith("/api/fleet/"):
                return self._fleet_get(path, query, store)
            return self._json({"error": "not found"}, 404)

        def _overview(self, store: Store, role: str) -> dict:
            from . import posture
            last = store.last_sample("os")
            out = {
                "host": host_label, "version": __version__, "role": role,
                "auth_required": auth.required,
                "ts": last[0] if last else None,
                "os": last[1] if last else {},
                "posture": posture.compute(cfg, store),
                "checklist": posture.checklist(cfg, store),
                "fleet_hub": hub_on(store),
                "unread": len(notifications.unread(data_dir)),
                "tokens_total": sum(t["total"] or 0 for t in store.token_totals()),
            }
            try:
                from . import platforms
                out["os_label"] = os_label or platforms.os_label()
            except Exception:  # noqa: BLE001
                out["os_label"] = platform.system()
            out["audit"] = _audit_state(data_dir)
            if cfg is not None:
                from . import agent as agent_mod
                usable, why = agent_mod.brain_status(cfg)
                out["brain"] = {"usable": usable, "reason": why,
                                "provider": cfg.provider, "model": cfg.model}
                from . import config as _config, policy as _policy
                out["policy_tier"] = tier_now()
                out["policy"] = {
                    "tiers": [{"tier": t, "name": _policy.TIER_INFO[t][0],
                               "allows": _policy.TIER_INFO[t][1]} for t in _policy.TIERS],
                    "commands": _catalog_summary(cfg),
                    "raise_allowed": tier_raise_allowed(),
                    "env_override": bool(_config.policy_env_override()) and tier_io is not None}
                out["offline"] = bool(getattr(cfg, "offline", False))
            else:
                out["brain"] = {"usable": False, "reason": "no config loaded"}
                out["policy_tier"] = "suggest"
                out["offline"] = False
            try:
                from . import heartbeat, memory
                out["learn"] = {"memory": memory.counts(store), "heartbeat": heartbeat.pulse(store)}
            except Exception:  # noqa: BLE001
                out["learn"] = None
            hist = posture.history(store, 30)
            out["health_history"] = hist[-400:]
            out["health_trend"] = posture.trend(hist)
            return out

        def _fleet_get(self, path: str, query: dict, store: Store):
            from . import fleet
            if not hub_on(store):
                return self._json({"error": "fleet hub not enabled"}, 503)
            st = fleet.settings_from(cfg)
            states = [_public_node(n) for n in fleet.node_states(store, st)]
            # the hub is a machine too: show it beside the ones that report in
            # (unless it has joined itself and already has a row)
            try:
                me = fleet.local_state(cfg, store, st, name=host_label,
                                       os_label=os_label or "")
                if all(n["node_id"] != me["node_id"] for n in states):
                    states.insert(0, me)
            except Exception:  # noqa: BLE001 — never lose the fleet over the local row
                pass
            if path == "/api/fleet/nodes":
                summ = fleet.fleet_summary(states)
                scores = [n["meta"].get("score") for n in states
                          if n["meta"].get("score") is not None and not n["silent"]]
                summ["avg_score"] = round(sum(scores) / len(scores), 1) if scores else None
                return self._json({"host": host_label, "summary": summ, "nodes": states})
            if path == "/api/fleet/node":
                node_id = (query.get("id") or [""])[0]
                node = next((n for n in states if n["node_id"] == node_id), None)
                if node is None:
                    return self._json({"error": "unknown node"}, 404)
                return self._json({"node": node,
                                   "history": store.fleet_report_history(node_id, 120)})
            if path == "/api/fleet/export.csv":
                return self._send(200, _fleet_csv(states).encode("utf-8"),
                                  "text/csv; charset=utf-8",
                                  extra=[("Content-Disposition",
                                          'attachment; filename="wrench-fleet.csv"')])
            return self._json({"error": "not found"}, 404)

        # ---------- POST ----------
        def do_POST(self):  # noqa: N802
            path = urlparse(self.path).path
            self._body_read = False
            if self.headers.get("Transfer-Encoding"):
                # only Content-Length bodies are accepted; a chunked body would
                # otherwise be read as zero bytes and its chunks as a new request
                self.close_connection = True
                return self._json({"error": "Content-Length required"}, 411)
            try:
                if path == "/api/fleet/report":
                    return self._fleet_report()
                if not auth.host_allowed(self.headers.get("Host", "")):
                    return self._json({"error": "unrecognized Host header"}, 421)
                if not auth.same_origin(self.headers):
                    return self._json({"error": "cross-origin request refused"}, 403)
                if path == "/login":
                    return self._login()
                if path == "/api/fleet/connect":
                    return self._fleet_connect()
                if path == "/logout":
                    return self._json({"ok": True},
                                      extra=[("Set-Cookie", auth.clear_cookie())])
                if path == "/api/notifications/read":
                    return self._mark_read()
                if path == "/api/chat":
                    return self._chat()
                if path == "/api/fleet/forget":
                    return self._fleet_forget()
                if path == "/api/policy":
                    return self._policy_post()
                if path == "/api/memory":
                    return self._memory_post()
                if path == "/api/jobs":
                    return self._jobs_post()
                return self._json({"error": "not found"}, 404)
            except BrokenPipeError:
                return None
            except Exception as e:  # noqa: BLE001
                return self._json({"error": f"internal error ({e.__class__.__name__})"}, 500)

        def _login(self):
            client = self._client()
            if limiter.blocked(client):
                return self._json({"error": "too many attempts — wait a minute"}, 429,
                                  extra=[("Retry-After", "60")])
            payload = self._json_body()
            if payload is None:
                return None
            role = auth.role_for_secret(str(payload.get("password") or payload.get("token") or ""))
            if role is None:
                limiter.fail(client)
                self._audit("web.login.failed", {"client": client})
                return self._json({"error": "that password or token is not valid"}, 401)
            self._audit("web.login", {"client": client, "role": role})
            return self._json({"ok": True, "role": role},
                              extra=[("Set-Cookie", auth.session_cookie(role))])

        def _audit(self, kind: str, detail: dict) -> None:
            try:
                from . import audit
                audit.append(data_dir, kind, detail, actor="web")
            except Exception:  # noqa: BLE001
                pass

        def _mark_read(self):
            if self._gate("admin") is None:
                return None
            payload = self._json_body()
            if payload is None:
                return None
            raw_ids = payload.get("ids")
            ids = [str(i) for i in raw_ids] if isinstance(raw_ids, list) else None
            return self._json({"marked": notifications.mark_read(data_dir, ids)})

        def _chat(self):
            if cfg is None:
                return self._json({"error": "chat is not enabled on this server"}, 503)
            if self._gate("admin") is None:
                return None
            payload = self._json_body()
            if payload is None:
                return None
            message = str(payload.get("message", "")).strip()[:4000]
            if not message:
                return self._json({"error": "empty message"}, 400)
            from . import agent as agent_mod
            usable, why = agent_mod.brain_status(cfg)
            if not usable:
                return self._json({"error": f"no brain available — {why}. "
                                            "Run `wrench init` to configure one."}, 503)
            store = Store(db_path)
            try:
                with chat_lock:   # one conversation, one turn at a time
                    convo = "\n".join(f"{m['role']}: {m['content'][:500]}"
                                      for m in chat_history[-6:])
                    goal = (f"Conversation so far:\n{convo}\n\nHuman's new message: "
                            f"{message}") if chat_history else message
                    # Web chat investigates; it never changes the machine. With no
                    # confirm channel "repair" already cannot act — but
                    # "autonomous" needs no confirmation, so pin the tier.
                    import copy
                    chat_cfg = copy.copy(cfg)
                    chat_cfg.policy_tier = "suggest"
                    agent = agent_mod.Agent(chat_cfg, store)
                    res = agent.run(goal, purpose="web-chat")
                    chat_history.append({"role": "user", "content": message})
                    chat_history.append({"role": "assistant", "content": res["answer"]})
                    del chat_history[:-CHAT_HISTORY_MAX]
                return self._json({"reply": res["answer"], "tokens": res["tokens"],
                                   "steps": len(res["steps"]), "model": cfg.model})
            finally:
                store.close()

        def _policy_post(self):
            """Change the policy tier. Lowering it is always allowed. Raising it
            hands the agent the ability to act, so from the web that needs an
            explicit opt-in ([web] allow_tier_raise) — a dashboard token alone
            must not be enough to give wrench hands."""
            if cfg is None:
                return self._json({"error": "no configuration loaded"}, 503)
            if self._gate("admin") is None:
                return None
            payload = self._json_body()
            if payload is None:
                return None
            from . import config as _config, policy
            want = str(payload.get("tier", "")).strip().lower()
            if want not in policy.TIERS:
                return self._json({"error": "unknown tier"}, 400)
            have = tier_now()
            if want == have:
                return self._json({"ok": True, "tier": have, "changed": False})
            if tier_io is not None and _config.policy_env_override():
                return self._json({"error": "WRENCH_POLICY is set in the server's environment "
                                            "and overrides the config file"}, 409)
            if policy.tier_rank(want) > policy.tier_rank(have) and not tier_raise_allowed():
                return self._json({
                    "error": "raising the tier from the dashboard is switched off",
                    "command": f"wrench policy {want}",
                    "hint": "run the command in a terminal on this machine, or set "
                            "[web] allow_tier_raise = true"}, 403)
            try:
                if tier_io is not None:
                    tier_io[1](want)
                cfg.policy_tier = want
            except Exception as e:  # noqa: BLE001
                return self._json({"error": f"could not save the tier ({e.__class__.__name__})"},
                                  500)
            self._audit("policy.tier_change", {"from": have, "to": want, "via": "web",
                                               "client": self._client()})
            return self._json({"ok": True, "tier": want, "changed": True})

        def _memory_post(self):
            """add / approve / reject / forget / pin / unpin. Admin only: what is
            written here steers the agent, so it is the operator's word."""
            if self._gate("admin") is None:
                return None
            payload = self._json_body()
            if payload is None:
                return None
            from . import memory
            action = str(payload.get("action", ""))
            store = Store(db_path)
            try:
                if action == "add":
                    try:
                        m = memory.add(store, str(payload.get("text", ""))[:2000],
                                       str(payload.get("kind", "fact")), source="user",
                                       origin="web", cfg=cfg)
                    except memory.MemoryError_ as e:
                        return self._json({"error": str(e)}, 400)
                    return self._json({"ok": True, "memory": m})
                try:
                    mem_id = int(payload.get("id"))
                except (TypeError, ValueError, OverflowError):
                    return self._json({"error": "id required"}, 400)
                if action in ("pin", "unpin"):
                    m = memory.set_pinned(store, mem_id, action == "pin")
                elif action in ("approve", "reject", "forget"):
                    m = memory.set_status(store, mem_id, {
                        "approve": "active", "reject": "rejected",
                        "forget": "forgotten"}[action], cfg=cfg)
                else:
                    return self._json({"error": "unknown action"}, 400)
            finally:
                store.close()
            if m is None:
                return self._json({"error": "unknown memory"}, 404)
            return self._json({"ok": True, "memory": m})

        def _jobs_post(self):
            """approve / pause / resume / rm. Jobs are created from the CLI (or
            proposed by the agent); the dashboard decides their fate."""
            if self._gate("admin") is None:
                return None
            payload = self._json_body()
            if payload is None:
                return None
            from . import heartbeat
            action, name = str(payload.get("action", "")), str(payload.get("name", ""))[:60]
            store = Store(db_path)
            try:
                try:
                    if action in ("approve", "resume"):
                        res = heartbeat.set_job_status(store, name, "active", cfg=cfg)
                    elif action == "pause":
                        res = heartbeat.set_job_status(store, name, "paused", cfg=cfg)
                    elif action == "rm":
                        res = heartbeat.remove_job(store, name, cfg=cfg)
                    else:
                        return self._json({"error": "unknown action"}, 400)
                except heartbeat.HeartbeatError as e:
                    return self._json({"error": str(e)}, 400)
            finally:
                store.close()
            if not res:
                return self._json({"error": "unknown job"}, 404)
            return self._json({"ok": True})

        def _fleet_forget(self):
            if self._gate("admin") is None:
                return None
            payload = self._json_body()
            if payload is None:
                return None
            node_id = str(payload.get("node_id", ""))[:120]
            store = Store(db_path)
            try:
                gone = store.delete_fleet_node(node_id)
            finally:
                store.close()
            if not gone:
                return self._json({"error": "unknown node"}, 404)
            self._audit("fleet.forget", {"node_id": node_id, "client": self._client()})
            return self._json({"ok": True})

        def _fleet_connect(self):
            """`wrench fleet connect`: a machine presents the hub's admin
            password once and is handed a key of its own. Same rate limit and
            audit trail as a browser sign-in; nothing here needs a session."""
            from . import fleet
            client = self._client()
            if limiter.blocked(client):
                return self._json({"error": "too many attempts — wait a minute"}, 429,
                                  extra=[("Retry-After", "60")])
            payload = self._json_body()
            if payload is None:
                return None
            node_id = fleet.clean_node_id(payload.get("node_id"))
            st = fleet.settings_from(cfg) if cfg is not None else None
            store = Store(db_path)
            try:
                if st is None or not hub_on(store):
                    return self._json({"error": "this machine is not running as a fleet hub — "
                                                "start it with `wrench fleet serve`"}, 503)
                if not st.connect:
                    return self._json({"error": "this hub does not accept `fleet connect` "
                                                "([fleet] connect = false) — use an enrollment "
                                                "key: `wrench fleet enroll`"}, 403)
                if not (auth.has_password or auth.admin_token):
                    return self._json({"error": "this hub has no password — set one there "
                                                "with `wrench password`"}, 403)
                if not node_id:
                    return self._json({"error": "a node name is required"}, 400)
                secret = str(payload.get("password") or payload.get("token") or "")
                if auth.role_for_secret(secret) != "admin":
                    limiter.fail(client)
                    self._audit("fleet.connect.failed", {"client": client, "node_id": node_id})
                    return self._json({"error": "that password is not valid"}, 401)
                res = fleet.connect_grant(store, node_id)
            finally:
                store.close()
            self._audit("fleet.connect", {"client": client, "node_id": node_id,
                                          "key_id": res["key_id"],
                                          "reconnected": res["reconnected"]})
            return self._json({"ok": True, "token": res["token"], "key_id": res["key_id"],
                               "node_id": node_id, "reconnected": res["reconnected"],
                               "hub": host_label})

        def _fleet_report(self):
            """Node report ingest. Authenticated by HMAC signature, not session."""
            from . import fleet
            client = self._client()
            if limiter.blocked("fleet:" + client):
                return self._json({"error": "too many rejected reports"}, 429,
                                  extra=[("Retry-After", "60")])
            raw = self._body(fleet.MAX_REPORT_BYTES)
            if raw is None:
                return None
            if not raw:
                return self._json({"error": "empty report"}, 400)
            store = Store(db_path)
            try:
                if not hub_on(store):
                    return self._json({"error": "fleet hub not enabled"}, 503)
                st = fleet.settings_from(cfg)
                res = fleet.authenticate(store, st, self.headers, raw)
                if not res.ok:
                    limiter.fail("fleet:" + client)
                    return self._json({"error": res.error}, res.code)
                report = fleet.parse_report(raw)
                if report is None:
                    return self._json({"error": "malformed report"}, 400)
                try:
                    row = fleet.ingest(store, st, report, res)
                except fleet.IngestRejected as e:
                    return self._json({"error": e.message}, e.code)
                fleet.audit_registration(cfg, store, row)
                # a node that was silent and just reported is live again — say so now
                if row.get("silent"):
                    fleet.check_silent_nodes(cfg, store, st)
                return self._json({"ok": True, "node_id": row["node_id"],
                                   "report_count": row["report_count"]})
            finally:
                store.close()

    return Handler


_audit_cache: dict = {}
_audit_cache_lock = threading.Lock()


def _audit_state(data_dir: Path) -> dict:
    """Audit-chain verdict for the dashboard, re-verified only when the log or
    its head changed (every open page polls this; the walk is O(log size))."""
    from . import audit
    try:
        sig = tuple((p.stat().st_size, p.stat().st_mtime_ns) if p.exists() else None
                    for p in (audit.audit_path(data_dir), audit.head_path(data_dir)))
    except OSError:
        sig = None
    key = str(data_dir)
    with _audit_cache_lock:
        hit = _audit_cache.get(key)
        if hit and sig is not None and hit[0] == sig:
            return hit[1]
    try:
        v = audit.verify(data_dir)
        state = {"intact": v["intact"], "count": v["count"], "reason": v["reason"]}
    except Exception as e:  # noqa: BLE001 — "could not verify" is never shown as fine
        state = {"intact": False, "count": 0,
                 "reason": f"audit log could not be verified ({e.__class__.__name__})"}
    with _audit_cache_lock:
        _audit_cache[key] = (sig, state)
    return state


def _public_node(n: dict) -> dict:
    """A node row for API consumers — credential fingerprints stay on the hub."""
    return {k: v for k, v in n.items() if k not in ("token_hash", "key_id")}


def _fleet_csv(states: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["node_id", "hostname", "state", "status", "health_score", "grade", "os",
                "arch", "wrench_version", "max_disk_pct", "mem_pct", "last_seen_utc",
                "report_count", "tags", "worst_finding"])
    for n in states:
        meta, gauges = n.get("meta") or {}, n.get("gauges") or {}
        disks = (gauges.get("disk_pct") or {}).values()
        worst = next((f.get("text", "") for f in n.get("findings") or []
                      if str(f.get("severity", "")).lower() in ("critical", "error", "warning")), "")
        row = [n["node_id"], n.get("hostname", ""), "silent" if n["silent"] else n["color"],
               n.get("status", ""), meta.get("score", ""), meta.get("grade", ""),
               meta.get("os_label", ""), meta.get("arch", ""), n.get("wrench_version", ""),
               max(disks, default=""), gauges.get("mem_pct", ""),
               time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(n.get("last_seen") or 0)),
               n.get("report_count", ""), " ".join(meta.get("tags") or []), worst]
        # neutralize spreadsheet formula injection: node-supplied text must not
        # be evaluated by Excel when an operator opens the export
        w.writerow([("'" + c) if isinstance(c, str)
                     and c[:1] in ("=", "+", "-", "@", "\t", "\r") else c
                    for c in row])
    return buf.getvalue()


class _QuietServer(ThreadingHTTPServer):
    """Client-side failures (a dropped connection, a failed or abandoned TLS
    handshake, a timeout) are routine on a network listener — not tracebacks."""

    def handle_error(self, request, client_address):
        import sys
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError, OSError)):
            return
        super().handle_error(request, client_address)


def tls_context(cert: str, key: str) -> ssl.SSLContext:
    """A server-side TLS context (TLS 1.2+) for the dashboard / hub listener."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key or None)
    return ctx


def serve(db_path, port: int = 8787, host_label: str = "localhost",
          bind: str = "127.0.0.1", sample_thread: bool = True, cfg=None,
          auth: webauth.AuthConfig | None = None, fleet_hub: bool = False,
          tls_cert: str = "", tls_key: str = "", os_label: str | None = None,
          tier_io=None):
    """Build the HTTP(S) server. Optionally keep sampling in the background.

    Returns the server; the caller runs ``serve_forever()``. The resolved
    access policy is attached as ``httpd.auth`` and the scheme as
    ``httpd.scheme`` so the CLI can print an accurate URL.
    """
    from .sensors import sample_all

    use_tls = bool(tls_cert)
    if auth is None:
        auth = (webauth.resolve(cfg, bind, Path(db_path).parent, tls=use_tls)
                if cfg is not None else webauth.AuthConfig(bind=bind, tls=use_tls))
    auth.tls = use_tls

    if sample_thread:
        def sampler():
            while True:
                try:
                    s = Store(db_path)
                    try:
                        sample_all(s)
                        s.maybe_prune(getattr(cfg, "retention_days", 30) if cfg else 30)
                        if cfg is not None:
                            from . import posture
                            posture.record(cfg, s, min_gap_s=1800)
                    finally:
                        s.close()
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(30)

        threading.Thread(target=sampler, name="wrench-sampler", daemon=True).start()

    if fleet_hub and cfg is not None:
        from . import fleet
        fleet.start_sweeper(cfg, db_path)

    httpd = _QuietServer(
        (bind, port), make_handler(db_path, host_label, cfg=cfg, auth=auth, fleet_hub=fleet_hub,
                                   os_label=os_label, tier_io=tier_io))
    httpd.daemon_threads = True
    if use_tls:
        httpd.socket = tls_context(tls_cert, tls_key).wrap_socket(
            httpd.socket, server_side=True, do_handshake_on_connect=False)
    httpd.auth = auth                      # type: ignore[attr-defined]
    httpd.scheme = "https" if use_tls else "http"   # type: ignore[attr-defined]
    return httpd
