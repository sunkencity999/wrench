"""Notification channels — reach the admin where they are.

A channel is a named destination with its own severity threshold:

    [notify.channels.ops]            # everything worth attention, to the team
    type = "slack"
    secret_file = "~/.config/wrench/notify/ops.secret"

    [notify.channels.phone]          # only what cannot wait, to a phone
    type = "telegram"
    chat_id = "123456789"
    min_severity = "critical"
    secret_file = "~/.config/wrench/notify/phone.secret"

    [notify.channels.mail]
    type = "email"
    host = "smtp.example.com"
    port = 587
    security = "starttls"            # starttls | ssl | none
    username = "alerts@example.com"
    from = "wrench <alerts@example.com>"
    to = ["oncall@example.com"]
    secret_file = "~/.config/wrench/notify/mail.secret"

Types: ``email`` (SMTP), ``telegram`` (a bot), ``slack``, ``teams``,
``discord`` (incoming webhooks) and ``webhook`` (the generic JSON POST — ntfy
and anything else).

`wrench notify setup` writes these; `wrench notify test` proves they work.

Rules:

* **The secret is the credential and nothing else**: a webhook URL, a bot
  token, an SMTP password. It lives in an owner-only file next to the config
  (or ``WRENCH_NOTIFY_<NAME>_SECRET``), never in the audit log, never in an
  error message, never on screen.
* **A channel that fails never breaks the caller** and never stops the other
  channels. Failures go to the notify log, with the secret redacted.
* **Offline mode** skips any channel whose server is not on a local or
  private address.

Stdlib only: ``urllib`` and ``smtplib``.
"""

from __future__ import annotations

import json
import os
import platform
import re
import smtplib
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path

HTTP_TIMEOUT_S = 12
SMTP_TIMEOUT_S = 20
TELEGRAM_API = "https://api.telegram.org"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")

TYPES = {
    "email": {"label": "Email (SMTP)", "secret": "SMTP password (enter for none)",
              "secret_optional": True},
    "telegram": {"label": "Telegram bot", "secret": "bot token (from @BotFather)"},
    "slack": {"label": "Slack incoming webhook", "secret": "webhook URL",
              "url_prefix": "https://hooks.slack.com/"},
    "teams": {"label": "Microsoft Teams webhook", "secret": "webhook URL"},
    "discord": {"label": "Discord webhook", "secret": "webhook URL",
                "url_prefix": "https://discord"},
    "webhook": {"label": "Generic JSON webhook (ntfy, …)", "secret": "webhook URL"},
}
URL_TYPES = ("slack", "teams", "discord", "webhook")
SEV_EMOJI = {"critical": "🔴", "error": "🔴", "attention": "🟠", "warning": "🟠",
             "info": "🔵", "ok": "🟢"}


class ChannelError(Exception):
    """A send or setup failure, already safe to show (no secret in it)."""


@dataclass
class Channel:
    name: str
    type: str
    min_severity: str = ""
    settings: dict = field(default_factory=dict)
    secret: str = ""

    @property
    def destination(self) -> str:
        """Where it goes, safe to display."""
        s = self.settings
        if self.type == "email":
            return ", ".join(s.get("to") or []) + f" via {s.get('host', '?')}"
        if self.type == "telegram":
            return f"chat {s.get('chat_id', '?')}" + (f" ({s['chat_name']})"
                                                       if s.get("chat_name") else "")
        host = urllib.parse.urlsplit(self.secret).hostname if self.secret else ""
        return host or "(no URL)"

    def server_host(self) -> str:
        """The host this channel talks to (for the offline-mode check)."""
        if self.type == "email":
            return str(self.settings.get("host") or "")
        if self.type == "telegram":
            return urllib.parse.urlsplit(str(self.settings.get("api_base") or TELEGRAM_API)).hostname or ""
        return urllib.parse.urlsplit(self.secret).hostname or ""


# ---------------------------------------------------------------- config
def valid_name(name: str) -> bool:
    return bool(NAME_RE.fullmatch(name or ""))


def secret_path(name: str) -> Path:
    from . import config
    return Path(config.CONFIG_DIR) / "notify" / f"{name}.secret"


def _read_secret(name: str, sec: dict) -> str:
    env = os.environ.get("WRENCH_NOTIFY_" + name.upper().replace("-", "_") + "_SECRET")
    if env:
        return env.strip()
    for key in ("url", "token", "password", "secret"):
        if sec.get(key):
            return str(sec[key]).strip()
    paths = []
    if sec.get("secret_file"):
        paths.append(Path(str(sec["secret_file"])).expanduser())
    paths.append(secret_path(name))
    for p in paths:
        try:
            v = p.read_text(encoding="utf-8").strip()
            if v:
                return v
        except OSError:
            continue
    return ""


def load(cfg) -> list[Channel]:
    """The configured channels, in name order. Malformed entries are skipped."""
    sec = (getattr(cfg, "raw", None) or {}).get("notify", {})
    chans = sec.get("channels") if isinstance(sec, dict) else None
    out: list[Channel] = []
    if not isinstance(chans, dict):
        return out
    for name in sorted(chans):
        c = chans[name]
        if not isinstance(c, dict) or not valid_name(str(name)):
            continue
        ctype = str(c.get("type", "")).lower()
        if ctype not in TYPES or c.get("enabled") is False:
            continue
        settings = {k: v for k, v in c.items()
                    if k not in ("type", "min_severity", "url", "token", "password",
                                 "secret", "secret_file", "enabled")}
        if isinstance(settings.get("to"), str):
            settings["to"] = [settings["to"]]
        out.append(Channel(name=str(name), type=ctype,
                           min_severity=str(c.get("min_severity", "") or ""),
                           settings=settings, secret=_read_secret(str(name), c)))
    return out


def save_secret(name: str, secret: str) -> Path:
    path = secret_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path.parent, 0o700)
    tmp = path.with_name(path.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(secret + "\n")
    if os.name == "posix":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def save(channel: Channel) -> Path:
    """Write the channel to the config (and its secret to an owner-only file)."""
    from . import config
    if not valid_name(channel.name):
        raise ValueError("a channel name is lowercase letters, digits and dashes")
    if channel.type not in TYPES:
        raise ValueError(f"unknown channel type {channel.type!r}")
    values: dict = {"type": channel.type}
    if channel.min_severity:
        values["min_severity"] = channel.min_severity
    for k, v in channel.settings.items():
        if v not in (None, "", []):
            values[k] = v
    if channel.secret:
        values["secret_file"] = str(save_secret(channel.name, channel.secret))
    remove(channel.name, keep_secret=True)        # replace, never merge with a stale one
    return config.set_section_values(f"notify.channels.{channel.name}", values)


def remove(name: str, keep_secret: bool = False) -> bool:
    """Delete a channel's section from the config, and its secret file."""
    from . import config
    gone = False
    path = Path(config.CONFIG_PATH)
    header = f"[notify.channels.{name}]"
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError:
        lines = []
    out, skipping = [], False
    for line in lines:
        stripped = line.strip()
        if stripped == header:
            skipping, gone = True, True
            continue
        if skipping and stripped.startswith("["):
            skipping = False
        if not skipping:
            out.append(line)
    if gone:
        while len(out) > 1 and out[-1].strip() == "" and out[-2].strip() == "":
            out.pop()
        tmp = path.with_name(path.name + ".new")
        tmp.write_text("".join(out), encoding="utf-8")
        if os.name == "posix":
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    if not keep_secret:
        try:
            secret_path(name).unlink()
            gone = True
        except OSError:
            pass
    return gone


# ---------------------------------------------------------------- the message
def host_label() -> str:
    return platform.node() or "this machine"


def message(rec: dict, link: str = "") -> dict:
    """One alert as the parts every channel renders from."""
    sev = str(rec.get("severity", "attention")).lower()
    kind = str(rec.get("kind", "patrol"))
    summary = str(rec.get("summary", "")).strip() or "(no details)"
    host = host_label()
    return {
        "severity": sev, "kind": kind, "summary": summary, "host": host,
        "emoji": SEV_EMOJI.get(sev, "🟠"),
        "title": f"wrench · {host} · {sev}",
        "when": time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(rec.get("ts") or time.time())),
        "link": link if link.startswith(("http://", "https://")) else "",
    }


def dashboard_link(cfg, rec: dict) -> str:
    """A link worth sending to a phone: only when the operator has said where
    the dashboard is reachable (``[notify] dashboard_url``). A localhost
    address means nothing on another device."""
    sec = (getattr(cfg, "raw", None) or {}).get("notify", {})
    base = str(sec.get("dashboard_url", "") if isinstance(sec, dict) else "").rstrip("/")
    if not base.startswith(("http://", "https://")):
        return ""
    nid = "".join(c for c in str(rec.get("id", "")) if c.isalnum())[:40]
    return f"{base}/#notification={nid}" if nid else base


def _redact(text: str, secret: str) -> str:
    text = str(text)
    if secret:
        text = text.replace(secret, "•••")
        tail = secret.rsplit("/", 1)[-1]
        if len(tail) >= 8:
            text = text.replace(tail, "•••")
    return re.sub(r"bot\d+:[A-Za-z0-9_-]{20,}", "bot•••", text)


# ---------------------------------------------------------------- senders
def _post_json(url: str, payload: dict, secret: str = "", opener=None,
               timeout: float = HTTP_TIMEOUT_S) -> dict:
    if not url.lower().startswith(("http://", "https://")):
        raise ChannelError("the address must start with http:// or https://")
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "wrench-notify"})
    try:
        with (opener or urllib.request.urlopen)(req, timeout=timeout) as resp:
            raw = resp.read(65536)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read(500).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001
            pass
        raise ChannelError(_redact(f"HTTP {e.code}" + (f": {detail[:200]}" if detail else ""),
                                   secret)) from None
    except Exception as e:  # noqa: BLE001
        reason = getattr(e, "reason", e)
        raise ChannelError(_redact(f"{reason.__class__.__name__}: {reason}", secret)) from None
    try:
        return json.loads(raw.decode("utf-8", "replace")) if raw.strip().startswith(b"{") else {}
    except ValueError:
        return {}


def _text(m: dict) -> str:
    lines = [f"{m['emoji']} {m['title']}", m["summary"], f"{m['kind']} · {m['when']}"]
    if m["link"]:
        lines.append(m["link"])
    return "\n".join(lines)


def _send_slack(ch: Channel, m: dict, opener=None) -> None:
    def esc(s: str) -> str:                       # Slack's three reserved characters
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = (f"{m['emoji']} *{esc(m['title'])}*\n{esc(m['summary'])}\n"
            f"_{esc(m['kind'])} · {esc(m['when'])}_")
    if m["link"]:
        text += f"\n<{m['link']}|Show in the dashboard>"
    _post_json(ch.secret, {"text": text}, ch.secret, opener)


def _send_discord(ch: Channel, m: dict, opener=None) -> None:
    _post_json(ch.secret, {"content": _text(m)[:1900], "allowed_mentions": {"parse": []}},
               ch.secret, opener)


def _send_teams(ch: Channel, m: dict, opener=None) -> None:
    body = [
        {"type": "TextBlock", "weight": "Bolder", "wrap": True,
         "text": f"{m['emoji']} {m['title']}"},
        {"type": "TextBlock", "wrap": True, "text": m["summary"]},
        {"type": "TextBlock", "isSubtle": True, "wrap": True, "spacing": "None",
         "text": f"{m['kind']} · {m['when']}"},
    ]
    card: dict = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                  "type": "AdaptiveCard", "version": "1.4", "body": body}
    if m["link"]:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Show in the dashboard",
                            "url": m["link"]}]
    _post_json(ch.secret, {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
        "content": card}]}, ch.secret, opener)


def _send_webhook(ch: Channel, m: dict, opener=None) -> None:
    text = f"🔧 wrench {m['kind']} [{m['severity']}]: {m['summary']}"
    _post_json(ch.secret, {
        "title": m["title"], "message": m["summary"], "text": text, "content": text,
        "severity": m["severity"], "kind": m["kind"], "host": m["host"],
        "link": m["link"] or None}, ch.secret, opener)


def _telegram_call(token: str, method: str, payload: dict, api_base: str = "",
                   opener=None, timeout: float = HTTP_TIMEOUT_S) -> dict:
    if not re.fullmatch(r"\d+:[A-Za-z0-9_-]{20,}", token or ""):
        raise ChannelError("that does not look like a Telegram bot token "
                           "(it looks like 123456:ABC-DEF…)")
    url = f"{(api_base or TELEGRAM_API).rstrip('/')}/bot{token}/{method}"
    d = _post_json(url, payload, token, opener, timeout)
    if not d.get("ok", False):
        raise ChannelError(_redact("Telegram said: " + str(d.get("description", "no")), token))
    return d


def _send_telegram(ch: Channel, m: dict, opener=None) -> None:
    chat = str(ch.settings.get("chat_id") or "")
    if not chat:
        raise ChannelError("no chat_id is set for this channel")
    _telegram_call(ch.secret, "sendMessage",
                   {"chat_id": chat, "text": _text(m)[:4000],
                    "disable_web_page_preview": True},
                   str(ch.settings.get("api_base") or ""), opener)


def telegram_bot_name(token: str, api_base: str = "", opener=None) -> str:
    """Prove a bot token and return the bot's @username."""
    d = _telegram_call(token, "getMe", {}, api_base, opener)
    return str((d.get("result") or {}).get("username") or "")


def telegram_find_chats(token: str, api_base: str = "", opener=None) -> list[dict]:
    """Chats that have written to the bot recently: [{id, name}], newest first."""
    d = _telegram_call(token, "getUpdates", {"timeout": 0, "allowed_updates": ["message"]},
                       api_base, opener)
    seen: dict[str, dict] = {}
    for u in d.get("result") or []:
        chat = ((u.get("message") or u.get("channel_post") or {}).get("chat")) or {}
        if chat.get("id") is None:
            continue
        name = chat.get("title") or " ".join(
            x for x in (chat.get("first_name"), chat.get("last_name")) if x) \
            or chat.get("username") or str(chat["id"])
        seen.pop(str(chat["id"]), None)        # re-insert: the latest message wins the order
        seen[str(chat["id"])] = {"id": str(chat["id"]), "name": str(name)[:80]}
    return list(reversed(list(seen.values())))


def _send_email(ch: Channel, m: dict, smtp_factory=None) -> None:
    s = ch.settings
    host = str(s.get("host") or "")
    to = [str(x) for x in (s.get("to") or []) if str(x).strip()]
    sender = str(s.get("from") or s.get("username") or "")
    if not host or not to or not parseaddr(sender)[1]:
        raise ChannelError("an email channel needs host, from and to")
    security = str(s.get("security", "starttls")).lower()
    if security not in ("starttls", "ssl", "none"):
        raise ChannelError("security must be starttls, ssl or none")
    port = int(s.get("port") or {"ssl": 465, "starttls": 587, "none": 25}[security])
    msg = EmailMessage()
    # a header is one line: a finding's text must not be able to add another
    one_line = " ".join(m["summary"].split())
    msg["Subject"] = f"[wrench] {m['severity']} on {m['host']}: {one_line}"[:180]
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="wrench.local")
    msg["Auto-Submitted"] = "auto-generated"
    body = f"{m['summary']}\n\nmachine:  {m['host']}\nseverity: {m['severity']}\n" \
           f"source:   {m['kind']}\nwhen:     {m['when']}\n"
    if m["link"]:
        body += f"\nShow in the dashboard: {m['link']}\n"
    body += "\n-- \nSent by wrench on this machine. Change where alerts go: wrench notify\n"
    msg.set_content(body)
    username = str(s.get("username") or "")
    try:
        if smtp_factory is not None:
            conn = smtp_factory(host, port, security)
        elif security == "ssl":
            conn = smtplib.SMTP_SSL(host, port, timeout=SMTP_TIMEOUT_S,
                                    context=ssl.create_default_context())
        else:
            conn = smtplib.SMTP(host, port, timeout=SMTP_TIMEOUT_S)
        with conn:
            if security == "starttls":
                conn.starttls(context=ssl.create_default_context())
            if username and ch.secret:
                conn.login(username, ch.secret)
            elif ch.secret and security == "none":
                raise ChannelError("refusing to send a password without TLS")
            conn.send_message(msg, from_addr=parseaddr(sender)[1], to_addrs=to)
    except ChannelError:
        raise
    except smtplib.SMTPAuthenticationError as e:
        raise ChannelError(f"the mail server refused the login ({e.smtp_code}). Many "
                           "providers need an app password rather than your normal "
                           "one.") from None
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        raise ChannelError(_redact(f"{e.__class__.__name__}: {e}", ch.secret)[:300]) from None


_SENDERS = {"slack": _send_slack, "discord": _send_discord, "teams": _send_teams,
            "webhook": _send_webhook, "telegram": _send_telegram}


def send(ch: Channel, rec: dict, link: str = "", opener=None, smtp_factory=None) -> None:
    """Send one alert to one channel. Raises ChannelError (secret-free)."""
    if ch.type != "email" and not ch.secret:
        raise ChannelError("no " + ("URL" if ch.type in URL_TYPES else "token")
                           + " is stored for this channel — run: wrench notify setup")
    m = message(rec, link)
    if ch.type == "email":
        return _send_email(ch, m, smtp_factory)
    return _SENDERS[ch.type](ch, m, opener)


# ---------------------------------------------------------------- fan-out
def deliver(cfg, rec: dict, data_dir, force: bool = False, block_public: bool = False,
            only: str | None = None, opener=None, smtp_factory=None, log=None) -> dict:
    """Send ``rec`` to every channel whose threshold it meets.

    ``force``: the operator asked for this (a scheduled brief, a test) — ignore
    thresholds. Returns {name: (ok, detail)}. Never raises."""
    from . import notifications as _n
    results: dict = {}
    try:
        st = _n.settings_from(cfg)
        chans = load(cfg)
    except Exception:  # noqa: BLE001
        return results
    sev = rec.get("severity", "attention")
    link = dashboard_link(cfg, rec)
    for ch in chans:
        if only and ch.name != only:
            continue
        if not force and not _n.should_notify(sev, ch.min_severity or st.min_severity):
            continue
        try:
            if block_public:
                from . import offline as _offline
                if not _offline.host_is_private(ch.server_host()):
                    raise ChannelError("offline mode: skipped (not a local or private address)")
            send(ch, rec, link, opener=opener, smtp_factory=smtp_factory)
            results[ch.name] = (True, "sent")
        except ChannelError as e:
            results[ch.name] = (False, str(e))
        except Exception as e:  # noqa: BLE001 — one channel never breaks the rest
            results[ch.name] = (False, _redact(f"{e.__class__.__name__}: {e}", ch.secret)[:300])
        if not results[ch.name][0]:
            (log or _n._log)(Path(data_dir), f"channel {ch.name} ({ch.type}) failed: "  # noqa: SLF001
                                             f"{results[ch.name][1]}")
    return results


def thresholds(cfg) -> list[str]:
    """Each channel's own threshold (for deciding whether an event is worth
    recording at all)."""
    try:
        return [c.min_severity for c in load(cfg) if c.min_severity]
    except Exception:  # noqa: BLE001
        return []
