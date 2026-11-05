"""wrench web — local dashboard. stdlib http.server + a single dark page.

Endpoints:
  /                 dashboard
  /api/summary      latest sample + counts
  /api/timeline     24h of os samples (downsampled)
  /api/drift        recent drift events
  /api/patrols      recent patrol reports
  /api/actions      action log
  /api/tokens       token spend by model
  /api/webintel     cached CVE/EOL scan
  /api/notifications          unread patrol notifications (toast funnel)
  POST /api/notifications/read  mark notifications read ({"ids": [...] } or all)
  POST /api/chat    talk to the agent (same loop as `wrench chat`)

Security posture: binds 127.0.0.1 by default; /api/chat additionally enforces
localhost Host/Origin (same-origin only) and a request-size cap.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import notifications
from .store import Store

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wrench — dashboard</title>
<style>
:root { --bg:#0b0e14; --panel:#11151f; --border:#1f2633; --fg:#dce3ee; --dim:#7d8799;
  --ok:#3fb950; --warn:#d29922; --crit:#f85149; --accent:#58a6ff; --mag:#bc8cff; --cyan:#39c5cf;
  --shadow:0 10px 30px rgba(0,0,0,.45); }
html[data-theme="light"] { --bg:#f3f5f9; --panel:#ffffff; --border:#d9dfe8; --fg:#1a2230;
  --dim:#5c6775; --accent:#0969da; --mag:#8250df; --cyan:#1b7c83;
  --shadow:0 10px 30px rgba(30,40,60,.12); }
* { box-sizing:border-box; margin:0; }
body { background:var(--bg); color:var(--fg);
  font:14px/1.5 'SF Mono',ui-monospace,Menlo,Consolas,monospace; padding:1.2rem;
  transition:background .25s,color .25s; }
header { display:flex; align-items:baseline; gap:1rem; margin-bottom:1.2rem; flex-wrap:wrap; }
header h1 { font-size:1.4rem; } header .dim { color:var(--dim); font-size:.85rem; }
header .right { margin-left:auto; display:flex; gap:.6rem; align-items:center; }
.kbd { border:1px solid var(--border); border-bottom-width:2px; border-radius:5px;
  padding:0 .45em; font-size:.78rem; color:var(--dim); background:var(--panel); }
.pulse { display:inline-block; width:9px; height:9px; border-radius:50%; background:var(--ok);
  animation:pulse 2s infinite; margin-right:.4rem; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:1rem; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:12px;
  padding:1rem 1.2rem; overflow:hidden; transition:border-color .2s, transform .2s; }
.panel:hover { border-color:color-mix(in srgb, var(--accent) 35%, var(--border)); }
.panel h2 { font-size:.8rem; text-transform:uppercase; letter-spacing:.12em;
  color:var(--dim); margin-bottom:.8rem; }
.panel.wide { grid-column:1/-1; }
.gauges { display:flex; gap:1.5rem; flex-wrap:wrap; }
.gauge { text-align:center; }
.gauge .num { font-size:1.7rem; font-weight:bold; }
.gauge .lbl { color:var(--dim); font-size:.75rem; text-transform:uppercase; }
.ok { color:var(--ok); } .warn { color:var(--warn); } .crit { color:var(--crit); }
svg text { font:10px ui-monospace,monospace; fill:var(--dim); }
.feed { max-height:300px; overflow-y:auto; }
.feed-item { padding:.45rem 0; border-bottom:1px solid var(--border); font-size:.85rem; }
.feed-item:last-child { border:none; }
.feed-item .when { color:var(--dim); font-size:.75rem; }
.badge { display:inline-block; padding:0 .5rem; border-radius:5px; font-size:.75rem;
  font-weight:bold; margin-right:.4rem; }
.badge.ok { background:#12301c; color:var(--ok); } .badge.attention { background:#33290f; color:var(--warn); }
.badge.critical,.badge.error { background:#381417; color:var(--crit); }
.badge.drift { background:#15232f; color:var(--accent); }
.badge.action { background:#241b33; color:var(--mag); }
.badge.vuln { background:#381417; color:var(--crit); }
.badge.eol { background:#33290f; color:var(--warn); }
.tokens-row { display:flex; justify-content:space-between; padding:.3rem 0;
  border-bottom:1px solid var(--border); font-size:.85rem; }
.tokens-row:last-child { border:none; }
.big { font-size:1.6rem; font-weight:bold; color:var(--mag); }
details summary { cursor:pointer; color:var(--accent); font-size:.8rem; }

/* ---- notification toasts ---- */
#toasts { position:fixed; top:1rem; right:1rem; z-index:70; display:flex;
  flex-direction:column; gap:.6rem; max-width:340px; }
.toast { background:var(--panel); border:1px solid var(--border);
  border-left:4px solid var(--warn); border-radius:10px; padding:.7rem .9rem;
  font-size:.85rem; box-shadow:var(--shadow); cursor:pointer;
  animation:toast-in .25s ease-out; transition:opacity .5s; }
.toast.critical, .toast.error { border-left-color:var(--crit); }
.toast .when { color:var(--dim); font-size:.72rem; margin-top:.3rem; }
.toast.fade { opacity:0; }
@keyframes toast-in { from { opacity:0; transform:translateX(24px); } to { opacity:1; } }
details pre { white-space:pre-wrap; font-size:.75rem; color:var(--dim);
  margin-top:.5rem; max-height:260px; overflow-y:auto; }
footer { color:var(--dim); font-size:.75rem; margin-top:1.4rem; text-align:center; }
a { color:var(--accent); }

/* ---- chat ---- */
#chat-fab { position:fixed; right:1.4rem; bottom:1.4rem; width:58px; height:58px;
  border-radius:50%; background:var(--accent); color:#fff; font-size:1.7rem; border:none;
  cursor:pointer; box-shadow:var(--shadow); z-index:50; transition:transform .18s;
  display:flex; align-items:center; justify-content:center; }
#chat-fab:hover { transform:scale(1.08) rotate(-12deg); }
#chat-panel { position:fixed; right:1.4rem; bottom:5.6rem; width:min(420px, calc(100vw - 2.8rem));
  height:min(560px, calc(100vh - 8rem)); background:var(--panel); border:1px solid var(--border);
  border-radius:16px; box-shadow:var(--shadow); z-index:51; display:none;
  flex-direction:column; overflow:hidden;
  transform-origin:bottom right; }
#chat-panel.open { display:flex; animation:chat-in .22s ease-out; }
@keyframes chat-in { from { opacity:0; transform:scale(.88) translateY(12px); }
  to { opacity:1; transform:none; } }
#chat-head { padding:.8rem 1rem; border-bottom:1px solid var(--border);
  display:flex; align-items:center; gap:.6rem; }
#chat-head .t { font-weight:bold; }
#chat-head .s { color:var(--dim); font-size:.75rem; }
#chat-head button { margin-left:auto; background:none; border:none; color:var(--dim);
  font-size:1.1rem; cursor:pointer; }
#chat-log { flex:1; overflow-y:auto; padding:1rem; display:flex; flex-direction:column; gap:.7rem; }
.msg { max-width:88%; padding:.55rem .8rem; border-radius:12px; font-size:.86rem;
  white-space:pre-wrap; word-wrap:break-word; animation:msg-in .18s ease-out; }
@keyframes msg-in { from { opacity:0; transform:translateY(6px); } to { opacity:1; } }
.msg.you { align-self:flex-end; background:var(--accent); color:#fff;
  border-bottom-right-radius:4px; }
.msg.bot { align-self:flex-start; background:color-mix(in srgb, var(--panel) 60%, var(--bg));
  border:1px solid var(--border); border-bottom-left-radius:4px; }
.msg.bot .meta { display:block; color:var(--dim); font-size:.7rem; margin-top:.35rem; }
.typing { align-self:flex-start; display:flex; gap:.25rem; padding:.7rem .9rem; }
.typing span { width:7px; height:7px; border-radius:50%; background:var(--dim);
  animation:blink 1.2s infinite; }
.typing span:nth-child(2){ animation-delay:.2s } .typing span:nth-child(3){ animation-delay:.4s }
@keyframes blink { 0%,80%,100%{opacity:.25} 40%{opacity:1} }
#chat-form { display:flex; gap:.5rem; padding:.7rem; border-top:1px solid var(--border); }
#chat-input { flex:1; background:var(--bg); border:1px solid var(--border); color:var(--fg);
  border-radius:9px; padding:.55rem .7rem; font:inherit; outline:none; }
#chat-input:focus { border-color:var(--accent); }
#chat-send { background:var(--accent); border:none; color:#fff; border-radius:9px;
  padding:0 1rem; cursor:pointer; font:inherit; font-weight:bold; }
#chat-send:disabled { opacity:.5; cursor:default; }

/* ---- shortcuts overlay ---- */
#overlay { position:fixed; inset:0; background:rgba(0,0,0,.55); z-index:60; display:none;
  align-items:center; justify-content:center; }
#overlay.open { display:flex; }
#overlay .card { background:var(--panel); border:1px solid var(--border); border-radius:14px;
  padding:1.4rem 1.8rem; box-shadow:var(--shadow); min-width:300px; }
#overlay h3 { margin-bottom:.9rem; font-size:1rem; }
#overlay .row { display:flex; justify-content:space-between; gap:2rem; padding:.3rem 0;
  font-size:.88rem; color:var(--dim); }
#overlay .row .kbd { color:var(--fg); }
</style></head><body>
<header>
  <h1>🔧 wrench</h1>
  <span class="dim"><span class="pulse"></span>live · <span id="host">…</span> · refreshes every 15s</span>
  <span class="dim" id="updated"></span>
  <span class="right">
    <span class="dim">press <span class="kbd">?</span> for shortcuts</span>
    <button class="kbd" id="theme-btn" title="toggle theme (t)" style="cursor:pointer">◐</button>
  </span>
</header>
<div class="grid">
  <div class="panel wide">
    <h2>vitals — last 24h</h2>
    <div class="gauges" id="gauges"></div>
    <div id="charts" style="margin-top:1rem"></div>
  </div>
  <div class="panel"><h2>patrol feed</h2><div class="feed" id="patrols"></div></div>
  <div class="panel"><h2>drift feed — what changed on this box</h2><div class="feed" id="drift"></div></div>
  <div class="panel"><h2>security intel — OSV.dev + endoflife.date</h2><div class="feed" id="webintel"></div></div>
  <div class="panel"><h2>agent action log</h2><div class="feed" id="actions"></div></div>
  <div class="panel"><h2>token spend</h2><div id="tokens"></div></div>
</div>
<footer>wrench — an intentional local sysadmin agent ·
<a href="https://github.com/sunkencity999/wrench">github.com/sunkencity999/wrench</a></footer>

<div id="toasts" aria-live="polite"></div>
<button id="chat-fab" title="chat with wrench (c)">🔧</button>
<div id="chat-panel" role="dialog" aria-label="chat with wrench">
  <div id="chat-head"><span>🔧</span><div><div class="t">wrench</div>
    <div class="s">the sysadmin that lives here</div></div>
    <button id="chat-close" title="close (Esc)">✕</button></div>
  <div id="chat-log"></div>
  <form id="chat-form"><input id="chat-input" autocomplete="off"
    placeholder="ask me anything about this machine…" maxlength="2000">
  <button id="chat-send" type="submit">▸</button></form>
</div>

<div id="overlay"><div class="card">
  <h3>keyboard shortcuts</h3>
  <div class="row"><span>toggle chat</span><span class="kbd">c</span></div>
  <div class="row"><span>refresh data</span><span class="kbd">r</span></div>
  <div class="row"><span>toggle theme</span><span class="kbd">t</span></div>
  <div class="row"><span>this overlay</span><span class="kbd">?</span></div>
  <div class="row"><span>close panels</span><span class="kbd">Esc</span></div>
</div></div>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ago = ts => { const d = Date.now()/1000 - ts;
  if (d < 90) return Math.round(d)+'s ago';
  if (d < 5400) return Math.round(d/60)+'m ago';
  if (d < 172800) return (d/3600).toFixed(1)+'h ago';
  return (d/86400).toFixed(1)+'d ago'; };
const clsFor = p => p < 70 ? 'ok' : p < 90 ? 'warn' : 'crit';

function chart(title, pts, color, unit='%', maxY) {
  if (!pts.length) return '';
  const W = 860, H = 90, PL = 44, PB = 14;
  const t0 = pts[0][0], t1 = pts[pts.length-1][0] || t0+1;
  const ymax = maxY ?? Math.max(...pts.map(p=>p[1]), 1) * 1.15;
  const X = t => PL + (t - t0) / Math.max(t1 - t0, 1) * (W - PL - 8);
  const Y = v => (H - PB) - v / ymax * (H - PB - 12);
  const path = pts.map((p,i) => (i?'L':'M') + X(p[0]).toFixed(1) + ',' + Y(p[1]).toFixed(1)).join('');
  const area = path + `L${X(t1).toFixed(1)},${H-PB}L${X(t0).toFixed(1)},${H-PB}Z`;
  const last = pts[pts.length-1][1];
  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;height:${H}px;display:block">
    <text x="0" y="12">${esc(title)}</text>
    <text x="${W-8}" y="12" text-anchor="end" style="fill:${color};font-weight:bold">${last.toFixed(1)}${unit}</text>
    <line x1="${PL}" y1="${H-PB}" x2="${W-8}" y2="${H-PB}" stroke="var(--border)"/>
    <path d="${area}" fill="${color}" opacity="0.12"/>
    <path d="${path}" fill="none" stroke="${color}" stroke-width="1.6"/>
  </svg>`;
}

async function j(u) { const r = await fetch(u); return r.json(); }

async function refresh() {
  try {
    const [sum, tl, drift, patrols, actions, tokens, wi] = await Promise.all([
      j('/api/summary'), j('/api/timeline'), j('/api/drift'),
      j('/api/patrols'), j('/api/actions'), j('/api/tokens'), j('/api/webintel')]);

    $('host').textContent = sum.host || 'localhost';
    $('updated').textContent = 'updated ' + new Date().toLocaleTimeString();

    const os = sum.os || {};
    const g = [];
    const gauge = (lbl, v, unit='%') =>
      g.push(`<div class="gauge"><div class="num ${clsFor(v)}">${(v??0).toFixed(0)}<span style="font-size:.9rem">${unit}</span></div><div class="lbl">${lbl}</div></div>`);
    gauge('cpu', os.cpu_pct); gauge('mem', os.mem_pct); gauge('swap', os.swap_pct);
    for (const [m,p] of Object.entries(os.disk_pct || {})) gauge('disk '+m, p);
    g.push(`<div class="gauge"><div class="num" style="color:var(--cyan)">${os.n_procs??'—'}</div><div class="lbl">procs</div></div>`);
    g.push(`<div class="gauge"><div class="num" style="color:var(--cyan)">${os.uptime_s?Math.round(os.uptime_s/3600)+'h':'—'}</div><div class="lbl">uptime</div></div>`);
    $('gauges').innerHTML = g.join('');

    $('charts').innerHTML =
      chart('cpu %', tl.map(s=>[s.ts, s.cpu_pct||0]), 'var(--accent)', '%', 100) +
      chart('mem %', tl.map(s=>[s.ts, s.mem_pct||0]), 'var(--mag)', '%', 100) +
      chart('net ↓ KB/s', tl.map(s=>[s.ts, s.net_recv_rate_kbs||0]), 'var(--cyan)', '') +
      chart('load 1m', tl.map(s=>[s.ts, s.load_1m||0]), 'var(--warn)', '');

    $('patrols').innerHTML = patrols.length ? patrols.map(p => `
      <div class="feed-item" data-ts="${p.ts}"><span class="badge ${esc(p.status)}">${esc(p.status)}</span>${esc(p.summary)}
      <div class="when">${ago(p.ts)} · ${esc(p.model||'')} · ${p.tokens} tok</div>
      <details><summary>full report</summary><pre>${esc(p.report_md)}</pre></details></div>`).join('')
      : '<div class="feed-item dim">no patrols yet — run <b>wrench patrol</b></div>';

    $('drift').innerHTML = drift.length ? drift.map(d => `
      <div class="feed-item"><span class="badge drift">${esc(d.kind)}</span>${esc(d.summary)}
      <div class="when">${ago(d.ts)}</div>
      ${Array.isArray(d.details) && d.details.length ? `<details><summary>${d.details.length} change(s)</summary><pre>${esc(d.details.join('\n'))}</pre></details>` : ''}</div>`).join('')
      : '<div class="feed-item dim">no drift recorded — this box is exactly as you left it</div>';

    if (wi && wi.ts) {
      const items = [];
      for (const v of (wi.vulns || []).slice(0, 12))
        items.push(`<div class="feed-item"><span class="badge vuln">CVE</span><b>${esc(v.package)}</b> ${esc(v.version)}
          — ${esc((v.aliases||[]).join(', ') || v.vuln_id)}${v.fixed ? ` <span class="ok">fixed in ${esc(v.fixed)}</span>` : ''}
          <div class="when">${esc(v.summary || '')}</div></div>`);
      if ((wi.vulns || []).length > 12)
        items.push(`<div class="feed-item dim">…and ${wi.vulns.length - 12} more — run <b>wrench cve</b></div>`);
      for (const e of (wi.eol || []))
        items.push(`<div class="feed-item"><span class="badge ${e.is_eol ? 'eol' : 'ok'}">${e.is_eol ? 'EOL' : 'OK'}</span>${esc(e.label)}</div>`);
      $('webintel').innerHTML = items.join('') +
        `<div class="feed-item when">scanned ${ago(wi.ts)} · ${wi.packages_checked} packages${wi.online === false ? ' · offline (cached)' : ''}</div>`;
    } else {
      $('webintel').innerHTML = '<div class="feed-item dim">no scan yet — run <b>wrench cve</b></div>';
    }

    $('actions').innerHTML = actions.length ? actions.map(a => `
      <div class="feed-item"><span class="badge action">${esc(a.kind)}</span><code>${esc(a.command)}</code>
      <div class="when">${ago(a.ts)} · tier ${esc(a.tier)} · ${a.approved?'✓ ran':'✗ blocked'}</div></div>`).join('')
      : '<div class="feed-item dim">no agent actions yet</div>';

    const total = tokens.reduce((s,t)=>s+t.total, 0);
    $('tokens').innerHTML = `<div class="big">${total.toLocaleString()}</div>
      <div class="dim" style="margin-bottom:.6rem">total tokens across ${tokens.reduce((s,t)=>s+t.calls,0)} calls</div>`
      + tokens.map(t => `<div class="tokens-row"><span>${esc(t.provider)}/${esc(t.model)}</span>
        <span>${t.total.toLocaleString()} <span class="dim">(${t.calls} calls)</span></span></div>`).join('');
  } catch (e) { console.error(e); }
  pollNotifs();
}
refresh(); setInterval(refresh, 15000);

/* ---- notification toasts ("wrench taps you on the shoulder") ---- */
const seenNotif = new Set();
async function pollNotifs() {
  try {
    const list = await j('/api/notifications');
    for (const n of list) {
      if (seenNotif.has(n.id)) continue;
      seenNotif.add(n.id);
      showToast(n);
    }
  } catch (e) { /* inbox unavailable — stay quiet */ }
}
function showToast(n) {
  const t = document.createElement('div');
  t.className = 'toast ' + esc(n.severity);
  t.innerHTML = `<b>\u{1F514} patrol: ${esc(n.severity)}</b><div>${esc(n.summary)}</div>` +
    `<div class="when">${ago(n.ts)} · click to open the report</div>`;
  t.onclick = async () => {
    try {
      await fetch('/api/notifications/read', { method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ ids: [n.id] }) });
    } catch (e) { /* best effort */ }
    t.remove();
    openPatrol(n.report_id);
  };
  $('toasts').appendChild(t);
  setTimeout(() => { t.classList.add('fade'); setTimeout(() => t.remove(), 600); }, 25000);
}
function openPatrol(ts) {
  const el = document.querySelector(`#patrols .feed-item[data-ts="${ts}"]`);
  if (!el) return;
  const d = el.querySelector('details');
  if (d) d.open = true;
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

/* ---- theme ---- */
function setTheme(t) { document.documentElement.dataset.theme = t;
  localStorage.setItem('wrench-theme', t); }
setTheme(localStorage.getItem('wrench-theme') || 'dark');
const toggleTheme = () =>
  setTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light');
$('theme-btn').onclick = toggleTheme;

/* ---- chat ---- */
let chatBusy = false, greeted = false;
const panel = $('chat-panel'), log = $('chat-log'), input = $('chat-input');
function addMsg(cls, text, meta) {
  const d = document.createElement('div');
  d.className = 'msg ' + cls;
  d.textContent = text;
  if (meta) { const m = document.createElement('span'); m.className = 'meta';
    m.textContent = meta; d.appendChild(m); }
  log.appendChild(d); log.scrollTop = log.scrollHeight;
  return d;
}
function toggleChat(open) {
  const want = open ?? !panel.classList.contains('open');
  panel.classList.toggle('open', want);
  if (want) {
    if (!greeted) { greeted = true;
      addMsg('bot', "I'm wrench. I live here. Ask me anything about this machine — " +
        "what's eating RAM, what changed overnight, whether that port should be open."); }
    input.focus();
  }
}
$('chat-fab').onclick = () => toggleChat();
$('chat-close').onclick = () => toggleChat(false);
$('chat-form').onsubmit = async (e) => {
  e.preventDefault();
  const q = input.value.trim();
  if (!q || chatBusy) return;
  input.value = '';
  addMsg('you', q);
  chatBusy = true; $('chat-send').disabled = true;
  const t = document.createElement('div'); t.className = 'typing';
  t.innerHTML = '<span></span><span></span><span></span>';
  log.appendChild(t); log.scrollTop = log.scrollHeight;
  try {
    const r = await fetch('/api/chat', { method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ message: q }) });
    const d = await r.json();
    t.remove();
    if (d.error) addMsg('bot', '⚠ ' + d.error);
    else addMsg('bot', d.reply, `${d.model || ''} · ${d.tokens} tokens · ${d.steps} tool call(s)`);
  } catch (err) { t.remove(); addMsg('bot', '⚠ ' + err); }
  chatBusy = false; $('chat-send').disabled = false; input.focus();
};

/* ---- keyboard shortcuts ---- */
const overlay = $('overlay');
overlay.onclick = (e) => { if (e.target === overlay) overlay.classList.remove('open'); };
document.addEventListener('keydown', (e) => {
  if (e.target === input) {
    if (e.key === 'Escape') { toggleChat(false); input.blur(); }
    return;
  }
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  if (e.key === '?') overlay.classList.toggle('open');
  else if (e.key === 'c') toggleChat();
  else if (e.key === 'r') { refresh(); }
  else if (e.key === 't') toggleTheme();
  else if (e.key === 'Escape') { overlay.classList.remove('open'); toggleChat(false); }
  else return;
  e.preventDefault();
});
</script></body></html>
"""


def _downsample(samples: list[tuple[float, dict]], target: int = 240) -> list[dict]:
    if len(samples) <= target:
        rows = samples
    else:
        step = len(samples) / target
        rows = [samples[int(i * step)] for i in range(target)]
    keys = ("cpu_pct", "mem_pct", "swap_pct", "load_1m", "net_recv_rate_kbs",
            "net_sent_rate_kbs", "disk_root_pct", "n_procs")
    return [{"ts": ts, **{k: p.get(k) for k in keys}} for ts, p in rows]


MAX_CHAT_BODY = 16 * 1024
CHAT_HISTORY_MAX = 12


def _is_local_origin(value: str | None) -> bool:
    """True for missing Origin (curl, same-origin GET) or a localhost origin."""
    if not value:
        return True
    host = urlparse(value).hostname or ""
    return host in ("127.0.0.1", "localhost", "::1")


def make_handler(db_path, host_label: str, cfg=None):
    chat_lock = threading.Lock()
    chat_history: list[dict] = []   # session-scoped conversation memory
    data_dir = Path(db_path).parent  # notifications inbox lives next to the db

    class Handler(BaseHTTPRequestHandler):
        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, text: str):
            body = text.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # quiet
            pass

        def do_GET(self):  # noqa: N802
            path = urlparse(self.path).path
            store = Store(db_path)  # per-request connection (sqlite + threads)
            try:
                if path == "/":
                    return self._html(DASHBOARD_HTML)
                if path == "/api/summary":
                    last = store.last_sample("os")
                    return self._json({
                        "host": host_label,
                        "ts": last[0] if last else None,
                        "os": last[1] if last else {},
                    })
                if path == "/api/timeline":
                    return self._json(_downsample(store.recent_samples("os", 86400)))
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
                    return self._json(notifications.unread(data_dir))
                self._json({"error": "not found"}, 404)
            finally:
                store.close()

        def do_POST(self):  # noqa: N802
            path = urlparse(self.path).path
            if path == "/api/notifications/read":
                if not _is_local_origin(self.headers.get("Origin")):
                    return self._json({"error": "forbidden"}, 403)
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except ValueError:
                    length = 0
                ids = None
                if 0 < length <= MAX_CHAT_BODY:
                    try:
                        payload = json.loads(self.rfile.read(length).decode())
                        raw_ids = payload.get("ids")
                        if isinstance(raw_ids, list):
                            ids = [str(i) for i in raw_ids]
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        return self._json({"error": "invalid JSON"}, 400)
                marked = notifications.mark_read(data_dir, ids)
                return self._json({"marked": marked})
            if path != "/api/chat":
                return self._json({"error": "not found"}, 404)
            if cfg is None:
                return self._json({"error": "chat is not enabled on this server"}, 503)
            # same-origin only: the dashboard binds localhost; reject foreign origins.
            if not _is_local_origin(self.headers.get("Origin")):
                return self._json({"error": "forbidden"}, 403)
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                length = 0
            if not 0 < length <= MAX_CHAT_BODY:
                return self._json({"error": "bad request size"}, 413)
            try:
                payload = json.loads(self.rfile.read(length).decode())
                message = str(payload.get("message", "")).strip()
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._json({"error": "invalid JSON"}, 400)
            if not message:
                return self._json({"error": "empty message"}, 400)

            from .agent import Agent   # late import: keep GET path light
            store = Store(db_path)
            try:
                with chat_lock:   # one conversation, one turn at a time
                    convo = "\n".join(f"{m['role']}: {m['content'][:500]}"
                                      for m in chat_history[-6:])
                    goal = (f"Conversation so far:\n{convo}\n\nHuman's new message: "
                            f"{message}") if chat_history else message
                    agent = Agent(cfg, store)   # no confirm_fn → mutations stay blocked
                    res = agent.run(goal, purpose="web-chat")
                    chat_history.append({"role": "user", "content": message})
                    chat_history.append({"role": "assistant", "content": res["answer"]})
                    del chat_history[:-CHAT_HISTORY_MAX]
                return self._json({
                    "reply": res["answer"],
                    "tokens": res["tokens"],
                    "steps": len(res["steps"]),
                    "model": cfg.model,
                })
            except Exception as e:  # noqa: BLE001
                return self._json({"error": f"{e.__class__.__name__}: {e}"}, 500)
            finally:
                store.close()

    return Handler


def serve(db_path, port: int = 8787, host_label: str = "localhost",
          bind: str = "127.0.0.1", sample_thread: bool = True, cfg=None):
    """Serve the dashboard. Optionally keep sampling in the background."""
    from .sensors import sample_all

    if sample_thread:
        def sampler():
            while True:
                try:
                    s = Store(db_path)
                    sample_all(s)
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(30)

        threading.Thread(target=sampler, daemon=True).start()

    httpd = ThreadingHTTPServer((bind, port), make_handler(db_path, host_label, cfg=cfg))
    return httpd
