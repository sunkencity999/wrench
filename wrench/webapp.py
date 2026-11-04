"""wrench web — local dashboard. stdlib http.server + a single dark page.

Endpoints:
  /                 dashboard
  /api/summary      latest sample + counts
  /api/timeline     24h of os samples (downsampled)
  /api/drift        recent drift events
  /api/patrols      recent patrol reports
  /api/actions      action log
  /api/tokens       token spend by model
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .store import Store

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wrench — dashboard</title>
<style>
:root { --bg:#0b0e14; --panel:#11151f; --border:#1f2633; --fg:#dce3ee; --dim:#7d8799;
  --ok:#3fb950; --warn:#d29922; --crit:#f85149; --accent:#58a6ff; --mag:#bc8cff; --cyan:#39c5cf; }
* { box-sizing:border-box; margin:0; }
body { background:var(--bg); color:var(--fg);
  font:14px/1.5 'SF Mono',ui-monospace,Menlo,Consolas,monospace; padding:1.2rem; }
header { display:flex; align-items:baseline; gap:1rem; margin-bottom:1.2rem; flex-wrap:wrap; }
header h1 { font-size:1.4rem; } header .dim { color:var(--dim); font-size:.85rem; }
.pulse { display:inline-block; width:9px; height:9px; border-radius:50%; background:var(--ok);
  animation:pulse 2s infinite; margin-right:.4rem; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(340px,1fr)); gap:1rem; }
.panel { background:var(--panel); border:1px solid var(--border); border-radius:12px;
  padding:1rem 1.2rem; overflow:hidden; }
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
.tokens-row { display:flex; justify-content:space-between; padding:.3rem 0;
  border-bottom:1px solid var(--border); font-size:.85rem; }
.tokens-row:last-child { border:none; }
.big { font-size:1.6rem; font-weight:bold; color:var(--mag); }
details summary { cursor:pointer; color:var(--accent); font-size:.8rem; }
details pre { white-space:pre-wrap; font-size:.75rem; color:var(--dim);
  margin-top:.5rem; max-height:260px; overflow-y:auto; }
footer { color:var(--dim); font-size:.75rem; margin-top:1.4rem; text-align:center; }
a { color:var(--accent); }
</style></head><body>
<header>
  <h1>🔧 wrench</h1>
  <span class="dim"><span class="pulse"></span>live · <span id="host">…</span> · refreshes every 15s</span>
  <span class="dim" id="updated"></span>
</header>
<div class="grid">
  <div class="panel wide">
    <h2>vitals — last 24h</h2>
    <div class="gauges" id="gauges"></div>
    <div id="charts" style="margin-top:1rem"></div>
  </div>
  <div class="panel"><h2>patrol feed</h2><div class="feed" id="patrols"></div></div>
  <div class="panel"><h2>drift feed — what changed on this box</h2><div class="feed" id="drift"></div></div>
  <div class="panel"><h2>agent action log</h2><div class="feed" id="actions"></div></div>
  <div class="panel"><h2>token spend</h2><div id="tokens"></div></div>
</div>
<footer>wrench — an intentional local sysadmin agent ·
<a href="https://github.com/sunkencity999/wrench">github.com/sunkencity999/wrench</a></footer>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ago = ts => { const d = Date.now()/1000 - ts;
  if (d < 90) return Math.round(d)+'s ago';
  if (d < 5400) return Math.round(d/60)+'m ago';
  if (d < 172800) return (d/3600).toFixed(1)+'h ago';
  return (d/86400).toFixed(1)+'d ago'; };
const colorFor = p => p < 70 ? 'var(--ok)' : p < 90 ? 'var(--warn)' : 'var(--crit)';
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
    const [sum, tl, drift, patrols, actions, tokens] = await Promise.all([
      j('/api/summary'), j('/api/timeline'), j('/api/drift'),
      j('/api/patrols'), j('/api/actions'), j('/api/tokens')]);

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
      <div class="feed-item"><span class="badge ${esc(p.status)}">${esc(p.status)}</span>${esc(p.summary)}
      <div class="when">${ago(p.ts)} · ${esc(p.model||'')} · ${p.tokens} tok</div>
      <details><summary>full report</summary><pre>${esc(p.report_md)}</pre></details></div>`).join('')
      : '<div class="feed-item dim">no patrols yet — run <b>wrench patrol</b></div>';

    $('drift').innerHTML = drift.length ? drift.map(d => `
      <div class="feed-item"><span class="badge drift">${esc(d.kind)}</span>${esc(d.summary)}
      <div class="when">${ago(d.ts)}</div>
      ${Array.isArray(d.details) && d.details.length ? `<details><summary>${d.details.length} change(s)</summary><pre>${esc(d.details.join('\n'))}</pre></details>` : ''}</div>`).join('')
      : '<div class="feed-item dim">no drift recorded — this box is exactly as you left it</div>';

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
}
refresh(); setInterval(refresh, 15000);
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


def make_handler(db_path, host_label: str):
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
                self._json({"error": "not found"}, 404)
            finally:
                store.close()

    return Handler


def serve(db_path, port: int = 8787, host_label: str = "localhost",
          bind: str = "127.0.0.1", sample_thread: bool = True):
    """Serve the dashboard. Optionally keep sampling in the background."""
    import threading

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

    httpd = ThreadingHTTPServer((bind, port), make_handler(db_path, host_label))
    return httpd
