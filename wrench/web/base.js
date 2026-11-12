/* wrench web — shared helpers for every page. No dependencies, no build step. */
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ago = (ts) => {
  const d = Math.max(0, Date.now() / 1000 - ts);
  if (d < 90) return Math.round(d) + 's ago';
  if (d < 5400) return Math.round(d / 60) + 'm ago';
  if (d < 172800) return (d / 3600).toFixed(1) + 'h ago';
  return (d / 86400).toFixed(1) + 'd ago';
};
const dur = (s) => {
  if (s == null) return '—';
  if (s < 3600) return Math.round(s / 60) + 'm';
  if (s < 172800) return (s / 3600).toFixed(1) + 'h';
  return Math.round(s / 86400) + 'd';
};
const stateOf = (pct) => (pct == null ? 'unknown' : pct < 80 ? 'ok' : pct < 90 ? 'attention' : 'critical');

/* Status is always icon + label — colour never carries the meaning alone. */
const ICONS = {
  ok: '<path d="M3 8.5l3.2 3L13 4.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  attention: '<path d="M8 2.2l6.3 11H1.7z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M8 6.4v3.2M8 11.6v.2" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
  critical: '<circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M5.6 5.6l4.8 4.8M10.4 5.6l-4.8 4.8" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
  unknown: '<circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="2.5 2.5"/>',
  silent: '<path d="M2 8h3l2-4 2 8 2-4h3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" opacity=".55"/><path d="M2.5 13.5l11-11" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
};
const KIND = { ok: 'ok', good: 'ok', green: 'ok', attention: 'attention', warning: 'attention',
  yellow: 'attention', critical: 'critical', error: 'critical', red: 'critical', silent: 'silent' };
const LABEL = { ok: 'Healthy', attention: 'Attention', critical: 'Critical', error: 'Error',
  warning: 'Warning', info: 'Info', unknown: 'No data', silent: 'Silent', green: 'Healthy',
  yellow: 'Attention', red: 'Critical', recommendation: 'Advice' };
function badge(state, label) {
  const s = String(state || 'unknown').toLowerCase();
  const icon = ICONS[KIND[s] || 'unknown'];
  return `<span class="status ${esc(s)}"><svg viewBox="0 0 16 16" aria-hidden="true">${icon}</svg>${esc(label || LABEL[s] || s)}</span>`;
}

async function api(path, opts) {
  const r = await fetch(path, { credentials: 'same-origin', ...opts });
  if (r.status === 401) { location.href = '/login?next=' + encodeURIComponent(location.pathname); throw new Error('auth'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
  return data;
}
const post = (path, body) => api(path, { method: 'POST',
  headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });

/* ---- theme: follows the OS until the viewer picks one ---- */
function applyTheme(t) {
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
function currentTheme() {
  return document.documentElement.dataset.theme
    || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
}
function toggleTheme() {
  const next = currentTheme() === 'light' ? 'dark' : 'light';
  try { localStorage.setItem('wrench-theme', next); } catch (e) { /* private mode */ }
  applyTheme(next);
}
try { applyTheme(localStorage.getItem('wrench-theme')); } catch (e) { /* private mode */ }

/* ---- drawers ---- */
function openDrawer(id) {
  document.querySelectorAll('.drawer.open').forEach((d) => d.classList.remove('open'));
  $(id).classList.add('open'); $('scrim').classList.add('open');
  const f = $(id).querySelector('[data-autofocus]'); if (f) f.focus();
}
function closeDrawers() {
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  document.querySelectorAll('.drawer.open').forEach((d) => d.classList.remove('open'));
  const s = $('scrim'); if (s) s.classList.remove('open');
}

/* ---- a single-series time chart with a crosshair + tooltip ----
   One measure per chart, one hue (the title names the series, so no legend).
   Different units get their own small chart, never a second axis. */
function lineChart(el, { title, points, unit = '', max, fmt }) {
  const f = fmt || ((v) => (v >= 100 ? v.toFixed(0) : v.toFixed(1)));
  if (!points.length) {
    el.innerHTML = `<div class="title"><span>${esc(title)}</span></div><div class="empty">no samples in this range yet</div>`;
    return;
  }
  // drawn at the element's real pixel width so text is never stretched
  const W = Math.max(240, Math.round(el.clientWidth || 600)), H = 96, L = 34, R = 6, T = 6, B = 16;
  const t0 = points[0][0], t1 = Math.max(points[points.length - 1][0], t0 + 1);
  const top = max ?? niceMax(Math.max(...points.map((p) => p[1])));
  const X = (t) => L + (t - t0) / (t1 - t0) * (W - L - R);
  const Y = (v) => (H - B) - Math.min(v, top) / top * (H - B - T);
  const d = points.map((p, i) => (i ? 'L' : 'M') + X(p[0]).toFixed(1) + ' ' + Y(p[1]).toFixed(1)).join('');
  const last = points[points.length - 1];
  const span = t1 - t0;
  const tick = (t) => new Date(t * 1000).toLocaleString([], span > 172800
    ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' });
  el.innerHTML = `
    <div class="title"><span>${esc(title)}</span><b>${f(last[1])}${esc(unit)}</b></div>
    <svg viewBox="0 0 ${W} ${H}" role="img"
         aria-label="${esc(title)}: latest ${f(last[1])}${esc(unit)}">
      <line class="gridline" x1="${L}" x2="${W - R}" y1="${Y(top)}" y2="${Y(top)}"/>
      <line class="gridline" x1="${L}" x2="${W - R}" y1="${Y(top / 2)}" y2="${Y(top / 2)}"/>
      <line class="gridline" x1="${L}" x2="${W - R}" y1="${H - B}" y2="${H - B}"/>
      <text class="axis" x="${L - 5}" y="${Y(top) + 3.5}" text-anchor="end">${tickFmt(top)}</text>
      <text class="axis" x="${L - 5}" y="${Y(top / 2) + 3.5}" text-anchor="end">${tickFmt(top / 2)}</text>
      <text class="axis" x="${L - 5}" y="${H - B + 3.5}" text-anchor="end">0</text>
      <text class="axis" x="${L}" y="${H - 2}">${esc(tick(t0))}</text>
      <text class="axis" x="${W - R}" y="${H - 2}" text-anchor="end">${esc(tick(t1))}</text>
      <path class="area" d="${d}L${X(t1).toFixed(1)} ${H - B}L${X(t0).toFixed(1)} ${H - B}Z"/>
      <path class="line" d="${d}"/>
      <line class="cross" y1="${T}" y2="${H - B}"/>
      <circle class="marker" r="4"/>
      <rect class="hit" x="${L}" y="0" width="${W - L - R}" height="${H}" fill="transparent"/>
    </svg><div class="tip"></div>`;
  const svg = el.querySelector('svg'), cross = el.querySelector('.cross'),
    marker = el.querySelector('.marker'), tip = el.querySelector('.tip');
  const move = (ev) => {
    const box = svg.getBoundingClientRect();
    const x = ((ev.touches ? ev.touches[0].clientX : ev.clientX) - box.left) / box.width * W;
    const t = t0 + (Math.min(Math.max(x, L), W - R) - L) / (W - L - R) * (t1 - t0);
    let lo = 0, hi = points.length - 1;                    // nearest sample by time
    while (hi - lo > 1) { const m = (lo + hi) >> 1; (points[m][0] < t ? (lo = m) : (hi = m)); }
    const p = (t - points[lo][0]) < (points[hi][0] - t) ? points[lo] : points[hi];
    const px = X(p[0]), py = Y(p[1]);
    cross.setAttribute('x1', px); cross.setAttribute('x2', px); cross.style.visibility = 'visible';
    marker.setAttribute('cx', px); marker.setAttribute('cy', py); marker.style.visibility = 'visible';
    tip.innerHTML = `<b>${f(p[1])}${esc(unit)}</b> <span class="dim">${esc(new Date(p[0] * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }))}</span>`;
    tip.style.visibility = 'visible';
    const left = px / W * box.width;
    tip.style.left = Math.min(Math.max(left - tip.offsetWidth / 2, 0), box.width - tip.offsetWidth) + 'px';
  };
  const leave = () => { cross.style.visibility = marker.style.visibility = tip.style.visibility = 'hidden'; };
  svg.addEventListener('mousemove', move); svg.addEventListener('touchmove', move, { passive: true });
  svg.addEventListener('mouseleave', leave); svg.addEventListener('touchend', leave);
}
const tickFmt = (v) => (Number.isInteger(v) ? String(v) : v >= 10 ? v.toFixed(0) : String(+v.toFixed(2)));
function niceMax(v) {
  if (!(v > 0)) return 1;
  const mag = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * mag) return m * mag;
  return 10 * mag;
}

/* ---- click any command to copy it ---- */
const cmd = (c) => `<code class="cmd" title="click to copy">${esc(c)}</code>`;
document.addEventListener('click', async (e) => {
  const el = e.target.closest('code.cmd'); if (!el) return;
  e.stopPropagation();
  try { await navigator.clipboard.writeText(el.textContent); } catch (x) { return; }
  const was = el.textContent; el.classList.add('copied'); el.textContent = 'copied';
  setTimeout(() => { el.classList.remove('copied'); el.textContent = was; }, 900);
});

/* ---- sparkline (no axes: the caption carries the range) ---- */
function sparkline(points, max = 100) {
  if (points.length < 2) return '';
  const W = 300, H = 44, t0 = points[0][0], t1 = Math.max(points[points.length - 1][0], t0 + 1);
  const lo = Math.max(0, Math.min(...points.map((p) => p[1])) - 8), hi = Math.min(max, Math.max(...points.map((p) => p[1])) + 8);
  const X = (t) => (t - t0) / (t1 - t0) * W, Y = (v) => H - 3 - (v - lo) / Math.max(hi - lo, 1) * (H - 6);
  const d = points.map((p, i) => (i ? 'L' : 'M') + X(p[0]).toFixed(1) + ' ' + Y(p[1]).toFixed(1)).join('');
  return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">
    <path class="a" d="${d}L${W} ${H}L0 ${H}Z"/><path class="l" d="${d}" vector-effect="non-scaling-stroke"/></svg>`;
}

/* ---- command palette: ⌘K / Ctrl-K ---- */
function initPalette(getActions) {
  const root = $('palette'), input = $('palette-input'), list = $('palette-list');
  let items = [], sel = 0;
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    items = getActions().filter((a) => !q || (a.label + ' ' + a.group + ' ' + (a.hint || '')).toLowerCase().includes(q)).slice(0, 40);
    sel = Math.min(sel, Math.max(items.length - 1, 0));
    list.innerHTML = items.map((a, i) => `<li role="option" data-i="${i}" aria-selected="${i === sel}">
      <span class="g">${esc(a.group)}</span><span>${esc(a.label)}</span>${a.hint ? `<span class="h">${esc(a.hint)}</span>` : ''}</li>`).join('')
      || '<li class="dim" style="cursor:default">No matches</li>';
    const cur = list.querySelector('[aria-selected="true"]'); if (cur) cur.scrollIntoView({ block: 'nearest' });
  };
  const open = () => { root.classList.add('open'); input.value = ''; sel = 0; draw(); input.focus(); };
  const close = () => root.classList.remove('open');
  const run = (i) => { const a = items[i]; if (!a) return; close(); a.run(); };
  input.addEventListener('input', () => { sel = 0; draw(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { sel = Math.min(sel + 1, items.length - 1); draw(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
    else if (e.key === 'Enter') { run(sel); e.preventDefault(); }
    else if (e.key === 'Escape') { close(); e.stopPropagation(); }
  });
  list.addEventListener('click', (e) => { const li = e.target.closest('li[data-i]'); if (li) run(Number(li.dataset.i)); });
  root.addEventListener('click', (e) => { if (e.target === root) close(); });
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); root.classList.contains('open') ? close() : open(); }
  });
  const btn = $('palette-btn'); if (btn) btn.addEventListener('click', open);
  return { open, close };
}
const copyText = async (t) => { try { await navigator.clipboard.writeText(t); } catch (x) { /* denied */ } };

/* ---- top bar wiring shared by pages ---- */
/* ---- machine picker: this machine, all machines, or one connected machine ---- */
function fillMachines(nodes, current) {
  const sel = $('machine'); if (!sel) return;
  if (document.activeElement === sel) return;          // never rebuild an open menu
  const word = (n) => (n.silent ? 'silent' : { green: 'healthy', yellow: 'attention', red: 'critical' }[n.color] || '');
  const others = nodes.filter((n) => !n.local);
  sel.innerHTML = `<option value="/">This machine</option>`
    + `<option value="/fleet">All machines (${nodes.length})</option>`
    + (others.length ? `<optgroup label="Connected machines">${others.map((n) =>
      `<option value="/fleet?node=${encodeURIComponent(n.node_id)}">${esc(n.node_id)} — ${word(n)}</option>`).join('')}</optgroup>` : '');
  sel.value = current; if (sel.selectedIndex < 0) sel.value = '/fleet';
  sel.hidden = false;
}

function wireChrome() {
  const th = $('theme-btn'); if (th) th.addEventListener('click', toggleTheme);
  const sc = $('scrim'); if (sc) sc.addEventListener('click', closeDrawers);
  document.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', closeDrawers));
  const so = $('signout');
  if (so) so.addEventListener('click', async () => { try { await post('/logout'); } catch (e) { /* gone anyway */ } location.href = '/login'; });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawers(); });
}
