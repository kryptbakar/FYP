/* =====================================================================
   Router, keyboard navigation, live/demo indicator, boot.
   Keys: 1–4 switch views · / focus search · j/k move selection · Enter open · Esc back.
   ===================================================================== */
'use strict';

const ROUTES = {
  overview:   { title: 'Overview', crumb: 'Security posture at a glance', icon: 'overview', key: '1', sec: 'Monitor', view: viewOverview },
  triage:     { title: 'Triage', crumb: 'Ranked decisions', icon: 'triage', key: '2', sec: 'Monitor', view: viewTriage },
  hunt:       { title: 'Hunt', crumb: 'Search raw telemetry', icon: 'hunt', key: '3', sec: 'Monitor', view: viewHunt },
  coverage:   { title: 'Coverage', crumb: 'ATT&CK coverage & posture trend', icon: 'matrix', key: '', sec: 'Monitor', view: viewCoverage },
  cases:      { title: 'Cases', crumb: 'Incidents, correlation & signed audit', icon: 'cases', key: '4', sec: 'Investigate', view: viewIncidents },
  assets:     { title: 'Assets', crumb: 'Inventory & host detail', icon: 'assets', key: '5', sec: 'Investigate', view: viewAssets },
  livehunt:   { title: 'Live Hunt', crumb: 'Fleet artifact collection', icon: 'target', key: '', sec: 'Investigate', view: viewLiveHunt },
  intel:      { title: 'Threat Intel', crumb: 'Attribution, IOCs & fusion clusters', icon: 'intel', key: '', sec: 'Investigate', view: viewIntel },
  compliance: { title: 'Compliance', crumb: 'CIS posture & hash-chained evidence', icon: 'shield', key: '6', sec: 'Assure', view: viewCompliance },
  trust:      { title: 'Trust Center', crumb: 'Audit integrity & air-gap assurance', icon: 'shieldcheck', key: '7', sec: 'Assure', view: viewTrust },
  fusion:     { title: 'Sensors & Fusion', crumb: 'Pipeline health & integrated tools', icon: 'fusion', key: '8', sec: 'Operate', view: viewFusion },
  manager:    { title: 'Operations', crumb: 'Queue health, SLA & analyst workload', icon: 'manager', key: '9', sec: 'Operate', view: viewManager },
  detections: { title: 'Detections', crumb: 'Detection-rule management', icon: 'rules', key: '', sec: 'Operate', view: viewDetections },
  alerting:   { title: 'Alerting', crumb: 'Channels, routing & delivery', icon: 'alert', key: '', sec: 'Operate', view: viewAlerting },
  playbooks:  { title: 'Playbooks', crumb: 'SOAR automation', icon: 'fusion', key: '', sec: 'Operate', view: viewPlaybooks },
  reports:    { title: 'Reports', crumb: 'Posture, compliance & executive reports', icon: 'report', key: '', sec: 'Operate', view: viewReports },
  dashboards: { title: 'Dashboards', crumb: 'Grafana metrics & trends', icon: 'dash', key: '', sec: 'Operate', view: viewDashboards },
  model:      { title: 'Model', crumb: 'Risk model card & transparency', icon: 'model', key: '', sec: 'Operate', view: viewModel },
  settings:   { title: 'Settings', crumb: 'Identity, integrations & retention', icon: 'gear', key: '', sec: 'Operate', view: viewSettings },
  search:     { title: 'Search', crumb: 'Global results', icon: 'hunt', key: '', sec: '_hidden', view: viewSearch },
};
const SECTIONS = ['Monitor', 'Investigate', 'Assure', 'Operate'];
let current = 'overview', selIdx = -1;

function buildNav() {
  const nav = $('#nav'); nav.innerHTML = '';
  for (const s of SECTIONS) {
    nav.append(h('div', { class: 'nav-sec' }, s));
    for (const [k, r] of Object.entries(ROUTES)) {
      if (r.sec !== s) continue;
      nav.append(h('a', { 'data-route': k, tabindex: '0', onclick: () => go(k), onkeydown: e => { if (e.key === 'Enter') go(k); },
        html: ic(r.icon) + `<span>${r.title}</span>` + (r.key ? `<span class="key">${r.key}</span>` : '') }));
    }
  }
}
function go(route) {
  if (!ROUTES[route]) route = 'overview';
  // tear down any per-view timers (e.g. the Overview live ticker) before switching
  if (window._viewCleanup) { try { window._viewCleanup(); } catch {} window._viewCleanup = null; }
  current = route; selIdx = -1; location.hash = route;
  const r = ROUTES[route];
  $('#title').textContent = r.title; $('#crumb').textContent = r.crumb;
  $$('#nav a').forEach(a => a.classList.toggle('active', a.dataset.route === route));
  closeDrawer();
  const root = $('#view'); root.innerHTML = '';
  $('#scroll').scrollTop = 0;
  r.view(root).catch(e => { root.innerHTML = ''; root.append(h('div', { class: 'empty' }, 'Error: ' + e.message)); });
}

/* keyboard list selection (cards in Triage, rows elsewhere) */
function selectables() { return $$('#view .card, #view .tbl tbody tr'); }
function moveSel(d) {
  const els = selectables(); if (!els.length) return;
  selIdx = Math.max(0, Math.min(els.length - 1, selIdx + d));
  els.forEach((e, i) => e.classList.toggle('sel', i === selIdx));
  els[selIdx].scrollIntoView({ block: 'nearest' });
}
function openSel() { const els = selectables(); if (selIdx >= 0 && els[selIdx]) els[selIdx].click(); }

// Entity-chip pivot: filter the Triage queue by the clicked entity (asset/CVE/tool/IP).
window.pivot = function (val) {
  STATE.q = String(val); const q = $('#q'); if (q) q.value = STATE.q;
  closeDrawer();
  if (current !== 'triage') go('triage'); else if (window._renderCards) window._renderCards();
};

function updateLive(mode) {
  const el = $('#live'), lbl = $('#live-label');
  el.className = 'live ' + (mode === 'live' ? 'live' : mode === 'demo' ? 'demo' : '');
  lbl.textContent = mode === 'live' ? 'LIVE /api' : mode === 'demo' ? 'DEMO DATA' : 'connecting…';
}

async function boot() {
  buildNav();
  API._onmode = updateLive;
  $('#scrim').addEventListener('click', closeDrawer);
  const q = $('#q');
  q.addEventListener('input', () => { STATE.q = q.value; if (current === 'triage' && window._renderCards) window._renderCards(); });

  document.addEventListener('keydown', e => {
    // Command palette (⌘K / Ctrl+K) works from anywhere, even inside inputs.
    if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); openPalette(); return; }
    const tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') {
      if (e.target === q) {
        if (e.key === 'Escape') q.blur();
        if (e.key === 'Enter' && q.value.trim()) { STATE.q = q.value; go('search'); q.blur(); }
      } else if (e.key === 'Escape') { e.target.blur(); }
      return; // don't fire single-key shortcuts while typing
    }
    if (e.key === '/') { e.preventDefault(); q.focus(); return; }
    if (e.key === 'Escape') { closePalette(); closeAlerts(); closeDrawer(); return; }
    if (e.key === 'j') { moveSel(1); return; }
    if (e.key === 'k') { moveSel(-1); return; }
    if (e.key === 'Enter') { openSel(); return; }
    const route = Object.keys(ROUTES).find(k => ROUTES[k].key === e.key);
    if (route) go(route);
  });

  // footer / status
  const [ver, ready, chain] = await Promise.all([API.version(), API.ready(), API.chain()]);
  $('#api-ver').textContent = (ver.version || '—');
  $('#chain-stat').innerHTML = chain.ok ? 'intact ✓' : 'check';
  const ok = ready.status === 'ready' || ready.status === 'ok';
  $('#store-dot').className = 'statdot ' + (ok ? 'active' : 'optional');
  $('#store-stat').textContent = ok ? 'stores healthy' : 'stores degraded';
  // model version (best-effort from a finding explanation)
  try { const rk = await API.ranking(); if (rk[0]) { const ex = await API.explain(rk[0].id); $('#model-ver').textContent = ((ex.ml_explanation || {}).model_version || '—').replace('xgb-', ''); } } catch {}

  // signed-in user (local session) → topbar chip with sign-out
  const uc = $('#userchip');
  if (uc && API.user) {
    uc.innerHTML = '';
    uc.append(h('span', { class: 'av' }, (API.user[0] || '?').toUpperCase()),
      h('div', { class: 'ui' }, h('div', { class: 'un' }, API.user), h('div', { class: 'rl' }, API.role || 'viewer')));
    uc.title = 'click to sign out';
    uc.style.cursor = 'pointer';
    uc.onclick = async () => { await API.logout(); location.reload(); };
  }

  // organization chip (multi-tenancy foundation)
  try { const orgs = await API.tenants(); const oc = $('#orgchip'); if (oc && orgs && orgs.length) { oc.textContent = orgs[0].name; oc.title = orgs.map(o => o.name).join(' · '); } } catch {}

  // table density toggle (topbar)
  const db = $('#density'); if (db) { db.addEventListener('click', toggleDensity); if (document.body.classList.contains('compact')) db.classList.add('on'); }

  // alerts inbox (topbar bell)
  const bell = $('#bell'); if (bell) bell.addEventListener('click', e => { e.stopPropagation(); toggleAlerts(); });
  document.addEventListener('click', e => { const pop = $('#alerts-pop'); if (pop && !pop.hidden && !pop.contains(e.target) && e.target !== bell && !bell.contains(e.target)) pop.hidden = true; });
  try { await loadAlerts(); } catch {}

  routeFromHash(true);
}
// Hash routing, incl. deep-link to a finding: #f/<id> opens its detail drawer.
function routeFromHash(initial) {
  const hash = location.hash.slice(1);
  if (hash.startsWith('f/')) { if (current !== 'triage' || initial) go('triage'); openFinding(hash.slice(2)); return; }
  if (ROUTES[hash]) { if (hash !== current || initial) go(hash); }
  else if (initial) go('overview');
}
window.addEventListener('hashchange', () => routeFromHash(false));

/* ---- command palette (⌘K / Ctrl+K) — jump to any page ---------------- */
let _cmdkItems = [], _cmdkSel = 0, _cmdkWired = false;
function openPalette() {
  const box = $('#cmdk'); if (!box || $('#login') && !$('#login').hidden) return; // not before login
  box.hidden = false;
  const input = $('#cmdk-input');
  if (!_cmdkWired) {
    input.addEventListener('input', () => renderPalette(input.value));
    input.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); paletteNav(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); paletteNav(-1); }
      else if (e.key === 'Enter') { e.preventDefault(); paletteEnter(); }
      else if (e.key === 'Escape') { e.preventDefault(); closePalette(); }
    });
    box.addEventListener('click', e => { if (e.target === box) closePalette(); });
    _cmdkWired = true;
  }
  input.value = ''; renderPalette(''); input.focus();
}
function closePalette() { const box = $('#cmdk'); if (box) box.hidden = true; }
// Deep actions — run a workflow straight from the palette, not just navigate. Writes are
// RBAC-gated via requireAct() so viewers get the read-only toast instead of a failed call.
const CMDK_ACTIONS = [
  { title: 'Correlate incidents now', sec: 'Action', icon: 'cases', run: async () => {
      if (!requireAct()) return; toast('Correlating findings…');
      const r = await API.correlate(); toast(`Correlation complete — ${(r.created || []).length || r.correlated_groups || 0} incident(s)`, true); go('cases'); } },
  { title: 'Generate posture report', sec: 'Action', icon: 'report', run: async () => {
      if (!requireAct()) return; toast('Generating posture report…'); await API.generateReport('posture'); toast('Posture report generated', true); go('reports'); } },
  { title: 'Generate compliance report', sec: 'Action', icon: 'report', run: async () => {
      if (!requireAct()) return; toast('Generating compliance report…'); await API.generateReport('compliance'); toast('Compliance report generated', true); go('reports'); } },
  { title: 'Dispatch pending alerts', sec: 'Action', icon: 'alert', run: async () => {
      if (!requireAct()) return; toast('Dispatching…'); const r = await API.dispatchAlerts(); toast(`Dispatched ${r.deliveries || 0} alert(s)`, true); } },
  { title: 'Toggle table density', sec: 'Action', icon: 'gear', run: () => toggleDensity() },
  { title: 'Sign out', sec: 'Action', icon: 'gear', run: async () => { await API.logout(); location.reload(); } },
];
function paletteSource(ql) {
  const routes = Object.entries(ROUTES)
    .filter(([k, r]) => r.sec !== '_hidden' && `${r.title} ${r.sec} ${r.crumb}`.toLowerCase().includes(ql))
    .map(([k, r]) => ({ key: k, title: r.title, sec: r.sec, icon: r.icon }));
  const acts = CMDK_ACTIONS.filter(a => `${a.title} ${a.sec}`.toLowerCase().includes(ql));
  return routes.concat(acts);
}
function renderPalette(query) {
  const list = $('#cmdk-list');
  _cmdkItems = paletteSource((query || '').toLowerCase());
  _cmdkSel = 0; list.innerHTML = '';
  if (!_cmdkItems.length) { list.append(h('div', { class: 'faint', style: 'padding:16px;text-align:center;font-size:12px' }, 'No match.')); return; }
  _cmdkItems.forEach((it, i) => list.append(h('div', { class: 'cmdk-item' + (i === 0 ? ' sel' : ''), onclick: () => runPaletteItem(it) },
    h('span', { html: ic(it.icon), style: 'width:15px;height:15px;color:var(--muted);display:inline-flex' }),
    h('span', { style: 'flex:1' }, it.title),
    h('span', { class: it.run ? 'cmdk-tag' : 'faint', style: 'font-size:10.5px' }, it.sec))));
}
function paletteNav(d) {
  if (!_cmdkItems.length) return;
  _cmdkSel = (_cmdkSel + d + _cmdkItems.length) % _cmdkItems.length;
  const els = $$('#cmdk-list .cmdk-item');
  els.forEach((el, i) => el.classList.toggle('sel', i === _cmdkSel));
  if (els[_cmdkSel]) els[_cmdkSel].scrollIntoView({ block: 'nearest' });
}
function runPaletteItem(it) { closePalette(); if (it.run) it.run(); else go(it.key); }
function paletteEnter() { const it = _cmdkItems[_cmdkSel]; if (it) runPaletteItem(it); }

/* ---- table density toggle + click-to-sort (shared across every .tbl) ---- */
function toggleDensity() {
  const compact = document.body.classList.toggle('compact');
  localStorage.setItem('vyrex_density', compact ? 'compact' : 'comfortable');
  const b = $('#density'); if (b) b.classList.toggle('on', compact);
  toast(compact ? 'Compact rows' : 'Comfortable rows', true);
}
if (localStorage.getItem('vyrex_density') === 'compact') document.body.classList.add('compact');

// One delegated handler makes every table (current and future) sortable by clicking a header.
// Sorts the existing <tr> nodes in place (preserves their click handlers) by visible cell text,
// auto-detecting numeric columns; skips blank/action headers.
document.addEventListener('click', e => {
  const th = e.target.closest && e.target.closest('table.tbl thead th');
  if (th) sortTable(th);
});
function sortTable(th) {
  const headRow = th.parentNode, table = th.closest('table'), tbody = table.tBodies[0];
  if (!tbody || !th.textContent.trim() || th.classList.contains('nosort')) return;
  const idx = Array.prototype.indexOf.call(headRow.children, th);
  const rows = Array.prototype.slice.call(tbody.rows).filter(r => r.cells.length > idx);
  if (rows.length < 2) return;
  const dir = th.dataset.sort === 'asc' ? 'desc' : 'asc';
  Array.prototype.forEach.call(headRow.children, c => { delete c.dataset.sort; c.classList.remove('sorted'); });
  const val = r => (r.cells[idx] ? r.cells[idx].textContent.trim() : '');
  const num = s => { const m = String(s).replace(/[,%$\s]/g, '').match(/-?\d+(\.\d+)?/); return m ? parseFloat(m[0]) : null; };
  const allNum = rows.every(r => val(r) !== '' && num(val(r)) !== null);
  rows.sort((a, b) => {
    const x = val(a), y = val(b);
    const c = allNum ? num(x) - num(y) : x.localeCompare(y, undefined, { numeric: true, sensitivity: 'base' });
    return dir === 'asc' ? c : -c;
  });
  rows.forEach(r => tbody.appendChild(r));
  th.dataset.sort = dir; th.classList.add('sorted');
}

/* ---- auth gate: require login before the app boots ------------------- */
window.canAct = () => API.role !== 'viewer';   // viewer = read-only
function requireAct() { if (!window.canAct()) { toast('Read-only (viewer role) — sign in as analyst/admin to act', false); return false; } return true; }
async function gate() {
  if (API.token) {
    const me = await API.me();
    if (me && me.authenticated) {
      API.role = me.role || API.role; API.user = me.user || API.user;
      document.body.classList.add('role-' + (API.role || 'viewer'));
      boot(); return;
    }
    API.token = null; localStorage.removeItem('vyrex_token'); // stale/expired session
  }
  showLogin();
}
function showLogin() {
  const login = $('#login'); login.hidden = false;
  const form = $('#login-form'), err = $('#login-err'), btn = $('#login-go');
  form.onsubmit = async (e) => {
    e.preventDefault(); err.textContent = ''; btn.disabled = true; btn.textContent = 'Signing in…';
    try {
      const r = await API.login($('#login-user').value.trim(), $('#login-pass').value);
      if (r && r.token) {
        API._setSession(r); document.body.classList.add('role-' + (r.role || 'viewer'));
        login.hidden = true; boot(); return;
      }
      err.textContent = (r && r.error) || 'login failed';
    } catch (ex) {
      // never leave the button stuck — surface the error (e.g. stale cached api.js)
      err.textContent = 'login error: ' + ((ex && ex.message) || ex) + ' — try a hard refresh (Ctrl+Shift+R)';
    }
    btn.disabled = false; btn.textContent = 'Sign in'; $('#login-pass').value = '';
  };
  $('#login-user').focus();
}
gate();
