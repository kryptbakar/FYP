/* =====================================================================
   Router, keyboard navigation, live/demo indicator, boot.
   Keys: 1–4 switch views · / focus search · j/k move selection · Enter open · Esc back.
   ===================================================================== */
'use strict';

const ROUTES = {
  overview:   { title: 'Overview', crumb: 'Security posture at a glance', icon: 'overview', key: '1', sec: 'Monitor', view: viewOverview },
  triage:     { title: 'Triage', crumb: 'Ranked decisions', icon: 'triage', key: '2', sec: 'Monitor', view: viewTriage },
  hunt:       { title: 'Hunt', crumb: 'Search raw telemetry', icon: 'hunt', key: '3', sec: 'Monitor', view: viewHunt },
  cases:      { title: 'Cases', crumb: 'Incidents, correlation & signed audit', icon: 'cases', key: '4', sec: 'Investigate', view: viewIncidents },
  assets:     { title: 'Assets', crumb: 'Inventory & host detail', icon: 'assets', key: '5', sec: 'Investigate', view: viewAssets },
  compliance: { title: 'Compliance', crumb: 'CIS posture & hash-chained evidence', icon: 'shield', key: '6', sec: 'Assure', view: viewCompliance },
  trust:      { title: 'Trust Center', crumb: 'Audit integrity & air-gap assurance', icon: 'shieldcheck', key: '7', sec: 'Assure', view: viewTrust },
  fusion:     { title: 'Sensors & Fusion', crumb: 'Pipeline health & integrated tools', icon: 'fusion', key: '8', sec: 'Operate', view: viewFusion },
  manager:    { title: 'Operations', crumb: 'Queue health, SLA & analyst workload', icon: 'manager', key: '9', sec: 'Operate', view: viewManager },
  dashboards: { title: 'Dashboards', crumb: 'Grafana metrics & trends', icon: 'dash', key: '', sec: 'Operate', view: viewDashboards },
  model:      { title: 'Model', crumb: 'Risk model card & transparency', icon: 'model', key: '', sec: 'Operate', view: viewModel },
  settings:   { title: 'Settings', crumb: 'Identity, integrations & retention', icon: 'gear', key: '', sec: 'Operate', view: viewSettings },
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
    if (e.target === q) { if (e.key === 'Escape') q.blur(); return; }
    if (e.key === '/') { e.preventDefault(); q.focus(); return; }
    if (e.key === 'Escape') { closeAlerts(); closeDrawer(); return; }
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

  // signed-in user (SSO forward-auth, or demo identity) → topbar chip
  try {
    const me = await API.whoami(); const uc = $('#userchip');
    if (me && me.user) {
      uc.innerHTML = '';
      uc.append(h('span', { class: 'av' }, (me.user[0] || '?').toUpperCase()),
        h('div', { class: 'ui' }, h('div', { class: 'un' }, me.user), h('div', { class: 'rl' }, me.role || 'viewer')));
      uc.title = `${me.email || me.user} · ${me.sso}`;
    }
  } catch {}

  // organization chip (multi-tenancy foundation)
  try { const orgs = await API.tenants(); const oc = $('#orgchip'); if (oc && orgs && orgs.length) { oc.textContent = orgs[0].name; oc.title = orgs.map(o => o.name).join(' · '); } } catch {}

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
boot();
