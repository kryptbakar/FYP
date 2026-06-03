/* =====================================================================
   Router, keyboard navigation, live/demo indicator, boot.
   Keys: 1–4 switch views · / focus search · j/k move selection · Enter open · Esc back.
   ===================================================================== */
'use strict';

const ROUTES = {
  triage:     { title: 'Triage', crumb: 'Ranked decisions', icon: 'triage', key: '1', view: viewTriage },
  compliance: { title: 'Compliance', crumb: 'CIS posture & hash-chained evidence', icon: 'shield', key: '2', view: viewCompliance },
  cases:      { title: 'Cases', crumb: 'Incidents, correlation & signed audit', icon: 'cases', key: '3', view: viewIncidents },
  fusion:     { title: 'Sensors & Fusion', crumb: 'Pipeline health & integrated tools', icon: 'fusion', key: '4', view: viewFusion },
};
let current = 'triage', selIdx = -1;

function buildNav() {
  const nav = $('#nav'); nav.innerHTML = '';
  for (const [k, r] of Object.entries(ROUTES))
    nav.append(h('a', { 'data-route': k, tabindex: '0', onclick: () => go(k), onkeydown: e => { if (e.key === 'Enter') go(k); },
      html: ic(r.icon) + `<span>${r.title}</span><span class="key">${r.key}</span>` }));
}
function go(route) {
  if (!ROUTES[route]) route = 'triage';
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
    if (e.key === 'Escape') { closeDrawer(); return; }
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

  const start = (location.hash || '#triage').slice(1);
  go(ROUTES[start] ? start : 'triage');
}
window.addEventListener('hashchange', () => { const r = location.hash.slice(1); if (ROUTES[r] && r !== current) go(r); });
boot();
