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
  agent:      { title: 'AI Analyst', crumb: 'Agentic triage — self-hosted LLM', icon: 'model', key: '', sec: 'Operate', view: viewAgent },
  automation: { title: 'Automation', crumb: 'n8n engine — status & workflows', icon: 'activity', key: '', sec: 'Operate', view: viewAutomation },
  reports:    { title: 'Reports', crumb: 'Posture, compliance & executive reports', icon: 'report', key: '', sec: 'Operate', view: viewReports },
  dashboards: { title: 'Dashboards', crumb: 'Grafana metrics & trends', icon: 'dash', key: '', sec: 'Operate', view: viewDashboards },
  model:      { title: 'Model', crumb: 'Risk model card & transparency', icon: 'model', key: '', sec: 'Operate', view: viewModel },
  settings:   { title: 'Settings', crumb: 'Identity, integrations & retention', icon: 'gear', key: '', sec: 'Operate', view: viewSettings },
  vitals:     { title: 'Node Vitals', crumb: 'Appliance node telemetry (live /proc)', icon: 'activity', key: '', sec: 'Toolkit', view: viewVitals },
  news:       { title: 'Threat News', crumb: 'Bundled offline intel feed', icon: 'globe', key: '', sec: 'Toolkit', view: viewNews },
  loganalyzer:{ title: 'Log Analyzer', crumb: 'Heuristic log triage', icon: 'rules', key: '', sec: 'Toolkit', view: viewLogScan },
  phishing:   { title: 'Phishing Analyzer', crumb: 'Email IOC extraction + threat score', icon: 'alert', key: '', sec: 'Toolkit', view: viewPhishing },
  cvelookup:  { title: 'CVE Lookup', crumb: 'Resolve & explain a CVE (offline)', icon: 'score', key: '', sec: 'Toolkit', view: viewCveLookup },
  irplaybook: { title: 'IR Playbook', crumb: 'NIST SP 800-61 generator', icon: 'report', key: '', sec: 'Toolkit', view: viewIrPlaybook },
  portscan:   { title: 'Port Scanner', crumb: 'Internal TCP scan (range-guarded)', icon: 'target', key: '', sec: 'Toolkit', view: viewPortScan },
  assistant:  { title: 'Assistant', crumb: 'Offline security knowledge Q&A', icon: 'fusion', key: '', sec: 'Toolkit', view: viewAssistant },
  search:     { title: 'Search', crumb: 'Global results', icon: 'hunt', key: '', sec: '_hidden', view: viewSearch },
};
/* ---- hub-based information architecture ---------------------------------
   6 primary destinations (+ Settings). Each hub owns an ordered set of child
   routes surfaced as a sub-nav tab strip; tools are launched from a grid, not
   the rail. Route keys are unchanged, so deep-links + ⌘K still resolve. */
const HUBS = {
  home:        { title: 'Home',        icon: 'overview', key: '1', children: ['overview'] },
  triage:      { title: 'Triage',      icon: 'triage',   key: '2', children: ['triage'] },
  investigate: { title: 'Investigate', icon: 'hunt',     key: '3', children: ['cases', 'assets', 'hunt', 'intel', 'livehunt', 'coverage'] },
  automate:    { title: 'Automate',    icon: 'model',    key: '4', children: ['agent', 'automation', 'playbooks', 'alerting'] },
  assurance:   { title: 'Assurance',   icon: 'shield',   key: '5', children: ['compliance', 'trust', 'reports', 'model'] },
  operations:  { title: 'Operations',  icon: 'manager',  key: '6', children: ['fusion', 'manager', 'detections', 'dashboards'] },
  settings:    { title: 'Settings',    icon: 'gear',     key: '',  children: ['settings'] },
};
const PRIMARY = ['home', 'triage', 'investigate', 'automate', 'assurance', 'operations'];
const TOOLSET = ['vitals', 'news', 'loganalyzer', 'phishing', 'cvelookup', 'irplaybook', 'portscan', 'assistant'];
const ROUTE_HUB = {};
for (const [hk, hub] of Object.entries(HUBS)) for (const c of hub.children) ROUTE_HUB[c] = hk;
let current = 'overview', selIdx = -1;

/* last-visited child per hub (re-entering a hub returns you where you were) + palette recents */
let _hubLast = {}; try { _hubLast = JSON.parse(localStorage.getItem('vyrex_hublast') || '{}'); } catch {}
let _recent = []; try { _recent = JSON.parse(localStorage.getItem('vyrex_recent') || '[]'); } catch {}

function navItem(hk) {
  const hub = HUBS[hk];
  return h('a', { 'data-hub': hk, tabindex: '0', onclick: () => goHub(hk),
    onkeydown: e => { if (e.key === 'Enter') goHub(hk); },
    html: ic(hub.icon) + `<span>${hub.title}</span>` + (hub.key ? `<span class="key">${hub.key}</span>` : '') });
}
function buildNav() {
  const nav = $('#nav'); nav.innerHTML = '';
  PRIMARY.forEach(hk => nav.append(navItem(hk)));
  nav.append(h('div', { class: 'nav-div' }));
  nav.append(h('a', { 'data-tools': '1', tabindex: '0', onclick: openTools,
    onkeydown: e => { if (e.key === 'Enter') openTools(); },
    html: ic('layers') + '<span>Tools</span>' + '<span class="key">T</span>' }));
  nav.append(navItem('settings'));
}
function goHub(hk) {
  const hub = HUBS[hk]; if (!hub) return;
  const last = _hubLast[hk];
  go(last && hub.children.includes(last) ? last : hub.children[0]);
}
function buildTabs(route) {
  const strip = $('#tabs'); if (!strip) return;
  const hub = HUBS[ROUTE_HUB[route]];
  if (!hub || hub.children.length < 2) { strip.hidden = true; strip.innerHTML = ''; return; }
  strip.hidden = false; strip.innerHTML = '';
  hub.children.forEach(ck => {
    const r = ROUTES[ck]; if (!r) return;
    strip.append(h('a', { 'data-tab': ck, class: ck === route ? 'active' : '', tabindex: '0',
      onclick: () => go(ck), onkeydown: e => { if (e.key === 'Enter') go(ck); },
      html: ic(r.icon) + `<span>${r.title}</span>` }));
  });
}
function moveTab(d) {
  const hub = HUBS[ROUTE_HUB[current]]; if (!hub || hub.children.length < 2) return;
  let i = hub.children.indexOf(current); if (i < 0) i = 0;
  go(hub.children[(i + d + hub.children.length) % hub.children.length]);
}
function pushRecent(route) {
  if (!ROUTES[route] || route === 'search') return;
  _recent = [route, ..._recent.filter(r => r !== route)].slice(0, 6);
  try { localStorage.setItem('vyrex_recent', JSON.stringify(_recent)); } catch {}
}

/* ---- Tools launcher (app-grid) — standalone analyzers, off the rail ---- */
function openTools() {
  if ($('#login') && !$('#login').hidden) return;
  if ($('#tools')) return;
  const box = h('div', { class: 'tools-modal', id: 'tools', onclick: e => { if (e.target === box) closeTools(); } },
    h('div', { class: 'tools-card' },
      h('div', { class: 'tools-h' }, h('strong', { style: 'font-size:14px' }, 'Tools'),
        h('span', { class: 'faint', style: 'font-size:12px' }, 'Standalone analyzers & utilities'),
        h('span', { class: 'spring', style: 'flex:1' }),
        h('button', { class: 'sc-x', title: 'Close (Esc)', onclick: closeTools, html: ic('x') })),
      h('div', { class: 'tools-grid' }, TOOLSET.map(k => {
        const r = ROUTES[k]; if (!r) return null;
        return h('button', { class: 'tool-tile', onclick: () => { closeTools(); go(k); } },
          h('span', { class: 'tt-ic', html: ic(r.icon) }),
          h('span', { class: 'tt-t' }, r.title),
          h('span', { class: 'tt-d' }, r.crumb));
      }))));
  document.body.append(box);
}
function closeTools() { const b = $('#tools'); if (b) b.remove(); }
function go(route) {
  if (!ROUTES[route]) route = 'overview';
  // tear down any per-view timers (e.g. the Overview live ticker) before switching
  if (window._viewCleanup) { try { window._viewCleanup(); } catch {} window._viewCleanup = null; }
  current = route; selIdx = -1; location.hash = route;
  const r = ROUTES[route];
  $('#title').textContent = r.title; $('#crumb').textContent = r.crumb;
  const hk = ROUTE_HUB[route];
  if (hk) { _hubLast[hk] = route; try { localStorage.setItem('vyrex_hublast', JSON.stringify(_hubLast)); } catch {} }
  $$('#nav a[data-hub]').forEach(a => a.classList.toggle('active', a.dataset.hub === hk));
  buildTabs(route); pushRecent(route);
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
  // make the offline/demo state self-explanatory rather than silently swapping data
  el.title = mode === 'live' ? 'Connected to /api — live data'
    : mode === 'demo' ? (API._story ? 'Storyline Mode — showing scripted demo data' : 'API unreachable — showing bundled offline demo data')
    : 'Connecting to /api…';
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
    if (e.key === '?') { e.preventDefault(); toggleShortcuts(); return; }
    if (e.key === 'Escape') { const sh = $('#shortcuts'); if (sh) { sh.remove(); return; } if ($('#tools')) { closeTools(); return; } closePalette(); closeAlerts(); closeDrawer(); return; }
    if (e.key === 'j') { moveSel(1); return; }
    if (e.key === 'k') { moveSel(-1); return; }
    if (e.key === 'Enter') { openSel(); return; }
    if (e.key === 't' || e.key === 'T') { openTools(); return; }
    if (e.key === '[' || e.key === ']') { moveTab(e.key === ']' ? 1 : -1); return; }
    const hub = Object.keys(HUBS).find(k => HUBS[k].key && HUBS[k].key === e.key);
    if (hub) goHub(hub);
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

  // ⌘K omni affordance in the search bar → open the command palette
  const omniBtn = $('#omnik'); if (omniBtn) omniBtn.addEventListener('click', e => { e.preventDefault(); openPalette(); });

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
  if (ROUTES[hash]) { if (hash !== current || initial) go(hash); return; }
  if (hash) { showNotFound(hash); return; }   // unknown, non-empty hash → designed 404
  if (initial) go('overview');
}
function showNotFound(hash) {
  current = '';
  if (window._viewCleanup) { try { window._viewCleanup(); } catch {} window._viewCleanup = null; }
  $('#title').textContent = 'Not found';
  $('#crumb').textContent = '#' + hash;
  $$('#nav a').forEach(a => a.classList.remove('active'));
  closeDrawer();
  const root = $('#view'); root.innerHTML = ''; $('#scroll').scrollTop = 0;
  root.append(emptyState('That screen doesn’t exist',
    `No view is registered for "#${hash}". Press ⌘K to jump to a page, or head back to the Overview.`,
    'shield2', h('button', { class: 'btn primary', onclick: () => go('overview') }, 'Back to Overview')));
}
window.addEventListener('hashchange', () => routeFromHash(false));

/* ---- keyboard shortcuts cheat-sheet (press ?) ------------------------ */
function toggleShortcuts() {
  const existing = $('#shortcuts');
  if (existing) { existing.remove(); return; }
  const K = (k) => h('kbd', { class: 'kkey' }, k);
  const row = (keys, desc) => h('div', { class: 'shorts-row' },
    h('div', { class: 'shorts-keys' }, keys), h('div', { class: 'shorts-d' }, desc));
  const box = h('div', { class: 'shorts', id: 'shortcuts', onclick: e => { if (e.target.id === 'shortcuts') box.remove(); } },
    h('div', { class: 'shorts-card' },
      h('div', { class: 'shorts-h' }, h('strong', {}, 'Keyboard shortcuts'),
        h('span', { class: 'spring', style: 'flex:1' }),
        h('button', { class: 'sc-x', title: 'Close (Esc)', onclick: () => box.remove(), html: ic('x') })),
      h('div', { class: 'shorts-b' },
        row([K('⌘'), K('K')], 'Command palette — jump to a page or run an action'),
        row([K('/')], 'Focus the search bar'),
        row([K('1'), h('span', { class: 'kdash' }, '–'), K('6')], 'Jump to a hub (Home · Triage · Investigate · …)'),
        row([K('['), K(']')], 'Previous / next tab within the hub'),
        row([K('T')], 'Open the Tools launcher'),
        row([K('j'), K('k')], 'Move selection down / up'),
        row([K('↵')], 'Open the selected item'),
        row([K('Esc')], 'Close drawer · palette · this overlay'),
        row([K('?')], 'Show this help'))));
  document.body.append(box);
}

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
  { title: 'Run Demo Storyline', sec: 'Action', icon: 'target', run: () => { if (typeof startStory === 'function') startStory(); } },
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
// Palette items are grouped: Recent (empty query only) · Actions · then pages by hub.
function groupOf(k) { return HUBS[ROUTE_HUB[k]] ? HUBS[ROUTE_HUB[k]].title : (TOOLSET.includes(k) ? 'Tools' : 'Pages'); }
function paletteSource(ql) {
  const items = [];
  if (!ql) _recent.forEach(k => { const r = ROUTES[k]; if (r) items.push({ key: k, title: r.title, icon: r.icon, group: 'Recent' }); });
  CMDK_ACTIONS.filter(a => `${a.title} ${a.sec}`.toLowerCase().includes(ql))
    .forEach(a => items.push({ title: a.title, icon: a.icon, run: a.run, group: 'Actions' }));
  Object.entries(ROUTES)
    .filter(([k, r]) => r.sec !== '_hidden' && `${r.title} ${r.sec} ${r.crumb}`.toLowerCase().includes(ql))
    .forEach(([k, r]) => items.push({ key: k, title: r.title, icon: r.icon, group: groupOf(k) }));
  return items;
}
function renderPalette(query) {
  const list = $('#cmdk-list');
  _cmdkItems = paletteSource((query || '').toLowerCase());
  _cmdkSel = 0; list.innerHTML = '';
  if (!_cmdkItems.length) { list.append(h('div', { class: 'faint', style: 'padding:16px;text-align:center;font-size:12px' }, 'No match.')); return; }
  let lastGroup = null, i = 0;
  _cmdkItems.forEach((it) => {
    if (it.group !== lastGroup) { list.append(h('div', { class: 'cmdk-group' }, it.group)); lastGroup = it.group; }
    const sel = i === 0; i++;
    list.append(h('div', { class: 'cmdk-item' + (sel ? ' sel' : ''), onclick: () => runPaletteItem(it) },
      h('span', { html: ic(it.icon), style: 'width:15px;height:15px;color:var(--muted);display:inline-flex' }),
      h('span', { style: 'flex:1' }, it.title),
      h('span', { class: it.run ? 'cmdk-tag' : 'faint', style: 'font-size:10.5px' }, it.run ? '↵ run' : it.group)));
  });
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
  // caps-lock hint on the password field (a small thing premium tools get right)
  const pass = $('#login-pass');
  if (pass && !$('#login-caps')) {
    const caps = h('div', { class: 'login-caps', id: 'login-caps', hidden: true }, '⚠ Caps Lock is on');
    err.before(caps);
    const check = e => { caps.hidden = !(e.getModifierState && e.getModifierState('CapsLock')); };
    pass.addEventListener('keydown', check); pass.addEventListener('keyup', check);
  }
  $('#login-user').focus();
}
gate();
