/* =====================================================================
   The five views + the finding-detail drawer (the hero/XAI view).
   State is preserved across view switches so opening a finding and going
   back never loses the queue's filters or scroll.
   ===================================================================== */
'use strict';

const STATE = { ranking: [], assets: {}, filters: { domain: '', severity: '', tool: '', kev: false }, q: '' };

function assetMeta(id) { return STATE.assets[id] || { hostname: id }; }
function exposureOf(id) { const a = assetMeta(id); return a.exposure || null; }

/* ---- 4.1 Triage ------------------------------------------------------ */
async function viewTriage(root) {
  root.append(loading('Loading ranked decisions…'));
  const [ranking, assets] = await Promise.all([API.ranking(), API.assets()]);
  STATE.ranking = ranking; STATE.assets = {}; (assets || []).forEach(a => STATE.assets[a.host_id] = a);
  root.innerHTML = '';

  const tools = [...new Set(ranking.map(f => f.source_tool || 'agent'))].sort();
  const bar = h('div', { class: 'panel-h' },
    h('h2', {}, 'Decision queue'), h('span', { class: 'sub' }, '· ranked by composite risk'), h('span', { class: 'spring' }),
    h('div', { class: 'filters', id: 'filters' },
      sel('domain', ['', 'application', 'system', 'network'], STATE.filters.domain, 'domain'),
      sel('severity', ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], STATE.filters.severity, 'severity'),
      sel('tool', ['', ...tools], STATE.filters.tool, 'source_tool'),
      toggleBtn('KEV only', STATE.filters.kev, () => { STATE.filters.kev = !STATE.filters.kev; renderCards(); })));
  const list = h('div', { class: 'cards', id: 'cards' });
  root.append(h('div', { class: 'panel fade' }, bar, h('div', { style: 'padding:14px 16px' }, list)));
  renderCards();

  function renderCards() {
    $$('.toggle', bar).forEach(t => t.classList.toggle('on', t.textContent === 'KEV only' && STATE.filters.kev));
    const f = STATE.filters, q = STATE.q.toLowerCase();
    const rows = STATE.ranking.filter(r =>
      (!f.domain || r.domain === f.domain) &&
      (!f.severity || (r.severity || '').toUpperCase() === f.severity) &&
      (!f.tool || (r.source_tool || 'agent') === f.tool) &&
      (!f.kev || r.kev) &&
      (!q || `${r.title} ${r.asset_id} ${r.cve_id || ''} ${r.attack || ''}`.toLowerCase().includes(q)));
    list.innerHTML = '';
    if (!rows.length) { list.append(h('div', { class: 'empty' }, 'No findings match the current filters.')); return; }
    rows.forEach(r => list.append(decisionCard(r)));
  }
  function sel(id, opts, val, label) {
    const s = h('select', { onchange: e => { STATE.filters[id] = e.target.value; renderCards(); } },
      opts.map(o => h('option', { value: o, selected: o === val ? 'selected' : null }, o || `all ${label}`)));
    return s;
  }
  window._renderCards = renderCards;
}
function toggleBtn(label, on, onclick) { return h('span', { class: 'toggle' + (on ? ' on' : ''), onclick }, label); }

function decisionCard(r) {
  const c = band(r.risk_score);
  const meta = h('div', { class: 'meta' },
    chip(assetMeta(r.asset_id).hostname || r.asset_id, ''),
    exposureOf(r.asset_id) ? chip(exposureOf(r.asset_id), exposureOf(r.asset_id) === 'internet' ? 'warn' : '') : null,
    r.cve_id ? chip(r.cve_id, 'mono') : null,
    consensusChip(r.consensus),
    r.kev ? chip('KEV', 'kev') : null,
    r.epss ? chip('EPSS ' + pct(r.epss), '') : null,
    r.attack ? chip(r.attack, 'attack') : null,
    r.threat_intel ? chip('live IOC', 'intel') : null);
  const action = (r.domain === 'network' || c === 'critical') ? `Isolate ${assetMeta(r.asset_id).hostname || r.asset_id}` : 'Investigate';
  return h('div', { class: 'card', tabindex: '0', onclick: () => openFinding(r.id),
    onkeydown: e => { if (e.key === 'Enter') openFinding(r.id); } },
    h('div', { class: 'accent ' + c }),
    h('div', { class: 'body' }, h('div', { class: 'row', style: 'margin-bottom:7px' }, severity(r.severity)),
      h('div', { class: 'concl' }, r.title), meta),
    h('div', { class: 'scorebox' }, h('div', { class: 'v ' + c }, n0(r.risk_score)), h('div', { class: 'lb' }, 'risk')));
}

/* ---- 4.2 Finding detail (hero) -------------------------------------- */
async function openFinding(id) {
  const drawer = $('#drawer'), inner = $('#drawer-inner');
  $('#scrim').classList.add('show'); drawer.classList.add('show');
  inner.innerHTML = ''; inner.append(loading('Loading explanation…'));
  const [data, detail] = await Promise.all([API.explain(id), API.finding(id)]);
  // /explain.finding lacks asset_id/cve_id/cvss/epss/kev — /findings/{id} fills them in.
  const f = Object.assign({}, detail || {}, data.finding || {});
  if (!f.id && !f.title) {
    inner.innerHTML = '';
    inner.append(h('div', { class: 'drawer-h' }, h('div', { style: 'font-size:15px;font-weight:600' }, 'Finding not found'),
      h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })),
      h('div', { class: 'drawer-b' }, h('div', { class: 'empty' }, `No finding #${id} — it may have been resolved or not yet scored.`)));
    return;
  }
  const ml = data.ml_explanation || {}, comp = data.composite_components || {}, con = data.consensus || f.consensus || { n_tools: 1, weight: 0, tools: [f.source_tool || 'agent'] };
  const c = band(f.risk_score);
  inner.innerHTML = '';

  inner.append(h('div', { class: 'drawer-h' },
    h('div', { style: 'min-width:0' },
      h('div', { class: 'wrap', style: 'margin-bottom:9px' }, severity(f.severity), chip(f.source_tool || 'agent', 'tool'), consensusChip(con),
        f.kev ? chip('KEV', 'kev') : null, f.threat_intel ? chip('live IOC', 'intel') : null),
      h('div', { style: 'font-size:17px;font-weight:600;line-height:1.35' }, f.title),
      h('div', { class: 'faint', style: 'font-size:12px;margin-top:5px' }, `${f.domain} · ${assetMeta(f.asset_id).hostname || f.asset_id} · finding #${f.id}`)),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));

  const b = h('div', { class: 'drawer-b' }); inner.append(b);

  // conclusion + big score
  b.append(h('div', { class: 'block' },
    h('div', { class: 'hero' }, h('div', { class: 'big ' + c }, n0(f.risk_score)), h('div', { class: 'of' }, '/ 100 composite'),
      h('span', { style: 'flex:1' }), h('div', { style: 'text-align:right' },
        h('div', { class: 'mono', style: 'font-size:15px' }, n1(f.ml_risk_score)), h('div', { class: 'faint', style: 'font-size:10px;text-transform:uppercase;letter-spacing:1px' }, 'XGBoost ML')))));

  // SHAP waterfall — the differentiator
  if (Array.isArray(ml.waterfall) && ml.waterfall.length) {
    b.append(block('Why this score — SHAP waterfall', h('div', {}, waterfall(ml.waterfall),
      h('div', { class: 'faint', style: 'font-size:11px;margin-top:8px' }, 'Base value → each of the 10 risk factors → final ML score. Risk-raising factors extend right (amber/red); risk-lowering left (green).'))));
  } else if (Object.keys(comp).length) {
    b.append(block('Composite factor contributions', factorBars(comp)));
  }

  // multi-tool consensus
  b.append(block('Multi-tool consensus', consensusPanel(con)));

  // ATT&CK + threat intel
  const ctx = h('div', { class: 'kv' });
  if (f.attack) ctx.append(h('div', { class: 'k' }, 'ATT&CK'), h('div', {}, h('span', { class: 'mono' }, f.attack), ' · ', attackName(f.attack)));
  if (f.cvss_score) ctx.append(h('div', { class: 'k' }, 'CVSS'), h('div', { class: 'mono' }, n1(f.cvss_score)));
  if (f.epss) ctx.append(h('div', { class: 'k' }, 'EPSS'), h('div', { class: 'mono' }, pct(f.epss) + ' exploitation prob.'));
  if (f.threat_intel) { const ti = f.threat_intel; ctx.append(h('div', { class: 'k' }, 'MISP IOC'), h('div', {}, h('span', { class: 'mono' }, ti.indicator || JSON.stringify(ti)), ti.type ? ` · ${ti.type}` : '', ti.confidence ? ` · conf ${ti.confidence}` : '')); }
  if (ctx.children.length) b.append(block('ATT&CK & threat intel', ctx));

  // counterfactuals
  if (Array.isArray(ml.counterfactuals) && ml.counterfactuals.length)
    b.append(block('What-if (counterfactuals)', counterfactuals(ml.counterfactuals)));

  // provenance
  b.append(block('Evidence & provenance', provenance(detail || f)));

  // containment
  const destructive = f.domain === 'network' || c === 'critical';
  const proposed = { id: 'act-' + f.id, action: destructive ? 'isolate_host' : 'apply_patch', target: assetMeta(f.asset_id).hostname || f.asset_id, status: 'proposed', approvals: [] };
  b.append(block('Response — containment', approvalGate(proposed, {})));

  // feedback
  b.append(block('Analyst feedback', feedbackForm(f.id)));
}
function block(label, body) { return h('div', { class: 'block' }, h('div', { class: 'sec-label' }, label), body); }
function factorBars(comp) {
  const max = Math.max(1, ...Object.values(comp).map(Number));
  return h('div', {}, Object.entries(comp).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
    h('div', { class: 'wfr', style: 'grid-template-columns:128px 1fr 44px' },
      h('div', { class: 'k' }, k), h('div', { class: 'wftrack' }, h('div', { class: 'wfbar pos', style: `left:0;width:${(+v / max) * 100}%` })),
      h('div', { class: 'c' }, n1(v)))));
}
function feedbackForm(id) {
  let action = 'confirm_tp', priority = 70;
  const seg = h('div', { class: 'seg' });
  [['confirm_tp', 'Confirm TP'], ['mark_fp', 'Mark FP'], ['escalate', 'Escalate'], ['adjust', 'Adjust severity']].forEach(([v, l], i) => {
    const btn = h('button', { class: i === 0 ? 'sel' : '', onclick: () => { action = v; $$('button', seg).forEach(x => x.classList.remove('sel')); btn.classList.add('sel'); } }, l);
    seg.append(btn);
  });
  const note = h('textarea', { rows: '2', placeholder: 'Rationale…' });
  const submit = h('button', { class: 'btn primary', onclick: async () => {
    submit.disabled = true; submit.textContent = 'Saving…';
    await API.feedback(id, { analyst: 'analyst', action, label_priority: priority, comment: note.value || null });
    toast('Feedback captured — weighted 5× in the monthly XGBoost retrain', true); note.value = ''; submit.disabled = false; submit.textContent = 'Submit';
  } }, 'Submit');
  return h('div', { class: 'stack', style: 'gap:11px' }, seg, note,
    h('div', { class: 'row' }, h('span', { class: 'faint', style: 'font-size:11px;flex:1' }, 'Feedback is weighted 5× and feeds the monthly retraining loop.'), submit));
}
function closeDrawer() { $('#scrim').classList.remove('show'); $('#drawer').classList.remove('show'); }

/* ---- 4.3 Compliance -------------------------------------------------- */
async function viewCompliance(root) {
  root.append(loading('Loading compliance posture…'));
  const [summary, results, chain] = await Promise.all([API.compSummary(), API.compResults(), API.chain()]);
  root.innerHTML = '';
  const by = {}; (summary.by_status || []).forEach(s => by[s.status] = s.count);
  const graded = (by.pass || 0) + (by.fail || 0) + (by.partial || 0) || 1;
  const score = Math.round(((by.pass || 0) / graded) * 100);
  const regressed = (summary.per_asset || []).filter(a => +a.score_pct < 50).length;

  root.append(h('div', { class: 'stack fade' },
    h('div', { class: 'panel pad' },
      h('div', { class: 'sec-label', style: 'margin-bottom:8px' }, 'Posture'),
      h('div', { style: 'font-size:16px;font-weight:560;line-height:1.4' },
        `CIS posture ${score}% — ${by.fail || 0} controls failing across the estate` + (regressed ? `, ${regressed} host(s) below 50%.` : '.')),
      h('div', { class: 'row', style: 'margin-top:14px;gap:8px' },
        chip('chain ' + (chain.ok ? 'verified ✓' : 'BROKEN ✗'), chain.ok ? 'ok' : 'kev'),
        chip(`${chain.length ?? 0} evidence records`, 'mono'),
        h('span', { class: 'faint mono', style: 'font-size:10.5px' }, 'head ' + (chain.head_hash || '—').slice(0, 16)))),
    compTable(results)));
}
function compTable(results) {
  const byHost = {}; (results || []).forEach(r => { (byHost[r.asset_id] = byHost[r.asset_id] || []).push(r); });
  const tbl = h('table', { class: 'tbl' },
    h('thead', {}, h('tr', {}, ['Control', 'Title', 'Status', 'Host', 'Evidence'].map(t => h('th', {}, t)))),
    h('tbody', {}, (results || []).map(r => h('tr', {},
      h('td', { class: 'mono' }, r.rule_id),
      h('td', {}, r.title || '—'),
      h('td', {}, statusChip(r.status)),
      h('td', { class: 'mono' }, r.asset_id),
      h('td', {}, h('span', { class: 'faint mono', style: 'font-size:10.5px' }, 'hash-linked'))))));
  return h('div', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', {}, 'CIS controls'), h('span', { class: 'sub' }, `· ${(results || []).length} evaluated`)),
    h('div', { style: 'overflow-x:auto' }, tbl));
}
const statusChip = (s) => s === 'pass' ? chip('pass', 'ok') : s === 'fail' ? chip('fail', 'kev') : s === 'partial' ? chip('partial', 'warn') : chip(s || 'n/a');

/* ---- 4.4 Incidents --------------------------------------------------- */
async function viewIncidents(root) {
  root.append(loading('Loading cases…'));
  const [incidents, actions, audit] = await Promise.all([API.incidents(), API.actions(), API.auditVerify()]);
  root.innerHTML = '';
  if (!incidents.length) { root.append(h('div', { class: 'panel empty' }, 'No incidents open.')); return; }
  const list = h('div', { class: 'panel fade' },
    h('div', { class: 'panel-h' }, h('h2', {}, 'Cases'), h('span', { class: 'sub' }, `· ${incidents.length} · audit chain ${audit.ok ? 'verified ✓' : 'check'}`)),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['ID', 'Incident', 'Severity', 'Status', 'SLA', 'Findings', 'Opened'].map(t => h('th', {}, t)))),
      h('tbody', {}, incidents.map(i => h('tr', { onclick: () => openIncident(i, actions) },
        h('td', { class: 'mono' }, '#' + i.id),
        h('td', {}, i.title),
        h('td', {}, severity(i.severity)),
        h('td', {}, chip(i.status, i.status === 'open' ? 'warn' : 'ok')),
        h('td', {}, i.sla_breached ? chip('breached', 'kev') : chip('on track', 'ok')),
        h('td', { class: 'mono' }, String(i.finding_count ?? 0)),
        h('td', { class: 'faint' }, ago(i.created_at))))))));
  root.append(list);
}
function openIncident(inc, actions) {
  const inner = $('#drawer-inner'); $('#scrim').classList.add('show'); $('#drawer').classList.add('show');
  const acts = (actions || []).filter(a => a.incident_id === inc.id);
  inner.innerHTML = '';
  inner.append(h('div', { class: 'drawer-h' },
    h('div', {}, h('div', { class: 'wrap', style: 'margin-bottom:9px' }, severity(inc.severity), chip(inc.status, 'warn')),
      h('div', { style: 'font-size:17px;font-weight:600' }, inc.title),
      h('div', { class: 'faint', style: 'font-size:12px;margin-top:5px' }, `case #${inc.id} · owner ${inc.assignee || inc.created_by || '—'} · opened ${ago(inc.created_at)}`)),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));
  const b = h('div', { class: 'drawer-b' }); inner.append(b);
  b.append(block('SLA', h('div', { class: 'row' }, inc.sla_breached ? chip('breached', 'kev') : chip('on track', 'ok'), h('span', { class: 'faint mono', style: 'font-size:11px' }, 'due ' + (inc.sla_due || '—')))));
  b.append(block('Audit timeline (hash-chained)', acts.length ? h('div', {}, acts.map(a =>
    h('div', { class: 'cf' }, h('span', {}, h('span', { class: 'mono' }, a.action), ` → ${a.target || ''}`),
      h('span', { class: 'chip ' + (a.status && a.status.includes('contain') ? 'ok' : 'warn') }, a.status || 'proposed'))))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No actions recorded for this case.')));
}

/* ---- 4.5 Sensors & Fusion ------------------------------------------- */
async function viewFusion(root) {
  root.append(loading('Loading pipeline & sensors…'));
  const [ranking, stats, ver, chain] = await Promise.all([API.ranking(), API.stats(), API.version(), API.chain()]);
  root.innerHTML = '';
  const byTool = {}; let corroborated = 0, modelVer = '—';
  ranking.forEach(f => { const t = f.source_tool || 'agent'; byTool[t] = (byTool[t] || 0) + 1; if (f.consensus && f.consensus.n_tools > 1) corroborated++; });
  const ex = ranking[0] ? await API.explain(ranking[0].id) : null;
  modelVer = (ex && (ex.ml_explanation || {}).model_version) || (ex && (ex.finding || {}).model_version) || '—';

  // pipeline strip
  const stage = (nm, val, ds) => h('div', { class: 'stage' }, h('div', { class: 'nm' }, h('span', { class: 'statdot active' }), nm), h('div', { class: 'mv' }, val), h('div', { class: 'ds' }, ds));
  root.append(h('div', { class: 'stack fade' },
    h('div', { class: 'panel pad' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Pipeline'),
      h('div', { class: 'pipe' },
        stage('feed-sync', 'mirrored', 'NVD · EPSS · KEV (only egress)'),
        stage('ingest-edge', 'mTLS', 'authenticated telemetry'),
        stage('JetStream', 'streaming', 'durable broker · replay'),
        stage('workers', 'active', 'enrich · normalize · store'),
        stage('scoring', n0(stats.assets ? ranking.length : 0), 'findings scored'),
        stage('fusion', String(corroborated), 'clusters corroborated >1 tool'))),
    h('div', { class: 'panel pad' }, h('div', { class: 'row', style: 'margin-bottom:12px' }, h('div', { class: 'sec-label' }, 'Sensors & integrated tools'),
      h('span', { class: 'spring' }), h('span', { class: 'faint mono', style: 'font-size:10.5px' }, 'model ' + modelVer)),
      sensorsGrid(byTool))));
}
function sensorsGrid(byTool) {
  const TOOLS = [
    { nm: 'Endpoint agent', role: 'eBPF · osquery · YARA · FIM', env: 'system_info · fim_event', key: 'agent', st: 'active' },
    { nm: 'Suricata', role: 'Network IDS', env: 'ids_alert', key: 'suricata', st: 'monitoring' },
    { nm: 'Zeek', role: 'Traffic analysis', env: 'traffic_metadata', key: 'zeek', st: 'monitoring' },
    { nm: 'Wazuh', role: 'Host FIM / SCA', env: 'fim_event · scan_finding', key: 'wazuh', st: 'active' },
    { nm: 'Trivy', role: 'Image / package CVEs', env: 'scan_finding', key: 'trivy', st: 'active' },
    { nm: 'Nuclei', role: 'Template scans', env: 'scan_finding', key: 'nuclei', st: 'active' },
    { nm: 'MISP', role: 'IOC threat intel', env: 'ioc_match', key: 'misp', st: 'monitoring' },
    { nm: 'OpenCTI', role: 'ATT&CK mapping', env: 'attack tag', key: 'opencti', st: 'monitoring' },
    { nm: 'Sigma', role: 'Detection rules', env: 'log query', key: 'sigma', st: 'monitoring' },
    { nm: 'Falco', role: 'Runtime syscalls', env: 'runtime_alert', key: 'falco', st: 'optional' },
  ];
  return h('div', { class: 'sensors' }, TOOLS.map(t => {
    const cnt = byTool[t.key] || 0;
    const st = t.st === 'optional' ? 'optional' : (cnt > 0 ? 'active' : t.st);
    const label = t.st === 'optional' ? 'optional (D-031)' : (cnt > 0 ? 'active' : t.st);
    return h('div', { class: 'sensor' },
      h('div', { class: 'top' }, h('div', {}, h('div', { class: 'nm' }, t.nm), h('div', { class: 'role' }, t.role))),
      h('div', { class: 'stat' }, h('span', { class: 'statdot ' + st }), label,
        h('span', { style: 'flex:1' }), h('span', { class: 'mono faint' }, cnt ? `${cnt} findings` : '')),
      h('div', { class: 'faint mono', style: 'font-size:10px;margin-top:7px' }, t.env));
  }));
}
