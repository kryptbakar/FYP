/* =====================================================================
   The five views + the finding-detail drawer (the hero/XAI view).
   State is preserved across view switches so opening a finding and going
   back never loses the queue's filters or scroll.
   ===================================================================== */
'use strict';

const STATE = { ranking: [], assets: {}, filters: { domain: '', severity: '', tool: '', kev: false, sort: 'risk' }, q: '', selected: new Set() };
// triaged-away lifecycle states that leave the active queue (DefectDojo pattern)
const CLOSED_STATES = new Set(['false_positive', 'risk_accepted', 'mitigated', 'resolved']);

function assetMeta(id) { return STATE.assets[id] || { hostname: id }; }
function exposureOf(id) { const a = assetMeta(id); return a.exposure || null; }

/* ---- 4.1 Triage ------------------------------------------------------ */
async function viewTriage(root) {
  root.append(loading('Loading ranked decisions…'));
  const [ranking, assets] = await Promise.all([API.ranking(), API.assets()]);
  STATE.ranking = ranking; STATE.assets = {}; (assets || []).forEach(a => STATE.assets[a.host_id] = a);
  root.innerHTML = '';

  STATE.selected = new Set();
  const tools = [...new Set(ranking.map(f => f.source_tool || 'agent'))].sort();
  const SEVRANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const bar = h('div', { class: 'panel-h' },
    h('h2', {}, 'Decision queue'), h('span', { class: 'sub' }, '· ranked by composite risk'), h('span', { class: 'spring' }),
    h('div', { class: 'filters', id: 'filters' },
      sortSel(),
      sel('domain', ['', 'application', 'system', 'network'], STATE.filters.domain, 'domain'),
      sel('severity', ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], STATE.filters.severity, 'severity'),
      sel('tool', ['', ...tools], STATE.filters.tool, 'source_tool'),
      toggleBtn('KEV only', STATE.filters.kev, () => { STATE.filters.kev = !STATE.filters.kev; renderCards(); })));
  const bulk = h('div', { class: 'bulkbar', id: 'bulkbar', hidden: true });
  const list = h('div', { class: 'cards', id: 'cards' });
  root.append(h('div', { class: 'panel fade' }, bar, bulk, h('div', { style: 'padding:14px 16px' }, list)));
  renderCards();

  function filteredRows() {
    const f = STATE.filters, q = STATE.q.toLowerCase();
    let rows = STATE.ranking.filter(r =>
      !CLOSED_STATES.has(r.triage_status || 'open') &&
      (!f.domain || r.domain === f.domain) &&
      (!f.severity || (r.severity || '').toUpperCase() === f.severity) &&
      (!f.tool || (r.source_tool || 'agent') === f.tool) &&
      (!f.kev || r.kev) &&
      (!q || `${r.title} ${r.asset_id} ${r.cve_id || ''} ${r.attack || ''}`.toLowerCase().includes(q)));
    const s = f.sort || 'risk';
    rows = rows.slice().sort((a, b) =>
      s === 'cvss' ? (+b.cvss_score || 0) - (+a.cvss_score || 0) :
      s === 'epss' ? (+b.epss || 0) - (+a.epss || 0) :
      s === 'asset' ? String(a.asset_id).localeCompare(String(b.asset_id)) :
      s === 'severity' ? (SEVRANK[(b.severity || '').toUpperCase()] || 0) - (SEVRANK[(a.severity || '').toUpperCase()] || 0) :
      (+b.risk_score || 0) - (+a.risk_score || 0));
    return rows;
  }
  function renderCards() {
    $$('.toggle', bar).forEach(t => t.classList.toggle('on', t.textContent === 'KEV only' && STATE.filters.kev));
    const rows = filteredRows();
    list.innerHTML = '';
    if (!rows.length) { list.append(h('div', { class: 'empty' }, 'No findings match the current filters.')); renderBulk(); return; }
    rows.forEach(r => list.append(decisionCard(r)));
    renderBulk();
  }
  function renderBulk() {
    const n = STATE.selected.size;
    bulk.hidden = n === 0;
    if (!n) return;
    bulk.innerHTML = '';
    bulk.append(h('span', { class: 'bk-n' }, `${n} selected`),
      h('span', { class: 'spring', style: 'flex:1' }),
      h('button', { class: 'btn sm', onclick: () => bulkAct('escalate') }, 'Escalate'),
      h('button', { class: 'btn sm', onclick: () => bulkTriage('false_positive') }, 'False positive'),
      h('button', { class: 'btn sm', onclick: () => bulkTriage('resolved') }, 'Resolve'),
      h('button', { class: 'btn sm', onclick: () => { STATE.selected.clear(); renderCards(); } }, 'Clear'));
  }
  async function bulkAct(action) {
    const ids = [...STATE.selected];
    for (const id of ids) { try { await API.feedback(id, { analyst: 'analyst', action, comment: 'bulk action' }); } catch {} }
    toast(`${ids.length} finding(s) — ${action.replace('_', ' ')} submitted`, true);
    STATE.selected.clear(); renderCards();
  }
  async function bulkTriage(status) {
    const ids = [...STATE.selected];
    for (const id of ids) { try { await API.triage(id, { status }); } catch {} const r = STATE.ranking.find(x => x.id === id); if (r) r.triage_status = status; }
    toast(`${ids.length} finding(s) — ${status.replace('_', ' ')}`, true);
    STATE.selected.clear(); renderCards();
  }
  function sortSel() {
    return h('select', { onchange: e => { STATE.filters.sort = e.target.value; renderCards(); } },
      [['risk', 'sort: risk'], ['severity', 'sort: severity'], ['cvss', 'sort: CVSS'], ['epss', 'sort: EPSS'], ['asset', 'sort: asset']]
        .map(([v, l]) => h('option', { value: v, selected: (STATE.filters.sort || 'risk') === v ? 'selected' : null }, l)));
  }
  function sel(id, opts, val, label) {
    const s = h('select', { onchange: e => { STATE.filters[id] = e.target.value; renderCards(); } },
      opts.map(o => h('option', { value: o, selected: o === val ? 'selected' : null }, o || `all ${label}`)));
    return s;
  }
  window._renderCards = renderCards;
  window._renderBulk = renderBulk;
}
function selCheck(r) {
  return h('input', { type: 'checkbox', class: 'cbx', title: 'select', checked: STATE.selected.has(r.id) ? 'checked' : null,
    onclick: e => e.stopPropagation(),
    onchange: e => { if (e.target.checked) STATE.selected.add(r.id); else STATE.selected.delete(r.id); if (window._renderBulk) window._renderBulk(); } });
}
function toggleBtn(label, on, onclick) { return h('span', { class: 'toggle' + (on ? ' on' : ''), onclick }, label); }

function decisionCard(r) {
  const c = band(r.risk_score);
  const host = assetMeta(r.asset_id).hostname || r.asset_id;
  const meta = h('div', { class: 'meta' },
    eAsset(host),
    exposureOf(r.asset_id) ? chip(exposureOf(r.asset_id) + '-exposed', exposureOf(r.asset_id) === 'internet' ? 'warn' : '') : null,
    r.cve_id ? eCode(r.cve_id) : null,
    consensusChip(r.consensus),
    r.kev ? chip('KEV', 'kev') : null,
    exploitChip(r),
    cweChip(r),
    r.epss ? chip('EPSS ' + pct(r.epss), '') : null,
    predictedChip(r),
    r.attack ? chip(r.attack, 'attack') : null,
    r.threat_intel ? chip('Live IOC', 'intel') : null,
    triageChip(r.triage_status));
  return h('div', { class: 'card', tabindex: '0', onclick: () => openFinding(r.id),
    onkeydown: e => { if (e.key === 'Enter') openFinding(r.id); } },
    h('div', { class: 'body' }, h('div', { class: 'row', style: 'margin-bottom:8px' }, selCheck(r), severity(r.severity)),
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
  if (f.exploit_available == null) f.exploit_available = !!(f.kev || f.source_tool === 'nuclei');
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
        f.kev ? chip('KEV', 'kev') : null, exploitChip(f), f.threat_intel ? chip('live IOC', 'intel') : null, triageChip(f.triage_status)),
      h('div', { style: 'font-size:17px;font-weight:600;line-height:1.35' }, f.title),
      h('div', { class: 'faint', style: 'font-size:12px;margin-top:5px' }, `${f.domain} · ${assetMeta(f.asset_id).hostname || f.asset_id} · finding #${f.id}`)),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));

  const b = h('div', { class: 'drawer-b' }); inner.append(b);

  // big score
  b.append(h('div', { class: 'hero' }, h('div', { class: 'big ' + c }, n0(f.risk_score)), h('div', { class: 'of' }, '/ 100 composite'),
    h('span', { style: 'flex:1' }), h('div', { style: 'text-align:right' },
      h('div', { class: 'mono', style: 'font-size:15px' }, n1(f.ml_risk_score)),
      h('div', { class: 'linklike', style: 'font-size:10px', title: 'open the model card', onclick: () => go('model') }, 'XGBoost re-ranker ›'))));

  // stat chips
  b.append(statChips(f, con));

  // conclusion-first summary with entity highlighting
  b.append(findingSummary(f, con));

  // two columns: score factors (with expandable full waterfall) | consensus
  const left = h('div', {},
    h('div', { class: 'sec-label', style: 'margin-bottom:4px' }, 'Score factors (SHAP)'),
    h('div', { class: 'faint', style: 'font-size:10.5px;margin-bottom:11px' },
      'Composite weights are the primary signal; the ML layer re-ranks. ',
      h('span', { class: 'linklike', onclick: () => go('model') }, 'Model card ›')));
  if (ml.shap) {
    left.append(scoreFactorBars(ml.shap));
    if (Array.isArray(ml.waterfall) && ml.waterfall.length)
      left.append(h('details', { class: 'expander' }, h('summary', {}, 'Show full waterfall'),
        waterfall(ml.waterfall),
        h('div', { class: 'faint', style: 'font-size:11px;margin-top:8px' }, 'Base → each factor → final ML score. Risk-raising right; risk-lowering left.')));
  } else if (Object.keys(comp).length) { left.append(factorBars(comp)); }
  const right = h('div', {}, h('div', { class: 'sec-label', style: 'margin-bottom:11px' }, 'Multi-tool consensus'), consensusPanel(con));
  b.append(h('div', { class: 'cols2' }, left, right));

  // ATT&CK + threat intel
  const ctx = h('div', { class: 'kv' });
  if (f.attack) ctx.append(h('div', { class: 'k' }, 'ATT&CK'), h('div', {}, eCode(f.attack), ' · ', attackName(f.attack)));
  if (f.cwe) ctx.append(h('div', { class: 'k' }, 'CWE'), h('div', {}, eCode(f.cwe), ' · ', cweName(f.cwe)));
  if (f.cvss_score) ctx.append(h('div', { class: 'k' }, 'CVSS'), h('div', { class: 'mono' }, n1(f.cvss_score)));
  else if (f.cvss_predicted) ctx.append(h('div', { class: 'k' }, 'CVSS'), h('div', {}, chip('predicted', 'warn'), ' severity estimated from description'));
  if (f.epss) ctx.append(h('div', { class: 'k' }, 'EPSS'), h('div', {}, h('span', { class: 'mono' }, pct(f.epss)), ' exploitation probability'));
  if (f.exploit_refs && f.exploit_refs.length) ctx.append(h('div', { class: 'k' }, 'Public exploit'),
    h('div', { class: 'wrap' }, f.exploit_refs.slice(0, 4).map(r => chip(`${r.source}: ${r.ref}`, 'mono'))));
  if (f.threat_intel) { const ti = f.threat_intel; ctx.append(h('div', { class: 'k' }, 'MISP IOC'), h('div', {}, eNet(ti.indicator || 'indicator'), ti.type ? ` · ${ti.type}` : '', ti.confidence ? ` · confidence ${ti.confidence}` : '')); }
  if (ctx.children.length) b.append(block('ATT&CK & threat intel', ctx));

  // threat attribution + knowledge graph (OpenCTI)
  if (f.threat_intel || f.attack) {
    const gbox = h('div', {}, loading('Building graph…'));
    b.append(block('Attribution & knowledge graph', gbox));
    API.intelGraph(f.id).then(g => { gbox.innerHTML = ''; gbox.append(intelGraphView(g)); })
      .catch(() => { gbox.innerHTML = ''; gbox.append(h('div', { class: 'faint', style: 'font-size:12px' }, 'No attribution available.')); });
  }

  // automation (SOAR playbooks)
  b.append(block('Automation (SOAR)', playbookRunner(f)));

  // counterfactuals
  if (Array.isArray(ml.counterfactuals) && ml.counterfactuals.length)
    b.append(block('What-if (counterfactuals)', counterfactuals(ml.counterfactuals)));

  // provenance
  b.append(block('Evidence & provenance', provenance(detail || f)));

  // containment
  const destructive = f.domain === 'network' || c === 'critical';
  const proposed = { id: 'act-' + f.id, action: destructive ? 'isolate_host' : 'apply_patch', target: assetMeta(f.asset_id).hostname || f.asset_id, status: 'proposed', approvals: [] };
  b.append(block('Response — containment', approvalGate(proposed, {})));

  // lifecycle / risk acceptance (DefectDojo pattern)
  b.append(block('Lifecycle & risk acceptance', lifecyclePanel(f)));

  // feedback
  b.append(block('Analyst feedback', feedbackForm(f.id)));
}
function lifecyclePanel(f) {
  const cur = f.triage_status || 'open';
  const wrap = h('div', { class: 'stack', style: 'gap:11px' });
  const state = h('div', { class: 'row' }, h('span', { class: 'faint', style: 'font-size:12px' }, 'Current: '),
    triageChip(cur) || chip('open', ''));
  const seg = h('div', { class: 'seg' });
  const opts = [['investigating', 'Investigating'], ['mitigated', 'Mitigated'], ['resolved', 'Resolved'], ['false_positive', 'False positive']];
  opts.forEach(([v, l]) => seg.append(h('button', { class: cur === v ? 'sel' : '', onclick: () => setStatus(v) }, l)));
  // risk acceptance with expiry
  const until = h('input', { class: 'txt', type: 'date', style: 'max-width:170px' });
  const raRow = h('div', { class: 'row', style: 'gap:8px' },
    h('span', { class: 'faint', style: 'font-size:12px;flex:1' }, 'Accept risk until'),
    until, h('button', { class: 'btn sm', onclick: () => { if (!until.value) { toast('Pick an expiry date', false); return; } setStatus('risk_accepted', until.value); } }, 'Accept risk'));
  wrap.append(state, seg, raRow,
    h('div', { class: 'faint', style: 'font-size:11px' }, 'Triaged-away findings (false positive / risk accepted / mitigated / resolved) leave the active queue.'));
  async function setStatus(status, rau) {
    await API.triage(f.id, { status, risk_accepted_until: rau || null, note: null });
    f.triage_status = status;
    toast(`Finding marked ${TRIAGE_LABEL[status] || status}`, true);
    state.innerHTML = ''; state.append(h('span', { class: 'faint', style: 'font-size:12px' }, 'Current: '), triageChip(status) || chip('open', ''));
    $$('button', seg).forEach(btn => btn.classList.toggle('sel', btn.textContent.toLowerCase().replace(' ', '_') === status));
    if (STATE.ranking) { const row = STATE.ranking.find(x => x.id === f.id); if (row) row.triage_status = status; if (window._renderCards) window._renderCards(); }
  }
  return wrap;
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
  const [summary, results, chain, evidence] = await Promise.all([API.compSummary(), API.compResults(), API.chain(), API.compEvidence()]);
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
    compTable(results), evidencePanel(evidence)));
}
function evidencePanel(evidence) {
  return h('div', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Evidence records'),
    h('span', { class: 'sub' }, '· hash-chained, tamper-evident'), h('span', { class: 'spring', style: 'flex:1' }),
    csvBtn('CSV', 'vyrex-compliance-evidence.csv', () => [['id', 'rule', 'asset', 'status', 'recorded', 'hash'],
      ...(evidence || []).map(e => [e.id, e.rule_id, e.asset_id, e.status, e.recorded_at, e.hash])])),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['#', 'Control', 'Host', 'Status', 'Recorded', 'Hash (chain)'].map(t => h('th', {}, t)))),
      h('tbody', {}, (evidence || []).length ? evidence.map(e => h('tr', {},
        h('td', { class: 'mono' }, String(e.id)),
        h('td', { class: 'mono' }, e.rule_id),
        h('td', { class: 'mono' }, e.asset_id),
        h('td', {}, statusChip(e.status)),
        h('td', { class: 'mono', style: 'font-size:11px' }, ago(e.recorded_at)),
        h('td', {}, h('span', { class: 'faint mono', style: 'font-size:10px' }, (e.hash || '').slice(0, 18) + '…'))))
        : [h('tr', {}, h('td', { colspan: '6', class: 'faint', style: 'padding:16px;text-align:center' }, 'No evidence records yet.'))]))));
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
  return h('div', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', {}, 'CIS controls'), h('span', { class: 'sub' }, `· ${(results || []).length} evaluated`),
    h('span', { class: 'spring', style: 'flex:1' }),
    pdfBtn('PDF'),
    csvBtn('CSV', 'soc-compliance.csv', () => [['control', 'title', 'status', 'host'],
      ...(results || []).map(r => [r.rule_id, r.title || '', r.status, r.asset_id])])),
    h('div', { style: 'overflow-x:auto' }, tbl));
}
const statusChip = (s) => s === 'pass' ? chip('pass', 'ok') : s === 'fail' ? chip('fail', 'kev') : s === 'partial' ? chip('partial', 'warn') : chip(s || 'n/a');

/* ---- 4.4 Incidents --------------------------------------------------- */
const KCOLS = [
  ['New', ['open', 'new']],
  ['In progress', ['in_progress', 'triaged', 'investigating', 'acknowledged']],
  ['Contained', ['contained']],
  ['Remediated', ['resolved', 'closed', 'remediated']],
];
async function viewIncidents(root) {
  root.append(loading('Loading cases…'));
  const [incidents, actions, audit] = await Promise.all([API.incidents(), API.actions(), API.auditVerify()]);
  root.innerHTML = '';
  const colOf = (st) => { st = (st || '').toLowerCase(); const i = KCOLS.findIndex(c => c[1].includes(st)); return i < 0 ? 0 : i; };
  root.append(h('div', { class: 'panel-h', style: 'border:none;padding:0 2px 14px' },
    h('h2', {}, 'Cases'), h('span', { class: 'sub' }, `· ${incidents.length} open · audit chain ${audit.ok ? 'verified ✓' : 'needs check'}`),
    h('span', { class: 'spring', style: 'flex:1' }),
    h('button', { class: 'btn sm primary', title: 'group correlated high-risk findings into incidents',
      onclick: async (e) => { const btn = e.target.closest('button'); btn.disabled = true; btn.textContent = 'Correlating…';
        const r = await API.correlate({ min_score: 60, window_hours: 24 });
        toast(`${r.correlated_groups || 0} correlated case(s) created`, true); go('cases'); } }, 'Correlate findings')));
  const board = h('div', { class: 'kanban fade' });
  KCOLS.forEach((col, ci) => {
    const items = incidents.filter(i => colOf(i.status) === ci);
    const kc = h('div', { class: 'kcol' }, h('h3', {}, col[0], h('span', { class: 'ct' }, String(items.length))));
    if (items.length) items.forEach(i => kc.append(kanbanCard(i, actions)));
    else kc.append(h('div', { class: 'faint', style: 'font-size:11.5px;padding:4px 2px' }, 'None'));
    board.append(kc);
  });
  root.append(board);
}
function kanbanCard(i, actions) {
  return h('div', { class: 'kcard', tabindex: '0', onclick: () => openIncident(i, actions),
    onkeydown: e => { if (e.key === 'Enter') openIncident(i, actions); } },
    h('div', { class: 'row', style: 'justify-content:space-between' }, severity(i.severity),
      h('div', { class: 'row', style: 'gap:6px' }, i.auto_created ? chip('auto-correlated', 'consensus') : null, h('span', { class: 'faint mono', style: 'font-size:10.5px' }, '#' + i.id))),
    h('div', { class: 't' }, i.title),
    h('div', { class: 'row', style: 'gap:7px' }, i.sla_breached ? chip('SLA breached', 'kev') : chip('On track', 'ok'),
      h('span', { class: 'faint', style: 'font-size:11px' }, `${i.finding_count ?? 0} findings`)));
}
function openIncident(inc, actions) {
  const inner = $('#drawer-inner'); $('#scrim').classList.add('show'); $('#drawer').classList.add('show');
  const acts = (actions || []).filter(a => a.incident_id === inc.id);
  const evidence = (STATE.ranking || []).filter(r => r.asset_id === inc.asset_id);
  inner.innerHTML = '';
  inner.append(h('div', { class: 'drawer-h' },
    h('div', {}, h('div', { class: 'wrap', style: 'margin-bottom:9px' }, severity(inc.severity), chip(inc.status, 'warn'),
      inc.asset_id ? eAsset(assetMeta(inc.asset_id).hostname || inc.asset_id) : null),
      h('div', { style: 'font-size:17px;font-weight:600' }, inc.title),
      h('div', { class: 'faint', style: 'font-size:12px;margin-top:5px' }, `case #${inc.id} · owner ${inc.assignee || inc.created_by || '—'} · opened ${ago(inc.created_at)}`)),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));
  const b = h('div', { class: 'drawer-b' }); inner.append(b);

  b.append(block('SLA', h('div', { class: 'row' }, inc.sla_breached ? chip('breached', 'kev') : chip('on track', 'ok'),
    h('span', { class: 'faint mono', style: 'font-size:11px' }, 'due ' + (inc.sla_due || '—')))));

  // attack chain (kill-chain order over the linked findings' ATT&CK techniques)
  const chain = killChain(evidence);
  if (chain) b.append(block('Attack chain (MITRE ATT&CK)', chain));

  // linked evidence
  b.append(block(`Linked evidence (${evidence.length})`, evidence.length
    ? h('div', {}, evidence.map(r => h('div', { class: 'evrow', tabindex: '0', onclick: () => openFinding(r.id), onkeydown: e => { if (e.key === 'Enter') openFinding(r.id); } },
        h('span', { class: 'sc ' + band(r.risk_score) }, n0(r.risk_score)),
        h('span', { style: 'flex:1;min-width:0' }, r.title),
        r.cve_id ? eCode(r.cve_id) : null, r.attack ? chip(r.attack, 'attack') : null)))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No findings linked to this case yet.')));

  b.append(block('Response & audit timeline (hash-chained)', acts.length ? h('div', {}, acts.map(a =>
    h('div', { class: 'cf' }, h('span', {}, h('span', { class: 'mono' }, a.action), ` → ${a.target || ''}`),
      h('span', { class: 'chip ' + (a.status && (a.status.includes('contain') || a.status.includes('complet')) ? 'ok' : 'warn') }, a.status || 'proposed'))))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No actions recorded for this case.')));

  // case tasks + observables (TheHive)
  const tasksBox = h('div', {}, loading('Loading tasks…')); b.append(block('Tasks', tasksBox));
  const obsBox = h('div', {}, loading('Loading observables…')); b.append(block('Observables', obsBox));
  loadCasework(inc.id, tasksBox, obsBox);
}
const TASK_NEXT = { todo: 'in_progress', in_progress: 'done', done: 'todo' };
async function loadCasework(incId, tasksBox, obsBox) {
  renderTasks(incId, tasksBox, await API.tasks(incId).catch(() => []));
  renderObs(incId, obsBox, await API.observables(incId).catch(() => []));
}
function renderTasks(incId, box, tasks) {
  box.innerHTML = '';
  (tasks || []).forEach(t => box.append(h('div', { class: 'task' },
    h('span', { class: 'tk ' + t.status, title: 'cycle status', onclick: async () => {
      const ns = TASK_NEXT[t.status] || 'todo'; await API.patchTask(t.id, { status: ns }); t.status = ns; renderTasks(incId, box, tasks); } },
      t.status === 'done' ? '✓' : t.status === 'in_progress' ? '◐' : ''),
    h('span', { class: 'tl' + (t.status === 'done' ? ' done' : '') }, t.title),
    t.assignee ? chip(t.assignee, '') : h('span', { class: 'faint', style: 'font-size:10.5px' }, 'unassigned'))));
  const inp = h('input', { class: 'txt', placeholder: 'Add a task…', onkeydown: async e => {
    if (e.key === 'Enter' && inp.value.trim()) { const t = await API.addTask(incId, { title: inp.value.trim() }); tasks.push({ id: t.id, title: inp.value.trim(), status: 'todo' }); inp.value = ''; renderTasks(incId, box, tasks); } } });
  box.append(h('div', { class: 'row', style: 'margin-top:8px' }, inp));
}
function renderObs(incId, box, obs) {
  box.innerHTML = '';
  const TYPECLS = { ip: 'net', domain: 'net', url: 'net', host: 'asset', cve: 'code', hash: 'code' };
  if (obs && obs.length) box.append(h('div', { class: 'wrap' }, obs.map(o =>
    h('span', { class: 'obs' }, chip(o.type, ''), entityChip(o.value, TYPECLS[o.type] || 'code'),
      o.is_ioc ? chip('IOC', 'kev') : null, o.tlp ? chip('TLP:' + o.tlp, 'mono') : null))));
  else box.append(h('div', { class: 'faint', style: 'font-size:12px' }, 'No observables yet.'));
  box.append(h('div', { class: 'row', style: 'margin-top:10px;gap:8px' },
    h('button', { class: 'btn sm', onclick: async () => { await API.autoObservables(incId); toast('Observables seeded from linked findings', true); renderObs(incId, box, await API.observables(incId).catch(() => obs)); } }, 'Auto-seed from findings')));
}

/* Kill-chain ordering of ATT&CK techniques present in a finding set. */
const KILLCHAIN = [
  ['Initial access', ['T1190', 'T1133', 'T1566', 'T1078']],
  ['Execution', ['T1059', 'T1203', 'T1204']],
  ['Privilege escalation', ['T1068', 'T1548']],
  ['Defense evasion', ['T1562', 'T1070']],
  ['Command & control', ['T1071', 'T1071.001', 'T1090', 'T1571']],
  ['Exfiltration', ['T1041', 'T1048']],
  ['Impact', ['T1486']],
];
function killChain(findings) {
  const present = new Set((findings || []).map(f => f.attack).filter(Boolean));
  if (!present.size) return null;
  const phases = KILLCHAIN.map(([name, techs]) => {
    const hit = techs.filter(t => present.has(t) || present.has(String(t).split('.')[0]));
    return { name, hit };
  }).filter(p => p.hit.length);
  if (!phases.length) return null;
  const row = h('div', { class: 'killchain' });
  phases.forEach((p, i) => {
    row.append(h('div', { class: 'kphase' }, h('div', { class: 'pn' }, p.name),
      h('div', { class: 'pt' }, p.hit.map(t => chip(t, 'attack')))));
    if (i < phases.length - 1) row.append(h('div', { class: 'karr', html: ic('chevron') }));
  });
  return row;
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

/* ---- 4.6 Overview (executive landing — the default route) ------------ */
async function viewOverview(root) {
  root.append(loading('Loading security posture…'));
  const [ranking, stats, comp, incidents, chain, recent] = await Promise.all([
    API.ranking(), API.stats(), API.compSummary(), API.incidents(), API.chain(), API.recent(30)]);
  STATE.ranking = ranking;
  const assets = await API.assets(); STATE.assets = {}; (assets || []).forEach(a => STATE.assets[a.host_id] = a);
  root.innerHTML = '';

  const bands = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  ranking.forEach(r => bands[band(r.risk_score)]++);
  const kev = stats.kev_findings ?? ranking.filter(r => r.kev).length;
  const openInc = incidents.filter(i => !/resolved|closed|remediated/i.test(i.status || '')).length;
  const breaches = incidents.filter(i => i.sla_breached).length;
  const by = {}; (comp.by_status || []).forEach(s => by[s.status] = s.count);
  const graded = (by.pass || 0) + (by.fail || 0) + (by.partial || 0) || 1;
  const cis = Math.round(((by.pass || 0) / graded) * 100);
  const techniques = [...new Set(ranking.map(r => r.attack).filter(Boolean))];

  root.append(h('div', { class: 'kpis fade' },
    kpiCard('Critical exposure', String(bands.critical), `${bands.high} high · ${ranking.length} ranked`, bands.critical ? 'crit' : 'ok'),
    kpiCard('Known-exploited (KEV)', String(kev), 'CISA KEV-listed findings', kev ? 'warn' : 'ok'),
    kpiCard('Active incidents', String(openInc), breaches ? `${breaches} SLA breached` : 'all within SLA', breaches ? 'crit' : 'ok'),
    kpiCard('CIS posture', cis + '%', `${by.fail || 0} controls failing`, cis < 60 ? 'warn' : 'ok')));

  root.append(h('div', { class: 'panel pad fade' },
    h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Risk distribution'),
    riskBandBar(bands, ranking.length)));

  const topRisks = h('div', { class: 'panel' },
    h('div', { class: 'panel-h' }, h('h2', {}, 'Top risks now'), h('span', { class: 'sub' }, '· click to investigate'),
      h('span', { class: 'spring', style: 'flex:1' }),
      pdfBtn('PDF'),
      csvBtn('CSV', 'soc-top-risks.csv', () => [['rank', 'score', 'severity', 'asset', 'cve', 'title', 'attack'],
        ...ranking.map((r, i) => [i + 1, r.risk_score, r.severity, assetMeta(r.asset_id).hostname || r.asset_id, r.cve_id || '', r.title, r.attack || ''])])),
    h('div', {}, ranking.slice(0, 6).map(r => overviewRiskRow(r))));
  const side = h('div', { class: 'stack' },
    h('div', { class: 'panel pad' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'ATT&CK coverage'),
      h('div', { class: 'wrap' }, techniques.length ? techniques.map(t => chip(`${t} · ${attackName(t)}`, 'attack'))
        : h('span', { class: 'faint', style: 'font-size:12px' }, 'No techniques mapped yet.'))),
    h('div', { class: 'panel pad' }, h('div', { class: 'sec-label', style: 'margin-bottom:10px' }, 'Evidence integrity'),
      h('div', { class: 'row' }, chip(chain.ok ? 'chain intact ✓' : 'chain check', chain.ok ? 'ok' : 'kev'),
        h('span', { class: 'faint mono', style: 'font-size:10.5px' }, `${chain.length ?? 0} records`))));
  root.append(h('div', { class: 'cols2 fade', style: 'align-items:start' }, topRisks, side));

  const feed = h('div', {});
  root.append(h('div', { class: 'panel pad fade' },
    h('div', { class: 'row', style: 'margin-bottom:12px' }, h('div', { class: 'sec-label' }, 'Live detections'),
      h('span', { class: 'spring', style: 'flex:1' }), h('span', { class: 'live-dot' }),
      h('span', { class: 'faint', style: 'font-size:11px' }, 'near-real-time · polling')),
    feed));
  const seen = new Set();
  const paint = (items) => { feed.innerHTML = ''; (items || []).slice(0, 12).forEach(d => feed.append(detectionRow(d, seen))); };
  paint(recent);
  const t = setInterval(async () => { try { paint(await API.recent(30)); } catch {} }, 6000);
  window._viewCleanup = () => clearInterval(t);
}
function kpiCard(label, value, sub, tone) {
  return h('div', { class: 'kpi ' + (tone || '') },
    h('div', { class: 'lb' }, label), h('div', { class: 'vv' }, value), h('div', { class: 'sb' }, sub));
}
function riskBandBar(bands, total) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const t = total || order.reduce((a, k) => a + bands[k], 0) || 1;
  const bar = h('div', { class: 'rbar' }, order.filter(k => bands[k]).map(k =>
    h('div', { class: 'seg ' + k, style: `width:${(bands[k] / t) * 100}%`, title: `${SEVLABEL[k]}: ${bands[k]}` })));
  const legend = h('div', { class: 'rlegend' }, order.map(k =>
    h('span', {}, h('i', { class: 'ldot ' + k }), `${SEVLABEL[k]} `, h('b', { class: 'mono' }, String(bands[k])))));
  return h('div', {}, bar, legend);
}
function overviewRiskRow(r) {
  const c = band(r.risk_score);
  return h('div', { class: 'orow', tabindex: '0', onclick: () => openFinding(r.id), onkeydown: e => { if (e.key === 'Enter') openFinding(r.id); } },
    h('div', { class: 'sc ' + c }, n0(r.risk_score)),
    h('div', { style: 'min-width:0;flex:1' }, h('div', { class: 'tt' }, r.title),
      h('div', { class: 'wrap', style: 'margin-top:5px' }, severity(r.severity), eAsset(assetMeta(r.asset_id).hostname || r.asset_id),
        r.cve_id ? eCode(r.cve_id) : null, r.kev ? chip('KEV', 'kev') : null, exploitChip(r), consensusChip(r.consensus), triageChip(r.triage_status))));
}
function detectionRow(d, seen) {
  const isNew = seen && !seen.has(d.id); if (seen) seen.add(d.id);
  const c = band(d.risk_score);
  return h('div', { class: 'drow' + (isNew ? ' new' : ''), tabindex: '0', onclick: () => openFinding(d.id), onkeydown: e => { if (e.key === 'Enter') openFinding(d.id); } },
    h('span', { class: 'tm mono' }, ago(d.observed_at)),
    h('span', { class: 'tl mono' }, d.source_tool || 'agent'),
    severity(d.severity),
    h('span', { class: 'tx' }, d.title),
    h('span', { class: 'sc ' + c }, n0(d.risk_score)));
}

/* ---- 4.7 Hunt (full-text search over raw telemetry) ------------------ */
async function viewHunt(root) {
  root.innerHTML = '';
  const KINDS = ['', 'ids_alert', 'network_flow', 'fim_event', 'runtime_alert', 'traffic_metadata', 'osquery_result', 'scan_finding'];
  let kind = '', minutes = 1440;
  const input = h('input', { class: 'txt', placeholder: 'Lucene query — e.g. payload.dest_port:4444 or "Cobalt Strike"  ·  blank = all', onkeydown: e => { if (e.key === 'Enter') run(); } });
  const kindSel = h('select', { onchange: e => { kind = e.target.value; run(); } }, KINDS.map(k => h('option', { value: k }, k || 'all kinds')));
  const timeSel = h('select', { onchange: e => { minutes = +e.target.value; run(); } },
    [['60', 'last hour'], ['1440', 'last 24h'], ['10080', 'last 7d'], ['43200', 'last 30d']].map(([v, l]) => h('option', { value: v, selected: v === '1440' ? 'selected' : null }, l)));
  const results = h('div', { class: 'stack', style: 'gap:8px' });
  root.append(h('div', { class: 'panel pad fade' },
    h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Search raw telemetry (OpenSearch)'),
    h('div', { class: 'huntbar' }, input, kindSel, timeSel, h('button', { class: 'btn primary', onclick: () => run() }, 'Search'))),
    h('div', { class: 'panel', style: 'margin-top:14px' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Results'),
      h('span', { class: 'sub', id: 'huntcount' }, '')), h('div', { style: 'padding:8px 14px 14px' }, results)));
  run();
  async function run() {
    results.innerHTML = ''; results.append(loading('Searching…'));
    const r = await API.logs(input.value.trim(), kind, minutes);
    results.innerHTML = '';
    const cnt = $('#huntcount'); if (cnt) cnt.textContent = r.available === false ? '· OpenSearch unavailable (showing none)' : `· ${r.total} event(s)`;
    if (!r.hits || !r.hits.length) { results.append(h('div', { class: 'empty' }, 'No events match this query.')); return; }
    r.hits.forEach(hit => results.append(logRow(hit)));
  }
}
function logRow(hit) {
  const box = h('div', { class: 'prov' });
  const body = h('div', { class: 'prov-b' }, h('pre', {}, JSON.stringify(hit.payload || {}, null, 2)));
  const head = h('div', { class: 'prov-h', onclick: () => box.classList.toggle('open') },
    h('span', { html: ic('chevron'), style: 'width:13px;height:13px;color:var(--faint)' }),
    h('span', { class: 'mono faint', style: 'font-size:10.5px;min-width:64px' }, ago(hit.ingested_at)),
    chip(hit.kind || 'event', 'tool'),
    hit.hostname ? eAsset(hit.hostname) : null,
    h('span', { class: 'logline' }, logLine(hit)));
  box.append(head, body); return box;
}
function logLine(hit) {
  const p = hit.payload || {};
  if (hit.kind === 'ids_alert') return `${p.signature || 'alert'} — ${p.src_ip || ''}→${p.dest_ip || ''}:${p.dest_port || ''}`;
  if (hit.kind === 'network_flow') return `${p.direction || ''} ${p.local_ip || ''}:${p.local_port || ''} → ${p.remote_ip || ''}:${p.remote_port || ''}`;
  if (hit.kind === 'fim_event') return `${p.change || ''} ${p.path || ''}`;
  if (hit.kind === 'runtime_alert') return `${p.rule || ''} ${p.proc || ''}`;
  if (hit.kind === 'traffic_metadata') return `${p.service || ''} ${p['ssl.server_name'] || p['id.resp_h'] || ''}`;
  if (hit.kind === 'scan_finding') return `${p.check || p.policy || ''} — ${p.result || ''}`;
  return JSON.stringify(p).slice(0, 140);
}

/* ---- 4.8 Trust Center (audit integrity + air-gap assurance) ---------- */
async function viewTrust(root) {
  root.append(loading('Loading trust & audit state…'));
  const [resp, comp, events, actions, access] = await Promise.all([API.auditVerify(), API.chain(), API.auditEvents(40), API.actions(), API.accessAudit(50)]);
  root.innerHTML = '';

  root.append(h('div', { class: 'kpis fade' },
    integrityCard('Response audit chain', resp),
    integrityCard('Compliance evidence chain', comp),
    kpiCard('Air-gap egress', 'sealed', 'only feed-sync may reach the internet', 'ok')));

  const EGRESS = [
    ['feed-sync', 'NVD · EPSS · KEV mirror', 'allowed (sole egress)', true],
    ['api', 'analyst & integration traffic', 'denied', false],
    ['workers', 'enrichment & fan-out', 'denied', false],
    ['ingest-edge', 'agent mTLS ingest', 'denied', false],
    ['console', 'analyst UI', 'denied', false],
    ['opensearch · postgres · nats', 'data plane', 'denied', false],
  ];
  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' },
    h('div', { class: 'panel-h' }, h('h2', {}, 'Air-gap egress matrix'), h('span', { class: 'sub' }, '· default-deny; enforced by K3s NetworkPolicy / verify-egress')),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Service', 'Role', 'Outbound', ''].map(t => h('th', {}, t)))),
      h('tbody', {}, EGRESS.map(([s, role, state, eg]) => h('tr', {},
        h('td', { class: 'mono' }, s), h('td', {}, role), h('td', {}, chip(state, eg ? 'warn' : 'ok')),
        h('td', {}, eg ? chip('egress', 'warn') : chip('contained', 'ok')))))))));

  root.append(h('div', { class: 'panel pad fade', style: 'margin-top:14px' },
    h('div', { class: 'sec-label', style: 'margin-bottom:14px' }, 'Response-action audit timeline (hash-chained)'),
    events.length ? h('div', { class: 'timeline' }, events.map(e => auditEventRow(e, actions)))
      : h('div', { class: 'empty' }, 'No response actions recorded.')));

  // access audit — who viewed/changed what
  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' },
    h('div', { class: 'panel-h' }, h('h2', {}, 'Access audit'), h('span', { class: 'sub' }, '· who viewed or changed what'),
      h('span', { class: 'spring', style: 'flex:1' }),
      csvBtn('Export', 'soc-access-audit.csv', () => [['time', 'actor', 'role', 'tenant', 'method', 'path', 'status'],
        ...(access || []).map(a => [a.created_at, a.actor, a.role || '', a.tenant || '', a.method, a.path, a.status])])),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Time', 'Actor', 'Role', 'Method', 'Path', 'Status'].map(t => h('th', {}, t)))),
      h('tbody', {}, (access || []).length ? access.map(a => h('tr', {},
        h('td', { class: 'mono', style: 'font-size:11px' }, ago(a.created_at)),
        h('td', {}, a.actor === 'anonymous' ? h('span', { class: 'faint' }, 'anonymous') : eAsset(a.actor)),
        h('td', {}, a.role ? chip(a.role, '') : '—'),
        h('td', { class: 'mono' }, a.method),
        h('td', { class: 'mono', style: 'font-size:11px' }, a.path),
        h('td', {}, chip(String(a.status), String(a.status).startsWith('2') ? 'ok' : 'warn'))))
        : [h('tr', {}, h('td', { colspan: '6', class: 'faint', style: 'padding:20px;text-align:center' }, 'No access recorded yet.'))])))));
}
function integrityCard(label, v) {
  const ok = v && v.ok;
  return h('div', { class: 'kpi ' + (ok ? 'ok' : 'crit') },
    h('div', { class: 'lb' }, label),
    h('div', { class: 'vv', style: 'font-size:20px' }, ok ? 'intact ✓' : 'check ✗'),
    h('div', { class: 'sb mono' }, `${v && v.length != null ? v.length : '—'} records · head ${((v && v.head_hash) || '—').slice(0, 12)}`));
}
function auditEventRow(e, actions) {
  const act = (actions || []).find(a => a.id === e.action_id);
  const rec = e.record || {};
  const detail = rec.target ? `${rec.action_type || ''} → ${rec.target}`
    : (rec.output || (rec.approvals != null ? `${rec.approvals} approval(s)` : (rec.pubkey || '')));
  const tone = /(completed|signed|contained)/.test(e.event) ? 'ok' : /reject|fail/.test(e.event) ? 'bad' : '';
  return h('div', { class: 'tl-row' },
    h('span', { class: 'tl-dot ' + tone }),
    h('div', { style: 'flex:1;min-width:0' },
      h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'tl-ev' }, e.event), chip('action #' + e.action_id, 'mono'),
        act ? h('span', { class: 'faint', style: 'font-size:11px' }, act.target || '') : null),
      h('div', { class: 'faint', style: 'font-size:11.5px;margin-top:2px' }, detail)),
    h('div', { style: 'text-align:right' }, h('div', { class: 'faint mono', style: 'font-size:10.5px' }, e.actor || ''),
      h('div', { class: 'faint mono', style: 'font-size:10px' }, ago(e.created_at))));
}

/* ---- 4.9 Model card (risk-model transparency) ------------------------ */
async function viewModel(root) {
  root.append(loading('Loading model card…'));
  const m = await API.modelCard();
  root.innerHTML = '';

  root.append(h('div', { class: 'panel pad fade' },
    h('div', { class: 'row', style: 'gap:10px;margin-bottom:6px' }, h('h2', { style: 'font-size:16px;font-weight:560' }, 'Risk model'),
      h('span', { class: 'spring', style: 'flex:1' }), chip(m.honest_status || 're-ranker', 'consensus')),
    h('div', { class: 'kv', style: 'margin-top:10px' },
      h('div', { class: 'k' }, 'Version'), h('div', { class: 'mono' }, m.model_version || '—'),
      h('div', { class: 'k' }, 'Algorithm'), h('div', {}, m.algorithm || '—'),
      h('div', { class: 'k' }, 'Explainer'), h('div', {}, m.explainer || '—'),
      h('div', { class: 'k' }, 'Primary signal'), h('div', {}, m.primary_signal || '—'))));

  const w = m.composite_weights || {};
  const maxW = Math.max(0.001, ...Object.values(w).map(Number));
  root.append(h('div', { class: 'panel pad fade', style: 'margin-top:14px' },
    h('div', { class: 'sec-label', style: 'margin-bottom:4px' }, 'Composite weights — the primary, defensible signal'),
    h('div', { class: 'faint', style: 'font-size:11px;margin-bottom:12px' }, 'Hand-set, sum to 1.0. The ML layer re-ranks over these same factors.'),
    h('div', { class: 'sfbars' }, Object.entries(w).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
      h('div', { class: 'sfbar' }, h('div', { class: 'k' }, k),
        h('div', { class: 'tr' }, h('i', { class: 'pos', style: `left:0;width:${(v / maxW) * 100}%;background:var(--accent)` })),
        h('div', { class: 'c' }, (+v).toFixed(2)))))));

  const sc = m.scope || {};
  root.append(h('div', { class: 'kpis fade', style: 'margin-top:14px' },
    kpiCard('Findings scored (ML)', String(sc.findings_scored_by_ml ?? '—'), 'by the XGBoost re-ranker', ''),
    kpiCard('Findings scored (composite)', String(sc.findings_scored_by_composite ?? '—'), 'by the weighted formula', ''),
    kpiCard('Analyst labels', String(sc.analyst_labels_captured ?? 0), 'feedback weighted 5× in retrain', (sc.analyst_labels_captured ? 'ok' : 'warn'))));

  const lims = m.limitations || [];
  root.append(h('div', { class: 'panel pad fade', style: 'margin-top:14px' },
    h('div', { class: 'sec-label', style: 'margin-bottom:10px' }, 'Training provenance & known limitations'),
    h('div', { class: 'kv', style: 'margin-bottom:12px' },
      h('div', { class: 'k' }, 'Label source'), h('div', {}, (m.training || {}).label_source || '—'),
      h('div', { class: 'k' }, 'Bootstrap'), h('div', {}, (m.training || {}).bootstrap || '—'),
      h('div', { class: 'k' }, 'Retrain'), h('div', {}, (m.training || {}).retrain_cadence || '—')),
    h('div', { class: 'callout' }, h('strong', {}, 'Stated honestly: '),
      lims.length ? h('ul', { class: 'lims' }, lims.map(l => h('li', {}, l))) : 'No limitations recorded.')));
}

/* ---- 4.10 Assets (inventory + host detail) --------------------------- */
async function viewAssets(root) {
  root.append(loading('Loading asset inventory…'));
  const [assets, ranking] = await Promise.all([API.assets(), API.ranking()]);
  STATE.ranking = ranking; STATE.assets = {}; (assets || []).forEach(a => STATE.assets[a.host_id] = a);
  root.innerHTML = '';
  const cnt = {}, top = {};
  ranking.forEach(r => { cnt[r.asset_id] = (cnt[r.asset_id] || 0) + 1; top[r.asset_id] = Math.max(top[r.asset_id] || 0, +r.risk_score); });

  const tbl = h('table', { class: 'tbl' },
    h('thead', {}, h('tr', {}, ['Host', 'OS', 'IP', 'Exposure', 'Criticality', 'Findings', 'Top risk'].map(t => h('th', {}, t)))),
    h('tbody', {}, (assets || []).map(a => h('tr', { tabindex: '0', onclick: () => openAsset(a.host_id), onkeydown: e => { if (e.key === 'Enter') openAsset(a.host_id); } },
      h('td', {}, eAsset(a.hostname || a.host_id)),
      h('td', {}, a.os || '—'),
      h('td', { class: 'mono' }, a.ip || '—'),
      h('td', {}, a.exposure ? chip(a.exposure, a.exposure === 'internet' ? 'warn' : '') : '—'),
      h('td', {}, critBar(a.criticality)),
      h('td', { class: 'mono' }, String(cnt[a.host_id] || 0)),
      h('td', {}, top[a.host_id] ? h('span', { class: 'sc ' + band(top[a.host_id]), style: 'font-family:var(--mono)' }, n0(top[a.host_id])) : '—')))));
  root.append(h('div', { class: 'panel fade' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Asset inventory'),
    h('span', { class: 'sub' }, `· ${(assets || []).length} hosts`), h('span', { class: 'spring', style: 'flex:1' }),
    csvBtn('Export', 'soc-assets.csv', () => [['host', 'os', 'ip', 'exposure', 'criticality', 'findings'],
      ...(assets || []).map(a => [a.hostname || a.host_id, a.os || '', a.ip || '', a.exposure || '', a.criticality, cnt[a.host_id] || 0])])),
    h('div', { style: 'overflow-x:auto' }, tbl)));
}
function critBar(v) {
  const n = v == null ? 0.5 : +v;
  return h('span', { class: 'crit' }, h('span', { class: 'cbar' }, h('i', { style: `width:${n * 100}%` })), h('span', { class: 'mono faint', style: 'font-size:10.5px' }, n.toFixed(2)));
}
async function openAsset(id) {
  const inner = $('#drawer-inner'); $('#scrim').classList.add('show'); $('#drawer').classList.add('show');
  inner.innerHTML = ''; inner.append(loading('Loading host…'));
  const [data, flows] = await Promise.all([API.asset(id), API.logs(`host.host_id:${id} OR host.hostname:${id}`, 'network_flow', 10080)]);
  const a = (data && data.asset) || { host_id: id, hostname: id }; const findings = (data && data.findings) || []; const comp = (data && data.compliance) || [];
  inner.innerHTML = '';
  inner.append(h('div', { class: 'drawer-h' },
    h('div', {}, h('div', { style: 'font-size:17px;font-weight:600' }, a.hostname || a.host_id),
      h('div', { class: 'faint', style: 'font-size:12px;margin-top:5px' }, `${a.os || '—'} · ${a.ip || '—'} · ${a.exposure || 'internal'}-exposed`)),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));
  const b = h('div', { class: 'drawer-b' }); inner.append(b);

  // editable criticality (drives the composite score)
  let crit = a.criticality == null ? 0.5 : +a.criticality;
  const val = h('span', { class: 'mono', style: 'min-width:34px;text-align:right' }, crit.toFixed(2));
  const slider = h('input', { type: 'range', min: '0', max: '1', step: '0.05', value: String(crit), oninput: e => { crit = +e.target.value; val.textContent = crit.toFixed(2); } });
  const save = h('button', { class: 'btn primary sm', onclick: async () => { save.disabled = true; save.textContent = 'Saving…'; await API.patchAsset(id, crit); toast('Criticality updated — applied on the next scoring run', true); save.disabled = false; save.textContent = 'Save'; } }, 'Save');
  b.append(block('Business criticality', h('div', { class: 'stack', style: 'gap:8px' },
    h('div', { class: 'faint', style: 'font-size:11px' }, 'Feeds the composite risk score (4% weight). Tune to your business.'),
    h('div', { class: 'row' }, slider, val, h('span', { class: 'spring', style: 'flex:1' }), save))));

  b.append(block(`Findings (${findings.length})`, findings.length
    ? h('div', {}, findings.map(r => h('div', { class: 'evrow', tabindex: '0', onclick: () => openFinding(r.id), onkeydown: e => { if (e.key === 'Enter') openFinding(r.id); } },
        h('span', { class: 'sc ' + band(r.risk_score) }, n0(r.risk_score)),
        h('span', { style: 'flex:1;min-width:0' }, r.title),
        r.cve_id ? eCode(r.cve_id) : null, r.kev ? chip('KEV', 'kev') : null)))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No findings on this host.')));

  const flist = (flows && flows.hits) || [];
  b.append(block(`Network flows (${flist.length})`, flist.length
    ? h('div', {}, flist.map(hit => h('div', { class: 'cf' }, h('span', { class: 'mono', style: 'font-size:11.5px' }, logLine(hit)),
        h('span', { class: 'faint mono', style: 'font-size:10.5px' }, ago(hit.ingested_at)))))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No recent flows recorded.')));

  b.append(block(`Compliance (${comp.length})`, comp.length
    ? h('table', { class: 'tbl' }, h('tbody', {}, comp.slice(0, 30).map(c => h('tr', {},
        h('td', { class: 'mono' }, c.rule_id), h('td', {}, c.title || ''), h('td', {}, statusChip(c.status))))))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No compliance results.')));
}

/* ---- 4.11 Operations (SOC-manager view) ------------------------------ */
async function viewManager(root) {
  root.append(loading('Loading operations…'));
  const [ranking, incidents, stats] = await Promise.all([API.ranking(), API.incidents(), API.stats()]);
  root.innerHTML = '';
  const bands = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  ranking.forEach(r => bands[band(r.risk_score)]++);
  const open = incidents.filter(i => !/resolved|closed|remediated/i.test(i.status || ''));
  const breaches = incidents.filter(i => i.sla_breached);

  root.append(h('div', { class: 'kpis fade' },
    kpiCard('Queue depth', String(ranking.length), `${bands.critical} critical · ${bands.high} high`, bands.critical ? 'crit' : 'ok'),
    kpiCard('Open incidents', String(open.length), `${incidents.length} total`, ''),
    kpiCard('SLA breaches', String(breaches.length), breaches.length ? 'attention required' : 'all within SLA', breaches.length ? 'crit' : 'ok'),
    kpiCard('Assets monitored', String(stats.assets ?? '—'), 'across the estate', '')));

  // analyst workload
  const byAssignee = {}; incidents.forEach(i => { const k = i.assignee || 'unassigned'; byAssignee[k] = byAssignee[k] || { open: 0, total: 0 }; byAssignee[k].total++; if (!/resolved|closed|remediated/i.test(i.status || '')) byAssignee[k].open++; });
  const workload = h('div', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Analyst workload')),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Analyst', 'Open', 'Total'].map(t => h('th', {}, t)))),
      h('tbody', {}, Object.entries(byAssignee).map(([k, v]) => h('tr', {},
        h('td', {}, k === 'unassigned' ? h('span', { class: 'faint' }, 'unassigned') : eAsset(k)),
        h('td', { class: 'mono' }, String(v.open)), h('td', { class: 'mono' }, String(v.total))))))));

  // detection coverage by tool
  const byTool = {}; ranking.forEach(r => { const t = r.source_tool || 'agent'; byTool[t] = (byTool[t] || 0) + 1; });
  const maxT = Math.max(1, ...Object.values(byTool));
  const coverage = h('div', { class: 'panel pad' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Detection coverage by tool'),
    h('div', { class: 'sfbars' }, Object.entries(byTool).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
      h('div', { class: 'sfbar' }, h('div', { class: 'k' }, k),
        h('div', { class: 'tr' }, h('i', { class: 'pos', style: `left:0;width:${(v / maxT) * 100}%;background:var(--accent)` })),
        h('div', { class: 'c' }, String(v))))));
  root.append(h('div', { class: 'cols2 fade', style: 'align-items:start' }, workload, coverage));

  // SLA table
  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' }, h('div', { class: 'panel-h' }, h('h2', {}, 'SLA tracking'),
    h('span', { class: 'spring', style: 'flex:1' }), csvBtn('Export', 'soc-sla.csv', () => [['case', 'title', 'severity', 'status', 'assignee', 'due', 'breached'],
      ...incidents.map(i => [i.id, i.title, i.severity, i.status, i.assignee || '', i.sla_due || '', i.sla_breached ? 'yes' : 'no'])])),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Case', 'Severity', 'Status', 'Owner', 'Due', 'SLA'].map(t => h('th', {}, t)))),
      h('tbody', {}, incidents.map(i => h('tr', {},
        h('td', {}, h('span', { class: 'mono' }, '#' + i.id), ' ', i.title),
        h('td', {}, severity(i.severity)), h('td', {}, chip(i.status, 'warn')),
        h('td', {}, i.assignee || h('span', { class: 'faint' }, 'unassigned')),
        h('td', { class: 'mono', style: 'font-size:11px' }, (i.sla_due || '—').slice(0, 16).replace('T', ' ')),
        h('td', {}, i.sla_breached ? chip('breached', 'kev') : chip('on track', 'ok')))))))));
}

/* ---- 4.12 Settings (identity, integrations, retention, model loop) --- */
async function viewSettings(root) {
  root.append(loading('Loading settings…'));
  const [me, fb, dets] = await Promise.all([API.whoami(), API.feedbackStats(), API.detections()]);
  root.innerHTML = '';

  // identity & access
  const ROLES = [['admin', 'Full control — request & approve containment, manage settings'],
    ['analyst', 'Triage, investigate, request actions, submit feedback'],
    ['viewer', 'Read-only access to dashboards and findings']];
  root.append(h('div', { class: 'panel pad fade' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Identity & access (SSO)'),
    h('div', { class: 'kv' },
      h('div', { class: 'k' }, 'Signed in as'), h('div', {}, me.user ? eAsset(me.user) : h('span', { class: 'faint' }, 'not authenticated')),
      h('div', { class: 'k' }, 'Role'), h('div', {}, chip(me.role || 'viewer', 'consensus')),
      h('div', { class: 'k' }, 'Email'), h('div', { class: 'mono' }, me.email || '—'),
      h('div', { class: 'k' }, 'SSO'), h('div', {}, me.sso || 'none')),
    h('div', { class: 'sec-label', style: 'margin:18px 0 10px' }, 'Roles (Keycloak realm → RBAC)'),
    h('table', { class: 'tbl' }, h('tbody', {}, ROLES.map(([r, d]) => h('tr', {},
      h('td', {}, chip(r, me.role === r ? 'consensus' : '')), h('td', {}, d)))))));

  // integrations health
  const byTool = {}; dets.forEach(d => byTool[d.source_tool] = (byTool[d.source_tool] || 0) + (+d.hits || 0));
  root.append(h('div', { class: 'panel pad fade', style: 'margin-top:14px' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Integration health'),
    sensorsGrid(byTool)));

  // detection catalog
  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Detection catalog'),
    h('span', { class: 'sub' }, '· sources & rules with hit counts'), h('span', { class: 'spring', style: 'flex:1' }),
    csvBtn('Export', 'soc-detections.csv', () => [['source_tool', 'domain', 'hits', 'kev_hits'], ...dets.map(d => [d.source_tool, d.domain, d.hits, d.kev_hits])])),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Source', 'Domain', 'Hits', 'KEV', 'Top risk'].map(t => h('th', {}, t)))),
      h('tbody', {}, dets.map(d => h('tr', {},
        h('td', {}, chip(d.source_tool, 'tool')), h('td', {}, d.domain),
        h('td', { class: 'mono' }, String(d.hits)), h('td', { class: 'mono' }, String(d.kev_hits || 0)),
        h('td', {}, d.top_risk_score ? h('span', { class: 'sc ' + band(d.top_risk_score), style: 'font-family:var(--mono)' }, n0(d.top_risk_score)) : '—'))))))));

  // model feedback loop
  root.append(h('div', { class: 'cols2 fade', style: 'margin-top:14px;align-items:start' },
    h('div', { class: 'panel pad' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Analyst feedback loop'),
      h('div', { class: 'kv' },
        h('div', { class: 'k' }, 'Total labels'), h('div', { class: 'mono' }, String(fb.total ?? 0)),
        ...(fb.by_action || []).flatMap(x => [h('div', { class: 'k' }, x.action), h('div', { class: 'mono' }, String(x.n))])),
      h('div', { class: 'faint', style: 'font-size:11px;margin-top:10px' }, 'Folded into: ' + ((fb.incorporated_in_models || []).join(', ') || '—'))),
    h('div', { class: 'panel pad' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Data retention'),
      h('div', { class: 'kv' },
        h('div', { class: 'k' }, 'Telemetry (JetStream)'), h('div', {}, '7 days'),
        h('div', { class: 'k' }, 'Logs (OpenSearch)'), h('div', {}, '90 days'),
        h('div', { class: 'k' }, 'Findings & audit'), h('div', {}, 'retained (append-only)'),
        h('div', { class: 'k' }, 'Backups (Velero)'), h('div', {}, 'daily 30d · weekly 90d')),
      h('div', { class: 'faint', style: 'font-size:11px;margin-top:10px' }, 'Configured per deployment; shown for transparency.'))));
}

/* ---- 4.13 Alerts inbox (topbar bell) -------------------------------- */
let ALERTS = [];
async function loadAlerts() {
  try { await API.notificationsRefresh(); } catch {}
  try { ALERTS = await API.notifications(); } catch { ALERTS = []; }
  const un = (ALERTS || []).filter(a => !a.acknowledged).length;
  const badge = $('#bell-badge');
  if (badge) { badge.textContent = String(un); badge.hidden = !un; }
}
function toggleAlerts() {
  const pop = $('#alerts-pop'); if (!pop) return;
  if (!pop.hidden) { pop.hidden = true; return; }
  renderAlerts(pop); pop.hidden = false;
}
function closeAlerts() { const p = $('#alerts-pop'); if (p) p.hidden = true; }
function renderAlerts(pop) {
  pop.innerHTML = '';
  pop.append(h('div', { class: 'ap-h' }, h('span', { style: 'font-weight:500' }, 'Alerts'), h('span', { class: 'spring', style: 'flex:1' }),
    h('span', { class: 'linklike', style: 'font-size:11px', onclick: async () => { for (const a of (ALERTS || []).filter(x => !x.acknowledged)) { try { await API.ackNotification(a.id); } catch {} } await loadAlerts(); renderAlerts(pop); } }, 'Mark all read')));
  if (!ALERTS || !ALERTS.length) { pop.append(h('div', { class: 'empty', style: 'padding:24px' }, 'No alerts.')); return; }
  ALERTS.slice(0, 14).forEach(a => pop.append(alertRow(a, pop)));
}
function alertRow(a, pop) {
  const sev = a.severity === 'critical' ? 'critical' : a.severity === 'high' ? 'high' : 'medium';
  return h('div', { class: 'ap-row' + (a.acknowledged ? ' ack' : ''), onclick: () => { closeAlerts(); if (a.ref_type === 'finding') openFinding(a.ref_id); else go('cases'); } },
    h('span', { class: 'gl s-' + sev, style: 'margin-top:5px;flex:none' }),
    h('div', { style: 'flex:1;min-width:0' }, h('div', { class: 'ap-t' }, a.title), h('div', { class: 'ap-b' }, a.body || ''),
      h('div', { class: 'faint mono', style: 'font-size:10px;margin-top:3px' }, ago(a.created_at))),
    a.acknowledged ? null : h('button', { class: 'btn sm', onclick: async (e) => { e.stopPropagation(); try { await API.ackNotification(a.id); } catch {} await loadAlerts(); renderAlerts(pop); } }, 'Ack'));
}

/* ---- threat attribution + knowledge graph (OpenCTI) ----------------- */
function intelGraphView(g) {
  const a = g.attribution || {};
  const chain = h('div', { class: 'wrap', style: 'gap:6px' });
  const parts = [['indicator', a.indicator, 'net'], ['technique', a.technique, 'code'],
    ['malware', a.malware, null], ['actor', a.actor, null], ['campaign', a.campaign, null]].filter(p => p[1]);
  parts.forEach((p, i) => { chain.append(p[2] ? entityChip(p[1], p[2]) : chip(p[1], 'attack')); if (i < parts.length - 1) chain.append(h('span', { class: 'faint', style: 'font-size:12px' }, '→')); });
  const nodes = h('div', { class: 'wrap', style: 'margin-top:6px' }, (g.nodes || []).map(n =>
    chip(`${n.type}: ${n.label}`, (n.type === 'actor' || n.type === 'malware') ? 'kev' : '')));
  return h('div', { class: 'stack', style: 'gap:8px' },
    parts.length ? h('div', {}, h('div', { class: 'faint', style: 'font-size:11px;margin-bottom:6px' }, 'Attribution chain'), chain) : null,
    h('div', { class: 'faint', style: 'font-size:11px' }, `${(g.nodes || []).length} entities · ${(g.edges || []).length} relations`), nodes);
}

/* ---- SOAR playbook runner (in the finding drawer) ------------------- */
function playbookRunner(f) {
  const box = h('div', { class: 'stack', style: 'gap:8px' });
  const sel = h('select', {});
  API.playbooks().then(pbs => (pbs || []).forEach(p => sel.append(h('option', { value: p.id }, p.name)))).catch(() => {});
  const out = h('div', {});
  const run = h('button', { class: 'btn primary sm', onclick: async () => {
    if (!sel.value) return; run.disabled = true; run.textContent = 'Running…';
    const r = await API.runPlaybook(sel.value, { finding_id: f.id });
    out.innerHTML = '';
    out.append(h('div', { class: 'stack', style: 'gap:5px;margin-top:4px' }, (r.steps || []).map(s =>
      h('div', { class: 'row', style: 'gap:8px' }, chip(s.ok ? '✓' : '✗', s.ok ? 'ok' : 'kev'),
        h('span', { class: 'mono', style: 'font-size:11px' }, s.action), h('span', { class: 'faint', style: 'font-size:11px' }, s.detail || '')))));
    toast('Playbook run complete', true); run.disabled = false; run.textContent = 'Run playbook';
  } }, 'Run playbook');
  box.append(h('div', { class: 'faint', style: 'font-size:11px' }, 'Containment-safe automation; destructive steps only ever propose (two-person approval).'),
    h('div', { class: 'row', style: 'gap:8px' }, sel, run), out);
  return box;
}

/* ---- 4.15 Playbooks (SOAR) ------------------------------------------ */
async function viewPlaybooks(root) {
  root.append(loading('Loading playbooks…'));
  const [pbs, runs] = await Promise.all([API.playbooks(), API.playbookRuns()]);
  root.innerHTML = '';
  root.append(h('div', { class: 'panel fade' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Playbooks'),
    h('span', { class: 'sub' }, '· containment-safe automation (analyst-controlled)')),
    h('div', { class: 'pbgrid' }, (pbs || []).map(p => h('div', { class: 'pbcard' },
      h('div', { class: 'row', style: 'gap:8px' }, h('div', { class: 'pbn' }, p.name),
        h('span', { class: 'spring', style: 'flex:1' }), chip(p.trigger || 'manual', p.trigger === 'manual' ? '' : 'attack'), chip(p.enabled ? 'enabled' : 'off', p.enabled ? 'ok' : '')),
      h('div', { class: 'pbd' }, p.description || ''),
      h('div', { class: 'wrap', style: 'margin-top:8px' }, (p.actions || []).map(a => chip(a.type.replace('_', ' '), 'mono'))))))));
  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Recent runs'),
    h('span', { class: 'sub' }, `· ${(runs || []).length}`)),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Run', 'Playbook', 'Trigger', 'Steps', 'Status', 'By', 'When'].map(t => h('th', {}, t)))),
      h('tbody', {}, (runs || []).length ? runs.map(r => h('tr', {},
        h('td', { class: 'mono' }, '#' + r.id), h('td', {}, r.playbook_id), h('td', { class: 'mono', style: 'font-size:11px' }, r.trigger_ref || ''),
        h('td', {}, h('div', { class: 'wrap', style: 'gap:4px' }, (r.steps || []).map(s => chip(s.action, s.ok ? 'ok' : 'kev')))),
        h('td', {}, chip(r.status, r.status === 'completed' ? 'ok' : 'warn')), h('td', {}, r.run_by || ''),
        h('td', { class: 'mono', style: 'font-size:11px' }, ago(r.created_at))))
        : [h('tr', {}, h('td', { colspan: '7', class: 'faint', style: 'padding:18px;text-align:center' }, 'No runs yet.'))])))));
}

/* ---- 4.16 Live Hunt (Velociraptor fleet collection) ----------------- */
async function viewLiveHunt(root) {
  root.append(loading('Loading hunts…'));
  const hunts = await API.hunts();
  root.innerHTML = '';
  const ARTIFACTS = [['processes', 'running processes'], ['listening_ports', 'listening ports'], ['file_search', 'file search (glob)'], ['osquery', 'osquery SQL']];
  const name = h('input', { class: 'txt', placeholder: 'Hunt name…' });
  const art = h('select', {}, ARTIFACTS.map(([v, l]) => h('option', { value: v }, l)));
  const query = h('input', { class: 'txt', placeholder: 'query — osquery SQL / file glob (optional)' });
  const target = h('input', { class: 'txt', value: 'all', style: 'max-width:190px' });
  const run = h('button', { class: 'btn primary', onclick: async () => {
    if (!name.value.trim()) { toast('Name the hunt', false); return; }
    await API.createHunt({ name: name.value.trim(), artifact: art.value, query: query.value || null, target: target.value || 'all' });
    toast('Hunt queued — agents collect on next poll', true); go('livehunt');
  } }, 'Launch hunt');
  root.append(h('div', { class: 'panel pad fade' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Launch a live hunt (read-only fleet collection)'),
    h('div', { class: 'huntbar' }, name, art, query, target, run),
    h('div', { class: 'faint', style: 'font-size:11px;margin-top:8px' }, 'Collection-only — never executes a destructive action. Agents poll, collect the artifact, and return rows.')));
  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Hunts'), h('span', { class: 'sub' }, `· ${hunts.length}`)),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Hunt', 'Artifact', 'Target', 'Status', 'Results', 'When'].map(t => h('th', {}, t)))),
      h('tbody', {}, hunts.length ? hunts.map(hu => h('tr', { tabindex: '0', onclick: () => openHunt(hu.id), onkeydown: e => { if (e.key === 'Enter') openHunt(hu.id); } },
        h('td', {}, h('span', { class: 'mono' }, '#' + hu.id), ' ', hu.name),
        h('td', {}, chip(hu.artifact, 'mono')),
        h('td', { class: 'mono' }, hu.target),
        h('td', {}, chip(hu.status, hu.status === 'completed' ? 'ok' : hu.status === 'collecting' ? 'warn' : '')),
        h('td', { class: 'mono' }, String(hu.result_count ?? 0)),
        h('td', { class: 'mono', style: 'font-size:11px' }, ago(hu.created_at))))
        : [h('tr', {}, h('td', { colspan: '6', class: 'faint', style: 'padding:18px;text-align:center' }, 'No hunts yet — launch one above.'))])))));
}
async function openHunt(id) {
  const inner = $('#drawer-inner'); $('#scrim').classList.add('show'); $('#drawer').classList.add('show');
  inner.innerHTML = ''; inner.append(loading('Loading hunt…'));
  const hu = await API.hunt(id);
  inner.innerHTML = '';
  inner.append(h('div', { class: 'drawer-h' }, h('div', {}, h('div', { class: 'wrap', style: 'margin-bottom:9px' }, chip(hu.artifact || 'artifact', 'mono'), chip(hu.status || 'queued', hu.status === 'completed' ? 'ok' : 'warn')),
    h('div', { style: 'font-size:17px;font-weight:600' }, hu.name || ('Hunt #' + id)),
    h('div', { class: 'faint', style: 'font-size:12px;margin-top:5px' }, `target ${hu.target || 'all'} · by ${hu.created_by || '—'}`)),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));
  const b = h('div', { class: 'drawer-b' }); inner.append(b);
  const results = hu.results || [];
  if (!results.length) { b.append(h('div', { class: 'empty' }, 'No results collected yet — agents return rows as they poll.')); return; }
  results.forEach(r => {
    const rows = r.rows || [];
    const box = h('div', { class: 'block' }, h('div', { class: 'sec-label', style: 'margin-bottom:8px' }, eAsset(r.asset_id || r.agent_id), ` · ${r.row_count} rows · ${ago(r.collected_at)}`));
    if (rows.length) {
      const cols = [...new Set(rows.flatMap(x => Object.keys(x)))].slice(0, 6);
      box.append(h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, cols.map(c => h('th', {}, c)))),
        h('tbody', {}, rows.slice(0, 50).map(x => h('tr', {}, cols.map(c => h('td', { class: 'mono', style: 'font-size:11px' }, String(x[c] ?? '')))))))));
    } else box.append(h('div', { class: 'faint', style: 'font-size:12px' }, 'no rows from this host'));
    b.append(box);
  });
}

/* ---- 4.19 Reports Center -------------------------------------------- */
async function viewReports(root) {
  root.append(loading('Loading reports…'));
  const list = await API.reports();
  root.innerHTML = '';
  const gen = async (type) => { const r = await API.generateReport(type); toast(`${type} report generated`, true); go('reports'); openReport(r.id, r); };
  root.append(h('div', { class: 'panel pad fade' }, h('div', { class: 'sec-label', style: 'margin-bottom:12px' }, 'Generate a report'),
    h('div', { class: 'row', style: 'gap:10px;flex-wrap:wrap' },
      h('button', { class: 'btn primary', onclick: () => gen('posture') }, 'Security posture'),
      h('button', { class: 'btn', onclick: () => gen('compliance') }, 'Compliance'),
      h('button', { class: 'btn', onclick: () => gen('executive') }, 'Executive summary')),
    h('div', { class: 'faint', style: 'font-size:11px;margin-top:8px' }, 'Computed from live data, stored as a reproducible snapshot; open one to export PDF/CSV.')));
  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Generated reports'), h('span', { class: 'sub' }, `· ${(list || []).length}`)),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Report', 'Type', 'By', 'When'].map(t => h('th', {}, t)))),
      h('tbody', {}, (list || []).length ? list.map(r => h('tr', { tabindex: '0', onclick: () => openReport(r.id), onkeydown: e => { if (e.key === 'Enter') openReport(r.id); } },
        h('td', {}, r.title), h('td', {}, chip(r.type, r.type === 'executive' ? 'consensus' : 'mono')), h('td', {}, r.generated_by || '—'), h('td', { class: 'mono', style: 'font-size:11px' }, ago(r.created_at))))
        : [h('tr', {}, h('td', { colspan: '4', class: 'faint', style: 'padding:18px;text-align:center' }, 'No reports yet — generate one above.'))])))));
}
async function openReport(id, preloaded) {
  const inner = $('#drawer-inner'); $('#scrim').classList.add('show'); $('#drawer').classList.add('show');
  inner.innerHTML = ''; inner.append(loading('Loading report…'));
  const r = preloaded && preloaded.content ? preloaded : await API.report(id);
  const c = r.content || {};
  inner.innerHTML = '';
  inner.append(h('div', { class: 'drawer-h' }, h('div', {}, h('div', { class: 'wrap', style: 'margin-bottom:9px' }, chip(r.type || 'report', 'consensus')),
    h('div', { style: 'font-size:17px;font-weight:600' }, r.title || ('Report #' + id))),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));
  const b = h('div', { class: 'drawer-b', id: 'report-body' }); inner.append(b);

  if (c.kpis) {
    const k = c.kpis;
    b.append(block('Posture', h('div', { class: 'kpis', style: 'grid-template-columns:repeat(2,1fr)' },
      kpiCard('Open findings', String(k.open_findings ?? '—'), `${k.critical || 0} critical · ${k.high || 0} high`, k.critical ? 'crit' : 'ok'),
      kpiCard('KEV-listed', String(k.kev ?? '—'), `${k.exploit_available || 0} with exploits`, k.kev ? 'warn' : 'ok'),
      kpiCard('Avg composite risk', String(k.avg_risk ?? '—'), 'across findings', ''),
      kpiCard('Assets', String(k.assets ?? '—'), 'monitored', ''))));
  }
  if (c.posture_score != null) b.append(block('Executive metrics', h('div', { class: 'kv' },
    h('div', { class: 'k' }, 'Posture score'), h('div', { class: 'mono' }, String(c.posture_score)),
    h('div', { class: 'k' }, 'Compliance'), h('div', { class: 'mono' }, (c.compliance_score ?? '—') + '%'),
    h('div', { class: 'k' }, 'Open incidents'), h('div', { class: 'mono' }, String(c.open_incidents ?? 0)),
    h('div', { class: 'k' }, 'SLA breaches'), h('div', { class: 'mono' }, String(c.sla_breaches ?? 0)))));
  if (c.summary) b.append(block('Compliance', h('div', { class: 'kv' },
    h('div', { class: 'k' }, 'Score'), h('div', { class: 'mono' }, (c.summary.score_pct ?? '—') + '%'),
    h('div', { class: 'k' }, 'Pass'), h('div', { class: 'mono' }, String(c.summary.pass ?? 0)),
    h('div', { class: 'k' }, 'Fail'), h('div', { class: 'mono' }, String(c.summary.fail ?? 0)),
    h('div', { class: 'k' }, 'Evidence chain'), h('div', {}, chip((c.evidence_chain && c.evidence_chain.ok) ? 'intact ✓' : 'check', (c.evidence_chain && c.evidence_chain.ok) ? 'ok' : 'warn')))));
  const tr = c.top_risks || [];
  if (tr.length) b.append(block('Top risks', h('div', {}, tr.map(x => h('div', { class: 'evrow' },
    h('span', { class: 'sc ' + band(x.risk) }, n0(x.risk)), h('span', { style: 'flex:1;min-width:0' }, x.title),
    eAsset(x.asset_id), x.kev ? chip('KEV', 'kev') : null)))));
  const bt = c.by_tool || [];
  if (bt.length) { const max = Math.max(1, ...bt.map(t => t.n));
    b.append(block('Detections by tool', h('div', { class: 'sfbars' }, bt.map(t =>
      h('div', { class: 'sfbar' }, h('div', { class: 'k' }, t.tool),
        h('div', { class: 'tr' }, h('i', { class: 'pos', style: `left:0;width:${(t.n / max) * 100}%;background:var(--accent)` })),
        h('div', { class: 'c' }, String(t.n))))))); }

  b.append(h('div', { class: 'row noprint', style: 'gap:8px;margin-top:6px' }, pdfBtn('Export PDF'),
    csvBtn('Export CSV', `vyrex-${r.type || 'report'}.csv`, () => [['metric', 'value'],
      ...Object.entries(c.kpis || {}).map(([k2, v]) => [k2, v]), ...(c.top_risks || []).map(x => ['top_risk', `${x.title} (${x.risk})`])])));
}

/* ---- 4.18 Global search results ------------------------------------- */
async function viewSearch(root) {
  const q = STATE.q || '';
  root.innerHTML = '';
  if (!q.trim()) { root.append(h('div', { class: 'empty' }, 'Type a query in the search bar and press Enter.')); return; }
  root.append(loading(`Searching "${q}"…`));
  const r = await API.search(q);
  root.innerHTML = '';
  root.append(h('div', { class: 'panel-h', style: 'border:none;padding:0 2px 14px' }, h('h2', {}, `Results for "${q}"`), h('span', { class: 'sub' }, `· ${r.total} match(es)`)));
  const sect = (title, rows, render) => rows && rows.length ? h('div', { class: 'panel fade', style: 'margin-bottom:14px' },
    h('div', { class: 'panel-h' }, h('h2', {}, title), h('span', { class: 'sub' }, `· ${rows.length}`)),
    h('div', {}, rows.map(render))) : null;
  [
    sect('Findings', r.findings, f => h('div', { class: 'orow', tabindex: '0', onclick: () => openFinding(f.id), onkeydown: e => { if (e.key === 'Enter') openFinding(f.id); } },
      h('div', { class: 'sc ' + band(f.risk_score) }, n0(f.risk_score)),
      h('div', { style: 'flex:1;min-width:0' }, h('div', { class: 'tt' }, f.title),
        h('div', { class: 'wrap', style: 'margin-top:5px' }, severity(f.severity), eAsset(f.asset_id), f.cve_id ? eCode(f.cve_id) : null, f.kev ? chip('KEV', 'kev') : null)))),
    sect('Assets', r.assets, a => h('div', { class: 'orow', tabindex: '0', onclick: () => openAsset(a.host_id), onkeydown: e => { if (e.key === 'Enter') openAsset(a.host_id); } },
      h('span', { html: ic('assets'), style: 'width:18px;height:18px;color:var(--muted)' }),
      h('div', { style: 'flex:1' }, h('div', { class: 'tt' }, a.hostname || a.host_id),
        h('div', { class: 'wrap', style: 'margin-top:5px' }, chip(a.os || '—', 'mono'), a.ip ? eNet(a.ip) : null, a.exposure ? chip(a.exposure, a.exposure === 'internet' ? 'warn' : '') : null)))),
    sect('CVEs', r.cves, c => h('div', { class: 'orow', tabindex: '0', onclick: () => openCve(c.cve_id), onkeydown: e => { if (e.key === 'Enter') openCve(c.cve_id); } },
      h('div', { style: 'flex:1' }, h('div', { class: 'wrap' }, eCode(c.cve_id), c.cwe ? chip(c.cwe, 'mono') : null, c.kev ? chip('KEV', 'kev') : null, c.cvss_score ? chip('CVSS ' + n1(c.cvss_score), '') : null, h('span', { class: 'faint', style: 'font-size:11px' }, `${c.occurrences} finding(s)`))))),
    sect('Indicators', r.iocs, i => h('div', { class: 'orow', tabindex: '0', onclick: () => openIp(i.indicator), onkeydown: e => { if (e.key === 'Enter') openIp(i.indicator); } },
      h('div', { style: 'flex:1' }, h('div', { class: 'wrap' }, eNet(i.indicator), chip(i.type || 'ioc', 'mono'))))),
  ].filter(Boolean).forEach(s => root.append(s));
  if (!r.total) root.append(h('div', { class: 'empty' }, 'No matches.'));
}

/* ---- CVE entity page (drawer) --------------------------------------- */
async function openCve(cveId) {
  const inner = $('#drawer-inner'); $('#scrim').classList.add('show'); $('#drawer').classList.add('show');
  inner.innerHTML = ''; inner.append(loading('Loading CVE…'));
  const d = await API.entityCve(cveId); const m = d.meta || {};
  inner.innerHTML = '';
  inner.append(h('div', { class: 'drawer-h' }, h('div', {}, h('div', { class: 'wrap', style: 'margin-bottom:9px' },
    m.cvss_severity ? severity(m.cvss_severity) : null, d.kev ? chip('KEV', 'kev') : null, (d.exploits || []).length ? chip('exploit', 'exploit') : null),
    h('div', { style: 'font-size:18px;font-weight:600' }, cveId),
    h('div', { class: 'faint', style: 'font-size:12px;margin-top:5px' }, `${(d.affected_assets || []).length} affected asset(s) · ${(d.findings || []).length} finding(s)`)),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));
  const b = h('div', { class: 'drawer-b' }); inner.append(b);
  if (m.description) b.append(h('div', { class: 'summary' }, m.description));
  const kv = h('div', { class: 'kv' });
  if (m.cvss_score) kv.append(h('div', { class: 'k' }, 'CVSS'), h('div', { class: 'mono' }, n1(m.cvss_score)));
  if (m.cwe) kv.append(h('div', { class: 'k' }, 'CWE'), h('div', {}, eCode(m.cwe), ' · ', cweName(m.cwe)));
  if (d.epss) kv.append(h('div', { class: 'k' }, 'EPSS'), h('div', { class: 'mono' }, pct(d.epss.epss)));
  if (d.kev) kv.append(h('div', { class: 'k' }, 'KEV due'), h('div', { class: 'mono' }, d.kev.due_date || '—'));
  if (kv.children.length) b.append(block('CVE intelligence', kv));
  if ((d.exploits || []).length) b.append(block('Public exploits', h('div', { class: 'wrap' }, d.exploits.map(e => chip(`${e.source}: ${e.ref}`, 'mono')))));
  b.append(block(`Findings (${(d.findings || []).length})`, (d.findings || []).length
    ? h('div', {}, d.findings.map(f => h('div', { class: 'evrow', tabindex: '0', onclick: () => openFinding(f.id), onkeydown: e => { if (e.key === 'Enter') openFinding(f.id); } },
        h('span', { class: 'sc ' + band(f.risk_score) }, n0(f.risk_score)), h('span', { style: 'flex:1;min-width:0' }, f.title), eAsset(f.asset_id))))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No findings.')));
}

/* ---- IP / indicator entity page (drawer) ---------------------------- */
async function openIp(ip) {
  const inner = $('#drawer-inner'); $('#scrim').classList.add('show'); $('#drawer').classList.add('show');
  inner.innerHTML = ''; inner.append(loading('Loading indicator…'));
  const d = await API.entityIp(ip);
  inner.innerHTML = '';
  inner.append(h('div', { class: 'drawer-h' }, h('div', {}, h('div', { class: 'wrap', style: 'margin-bottom:9px' }, chip('indicator', 'mono'), (d.findings || []).length ? chip('active', 'kev') : null),
    h('div', { style: 'font-size:18px;font-weight:600;font-family:var(--mono)' }, ip),
    h('div', { class: 'faint', style: 'font-size:12px;margin-top:5px' }, `${(d.sightings || []).length} sighting(s) · ${(d.findings || []).length} finding(s)`)),
    h('div', { class: 'x', html: ic('x'), onclick: closeDrawer })));
  const b = h('div', { class: 'drawer-b' }); inner.append(b);
  b.append(block(`Sightings (${(d.sightings || []).length})`, (d.sightings || []).length
    ? h('div', {}, d.sightings.map(s => h('div', { class: 'cf' }, h('span', {}, eAsset(s.asset_id || '—'), ` · ${s.source || ''}`), h('span', { class: 'faint mono', style: 'font-size:11px' }, ago(s.seen_at)))))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No sightings recorded.')));
  b.append(block(`Findings (${(d.findings || []).length})`, (d.findings || []).length
    ? h('div', {}, d.findings.map(f => h('div', { class: 'evrow', tabindex: '0', onclick: () => openFinding(f.id), onkeydown: e => { if (e.key === 'Enter') openFinding(f.id); } },
        h('span', { class: 'sc ' + band(f.risk_score) }, n0(f.risk_score)), h('span', { style: 'flex:1;min-width:0' }, f.title), f.attack ? chip(f.attack, 'attack') : null)))
    : h('div', { class: 'faint', style: 'font-size:12px' }, 'No findings reference this indicator.')));
}

/* ---- 4.17 Threat Intelligence Center (attribution + IOC sightings + fusion clusters) -- */
async function viewIntel(root) {
  root.append(loading('Loading threat intelligence…'));
  const [attr, sight, clusters] = await Promise.all([API.attribution(), API.sightings(), API.clusters()]);
  root.innerHTML = '';
  const actors = attr.actors || [], malware = attr.malware || [];
  root.append(h('div', { class: 'kpis fade' },
    kpiCard('Threat actors', String(actors.length), actors[0] ? 'top: ' + actors[0].name : 'none attributed', actors.length ? 'crit' : ''),
    kpiCard('Malware families', String(malware.length), malware[0] ? 'top: ' + malware[0].name : 'none seen', malware.length ? 'warn' : ''),
    kpiCard('IOC sightings', String((sight || []).length), 'observed indicators', (sight || []).length ? 'warn' : ''),
    kpiCard('Fusion clusters', String((clusters || []).length), 'multi-tool corroboration', '')));

  const actorsTbl = h('div', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Threat actors'), h('span', { class: 'sub' }, '· by attributed findings')),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Actor', 'Findings'].map(t => h('th', {}, t)))),
      h('tbody', {}, actors.length ? actors.map(a => h('tr', {}, h('td', {}, chip(a.name, 'kev')), h('td', { class: 'mono' }, String(a.findings))))
        : [h('tr', {}, h('td', { colspan: '2', class: 'faint', style: 'padding:16px;text-align:center' }, 'No attribution yet.'))]))));
  const malTbl = h('div', { class: 'panel' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Malware'), h('span', { class: 'sub' }, '· families seen')),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Malware', 'Findings'].map(t => h('th', {}, t)))),
      h('tbody', {}, malware.length ? malware.map(m => h('tr', {}, h('td', {}, chip(m.name, 'warn')), h('td', { class: 'mono' }, String(m.findings))))
        : [h('tr', {}, h('td', { colspan: '2', class: 'faint', style: 'padding:16px;text-align:center' }, 'No malware seen.'))]))));
  root.append(h('div', { class: 'cols2 fade', style: 'align-items:start' }, actorsTbl, malTbl));

  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' }, h('div', { class: 'panel-h' }, h('h2', {}, 'Fusion clusters'), h('span', { class: 'sub' }, '· issues independent tools corroborate')),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Severity', 'Title', 'Asset', 'Tools', 'Top risk', ''].map(t => h('th', {}, t)))),
      h('tbody', {}, (clusters || []).length ? clusters.map(c => h('tr', { tabindex: '0', onclick: () => openFinding(c.primary_id), onkeydown: e => { if (e.key === 'Enter') openFinding(c.primary_id); } },
        h('td', {}, severity(c.severity)),
        h('td', {}, c.title),
        h('td', {}, eAsset(c.asset_id)),
        h('td', {}, h('div', { class: 'wrap', style: 'gap:4px' }, (c.tools || []).map(t => chip(t, 'mono')), chip((c.n_tools || 0) + ' agree', 'consensus'))),
        h('td', {}, h('span', { class: 'sc ' + band(c.top_risk_score), style: 'font-family:var(--mono)' }, n0(c.top_risk_score))),
        h('td', {}, h('span', { class: 'linklike', style: 'font-size:11px' }, 'investigate ›'))))
        : [h('tr', {}, h('td', { colspan: '6', class: 'faint', style: 'padding:16px;text-align:center' }, 'No multi-tool clusters yet.'))])))));

  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px' }, h('div', { class: 'panel-h' }, h('h2', {}, 'IOC sightings'), h('span', { class: 'sub' }, '· where indicators were observed'),
    h('span', { class: 'spring', style: 'flex:1' }), csvBtn('CSV', 'vyrex-sightings.csv', () => [['indicator', 'type', 'asset', 'source', 'seen'], ...(sight || []).map(s => [s.indicator, s.type || '', s.asset_id || '', s.source || '', s.seen_at])])),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Indicator', 'Type', 'Asset', 'Source', 'Seen'].map(t => h('th', {}, t)))),
      h('tbody', {}, (sight || []).length ? sight.map(s => h('tr', {},
        h('td', {}, eNet(s.indicator)),
        h('td', { class: 'mono' }, s.type || '—'),
        h('td', {}, s.asset_id ? eAsset(s.asset_id) : '—'),
        h('td', {}, chip(s.source || '—', 'mono')),
        h('td', { class: 'mono', style: 'font-size:11px' }, ago(s.seen_at))))
        : [h('tr', {}, h('td', { colspan: '5', class: 'faint', style: 'padding:16px;text-align:center' }, 'No sightings recorded.'))])))));
}

/* ---- 4.14 Dashboards (embedded Grafana) ----------------------------- */
async function viewDashboards(root) {
  root.innerHTML = '';
  const base = location.protocol + '//' + location.hostname + ':' + (window.GRAFANA_PORT || 3000);
  const DASH = [
    ['SOC overview', '/d/soc-overview', 'findings, risk bands & compliance — from PostgreSQL'],
    ['API metrics', '/d/soc-api-metrics', 'request rate, latency & errors — from Prometheus'],
  ];
  root.append(h('div', { class: 'panel pad fade' },
    h('div', { class: 'row', style: 'margin-bottom:12px' }, h('div', { class: 'sec-label' }, 'Grafana dashboards'),
      h('span', { class: 'spring', style: 'flex:1' }),
      h('a', { class: 'btn sm', href: base, target: '_blank', rel: 'noopener', html: ic('hunt') + '<span style="margin-left:6px">Open Grafana</span>' })),
    h('div', { class: 'dashgrid' }, DASH.map(([t, p, d]) => h('a', { class: 'dashcard', href: base + p, target: '_blank', rel: 'noopener' },
      h('div', { class: 'dt' }, t), h('div', { class: 'dd' }, d), h('div', { class: 'linklike', style: 'font-size:11px;margin-top:8px' }, 'Open ›'))))));
  root.append(h('div', { class: 'panel fade', style: 'margin-top:14px;overflow:hidden' },
    h('div', { class: 'panel-h' }, h('h2', {}, 'Embedded preview'), h('span', { class: 'sub' }, '· live Grafana — needs GF_SECURITY_ALLOW_EMBEDDING')),
    h('iframe', { class: 'gframe', src: base + '/d/soc-overview?theme=dark&kiosk', loading: 'lazy', referrerpolicy: 'no-referrer' })));
}
