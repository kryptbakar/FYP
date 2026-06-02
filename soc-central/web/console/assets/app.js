/* =====================================================================
   SOC Central — analyst console (dependency-free SPA).
   Router + API client + SVG charts + views. Calls the FastAPI same-origin
   via the nginx /api reverse proxy (see nginx.conf). No build step, no CDN.
   ===================================================================== */
'use strict';

const API = '/api';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---- tiny DOM builder ------------------------------------------------ */
function h(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'html') e.innerHTML = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    e.append(kid.nodeType ? kid : document.createTextNode(kid));
  }
  return e;
}

/* ---- API ------------------------------------------------------------- */
async function api(path, opts) {
  const r = await fetch(API + path, opts);
  if (!r.ok) throw new Error(`${path} → ${r.status}`);
  return r.status === 204 ? null : r.json();
}
async function apiSafe(path, fallback) { try { return await api(path); } catch { return fallback; } }

/* ---- formatting + severity ------------------------------------------ */
const SEV = { CRITICAL: 'crit', HIGH: 'high', MEDIUM: 'med', LOW: 'low', INFO: 'info' };
const SEVCOLOR = { crit: '#fb3b6b', high: '#fb923c', med: '#fbbf24', low: '#38bdf8', info: '#64748b' };
const sevClass = s => SEV[(s || 'INFO').toUpperCase()] || 'info';
function band(score) {
  const n = +score;
  if (n >= 80) return 'crit'; if (n >= 60) return 'high'; if (n >= 40) return 'med'; if (n >= 20) return 'low'; return 'info';
}
const bandLabel = { crit: 'Critical', high: 'High', med: 'Medium', low: 'Low', info: 'Info' };
const num = (v, d = 1) => (v == null ? '—' : (+v).toFixed(d));
const fmtDate = s => s ? new Date(s).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—';
const since = s => { if (!s) return '—'; const d = (Date.now() - new Date(s)) / 36e5; return d < 1 ? `${Math.round(d * 60)}m ago` : d < 24 ? `${Math.round(d)}h ago` : `${Math.round(d / 24)}d ago`; };

/* ---- icons ----------------------------------------------------------- */
const I = {
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  alert: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z',
  shield: 'M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z',
  server: 'M3 4h18v6H3zM3 14h18v6H3zM7 7h.01M7 17h.01',
  fire: 'M12 2s4 4 4 8a4 4 0 0 1-8 0c0-1 .5-2 1-2.5C9 9 12 7 12 2Z',
  bug: 'M8 7a4 4 0 0 1 8 0v4a4 4 0 0 1-8 0zM3 9h3M18 9h3M3 14h3M18 14h3M12 3V1',
  gauge: 'M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM12 14l4-4M5 19a9 9 0 1 1 14 0',
  link: 'M9 15l6-6M10 7l1-1a4 4 0 0 1 6 6l-1 1M14 17l-1 1a4 4 0 0 1-6-6l1-1',
  brain: 'M9 3a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 6 0V3.5A2.5 2.5 0 0 0 9 3ZM15 3a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-6 0',
};
const icon = (k, cls = '') => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${I[k]}"/></svg>`;

/* ---- charts (pure SVG) ---------------------------------------------- */
function donut(segments, centerBig, centerLab) {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  const R = 52, C = 2 * Math.PI * R; let off = 0;
  const rings = segments.filter(s => s.value > 0).map(s => {
    const len = (s.value / total) * C;
    const el = `<circle r="${R}" cx="64" cy="64" fill="none" stroke="${s.color}" stroke-width="16"
      stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 64 64)"
      stroke-linecap="butt"></circle>`;
    off += len; return el;
  }).join('');
  return h('div', { class: 'donut-wrap' },
    h('div', { html: `<svg width="128" height="128" viewBox="0 0 128 128">
        <circle r="${R}" cx="64" cy="64" fill="none" stroke="#16223a" stroke-width="16"></circle>${rings}</svg>` }),
    h('div', { class: 'donut-center', style: 'flex:1' },
      h('div', { class: 'big' }, String(centerBig)),
      h('div', { class: 'lab' }, centerLab),
      h('div', { class: 'legend' }, segments.map(s =>
        h('div', { class: 'item' }, h('span', { class: 'sw', style: `background:${s.color}` }), `${s.label} · ${s.value}`)))
    ));
}
function hbars(rows, max) {
  const m = max || Math.max(1, ...rows.map(r => r.value));
  return h('div', {}, rows.map(r => h('div', { class: 'hbar-row' },
    h('div', { class: 'k' }, r.label),
    h('div', { class: 'track' }, h('i', { style: `width:${(r.value / m) * 100}%;background:${r.color || '#38bdf8'}` })),
    h('div', { class: 'n' }, String(r.value)))));
}
function scoreMeter(score) {
  const b = band(score);
  return h('span', { class: 'score' },
    h('span', { class: 'bar' }, h('i', { style: `width:${Math.min(100, +score)}%;background:${SEVCOLOR[b]}` })),
    h('span', { class: 'v sev-text ' + b }, num(score, 0)));
}

/* ---- chips ----------------------------------------------------------- */
const sevPill = s => h('span', { class: 'pill ' + sevClass(s) }, (s || 'INFO').toUpperCase());
const toolPill = t => h('span', { class: 'pill tool' }, t || 'agent');
function consensusPill(c) {
  if (!c || (c.n_tools || 0) < 2) return null;
  return h('span', { class: 'pill consensus', title: 'Tools: ' + (c.tools || []).join(', ') },
    `⛓ ${c.n_tools} tools agree`);
}

/* ===================================================================== *
 *  VIEWS
 * ===================================================================== */
const state = { ranking: [], stats: null };

async function viewOverview(root) {
  root.append(loading());
  const [stats, ranking, incidents, comp] = await Promise.all([
    apiSafe('/stats/summary', {}), apiSafe('/risk/ranking?limit=500', []),
    apiSafe('/incidents?limit=200', []), apiSafe('/compliance/summary', {}),
  ]);
  state.ranking = ranking; state.stats = stats;
  root.innerHTML = '';

  const sevAgg = {};
  (stats.by_domain_severity || []).forEach(r => { sevAgg[r.severity] = (sevAgg[r.severity] || 0) + r.count; });
  const totalFindings = Object.values(sevAgg).reduce((a, b) => a + b, 0);
  const crit = sevAgg.CRITICAL || 0, high = sevAgg.HIGH || 0;
  const openInc = incidents.filter(i => i.status !== 'closed' && i.status !== 'resolved').length;
  const compPass = (comp.by_status || []).find(s => s.status === 'pass')?.count || 0;
  const compTotal = (comp.by_status || []).filter(s => ['pass', 'fail', 'partial'].includes(s.status)).reduce((a, s) => a + s.count, 0) || 1;

  // risk bands from ranking
  const bands = { crit: 0, high: 0, med: 0, low: 0, info: 0 };
  ranking.forEach(f => bands[band(f.risk_score)]++);
  // source tools + consensus
  const tools = {}; let corroborated = 0; const attacks = new Set();
  ranking.forEach(f => { tools[f.source_tool || 'agent'] = (tools[f.source_tool || 'agent'] || 0) + 1; if (f.consensus && f.consensus.n_tools > 1) corroborated++; if (f.attack) attacks.add(f.attack); });

  const kpi = (label, value, foot, ic, alarm) => h('div', { class: 'card kpi' + (alarm ? ' alarm' : '') },
    h('div', { class: 'glyph', html: icon(ic) }), h('div', { class: 'label' }, label),
    h('div', { class: 'value' }, String(value)), h('div', { class: 'foot' }, foot));

  root.append(
    h('div', { class: 'grid g-kpi fade-in', style: 'margin-bottom:16px' },
      kpi('Monitored Assets', stats.assets ?? '—', 'live telemetry', 'server'),
      kpi('Open Findings', totalFindings, `${ranking.length} risk-scored`, 'bug'),
      kpi('Critical / High', `${crit} / ${high}`, 'need triage', 'fire', crit > 0),
      kpi('KEV-flagged', stats.kev_findings ?? 0, 'known exploited', 'alert', (stats.kev_findings || 0) > 0),
      kpi('Open Incidents', openInc, `${incidents.length} total`, 'alert'),
      kpi('Compliance', Math.round((compPass / compTotal) * 100) + '%', 'CIS controls pass', 'shield'),
    ),
    h('div', { class: 'grid g-2 fade-in', style: 'margin-bottom:16px' },
      // top risks
      h('div', { class: 'card' },
        h('div', { class: 'card-h' }, h('h3', {}, 'Risk-Prioritized Queue'), h('span', { class: 'grow' }),
          h('span', { class: 'sub' }, 'exploit-aware composite + ML'),
          h('span', { class: 'btn ghost', style: 'padding:5px 12px;font-size:12px', onclick: () => go('triage') }, 'View all →')),
        h('table', { class: 'tbl' }, h('tbody', {}, ranking.slice(0, 7).map(f => findingRow(f, true))))),
      // risk posture donut
      h('div', { class: 'card pad' },
        h('div', { class: 'section-t' }, 'Risk Posture'),
        donut([
          { label: 'Critical', value: bands.crit, color: SEVCOLOR.crit },
          { label: 'High', value: bands.high, color: SEVCOLOR.high },
          { label: 'Medium', value: bands.med, color: SEVCOLOR.med },
          { label: 'Low', value: bands.low, color: SEVCOLOR.low },
          { label: 'Info', value: bands.info, color: SEVCOLOR.info },
        ], ranking.length, 'findings')),
    ),
    h('div', { class: 'grid g-3 fade-in' },
      // severity breakdown
      h('div', { class: 'card pad' }, h('div', { class: 'section-t' }, 'Severity Breakdown'),
        hbars([
          { label: 'Critical', value: sevAgg.CRITICAL || 0, color: SEVCOLOR.crit },
          { label: 'High', value: sevAgg.HIGH || 0, color: SEVCOLOR.high },
          { label: 'Medium', value: sevAgg.MEDIUM || 0, color: SEVCOLOR.med },
          { label: 'Low', value: sevAgg.LOW || 0, color: SEVCOLOR.low },
        ])),
      // fusion: tools
      h('div', { class: 'card pad' }, h('div', { class: 'section-t' }, `Detection Fusion · ${corroborated} corroborated`),
        hbars(Object.entries(tools).sort((a, b) => b[1] - a[1]).map(([k, v], i) =>
          ({ label: k, value: v, color: ['#38bdf8', '#6366f1', '#a855f7', '#34d399', '#fb923c'][i % 5] })))),
      // ATT&CK coverage
      h('div', { class: 'card pad' }, h('div', { class: 'section-t' }, `ATT&CK Coverage · ${attacks.size} techniques`),
        h('div', { class: 'cellwrap' }, attacks.size
          ? [...attacks].slice(0, 14).map(a => h('span', { class: 'pill attack' }, a))
          : [h('div', { class: 'muted' }, 'No mapped techniques yet')]),
        h('div', { class: 'section-t', style: 'margin-top:18px' }, 'Top Exploited CVEs'),
        h('div', {}, (stats.top_cves || []).slice(0, 5).map(c => h('div', { class: 'hbar-row', style: 'grid-template-columns:1fr auto' },
          h('div', { class: 'cellwrap' }, h('span', { class: 'mono' }, c.cve_id), c.kev ? h('span', { class: 'pill kev' }, 'KEV') : null),
          h('div', { class: 'n' }, `×${c.occurrences}`)))))
    ),
  );
}

function findingRow(f, compact) {
  const b = band(f.risk_score);
  const tds = [
    h('td', {}, h('span', { class: 'rankbadge' + (f.risk_rank <= 3 ? ' top' : '') }, '#' + (f.risk_rank ?? '—'))),
    h('td', {}, scoreMeter(f.risk_score)),
    h('td', { class: 'titlecell' },
      h('div', { class: 't' }, f.title || f.cve_id || 'finding'),
      h('div', { class: 'm' }, `${f.asset_id} · ${f.domain}`)),
    h('td', {}, h('div', { class: 'cellwrap' }, toolPill(f.source_tool), consensusPill(f.consensus))),
    h('td', {}, h('div', { class: 'cellwrap' },
      f.kev ? h('span', { class: 'pill kev' }, 'KEV') : null,
      f.attack ? h('span', { class: 'pill attack' }, f.attack) : null,
      f.threat_intel ? h('span', { class: 'pill intel' }, 'IOC') : null,
      (!f.kev && !f.attack && !f.threat_intel) ? h('span', { class: 'muted' }, '—') : null)),
  ];
  if (!compact) tds.push(h('td', {}, sevPill(f.severity)));
  return h('tr', { onclick: () => openFinding(f.id) }, tds);
}

async function viewTriage(root) {
  root.append(loading());
  const ranking = await apiSafe('/risk/ranking?limit=150', []);
  state.ranking = ranking;
  root.innerHTML = '';
  root.append(h('div', { class: 'card fade-in' },
    h('div', { class: 'card-h' }, h('h3', {}, 'Triage Queue'), h('span', { class: 'grow' }),
      h('span', { class: 'sub' }, `${ranking.length} findings · ranked by composite risk`)),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['Rank', 'Risk', 'Finding', 'Detected by', 'Signals', 'Severity'].map(t => h('th', {}, t)))),
      h('tbody', {}, ranking.length ? ranking.map(f => findingRow(f, false))
        : [h('tr', {}, h('td', { colspan: 6 }, h('div', { class: 'empty' }, 'No findings yet — run an assessment.')))])))));
}

async function viewIncidents(root) {
  root.append(loading());
  const inc = await apiSafe('/incidents?limit=200', []);
  root.innerHTML = '';
  root.append(h('div', { class: 'card fade-in' },
    h('div', { class: 'card-h' }, h('h3', {}, 'Incident Case Management'), h('span', { class: 'grow' }),
      h('span', { class: 'sub' }, `${inc.length} cases · SLA-tracked`)),
    h('div', { style: 'overflow-x:auto' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, ['ID', 'Incident', 'Severity', 'Status', 'SLA', 'Findings', 'Opened'].map(t => h('th', {}, t)))),
      h('tbody', {}, inc.length ? inc.map(i => h('tr', {},
        h('td', { class: 'num' }, '#' + i.id),
        h('td', {}, h('div', { class: 't', style: 'font-weight:560' }, i.title)),
        h('td', {}, sevPill(i.severity)),
        h('td', {}, h('span', { class: 'pill ' + (i.status === 'open' ? 'high' : i.status === 'resolved' || i.status === 'closed' ? 'ok' : 'info') }, i.status)),
        h('td', {}, i.sla_breached ? h('span', { class: 'pill crit' }, 'BREACHED') : h('span', { class: 'pill ok' }, 'on track'),
          h('div', { class: 'm muted', style: 'font-size:11px;margin-top:3px' }, fmtDate(i.sla_due))),
        h('td', { class: 'num' }, i.finding_count ?? 0),
        h('td', { class: 'muted' }, since(i.created_at)),
      )) : [h('tr', {}, h('td', { colspan: 7 }, h('div', { class: 'empty' }, 'No incidents open.')))])))));
}

async function viewCompliance(root) {
  root.append(loading());
  const [comp, chain] = await Promise.all([apiSafe('/compliance/summary', {}), apiSafe('/compliance/evidence/verify', {})]);
  root.innerHTML = '';
  const by = {}; (comp.by_status || []).forEach(s => by[s.status] = s.count);
  const graded = (by.pass || 0) + (by.fail || 0) + (by.partial || 0) || 1;
  root.append(
    h('div', { class: 'grid g-2 fade-in', style: 'margin-bottom:16px' },
      h('div', { class: 'card pad' }, h('div', { class: 'section-t' }, 'CIS Control Posture'),
        donut([
          { label: 'Pass', value: by.pass || 0, color: '#34d399' },
          { label: 'Fail', value: by.fail || 0, color: '#fb3b6b' },
          { label: 'Partial', value: by.partial || 0, color: '#fbbf24' },
          { label: 'N/A', value: by.not_applicable || 0, color: '#64748b' },
        ], Math.round(((by.pass || 0) / graded) * 100) + '%', 'compliant')),
      h('div', { class: 'card pad' }, h('div', { class: 'section-t' }, 'Tamper-Evident Evidence Chain'),
        h('div', { class: 'consensus-box', style: chain.ok ? '' : 'border-color:rgba(251,59,107,.4)' },
          h('div', { html: icon('shield'), style: `width:34px;height:34px;color:${chain.ok ? '#34d399' : '#fb3b6b'}` }),
          h('div', {}, h('div', { style: 'font-weight:650;font-size:15px' }, chain.ok ? 'Chain intact ✓' : 'Chain BROKEN ✗'),
            h('div', { class: 'muted', style: 'font-size:12px' }, `${chain.length ?? 0} hash-linked records (SHA-256)`))),
        h('div', { class: 'kv', style: 'margin-top:16px' },
          h('div', { class: 'k' }, 'Head hash'), h('div', { class: 'v mono', style: 'font-size:11px;word-break:break-all' }, chain.head_hash || '—'),
          h('div', { class: 'k' }, 'Records'), h('div', { class: 'v' }, String(chain.length ?? 0)))),
    ),
    h('div', { class: 'card fade-in' }, h('div', { class: 'card-h' }, h('h3', {}, 'Per-Asset Compliance Score')),
      h('div', { class: 'pad' }, hbars((comp.per_asset || []).map(a => ({ label: a.asset_id, value: Math.round(+a.score_pct), color: +a.score_pct >= 70 ? '#34d399' : +a.score_pct >= 40 ? '#fbbf24' : '#fb3b6b' })), 100)))
  );
}

/* ===================================================================== *
 *  FINDING DETAIL DRAWER (XAI)  — the centerpiece
 * ===================================================================== */
async function openFinding(id) {
  const drawer = $('#drawer'), ov = $('#overlay'), inner = $('#drawer-inner');
  ov.classList.add('show'); drawer.classList.add('show');
  inner.innerHTML = ''; inner.append(loading());
  const data = await apiSafe(`/findings/${id}/explain`, null);
  if (!data || !data.finding) { inner.innerHTML = ''; inner.append(h('div', { class: 'empty' }, 'No detail available.')); return; }
  const f = data.finding, ml = data.ml_explanation || {}, comp = data.composite_components || {}, con = data.consensus;
  inner.innerHTML = '';

  inner.append(
    h('div', { class: 'drawer-h' },
      h('div', {},
        h('div', { class: 'cellwrap', style: 'margin-bottom:8px' }, sevPill(f.severity), toolPill(f.source_tool), consensusPill(con),
          f.attack ? h('span', { class: 'pill attack' }, f.attack) : null,
          f.threat_intel ? h('span', { class: 'pill intel' }, 'Live IOC' ) : null),
        h('div', { style: 'font-size:18px;font-weight:680;line-height:1.3' }, f.title),
        h('div', { class: 'muted', style: 'margin-top:4px;font-size:12.5px' }, `${f.domain} · finding #${f.id}`)),
      h('div', { class: 'x', html: '✕', onclick: closeDrawer })),
  );

  const body = h('div', { class: 'drawer-b' });
  inner.append(body);

  // scores
  body.append(h('div', { class: 'grid', style: 'grid-template-columns:1fr 1fr' },
    scoreCard('Composite Risk', f.risk_score, 'transparent 10-factor weighted'),
    scoreCard('ML Risk (XGBoost)', f.ml_risk_score, 'learns non-linear interactions')));

  // consensus
  if (con && (con.n_tools || 0) >= 1) {
    const w = Math.round((con.weight || 0) * 100);
    body.append(h('div', {},
      h('div', { class: 'section-t' }, 'Multi-Tool Consensus'),
      h('div', { class: 'consensus-box' },
        h('div', { class: 'ring', html: ringSvg(con.weight || 0, con.n_tools) }),
        h('div', { style: 'flex:1' },
          h('div', { style: 'font-weight:650;margin-bottom:6px' },
            con.n_tools > 1 ? `Corroborated by ${con.n_tools} independent tools` : 'Single-source detection'),
          h('div', { class: 'tools' }, (con.tools || []).map(toolPill)),
          h('div', { class: 'muted', style: 'font-size:12px;margin-top:8px' },
            `Consensus weight ${w}% — ${con.n_tools > 1 ? 'raises priority; independent corroboration is a strong trust signal.' : 'no corroboration yet.'}`)))));
  }

  // SHAP waterfall (the star)
  if (Array.isArray(ml.waterfall) && ml.waterfall.length) {
    body.append(h('div', {},
      h('div', { class: 'section-t' }, `${icon('brain') ? '' : ''}Why this score — SHAP waterfall`),
      h('div', { class: 'card pad' }, waterfall(ml.waterfall)),
      h('div', { class: 'muted', style: 'font-size:11.5px;margin-top:8px' },
        'Each factor pushes the model\'s base value up (red) or down (green) to the final ML score.')));
  } else if (Object.keys(comp).length) {
    body.append(h('div', {}, h('div', { class: 'section-t' }, 'Composite factor contributions'),
      h('div', { class: 'card pad' }, hbars(Object.entries(comp).sort((a, b) => b[1] - a[1])
        .map(([k, v]) => ({ label: k, value: Math.round(+v) })), Math.max(...Object.values(comp).map(Number), 1)))));
  }

  // composite breakdown (always, if present)
  if (Object.keys(comp).length) {
    body.append(h('div', {}, h('div', { class: 'section-t' }, 'Composite breakdown (points of 100)'),
      h('div', { class: 'card pad' }, hbars(Object.entries(comp).sort((a, b) => b[1] - a[1])
        .map(([k, v]) => ({ label: k, value: Math.round(+v), color: '#6366f1' })), Math.max(...Object.values(comp).map(Number), 1)))));
  }

  // counterfactuals
  if (Array.isArray(ml.counterfactuals) && ml.counterfactuals.length) {
    body.append(h('div', {}, h('div', { class: 'section-t' }, 'What-if (counterfactuals)'),
      h('div', {}, ml.counterfactuals.map(c => h('div', { class: 'cf-item' },
        h('span', {}, c.change), h('span', { class: 'delta ' + ((c.delta || 0) < 0 ? 'down' : 'up') },
          `${(c.delta || 0) < 0 ? '' : '+'}${num(c.delta, 1)} → ${num(c.new_score, 0)}`))))));
  }

  // feedback
  body.append(feedbackForm(f.id));
}

function scoreCard(label, score, sub) {
  const b = band(score);
  return h('div', { class: 'card pad' },
    h('div', { class: 'label muted', style: 'font-size:11px;text-transform:uppercase;letter-spacing:.7px' }, label),
    h('div', { style: 'display:flex;align-items:baseline;gap:8px;margin-top:6px' },
      h('div', { class: 'sev-text ' + b, style: 'font-size:32px;font-weight:740;font-variant-numeric:tabular-nums' }, num(score, 1)),
      h('span', { class: 'pill ' + b }, bandLabel[b])),
    h('div', { class: 'muted', style: 'font-size:11.5px;margin-top:4px' }, sub));
}

function ringSvg(weight, n) {
  const R = 26, C = 2 * Math.PI * R, len = Math.max(0, Math.min(1, weight)) * C;
  return `<svg width="64" height="64" viewBox="0 0 64 64">
    <circle r="${R}" cx="32" cy="32" fill="none" stroke="#16223a" stroke-width="7"/>
    <circle r="${R}" cx="32" cy="32" fill="none" stroke="#34d399" stroke-width="7" stroke-linecap="round"
      stroke-dasharray="${len} ${C - len}" transform="rotate(-90 32 32)"/>
    <text x="32" y="37" text-anchor="middle" fill="#eaf1ff" font-size="18" font-weight="700" font-family="ui-monospace,monospace">${n}</text></svg>`;
}

function waterfall(rows) {
  const cums = rows.map(r => +r.cumulative);
  const lo = Math.min(0, ...cums), hi = Math.max(...cums), range = (hi - lo) || 1;
  const X = v => ((v - lo) / range) * 100;
  const baseCum = +rows[0].cumulative;
  const wrap = h('div', { class: 'waterfall' });
  rows.forEach((r, i) => {
    const isBase = i === 0, isFinal = i === rows.length - 1;
    const track = h('div', { class: 'wf-track' }, h('div', { class: 'axis', style: `left:${X(baseCum)}%` }));
    let left, width, cls, valTxt, valCls = '';
    if (isBase || isFinal) {
      left = X(0); width = X(+r.cumulative) - X(0); cls = 'anchor';
      valTxt = num(r.cumulative, 1);
    } else {
      const prev = +rows[i - 1].cumulative, cur = +r.cumulative;
      left = X(Math.min(prev, cur)); width = Math.abs(X(cur) - X(prev));
      const pos = (+r.contribution) >= 0; cls = pos ? 'pos' : 'neg';
      valCls = pos ? 'pos' : 'neg'; valTxt = (pos ? '+' : '') + num(r.contribution, 2);
    }
    track.append(h('div', { class: 'wf-bar ' + cls, style: `left:${left}%;width:${Math.max(width, 0.6)}%` }));
    const label = isBase ? 'base value' : isFinal ? 'ML score' : r.feature;
    wrap.append(h('div', { class: 'wf-row' + (isBase ? ' base' : '') + (isFinal ? ' final' : '') },
      h('div', { class: 'k' }, label), track, h('div', { class: 'val ' + valCls }, valTxt)));
  });
  return wrap;
}

function feedbackForm(id) {
  let action = 'accept', priority = 60;
  const box = h('div', {});
  const seg = h('div', { class: 'seg' });
  ['accept', 'escalate', 'deprioritize', 'dismiss'].forEach((a, i) => {
    const btn = h('button', { class: i === 0 ? 'sel' : '', onclick: () => { action = a; $$('button', seg).forEach(b => b.classList.remove('sel')); btn.classList.add('sel'); } }, a);
    seg.append(btn);
  });
  const prVal = h('span', { class: 'mono', style: 'color:var(--accent);font-weight:700' }, priority + '');
  const range = h('input', { class: 'range', type: 'range', min: '0', max: '100', value: priority, oninput: e => { priority = +e.target.value; prVal.textContent = priority; } });
  const comment = h('textarea', { rows: '2', placeholder: 'Analyst rationale (feeds the monthly retraining loop)…' });
  const submit = h('button', { class: 'btn primary', onclick: async () => {
    submit.textContent = 'Saving…'; submit.disabled = true;
    try {
      await api(`/findings/${id}/feedback`, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst: 'analyst', action, label_priority: priority, comment: comment.value || null }) });
      toast('Feedback captured — will steer the next retrain', true);
      comment.value = '';
    } catch { toast('Failed to submit feedback'); }
    submit.textContent = 'Submit feedback'; submit.disabled = false;
  } }, 'Submit feedback');

  box.append(
    h('div', { class: 'section-t' }, 'Analyst decision'),
    h('div', { class: 'card pad', style: 'display:flex;flex-direction:column;gap:14px' },
      seg,
      h('div', { class: 'field' }, h('label', {}, ['Priority label ', prVal, ' / 100']), range),
      h('div', { class: 'field' }, h('label', {}, 'Comment'), comment),
      h('div', { style: 'display:flex;justify-content:flex-end' }, submit)));
  return box;
}

/* ---- shell helpers --------------------------------------------------- */
function loading() { return h('div', { class: 'center-pad' }, h('div', { class: 'spinner' }), h('div', {}, 'Loading…')); }
function closeDrawer() { $('#overlay').classList.remove('show'); $('#drawer').classList.remove('show'); }
let toastT;
function toast(msg, ok) { const t = $('#toast'); t.className = 'toast show' + (ok ? ' ok' : ''); t.innerHTML = (ok ? '✓ ' : '⚠ ') + msg; clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 3200); }

/* ---- router ---------------------------------------------------------- */
const ROUTES = {
  overview: { title: 'Command Center', crumb: 'Real-time security posture', icon: 'grid', view: viewOverview },
  triage: { title: 'Triage', crumb: 'Risk-prioritized findings queue', icon: 'list', view: viewTriage },
  incidents: { title: 'Incidents', crumb: 'Case management & SLA tracking', icon: 'alert', view: viewIncidents },
  compliance: { title: 'Compliance', crumb: 'CIS posture & tamper-evident evidence', icon: 'shield', view: viewCompliance },
};
function buildNav() {
  const nav = $('#nav'); nav.innerHTML = '';
  for (const [key, r] of Object.entries(ROUTES))
    nav.append(h('div', { class: 'nav-item', 'data-route': key, onclick: () => go(key), html: icon(r.icon) + `<span>${r.title}</span>` }));
}
function go(route) {
  const r = ROUTES[route] || ROUTES.overview;
  location.hash = route;
  $('#page-title').textContent = r.title; $('#page-crumb').textContent = r.crumb;
  $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.route === route));
  closeDrawer();
  const root = $('#content'); root.innerHTML = '';
  r.view(root).catch(e => { root.innerHTML = ''; root.append(h('div', { class: 'empty' }, 'Error: ' + e.message)); });
}

/* ---- boot ------------------------------------------------------------ */
async function boot() {
  buildNav();
  $('#overlay').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

  // header status + footer
  const [ver, ready, chain] = await Promise.all([
    apiSafe('/version', {}), apiSafe('/health/ready', {}), apiSafe('/compliance/evidence/verify', {})]);
  $('#ver').textContent = ver.version || '·';
  $('#chain').innerHTML = chain.ok ? '<span class="statusdot"></span> intact' : '<span class="statusdot warn"></span> check';
  const ok = ready.status === 'ok' || ready.status === 'ready' || ready.ready;
  $('#topbar-stat').append(
    h('span', { class: 'tag-air' }, h('span', { class: 'statusdot' + (ok ? '' : ' warn') }), 'Stores ' + (ok ? 'healthy' : 'degraded')),
  );

  go((location.hash || '#overview').slice(1) in ROUTES ? location.hash.slice(1) : 'overview');
}
window.addEventListener('hashchange', () => { const r = location.hash.slice(1); if (r in ROUTES) go(r); });
boot();
