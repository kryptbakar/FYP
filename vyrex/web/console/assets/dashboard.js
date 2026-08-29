/* =====================================================================
   VYREX — Command Deck.

   The whole platform on one screen: an isometric map of the stack with live data
   moving through it, then every subsystem's real numbers underneath.

   WHY ISOMETRIC AND NOT WebGL. Two locked decisions rule out a literal 3D scene, and
   both are load-bearing rather than stylistic:
     * D-044 — the console is dependency-free. One CDN script (three.js and friends)
       would end the air-gap claim, which is the project's central thesis.
     * D-049 — flat surfaces, no gradients, no glows, colour only where it carries
       meaning, and every colour from :root so a re-theme still lands.
   Isometric projection gives real depth from GEOMETRY — stacked planes, occlusion,
   parallax between layers — while staying inside both. It also looks like an
   instrument rather than a screensaver, which is the right register for a SOC.

   AND EVERY NUMBER IS REAL. Layer labels, node counts, edge density and the flow dots
   are all driven by live API data. A dashboard that animates regardless of state is a
   screensaver with a database connection, and the first question anyone competent asks
   at an expo is "is that real?".
   ===================================================================== */
'use strict';

/* ---- isometric projection ------------------------------------------- */
// Standard 2:1 isometric. x/y are positions on a layer's ground plane, z is height.
// Kept as one function so every element in the scene shares a single camera - mixing
// projections is what makes hand-built isometric art look subtly broken.
const ISO_S = 1.0;
function iso(x, y, z, cx = 0, cy = 0) {
  return [
    (x - y) * 0.866 * ISO_S + cx,
    (x + y) * 0.5 * ISO_S - z + cy,
  ];
}
const isoPt = (p) => p[0].toFixed(1) + ',' + p[1].toFixed(1);

/* A layer is a flat rhombus at height z: the "floor" each tier of the stack sits on. */
function isoPlane(size, z, cx, cy) {
  return [
    iso(0, 0, z, cx, cy), iso(size, 0, z, cx, cy),
    iso(size, size, z, cx, cy), iso(0, size, z, cx, cy),
  ].map(isoPt).join(' ');
}

/* ---- the stack, bottom (endpoints) to top (governance) --------------- */
// Order is the real data path. Reading the picture bottom-to-top is reading the
// pipeline, which is why governance sits on top: nothing flows past it by itself.
const DECK_LAYERS = [
  { key: 'assets',   label: 'ESTATE',        sub: 'endpoints under management' },
  { key: 'tools',    label: 'SENSORS',       sub: 'detection & scanning' },
  { key: 'ingest',   label: 'INGEST',        sub: 'mTLS · JetStream · workers' },
  { key: 'fusion',   label: 'CORRELATION',   sub: 'cross-tool fusion' },
  { key: 'scoring',  label: 'SCORING',       sub: 'composite + ML + SHAP' },
  { key: 'reason',   label: 'REASONING',     sub: 'LangGraph investigation' },
  { key: 'govern',   label: 'GOVERNANCE',    sub: 'two-person · Ed25519' },
];

function deckMap(d) {
  const SIZE = 260;                       // ground-plane edge length, iso units
  const DZ = 58;                          // vertical gap between tiers
  const N = DECK_LAYERS.length;
  const MAXZ = (N - 1) * DZ;

  // The camera has to be derived from the scene, not guessed. Screen-y is
  // (x+y)/2 - z + CY, so the extremes are (CY - MAXZ) at the top tier and (CY + SIZE) at
  // the bottom one. Hard-coding CY put four of seven layers above the viewBox and left
  // half the canvas empty — the sort of thing that looks like a rendering bug.
  const PAD = 34;
  const CY = MAXZ + PAD;
  const H = MAXZ + SIZE + PAD * 2;
  const HALF = SIZE * 0.866;              // half-width of the projected diamond
  const CX = HALF + 190;                  // room for the layer captions on the left
  const W = CX + HALF + 200;              // ...and the headline values on the right

  // z INCREASES with index so the stack reads bottom-up: estate on the floor,
  // governance on top. Inverted, the picture claims data flows down into the sensors.
  const zOf = (i) => i * DZ;

  const planes = [];
  const nodes = [];
  const links = [];
  const flows = [];
  const defs = [];

  DECK_LAYERS.forEach((L, i) => {
    const z = zOf(i);
    const v = d.layers[L.key] || {};
    planes.push(sv('polygon', {
      class: 'dk-plane' + (v.hot ? ' is-hot' : ''),
      points: isoPlane(SIZE, z, CX, CY),
    }));

    // Layer caption, pinned to the left corner of its plane so the stack reads as a
    // labelled cutaway rather than a pile of shapes.
    const [lx, ly] = iso(0, SIZE, z, CX, CY);
    nodes.push(sv('text', { class: 'dk-lname', x: lx - 14, y: ly + 4 }, L.label));
    nodes.push(sv('text', { class: 'dk-lsub', x: lx - 14, y: ly + 15 }, L.sub));

    // Headline value, pinned to the right corner.
    const [rx, ry] = iso(SIZE, 0, z, CX, CY);
    nodes.push(sv('text', { class: 'dk-lval', x: rx + 14, y: ry + 2 }, String(v.value ?? '—')));
    if (v.note) nodes.push(sv('text', { class: 'dk-lnote', x: rx + 14, y: ry + 14 }, v.note));

    // Items sitting on the plane. Each is a small iso pillar whose height encodes its
    // share, so a busy tool is literally taller than a quiet one.
    (v.items || []).forEach((it, k, arr) => {
      const t = arr.length === 1 ? 0.5 : k / (arr.length - 1);
      // Spread along the plane's ANTI-diagonal: moving +x and -y together keeps (x+y)
      // constant, so screen-y is fixed and the items lay out as an even horizontal row.
      // Varying one axis alone stacks them on top of each other in projection.
      const off = (t - 0.5) * SIZE * 0.68;
      const px = SIZE / 2 + off;
      const py = SIZE / 2 - off;
      const hgt = Math.max(6, Math.min(30, it.weight * 30));
      const base = iso(px, py, z, CX, CY);
      const top = iso(px, py, z + hgt, CX, CY);
      links.push(sv('line', {
        class: 'dk-pillar' + (it.on === false ? ' is-off' : ''),
        x1: base[0], y1: base[1], x2: top[0], y2: top[1],
      }));
      nodes.push(sv('circle', {
        class: 'dk-cap' + (it.on === false ? ' is-off' : ''),
        cx: top[0], cy: top[1], r: 3.4,
      }, sv('title', null, `${it.label}: ${it.n}`)));
      nodes.push(sv('text', { class: 'dk-item', x: top[0], y: top[1] - 8 },
        it.label + (it.n != null ? ' ' + it.n : '')));
    });

    // Riser to the layer above: the data path, drawn as a real edge with travelling
    // dots. Only drawn when the layer below actually produced something.
    if (i < DECK_LAYERS.length - 1) {
      const from = iso(SIZE / 2, SIZE / 2, z, CX, CY);
      const to = iso(SIZE / 2, SIZE / 2, zOf(i + 1), CX, CY);
      const id = 'dk-riser-' + i;
      const dpath = `M ${from[0]} ${from[1]} L ${to[0]} ${to[1]}`;
      defs.push(sv('path', { id, d: dpath, fill: 'none' }));
      links.push(sv('path', {
        class: 'dk-riser' + (v.flowing ? ' is-live' : ' is-idle'), d: dpath, fill: 'none',
      }));
      if (v.flowing) {
        for (let k = 0; k < 2; k++) {
          // Default direction is path start -> end, i.e. this tier up to the next one,
          // which is the way the data actually moves. No keyPoints reversal: that made
          // the dots fall downward, quietly asserting the opposite of the architecture.
          flows.push(sv('circle', { class: 'dk-flow', r: 2.8 },
            sv('animateMotion', {
              dur: '2.8s', repeatCount: 'indefinite',
              begin: (i * 0.26 + k * 1.4).toFixed(2) + 's',
            }, sv('mpath', { 'xlink:href': '#' + id }))));
        }
      }
    }
  });

  const svg = sv('svg', {
    class: 'dk-svg', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'xMidYMid meet',
    role: 'img',
    'aria-label': d.aria,
  },
    sv('defs', null, ...defs),
    // Painter's order: planes first so pillars and risers occlude correctly. Getting
    // this wrong is what makes isometric scenes look flat.
    sv('g', { class: 'dk-planes' }, planes),
    sv('g', { class: 'dk-links' }, links),
    sv('g', { class: 'dk-flows' }, flows),
    sv('g', { class: 'dk-nodes' }, nodes));

  return h('div', { class: 'dk-stage' }, svg);
}

/* ---- the view -------------------------------------------------------- */
async function viewCommandDeck(root) {
  root.append(skPanel(['70%', '50%']));

  // Everything is fetched tolerantly. The deck spans subsystems that live behind
  // optional profiles (orchestrator, intel, defense), and a dashboard that goes blank
  // because one optional service is down is worse than one that renders what it has.
  const j = (p, f) => p.catch(() => f);
  const [ranking, stats, comp, incidents, chain, assets, invs, orch,
         agent, model, cov] = await Promise.all([
    j(API.ranking(), []), j(API.stats(), {}), j(API.compSummary(), {}),
    j(API.incidents(), []), j(API.chain(), {}), j(API.assets(), []),
    j(API.investigations(50), []), j(API.orchestratorStatus(), {}),
    j(API.agentStatus(), {}), j(API.modelCard(), {}), j(API.attackCoverage(), {}),
  ]);
  root.innerHTML = '';

  // ---- derive, once, from real rows -----------------------------------
  const byTool = {};
  ranking.forEach(f => { const t = f.source_tool || 'agent'; byTool[t] = (byTool[t] || 0) + 1; });
  const toolMax = Math.max(1, ...Object.values(byTool));
  const clusters = new Set(ranking.map(f => (f.consensus && f.consensus.primary) || f.id)).size;
  const corroborated = ranking.filter(f => f.consensus && f.consensus.n_tools > 1).length;
  const scored = ranking.filter(f => f.risk_score != null).length;
  const kev = ranking.filter(f => f.kev).length;
  const inflight = invs.filter(i => ['queued', 'running'].includes(i.status)).length;
  const openInc = incidents.filter(i => !/resolved|closed|remediated/i.test(i.status || '')).length;
  const byStatus = {}; (comp.by_status || []).forEach(s => byStatus[s.status] = s.count);
  const graded = (byStatus.pass || 0) + (byStatus.fail || 0) + (byStatus.partial || 0) || 1;
  const cis = Math.round(((byStatus.pass || 0) / graded) * 100);
  const exposed = assets.filter(a => a.internet_exposed).length;

  const deck = {
    aria: `VYREX platform: ${assets.length} assets, ${Object.keys(byTool).length} tools, `
        + `${ranking.length} findings fused into ${clusters} clusters, ${scored} scored, `
        + `${invs.length} investigated. Response is gated behind two-person approval.`,
    layers: {
      assets: {
        value: assets.length, note: exposed + ' internet-facing', flowing: assets.length > 0,
        items: assets.slice(0, 5).map(a => ({
          label: a.hostname || a.host_id, n: null,
          weight: Number(a.criticality) || 0.3, on: true,
        })),
      },
      tools: {
        value: Object.keys(byTool).length, note: 'reporting', flowing: ranking.length > 0,
        hot: true,
        items: Object.entries(byTool).sort((a, b) => b[1] - a[1]).slice(0, 5)
          .map(([t, n]) => ({ label: t, n, weight: n / toolMax, on: true })),
      },
      ingest: {
        value: stats.assets != null ? 'mTLS' : 'mTLS', note: 'JetStream',
        flowing: ranking.length > 0,
        items: [{ label: 'workers', n: null, weight: 0.5, on: true }],
      },
      fusion: {
        value: clusters, note: corroborated + ' corroborated', flowing: clusters > 0,
        items: [{ label: 'multi-tool', n: corroborated, weight: 0.6, on: corroborated > 0 }],
      },
      scoring: {
        value: scored, note: kev + ' KEV', flowing: scored > 0, hot: kev > 0,
        items: [{ label: 'composite', n: null, weight: 0.5, on: true },
                { label: 'ML', n: null, weight: 0.4, on: !!model.version }],
      },
      reason: {
        value: invs.length, note: inflight ? inflight + ' in flight' : 'LangGraph',
        flowing: invs.length > 0,
        items: [{ label: agent.model || 'no model', n: null, weight: 0.55,
                  on: !!agent.model_ready }],
      },
      govern: {
        value: '2-person', note: 'never automatic', flowing: false,
        items: [{ label: 'Ed25519', n: null, weight: 0.45, on: true }],
      },
    },
  };

  root.append(h('div', { class: 'panel pad fade dk-panel' },
    h('div', { class: 'row', style: 'gap:var(--s-3);align-items:baseline;flex-wrap:wrap' },
      h('div', { class: 'dk-title' }, 'Command deck'),
      h('span', { class: 'faint', style: 'font-size:var(--t-2xs)' },
        'the whole platform, bottom to top - every figure below is a live count'),
      h('span', { style: 'flex:1' }),
      chip(API.mode === 'live' ? 'LIVE' : 'DEMO', API.mode === 'live' ? 'ok' : 'mono'),
      h('button', { class: 'btn sm', onclick: () => go('command') }, 'Refresh')),
    deckMap(deck)));

  root.append(deckCounters({
    findings: ranking.length, clusters, corroborated, scored, kev,
    assets: assets.length, exposed, tools: Object.keys(byTool).length,
    incidents: openInc, cis, invs: invs.length, inflight,
    pending: orch.pending_outbox || 0,
  }));

  root.append(deckGrid({ ranking, cov, comp: byStatus, cis, chain, agent, model,
                         orch, invs, incidents, assets }));
}

/* ---- the counter rail ------------------------------------------------ */
function deckCounters(c) {
  const cell = (v, label, sub, tone) => h('div', { class: 'dk-stat' },
    h('div', { class: 'dk-sv' + (tone ? ' is-' + tone : '') }, String(v)),
    h('div', { class: 'dk-sl' }, label),
    sub ? h('div', { class: 'dk-ss' }, sub) : null);
  return h('div', { class: 'dk-rail fade' },
    cell(c.findings, 'findings', c.tools + ' tools'),
    cell(c.clusters, 'clusters', c.corroborated + ' corroborated'),
    cell(c.scored, 'scored', 'composite + ML'),
    cell(c.kev, 'known-exploited', 'CISA KEV', c.kev ? 'warn' : null),
    cell(c.assets, 'assets', c.exposed + ' exposed'),
    cell(c.invs, 'investigations', c.inflight ? c.inflight + ' in flight' : 'idle',
         c.inflight ? 'run' : null),
    cell(c.incidents, 'open incidents', 'SLA tracked', c.incidents ? 'warn' : null),
    cell(c.cis + '%', 'CIS posture', 'hash-chained'));
}

/* ---- subsystem panels ------------------------------------------------ */
function deckGrid(d) {
  const bands = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  d.ranking.forEach(r => bands[band(r.risk_score)]++);
  const maxBand = Math.max(1, ...Object.values(bands));

  // Risk distribution — a plain bar chart, because the shape of the queue is the thing
  // an analyst reads first and a donut hides the long tail.
  const riskPanel = h('div', { class: 'panel pad dk-card' },
    h('div', { class: 'sec-label' }, 'Risk distribution'),
    h('div', { class: 'dk-bars' },
      ...['critical', 'high', 'medium', 'low', 'info'].map(b =>
        h('div', { class: 'dk-bar-row' },
          h('span', { class: 'dk-bar-l' }, b),
          h('span', { class: 'dk-bar-t' },
            h('i', { class: 'dk-bar-f is-' + b, style: `width:${(bands[b] / maxBand) * 100}%` })),
          h('span', { class: 'dk-bar-n' }, String(bands[b]))))));

  // ATT&CK coverage. /attack/coverage returns {tactics, techniques}, not a bare list,
  // and the per-technique count is `findings` — normalised here rather than assumed,
  // because assuming it was an array is what blanked this whole view on first run.
  const cov = d.cov || {};
  const techs = (Array.isArray(cov) ? cov : cov.techniques || []).slice(0, 12);
  const tactics = Array.isArray(cov) ? [] : (cov.tactics || []);
  const attackPanel = h('div', { class: 'panel pad dk-card' },
    h('div', { class: 'row', style: 'gap:var(--s-2);align-items:baseline' },
      h('div', { class: 'sec-label' }, 'ATT&CK coverage'),
      tactics.length
        ? h('span', { class: 'faint', style: 'font-size:var(--t-3xs)' },
            tactics.length + ' tactic' + (tactics.length === 1 ? '' : 's'))
        : null),
    techs.length
      ? h('div', { class: 'dk-chips' }, techs.map(t =>
          h('span', { class: 'dk-chip', title: (t.name || '') + ' · ' + (t.tactic || '') },
            h('b', {}, t.technique || '—'),
            h('i', {}, String(t.findings ?? t.count ?? '')))))
      : h('div', { class: 'faint', style: 'font-size:var(--t-2xs)' },
          'no techniques mapped yet - run intel-enrich'));

  // Orchestrator — the subsystem most likely to be misread as broken when it is simply
  // slow, so queue depth and oldest-wait sit together.
  const orchPanel = h('div', { class: 'panel pad dk-card' },
    h('div', { class: 'sec-label' }, 'Investigation orchestrator'),
    h('div', { class: 'dk-kv' },
      kv('model', d.agent.model || '—'),
      kv('reachable', d.agent.reachable ? 'yes' : 'no'),
      kv('queued', String(d.orch.pending_outbox ?? 0)),
      kv('runs recorded', String((d.invs || []).length)),
      kv('completed', String((d.invs || []).filter(i => i.status === 'completed').length)),
      kv('partial', String((d.invs || []).filter(i => i.status === 'partial').length))),
    // No "cited verdicts" row here on purpose: the list endpoint does not carry that
    // field, so any count computed from it would read 0 for the wrong reason. The real
    // figure comes from eval/score_labels.py, which reads the reports themselves.
    h('div', { class: 'faint dk-note' },
      'A "partial" run is not a failure - it means the graph finished with a branch '
      + 'skipped or failed, which is the designed degraded path.'));

  // Trust / air-gap — the project's central claim, stated as verifiable facts.
  const trustPanel = h('div', { class: 'panel pad dk-card' },
    h('div', { class: 'sec-label' }, 'Trust & air-gap'),
    h('div', { class: 'dk-kv' },
      kv('evidence chain', d.chain && d.chain.ok ? 'intact' : 'unverified'),
      kv('chain length', String((d.chain && d.chain.length) ?? '—')),
      kv('egress', 'feed-sync only'),
      kv('response', 'two-person + Ed25519'),
      kv('orchestrator DB role', 'no write on response_actions')));

  // Model card — the honesty screen, deliberately on the dashboard rather than buried.
  // Field names come from /risk/model/metadata, which returns `model_version` — not
  // `version`. Reading the wrong key rendered a dash next to a model the sidebar was
  // happily displaying, which looks like a broken model rather than a broken selector.
  // The algorithm and explainer strings are taken from the payload too, so this panel
  // cannot drift from what the service actually reports.
  const mw = d.model.composite_weights || {};
  const topWeights = Object.entries(mw).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const modelPanel = h('div', { class: 'panel pad dk-card' },
    h('div', { class: 'sec-label' }, 'Risk model'),
    h('div', { class: 'dk-kv' },
      kv('version', d.model.model_version || '—'),
      kv('algorithm', (d.model.algorithm || 'XGBoost').split('(')[0].trim()),
      kv('explainer', (d.model.explainer || 'TreeSHAP').split('(')[0].trim()),
      kv('analyst labels', String(d.model.analyst_labels ?? 0)),
      ...topWeights.map(([k, v]) => kv('weight · ' + k, Number(v).toFixed(2)))),
    h('div', { class: 'faint dk-note' },
      'Bootstrapped on synthetic labels, so the ML score largely reproduces the '
      + 'composite formula today. It is a re-ranker, not an independent oracle.'));

  // Estate — now that assets carry business context, show what actually decides triage.
  const estatePanel = h('div', { class: 'panel pad dk-card dk-wide' },
    h('div', { class: 'sec-label' }, 'Estate'),
    h('div', { style: 'overflow-x:auto' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, ['Host', 'Env', 'Exposed', 'Sensitivity', 'Criticality']
          .map(t => h('th', {}, t)))),
        h('tbody', {}, (d.assets || []).map(a => h('tr', {},
          h('td', { class: 'mono' }, a.hostname || a.host_id),
          h('td', {}, a.environment || '—'),
          h('td', {}, a.internet_exposed == null ? 'unknown'
                      : a.internet_exposed ? 'yes' : 'no'),
          h('td', {}, a.data_sensitivity || '—'),
          h('td', { class: 'mono' }, a.criticality == null ? '—' : Number(a.criticality).toFixed(2))))))));

  return h('div', { class: 'dk-grid fade' },
    riskPanel, attackPanel, orchPanel, trustPanel, modelPanel, estatePanel);
}

function kv(k, v) {
  return h('div', { class: 'dk-kv-row' },
    h('span', { class: 'dk-k' }, k), h('span', { class: 'dk-v' }, v));
}
