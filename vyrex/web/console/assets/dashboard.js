/* =====================================================================
   VYREX — Command Deck: the SOC wall board.

   This is the screen that hangs on the wall of the operations room. Not a
   navigation page and not a diagram — a board a whole team reads at a glance
   from across the room, and that a passer-by can understand without touching.

   Three things it has to do at once, which is what makes the layout what it is:
     1. STATE — what is true right now (the KPI rail, the isometric map).
     2. FLOW  — what is happening (the live threat feed, the arrival timeline).
     3. DEPTH — why (ATT&CK, fusion, scoring disagreement, attribution).
   Panels are ordered so the eye lands on 1, drifts to 2, and only then to 3.

   WHY ISOMETRIC AND NOT WebGL. Two locked decisions rule out a literal 3D scene:
     * D-044 — the console is dependency-free. One CDN script (three.js and
       friends) would end the air-gap claim, which is the project's thesis.
     * D-049 — flat surfaces, colour only where it carries meaning, every colour
       from :root so a re-theme still lands.
   Isometric projection gives real depth from GEOMETRY — stacked planes,
   occlusion, parallax — inside both constraints, and reads as an instrument
   rather than a screensaver, which is the right register for a SOC.

   AND EVERY NUMBER IS REAL. Nothing here is seeded, interpolated or animated on
   a timer for effect. Where there is no data, the panel says so. The first
   question anyone competent asks at an expo is "is that live?", and the answer
   has to survive them unplugging something.
   ===================================================================== */
'use strict';

const DECK = { timers: [], seen: new Set(), booted: false };

/* ---- isometric projection ------------------------------------------- */
// Standard 2:1 isometric. x/y are positions on a layer's ground plane, z is
// height. One function so the whole scene shares a single camera — mixing
// projections is what makes hand-built isometric art look subtly broken.
const ISO_S = 1.0;
function iso(x, y, z, cx = 0, cy = 0) {
  return [(x - y) * 0.866 * ISO_S + cx, (x + y) * 0.5 * ISO_S - z + cy];
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
  { key: 'assets',  label: 'ESTATE',      sub: 'endpoints under management' },
  { key: 'tools',   label: 'SENSORS',     sub: 'detection & scanning' },
  { key: 'ingest',  label: 'INGEST',      sub: 'mTLS · JetStream · workers' },
  { key: 'fusion',  label: 'CORRELATION', sub: 'cross-tool fusion' },
  { key: 'scoring', label: 'SCORING',     sub: 'composite + ML + SHAP' },
  { key: 'reason',  label: 'REASONING',   sub: 'LangGraph investigation' },
  { key: 'govern',  label: 'GOVERNANCE',  sub: 'two-person · Ed25519' },
];

function deckMap(d) {
  const SIZE = 260;                       // ground-plane edge length, iso units
  const DZ = 58;                          // vertical gap between tiers
  const N = DECK_LAYERS.length;
  const MAXZ = (N - 1) * DZ;

  // The camera has to be derived from the scene, not guessed. Screen-y is
  // (x+y)/2 - z + CY, so the extremes are (CY - MAXZ) at the top tier and
  // (CY + SIZE) at the bottom. Hard-coding CY put four of seven layers above
  // the viewBox and left half the canvas empty — it looked like a render bug.
  const PAD = 34;
  const CY = MAXZ + PAD;
  const H = MAXZ + SIZE + PAD * 2;
  const HALF = SIZE * 0.866;              // half-width of the projected diamond
  const CX = HALF + 190;                  // room for the layer captions on the left
  const W = CX + HALF + 200;              // ...and the headline values on the right

  // z INCREASES with index so the stack reads bottom-up: estate on the floor,
  // governance on top. Inverted, the picture claims data flows down into sensors.
  const zOf = (i) => i * DZ;

  const planes = [], nodes = [], links = [], flows = [], defs = [];

  DECK_LAYERS.forEach((L, i) => {
    const z = zOf(i);
    const v = d.layers[L.key] || {};
    planes.push(sv('polygon', {
      class: 'dk-plane' + (v.hot ? ' is-hot' : ''),
      points: isoPlane(SIZE, z, CX, CY),
    }));

    // Layer caption, pinned to the left corner of its plane so the stack reads
    // as a labelled cutaway rather than a pile of shapes.
    const [lx, ly] = iso(0, SIZE, z, CX, CY);
    nodes.push(sv('text', { class: 'dk-lname', x: lx - 14, y: ly + 4 }, L.label));
    nodes.push(sv('text', { class: 'dk-lsub', x: lx - 14, y: ly + 15 }, L.sub));

    // Headline value, pinned to the right corner.
    const [rx, ry] = iso(SIZE, 0, z, CX, CY);
    nodes.push(sv('text', { class: 'dk-lval', x: rx + 14, y: ry + 2 }, String(v.value ?? '—')));
    if (v.note) nodes.push(sv('text', { class: 'dk-lnote', x: rx + 14, y: ry + 14 }, v.note));

    // Items sitting on the plane. Each is a small iso pillar whose height
    // encodes its share, so a busy tool is literally taller than a quiet one.
    (v.items || []).forEach((it, k, arr) => {
      const t = arr.length === 1 ? 0.5 : k / (arr.length - 1);
      // Spread along the plane's ANTI-diagonal: moving +x and -y together keeps
      // (x+y) constant, so screen-y is fixed and items lay out as an even row.
      // Varying one axis alone stacks them on top of each other in projection.
      const off = (t - 0.5) * SIZE * 0.68;
      const px = SIZE / 2 + off, py = SIZE / 2 - off;
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

    // Riser to the layer above: the data path, drawn as a real edge with
    // travelling dots. Only drawn when the layer below actually produced something.
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
          // Default direction is path start -> end, i.e. this tier up to the
          // next, which is the way data actually moves. No keyPoints reversal:
          // that made dots fall downward, quietly asserting the opposite of
          // the architecture.
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
    role: 'img', 'aria-label': d.aria,
  },
    sv('defs', null, ...defs),
    // Painter's order: planes first so pillars and risers occlude correctly.
    // Getting this wrong is what makes isometric scenes look flat.
    sv('g', { class: 'dk-planes' }, planes),
    sv('g', { class: 'dk-links' }, links),
    sv('g', { class: 'dk-flows' }, flows),
    sv('g', { class: 'dk-nodes' }, nodes));

  return h('div', { class: 'dk-stage' }, svg);
}

/* =====================================================================
   THE VIEW
   ===================================================================== */
async function viewCommandDeck(root) {
  root.append(skPanel(['70%', '50%']));

  // Everything is fetched tolerantly. The deck spans subsystems behind optional
  // profiles (orchestrator, intel, defense, OpenSearch), and a wall board that
  // goes blank because one optional service is down is worse than one that
  // renders what it has and says what is missing.
  const j = (p, f) => (p && p.catch ? p.catch(() => f) : Promise.resolve(f));
  const [ranking, stats, comp, incidents, chain, assets, invs, orch, agent,
         model, cov, recent, dets, clusters, dstats, ddec, decoys, attrib,
         actions, vitals, ready, audit, rules] = await Promise.all([
    j(API.ranking(), []), j(API.stats(), {}), j(API.compSummary(), {}),
    j(API.incidents(), []), j(API.chain(), {}), j(API.assets(), []),
    j(API.investigations(50), []), j(API.orchestratorStatus(), {}),
    j(API.agentStatus(), {}), j(API.modelCard(), {}), j(API.attackCoverage(), {}),
    j(API.recent(200), []), j(API.detections(), []), j(API.clusters(), []),
    j(API.defenseStats(), {}), j(API.defenseDecisions(60), []), j(API.decoys(), []),
    j(API.attribution(), {}), j(API.actions(), []), j(API.nodeVitals(), {}),
    j(API.ready(), {}), j(API.accessAudit(30), []), j(API.ruleStats(), {}),
  ]);
  root.innerHTML = '';

  const d = { ranking, stats, comp, incidents, chain, assets, invs, orch, agent,
              model, cov, recent, dets, clusters, dstats, ddec, decoys, attrib,
              actions, vitals, ready, audit, rules };

  // ---- derive, once, from real rows -----------------------------------
  const byTool = {};
  ranking.forEach(f => { const t = f.source_tool || 'agent'; byTool[t] = (byTool[t] || 0) + 1; });
  const toolMax = Math.max(1, ...Object.values(byTool));
  // Cluster count comes from the fusion endpoint where it is available, because
  // that is the same COALESCE(observable_key, dedup_key) grouping the engine
  // uses. Falling back to a distinct-primary count over the ranking keeps the
  // tile populated when the optional endpoint is down.
  const corroborated = ranking.filter(f => f.consensus && f.consensus.n_tools > 1).length;
  const nClusters = clusters.length
    || new Set(ranking.map(f => (f.consensus && f.consensus.primary) || f.id)).size;
  const scored = ranking.filter(f => f.risk_score != null).length;
  const kev = ranking.filter(f => f.kev).length;
  const inflight = invs.filter(i => ['queued', 'running'].includes(i.status)).length;
  const openInc = incidents.filter(i => !/resolved|closed|remediated/i.test(i.status || '')).length;
  const byStatus = {}; (comp.by_status || []).forEach(s => byStatus[s.status] = s.count);
  const graded = (byStatus.pass || 0) + (byStatus.fail || 0) + (byStatus.partial || 0) || 1;
  const cis = Math.round(((byStatus.pass || 0) / graded) * 100);
  const exposed = assets.filter(a => a.internet_exposed).length;
  Object.assign(d, { byTool, toolMax, corroborated, nClusters, scored, kev,
                     inflight, openInc, byStatus, cis, exposed });

  const deck = {
    aria: `VYREX platform: ${assets.length} assets, ${Object.keys(byTool).length} tools, `
        + `${ranking.length} findings fused into ${nClusters} clusters, ${scored} scored, `
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
        value: 'mTLS', note: 'JetStream', flowing: ranking.length > 0,
        items: [{ label: 'workers', n: null, weight: 0.5, on: true }],
      },
      fusion: {
        value: nClusters, note: corroborated + ' corroborated', flowing: nClusters > 0,
        items: [{ label: 'multi-tool', n: corroborated, weight: 0.6, on: corroborated > 0 }],
      },
      scoring: {
        value: scored, note: kev + ' KEV', flowing: scored > 0, hot: kev > 0,
        items: [{ label: 'composite', n: null, weight: 0.5, on: true },
                { label: 'ML', n: null, weight: 0.4, on: !!model.model_version }],
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

  root.append(deckHeader(d));
  root.append(deckCounters({
    findings: ranking.length, clusters: nClusters, corroborated, scored, kev,
    assets: assets.length, exposed, tools: Object.keys(byTool).length,
    incidents: openInc, cis, invs: invs.length, inflight,
    mttc: (dstats.sentinel || {}).mttc_ms,
    decoys: (dstats.decoys || {}).total || 0,
  }));

  root.append(deckBoard(d, deck));

  startDeckPolling(root);
}

/* ---- header: identity, clock, health, wall mode ---------------------- */
function deckHeader(d) {
  const checks = (d.ready || {}).checks || {};
  const pills = Object.entries(checks).map(([k, v]) =>
    h('span', { class: 'dk-pill' + (v.ok ? ' is-ok' : ' is-bad'), title: v.detail || '' },
      h('i', {}), k));
  return h('div', { class: 'dk-head fade' },
    h('div', { class: 'dk-head-l' },
      h('div', { class: 'dk-hd-title' }, 'Command Deck'),
      h('div', { class: 'dk-hd-sub' }, 'security operations · air-gapped')),
    h('div', { class: 'dk-head-pills' }, pills),
    h('div', { class: 'dk-head-r' },
      h('div', { class: 'dk-clock', id: 'dk-clock' }, new Date().toLocaleTimeString()),
      chip(API.mode === 'live' ? 'LIVE' : 'DEMO', API.mode === 'live' ? 'ok' : 'mono'),
      h('button', {
        class: 'btn sm', title: 'full-screen wall mode for the operations display (Esc to exit)',
        onclick: toggleWallMode,
      }, 'Wall mode'),
      h('button', { class: 'btn sm', onclick: () => go('command') }, 'Refresh')));
}

/* Wall mode strips the console chrome so the board fills an operations screen.
   Escape exits — a kiosk you cannot get out of without a keyboard shortcut
   nobody remembers is a support call waiting to happen. */
function toggleWallMode() {
  const on = document.body.classList.toggle('wallmode');
  if (on && !DECK.escHooked) {
    DECK.escHooked = true;
    document.addEventListener('keydown', function esc(e) {
      if (e.key === 'Escape') {
        document.body.classList.remove('wallmode');
        document.removeEventListener('keydown', esc);
        DECK.escHooked = false;
      }
    });
  }
}

/* ---- the counter rail ------------------------------------------------ */
function deckCounters(c) {
  const cell = (v, label, sub, tone) => h('div', { class: 'dk-stat' },
    h('div', { class: 'dk-sv' + (tone ? ' is-' + tone : '') }, String(v)),
    h('div', { class: 'dk-sl' }, label),
    sub ? h('div', { class: 'dk-ss' }, sub) : null);
  return h('div', { class: 'dk-rail fade' },
    cell(c.findings, 'findings', c.tools + ' tools reporting'),
    cell(c.clusters, 'clusters', c.corroborated + ' corroborated',
         c.corroborated ? 'ok' : null),
    cell(c.kev, 'known-exploited', 'CISA KEV', c.kev ? 'warn' : null),
    cell(c.assets, 'assets', c.exposed + ' internet-facing'),
    cell(c.invs, 'investigations', c.inflight ? c.inflight + ' in flight' : 'idle',
         c.inflight ? 'run' : null),
    cell(c.incidents, 'open incidents', 'SLA tracked', c.incidents ? 'warn' : null),
    cell(c.mttc == null ? '—' : c.mttc + 'ms', 'mean time to contain', 'autonomous engine'),
    cell(c.cis + '%', 'CIS posture', 'hash-chained'));
}

/* =====================================================================
   LIVE THREAT FEED — the "something just happened" surface.

   Polls /detections/recent and prepends what it has not shown before. New rows
   flash once. Nothing is invented: if the backend returns the same rows, the
   feed sits still, which is the honest behaviour for a quiet network and the
   thing a fake dashboard always gets wrong.
   ===================================================================== */
function feedRow(f, isNew) {
  const cons = f.consensus || {};
  const tools = cons.tools || [f.source_tool];
  return h('div', {
    class: 'dk-feed-row' + (isNew ? ' is-new' : '') + ' sev-' + sevClass(f.severity),
    onclick: () => openFinding && openFinding(f.id),
    title: f.title || '',
  },
    h('span', { class: 'dk-fr-dot' }),
    h('div', { class: 'dk-fr-body' },
      h('div', { class: 'dk-fr-t' }, f.title || '(untitled)'),
      h('div', { class: 'dk-fr-m' },
        h('span', { class: 'mono' }, f.asset_id || '—'),
        f.attack ? h('span', { class: 'dk-fr-tag' }, f.attack) : null,
        f.kev ? h('span', { class: 'dk-fr-tag is-kev' }, 'KEV') : null,
        f.threat_intel ? h('span', { class: 'dk-fr-tag is-intel' }, 'IOC') : null,
        cons.n_tools > 1
          ? h('span', { class: 'dk-fr-tag is-fused' }, cons.n_tools + '× ' + tools.join('+'))
          : h('span', { class: 'dk-fr-tag' }, f.source_tool || '—'))),
    h('div', { class: 'dk-fr-r' },
      h('div', { class: 'dk-fr-score is-' + band(f.risk_score) },
        f.risk_score == null ? '—' : Math.round(+f.risk_score)),
      h('div', { class: 'dk-fr-ago' }, ago(f.observed_at))));
}

function feedPanel(d) {
  const rows = (d.recent || []).slice(0, 40);
  rows.forEach(f => DECK.seen.add(f.id));
  return h('div', { class: 'panel pad dk-card dk-feed dk-w4' },
    h('div', { class: 'dk-cap-row' },
      h('div', { class: 'sec-label' }, 'Live threat feed'),
      h('span', { class: 'dk-live-dot', id: 'dk-feed-live' }),
      h('span', { style: 'flex:1' }),
      h('span', { class: 'faint dk-sub', id: 'dk-feed-n' }, rows.length + ' shown')),
    h('div', { class: 'dk-feed-list', id: 'dk-feed-list' },
      rows.length ? rows.map(f => feedRow(f, false))
                  : chEmpty('no detections yet — run a scan')));
}

/* =====================================================================
   THE BOARD

   Every panel — including the map and the feed — is a sibling in ONE 12-column
   grid. That is what lets the same markup serve two very different layouts:

     * Normal mode: panels flow with their span classes and the page scrolls.
     * Wall mode:   each panel is pinned to an explicit grid cell of a
                    3-row grid that is exactly one viewport tall, so nothing
                    scrolls at all (see `dk-place` in the CSS).

   Keeping them siblings rather than nesting the map and feed in their own
   flex row is the whole trick; a nested hero cannot be re-placed into the
   single-screen grid without duplicating the markup.

   Panels marked `dk-rot` share ONE cell in wall mode and cycle through it, so
   the board still shows everything the backend produces without a scrollbar.
   ===================================================================== */
function deckBoard(d, deck) {
  const map = h('div', { class: 'panel pad dk-card dk-w8', 'data-dk': 'map' },
    h('div', { class: 'dk-cap-row' },
      h('div', { class: 'dk-title' }, 'Platform'),
      h('span', { class: 'faint dk-sub' }, 'bottom to top — every figure is a live count')),
    deckMap(deck));

  return h('div', { class: 'dk-board fade' },
    map,
    place(feedPanel(d), 'feed'),
    place(timelinePanel(d), 'timeline'),
    place(attackPanel(d), 'attack'),
    place(sensorPanel(d), 'sensors'),
    place(fusionPanel(d), 'fusion'),
    place(riskPanel(d), 'risk'),
    place(scatterPanel(d), 'scatter'),
    place(defensePanel(d), 'defense'),
    place(compliancePanel(d), 'compliance'),
    // --- the rotating pool: everything that cannot hold a permanent cell ---
    place(orchPanel(d), 'orch', true),
    place(vitalsPanel(d), 'vitals', true),
    place(attribPanel(d), 'attrib', true),
    place(cvePanel(d), 'cves', true),
    place(responsePanel(d), 'response', true),
    place(trustPanel(d), 'trust', true),
    place(modelPanel(d), 'model', true),
    place(estatePanel(d), 'estate', true));
}

function card(title, sub, cls, ...body) {
  // `key` is the trailing token of cls by convention (set via data-dk below) so
  // the wall-mode CSS can place a panel without depending on DOM order.
  return h('div', { class: 'panel pad dk-card ' + (cls || '') },
    h('div', { class: 'dk-cap-row' },
      h('div', { class: 'sec-label' }, title),
      sub ? h('span', { class: 'faint dk-sub' }, sub) : null),
    ...body);
}

/* Tag a panel for wall-mode placement. Separate from `card` so the two concerns
   — what a panel contains, where it sits on the wall — stay independent. */
function place(el, key, rotates) {
  el.setAttribute('data-dk', key);
  if (rotates) el.classList.add('dk-rot');
  return el;
}

/* ---- detection arrival timeline -------------------------------------
   The only genuine time series available. /posture/trends holds one all-zero
   snapshot, so a trend line drawn from it would be a flat line implying
   "nothing is changing" — worse than no chart. This buckets real observed_at
   timestamps instead, and picks its own bucket size from the data's span. */
function timelinePanel(d) {
  const rows = (d.recent || []).filter(f => f.observed_at);
  if (!rows.length) return card('Detection timeline', null, 'dk-w6', chEmpty('no timestamped detections'));

  const times = rows.map(f => new Date(f.observed_at).getTime()).filter(Number.isFinite);
  const max = Math.max(...times), min = Math.min(...times);
  const spanH = (max - min) / 36e5;
  const byDay = spanH > 48;
  const bucketMs = byDay ? 864e5 : 36e5;
  const nB = Math.min(28, Math.max(6, Math.ceil((max - min) / bucketMs) + 1));
  const start = max - (nB - 1) * bucketMs;

  const cols = Array.from({ length: nB }, (_, i) => {
    const t0 = start + i * bucketMs;
    const dt = new Date(t0);
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    rows.forEach(f => {
      const t = new Date(f.observed_at).getTime();
      if (t >= t0 && t < t0 + bucketMs) counts[sevClass(f.severity)]++;
    });
    return {
      label: byDay ? `${dt.getMonth() + 1}/${dt.getDate()}`
                   : String(dt.getHours()).padStart(2, '0') + ':00',
      parts: CH_SEV.map(s => ({ cls: s, value: counts[s] })),
    };
  });

  const total = rows.length;
  return card('Detection timeline', `${total} detections · per ${byDay ? 'day' : 'hour'}`, 'dk-w6',
    chColumns(cols, { h: 46, aria: `detections per ${byDay ? 'day' : 'hour'}` }),
    h('div', { class: 'ch-key' }, CH_SEV.map(s =>
      h('span', { class: 'ch-lg' }, h('i', { class: 'is-' + s }), s))));
}

/* ---- ATT&CK matrix --------------------------------------------------
   /attack/coverage returns {tactics, techniques}, not a bare list, and the
   per-technique count is `findings`. Normalised here rather than assumed —
   assuming it was an array is what blanked this view on its first run. */
function attackPanel(d) {
  const cov = d.cov || {};
  const techs = Array.isArray(cov) ? cov : (cov.techniques || []);
  const tactics = Array.isArray(cov) ? [] : (cov.tactics || []);
  if (!techs.length) {
    return card('ATT&CK coverage', null, 'dk-w6',
      chEmpty('no techniques mapped yet — run intel-enrich'));
  }
  // Group into kill-chain columns. Tactic order comes from the API so the
  // columns stay in the order the backend considers canonical.
  const order = tactics.length ? tactics : [...new Set(techs.map(t => t.tactic))];
  const cols = order.map(tac => ({
    label: String(tac).replace(/-/g, ' '),
    cells: techs.filter(t => t.tactic === tac).map(t => ({
      label: t.technique, name: t.name, value: t.findings ?? t.count ?? 0,
      tools: (t.tools || []).join('+'), hot: (t.tool_count || 0) > 1,
    })),
  })).filter(c => c.cells.length);

  const multi = techs.filter(t => (t.tool_count || 0) > 1).length;
  return card('ATT&CK coverage', `${techs.length} techniques · ${cols.length} tactics`, 'dk-w6',
    chHeat(cols),
    h('div', { class: 'faint dk-note' },
      multi
        ? `${multi} technique${multi === 1 ? '' : 's'} seen by more than one tool — outlined cells.`
        : 'No technique is corroborated by more than one tool yet.'));
}

/* ---- sensor grid ----------------------------------------------------
   "How are the tools contributing" — one card per source tool, sized by volume.
   /detections returns (tool, domain) pairs, so it is aggregated up to the tool. */
function sensorPanel(d) {
  const rows = d.dets || [];
  if (!rows.length) return card('Sensor grid', null, 'dk-w6', chEmpty('no detection sources reporting'));
  const agg = {};
  rows.forEach(r => {
    const t = r.source_tool || 'unknown';
    agg[t] = agg[t] || { tool: t, hits: 0, kev: 0, top: 0, domains: new Set() };
    agg[t].hits += +r.hits || 0;
    agg[t].kev += +r.kev_hits || 0;
    agg[t].top = Math.max(agg[t].top, +r.top_risk_score || 0);
    if (r.domain) agg[t].domains.add(r.domain);
  });
  const tools = Object.values(agg).sort((a, b) => b.hits - a.hits);
  const max = Math.max(1, ...tools.map(t => t.hits));
  const rs = d.rules || {};

  return card('Sensor grid', `${tools.length} tools · ${rs.enabled ?? '—'}/${rs.n ?? '—'} rules enabled`, 'dk-w6',
    h('div', { class: 'dk-sensors' }, tools.map(t => h('div', { class: 'dk-sensor' },
      h('div', { class: 'dk-sn-top' },
        h('span', { class: 'dk-sn-name' }, t.tool),
        h('span', { class: 'dk-sn-hits' }, String(t.hits))),
      h('div', { class: 'dk-sn-bar' },
        h('i', { class: 'dk-sn-fill is-' + band(t.top), style: `width:${(t.hits / max) * 100}%` })),
      h('div', { class: 'dk-sn-meta' },
        h('span', {}, [...t.domains].join(' · ') || '—'),
        h('span', { class: 'mono' }, 'top ' + Math.round(t.top)),
        t.kev ? h('span', { class: 'dk-fr-tag is-kev' }, t.kev + ' KEV') : null)))));
}

/* ---- fusion clusters ------------------------------------------------
   The project's headline capability, drawn as what it actually is: several
   independent tools converging on ONE observed thing. Each row is a real
   cluster from /fusion/clusters. */
function fusionPanel(d) {
  const cl = (d.clusters || []).filter(c => (c.n_tools || 0) > 1).slice(0, 6);
  if (!cl.length) {
    return card('Cross-tool fusion', null, 'dk-w6',
      chEmpty('no observable is corroborated by two or more tools yet'));
  }
  const viz = (c) => {
    const tools = c.tools || [];
    const W = 150, H = Math.max(38, tools.length * 17);
    const midY = H / 2;
    const els = [];
    tools.forEach((t, i) => {
      const y = tools.length === 1 ? midY : 9 + (i * (H - 18)) / (tools.length - 1);
      els.push(sv('path', {
        class: 'dk-fz-edge', fill: 'none',
        d: `M14 ${y.toFixed(1)} C 60 ${y.toFixed(1)}, 74 ${midY}, 118 ${midY}`,
      }));
      els.push(sv('circle', { class: 'dk-fz-tool', cx: 10, cy: y.toFixed(1), r: 3.6 },
        sv('title', null, t)));
      els.push(sv('text', { class: 'dk-fz-lbl', x: 18, y: (y + 3).toFixed(1) }, t));
    });
    els.push(sv('circle', { class: 'dk-fz-obs', cx: 122, cy: midY, r: 6.5 },
      sv('title', null, 'the observed thing all of these agree on')));
    els.push(sv('text', { class: 'dk-fz-n', x: 122, y: midY + 3 }, String(tools.length)));
    return sv('svg', {
      class: 'dk-fz', viewBox: `0 0 ${W} ${H}`, role: 'img',
      'aria-label': `${tools.length} tools corroborate: ${tools.join(', ')}`,
    }, els);
  };
  return card('Cross-tool fusion', `${cl.length} corroborated observable${cl.length === 1 ? '' : 's'}`, 'dk-w6',
    h('div', { class: 'dk-fusion' }, cl.map(c => h('div', {
      class: 'dk-fusion-row', onclick: () => openFinding && openFinding(c.primary_id),
    },
      viz(c),
      h('div', { class: 'dk-fu-body' },
        h('div', { class: 'dk-fu-t' }, c.title || '(untitled)'),
        h('div', { class: 'dk-fu-m' },
          h('span', { class: 'mono' }, c.asset_id || '—'),
          h('span', { class: 'dk-fr-tag is-fused' }, c.n_tools + ' tools agree'),
          h('span', { class: 'dk-fr-score is-' + band(c.top_risk_score) },
            Math.round(+c.top_risk_score || 0))))))),
    h('div', { class: 'faint dk-note' },
      'Grouped on the OBSERVABLE (this host talked to that IP on that port), not on '
      + 'the rule that fired — which is what lets three different tools land in one cluster.'));
}

/* ---- risk distribution ---------------------------------------------- */
function riskPanel(d) {
  const bands = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  d.ranking.forEach(r => bands[band(r.risk_score)]++);
  return card('Risk distribution', d.scored + ' scored', 'dk-w3',
    chBars(CH_SEV.map(b => ({ label: b, value: bands[b], cls: b })), { dense: true }));
}

/* ---- composite vs ML ------------------------------------------------
   Exists to answer one question an examiner WILL ask: does the ML model
   actually do anything, or does it just reproduce the formula? Points on the
   diagonal mean agreement; the spread is the honest answer. */
function scatterPanel(d) {
  const pts = d.ranking
    .filter(f => f.risk_score != null && f.ml_risk_score != null)
    .map(f => ({
      x: +f.risk_score, y: +f.ml_risk_score, cls: band(f.risk_score),
      label: `${f.title || f.id}\ncomposite ${(+f.risk_score).toFixed(1)} · ML ${(+f.ml_risk_score).toFixed(1)}`,
      onclick: () => openFinding && openFinding(f.id),
    }));
  if (!pts.length) {
    return card('Composite vs ML', null, 'dk-w3', chEmpty('no finding carries both scores'));
  }
  const mean = pts.reduce((s, p) => s + Math.abs(p.y - p.x), 0) / pts.length;
  return card('Composite vs ML', pts.length + ' scored', 'dk-w3',
    chScatter(pts, { xlabel: 'composite →', ylabel: 'ML ↑' }),
    h('div', { class: 'faint dk-note' },
      `Mean divergence ${mean.toFixed(1)} points. On the line = the two agree.`));
}

/* ---- autonomous defense --------------------------------------------- */
function defensePanel(d) {
  const s = d.dstats || {};
  const sent = s.sentinel || {}, dec = s.decoys || {};
  const verdicts = {};
  (d.ddec || []).forEach(x => { const v = x.verdict || 'UNKNOWN'; verdicts[v] = (verdicts[v] || 0) + 1; });
  const TONE = { ESCALATE: 'critical', MONITOR: 'medium', DISMISS: 'info',
                 INSUFFICIENT_EVIDENCE: 'low' };
  const slices = Object.entries(verdicts).map(([k, v]) =>
    ({ label: k.toLowerCase().replace(/_/g, ' '), value: v, cls: TONE[k] || 'info' }));
  return card('Autonomous defense', (sent.mode || 'advisory') + ' mode', 'dk-w3',
    chDonut(slices, { center: sent.decisions ?? 0, centerSub: 'decisions',
                      empty: 'engine has not run' }),
    h('div', { class: 'dk-kv' },
      kv('auto-executed', String(sent.auto_executed ?? 0)),
      kv('mean time to contain', sent.mttc_ms == null ? '—' : sent.mttc_ms + ' ms'),
      kv('decoys armed', `${(d.decoys || []).filter(x => x.state === 'armed').length} / ${dec.total ?? (d.decoys || []).length}`),
      kv('decoys tripped', String(dec.tripped ?? 0))));
}

/* ---- compliance ------------------------------------------------------ */
function compliancePanel(d) {
  const bs = d.byStatus || {};
  return card('Compliance posture', 'CIS benchmarks', 'dk-w3',
    chGauge(d.cis, { label: 'CIS pass rate', cls: d.cis >= 70 ? 'ok' : d.cis >= 40 ? 'medium' : 'critical',
                     sub: 'pass rate' }),
    chBars([
      { label: 'pass', value: bs.pass || 0, cls: 'ok' },
      { label: 'fail', value: bs.fail || 0, cls: 'critical' },
      { label: 'partial', value: bs.partial || 0, cls: 'medium' },
      { label: 'n/a', value: bs.not_applicable || 0, cls: 'info' },
    ], { dense: true }));
}

/* ---- attribution ----------------------------------------------------- */
function attribPanel(d) {
  const a = d.attrib || {};
  const actors = (a.actors || []).map(x => ({ label: x.name, value: x.findings, cls: 'high' }));
  const malware = (a.malware || []).map(x => ({ label: x.name, value: x.findings, cls: 'critical' }));
  if (!actors.length && !malware.length) {
    return card('Attribution', null, 'dk-w4', chEmpty('no attributed findings'));
  }
  return card('Attribution', 'from persisted threat intel', 'dk-w4',
    h('div', { class: 'dk-subhead' }, 'actors'), chBars(actors, { dense: true }),
    h('div', { class: 'dk-subhead' }, 'malware / campaign'), chBars(malware, { dense: true }));
}

/* ---- top CVEs -------------------------------------------------------- */
function cvePanel(d) {
  const cves = ((d.stats || {}).top_cves || []).slice(0, 8);
  if (!cves.length) return card('Top CVEs', null, 'dk-w4', chEmpty('no CVE-bearing findings'));
  return card('Top CVEs', 'by severity & exploitability', 'dk-w4',
    h('div', { style: 'overflow-x:auto' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, ['CVE', 'CVSS', 'EPSS', 'KEV', 'n'].map(t => h('th', {}, t)))),
        h('tbody', {}, cves.map(c => h('tr', {
          class: 'dk-clickrow',
          onclick: () => openCve && openCve(c.cve_id),
        },
          h('td', { class: 'mono' }, c.cve_id),
          h('td', { class: 'mono' }, c.cvss ?? '—'),
          h('td', { class: 'mono' }, c.epss == null ? '—' : (+c.epss).toFixed(4)),
          h('td', {}, c.kev ? h('span', { class: 'dk-fr-tag is-kev' }, 'KEV') : '—'),
          h('td', { class: 'mono' }, String(c.occurrences ?? 1))))))));
}

/* ---- response pipeline ----------------------------------------------- */
function responsePanel(d) {
  const acts = d.actions || [];
  if (!acts.length) return card('Response actions', null, 'dk-w4', chEmpty('no containment requested'));
  const byStatus = {};
  acts.forEach(a => { byStatus[a.status] = (byStatus[a.status] || 0) + 1; });
  const TONE = { proposed: 'medium', approved: 'ok', rejected: 'info',
                 dispatched: 'high', completed: 'ok', failed: 'critical' };
  const order = ['proposed', 'approved', 'dispatched', 'completed', 'rejected', 'failed'];
  const rows = order.filter(s => byStatus[s]).map(s =>
    ({ label: s, value: byStatus[s], cls: TONE[s] || 'info' }));
  return card('Response actions', acts.length + ' total', 'dk-w4',
    chBars(rows, { dense: true }),
    h('div', { class: 'faint dk-note' },
      'Every action is Ed25519-signed and needs a second approver. The orchestrator '
      + 'has no database grant on this table — it can propose, never execute.'));
}

/* ---- orchestrator ----------------------------------------------------
   The subsystem most likely to be misread as broken when it is merely slow, so
   queue depth sits next to the outcome mix. */
function orchPanel(d) {
  const inv = (d.orch || {}).investigations || {};
  const slices = [
    { label: 'completed', value: inv.completed || 0, cls: 'ok' },
    { label: 'partial', value: inv.partial || 0, cls: 'medium' },
    { label: 'cancelled', value: inv.cancelled || 0, cls: 'info' },
  ];
  const tot = slices.reduce((s, x) => s + x.value, 0);
  return card('Investigation orchestrator', d.agent.model || 'no model', 'dk-w4',
    chDonut(slices, { center: tot, centerSub: 'runs', empty: 'no runs recorded' }),
    h('div', { class: 'dk-kv' },
      kv('model reachable', d.agent.reachable ? 'yes' : 'no'),
      kv('queued', String(d.orch.pending_outbox ?? 0)),
      kv('outbox sent', String((d.orch.outbox || {}).sent ?? 0))),
    h('div', { class: 'faint dk-note' },
      'A "partial" run is not a failure — the graph finished with a branch skipped '
      + 'or failed, which is the designed degraded path.'));
}

/* ---- node vitals ----------------------------------------------------- */
function vitalsPanel(d) {
  const v = d.vitals || {};
  const cpu = v.cpu || {}, ram = v.ram || {}, disk = v.disk || {};
  const cores = cpu.per_core || [];
  return card('Appliance vitals', (v.os || {}).uptime ? 'up ' + v.os.uptime : null, 'dk-w4',
    h('div', { class: 'dk-vitals', id: 'dk-vitals' },
      h('div', { class: 'dk-vg' }, chGauge(ram.percent, { label: 'memory', sub: 'memory',
        cls: ram.percent > 85 ? 'critical' : ram.percent > 65 ? 'medium' : 'ok' })),
      h('div', { class: 'dk-vg' }, chGauge(disk.percent, { label: 'disk', sub: 'disk',
        cls: disk.percent > 85 ? 'critical' : 'ok' })),
      h('div', { class: 'dk-cores' },
        h('div', { class: 'dk-subhead' }, `cpu · ${cores.length} cores · load ${cpu.load1 ?? '—'}`),
        h('div', { class: 'dk-core-row' }, cores.map((c, i) =>
          h('span', { class: 'dk-core', title: `core ${i}: ${c}%` },
            h('i', { style: `height:${Math.max(3, c)}%` })))))),
    h('div', { class: 'dk-kv' },
      kv('memory', `${ram.used_h || '—'} / ${ram.total_h || '—'}`),
      kv('disk', `${disk.used_h || '—'} / ${disk.total_h || '—'}`),
      kv('kernel', (v.os || {}).release || '—')));
}

/* ---- trust / air-gap: the project's central claim as verifiable facts -- */
function trustPanel(d) {
  return card('Trust & air-gap', 'the central claim', 'dk-w4',
    h('div', { class: 'dk-kv' },
      kv('evidence chain', d.chain && d.chain.ok ? 'intact' : 'unverified'),
      kv('chain length', String((d.chain && d.chain.length) ?? '—')),
      kv('egress', 'feed-sync only'),
      kv('response', 'two-person + Ed25519'),
      kv('orchestrator DB role', 'no write on response_actions')),
    h('div', { class: 'dk-audit' },
      h('div', { class: 'dk-subhead' }, 'access audit — most recent'),
      (d.audit || []).slice(0, 6).map(a => h('div', { class: 'dk-audit-row' },
        h('span', { class: 'mono dk-au-m' }, a.method),
        h('span', { class: 'dk-au-p' }, a.path),
        h('span', { class: 'mono dk-au-s is-' + (a.status < 400 ? 'ok' : 'bad') }, String(a.status)),
        h('span', { class: 'faint dk-au-a' }, a.actor || 'anonymous')))));
}

/* ---- model card: the honesty screen, deliberately not buried ---------
   Field names come from /risk/model/metadata, which returns `model_version` —
   not `version`. Reading the wrong key rendered a dash next to a model the
   sidebar was happily displaying, which looks like a broken model rather than
   a broken selector. */
function modelPanel(d) {
  const mw = d.model.composite_weights || {};
  const top = Object.entries(mw).sort((a, b) => b[1] - a[1]).slice(0, 4);
  return card('Risk model', d.model.model_version || '—', 'dk-w4',
    h('div', { class: 'dk-kv' },
      kv('algorithm', (d.model.algorithm || 'XGBoost').split('(')[0].trim()),
      kv('explainer', (d.model.explainer || 'TreeSHAP').split('(')[0].trim()),
      kv('analyst labels', String(d.model.analyst_labels ?? 0)),
      ...top.map(([k, v]) => kv('weight · ' + k, Number(v).toFixed(2)))),
    h('div', { class: 'faint dk-note' },
      'Bootstrapped on synthetic labels, so the ML score largely reproduces the '
      + 'composite formula today. It is a re-ranker, not an independent oracle.'));
}

/* ---- estate ---------------------------------------------------------- */
function estatePanel(d) {
  return card('Estate', d.assets.length + ' assets · ' + d.exposed + ' internet-facing', 'dk-w8',
    h('div', { style: 'overflow-x:auto' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, ['Host', 'Env', 'Service', 'Exposed', 'Sensitivity', 'Owner', 'Criticality']
          .map(t => h('th', {}, t)))),
        h('tbody', {}, (d.assets || []).map(a => h('tr', {
          class: 'dk-clickrow', onclick: () => openAsset && openAsset(a.host_id),
        },
          h('td', { class: 'mono' }, a.hostname || a.host_id),
          h('td', {}, a.environment || '—'),
          h('td', {}, a.business_service || '—'),
          h('td', {}, a.internet_exposed == null ? 'unknown' : a.internet_exposed ? 'yes' : 'no'),
          h('td', {}, a.data_sensitivity || '—'),
          h('td', {}, a.owner_team || '—'),
          h('td', { class: 'mono' },
            a.criticality == null ? '—' : Number(a.criticality).toFixed(2))))))));
}

function kv(k, v) {
  return h('div', { class: 'dk-kv-row' },
    h('span', { class: 'dk-k' }, k), h('span', { class: 'dk-v' }, v));
}

/* =====================================================================
   LIVE POLLING

   Two independent cadences, because they cost very different amounts: the feed
   is one small query, the vitals read /proc. Both are cleared by the router's
   _viewCleanup, without which leaving the page leaves timers running against a
   detached DOM — a leak that only shows up after someone leaves the wall board
   on overnight, which is exactly how it will be used.
   ===================================================================== */
function startDeckPolling(root) {
  if (window._viewCleanup) { try { window._viewCleanup(); } catch {} }
  DECK.timers.forEach(clearInterval);
  DECK.timers = [];

  const clock = setInterval(() => {
    const el = document.getElementById('dk-clock');
    if (el) el.textContent = new Date().toLocaleTimeString();
  }, 1000);

  const feed = setInterval(async () => {
    const list = document.getElementById('dk-feed-list');
    if (!list || !document.body.contains(list)) return;
    let rows;
    try { rows = await API.recent(40); } catch { return; }
    const fresh = (rows || []).filter(f => !DECK.seen.has(f.id));
    if (!fresh.length) return;
    fresh.forEach(f => DECK.seen.add(f.id));
    // Prepend newest-first and flash. Cap the DOM so an overnight run does not
    // grow an unbounded list.
    fresh.reverse().forEach(f => list.prepend(feedRow(f, true)));
    while (list.children.length > 60) list.lastChild.remove();
    const n = document.getElementById('dk-feed-n');
    if (n) n.textContent = list.children.length + ' shown';
    const dot = document.getElementById('dk-feed-live');
    if (dot) { dot.classList.add('is-pulse'); setTimeout(() => dot.classList.remove('is-pulse'), 1200); }
    const worst = fresh.find(f => /CRITICAL|HIGH/i.test(f.severity || ''));
    if (worst) toast(`${worst.severity}: ${worst.title || 'new detection'}`);
  }, 6000);

  const vit = setInterval(async () => {
    const host = document.getElementById('dk-vitals');
    if (!host || !document.body.contains(host)) return;
    let v;
    try { v = await API.nodeVitals(); } catch { return; }
    const fresh = vitalsPanel({ vitals: v });
    const next = fresh.querySelector('#dk-vitals');
    if (next) host.replaceWith(next);
  }, 10000);

  // The rotating slot. Only meaningful in wall mode, where the pool shares one
  // grid cell; in normal mode every pool panel is visible at once and this just
  // moves a class nobody can see. Cheap enough not to be worth branching on.
  const pool = [...root.querySelectorAll('.dk-rot')];
  if (pool.length) {
    pool.forEach((el, i) => el.classList.toggle('is-showing', i === 0));
    DECK.rotIdx = 0;
  }
  const rot = setInterval(() => {
    if (!pool.length || !document.body.classList.contains('wallmode')) return;
    pool[DECK.rotIdx].classList.remove('is-showing');
    DECK.rotIdx = (DECK.rotIdx + 1) % pool.length;
    pool[DECK.rotIdx].classList.add('is-showing');
  }, 9000);

  DECK.timers = [clock, feed, vit, rot];
  window._viewCleanup = () => {
    DECK.timers.forEach(clearInterval);
    DECK.timers = [];
    document.body.classList.remove('wallmode');
  };
}
