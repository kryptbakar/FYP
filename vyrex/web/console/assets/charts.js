/* =====================================================================
   VYREX — chart primitives.

   Hand-built inline SVG, because D-044 makes the console dependency-free: no
   Chart.js, no D3, no CDN. That constraint is the air-gap claim, so it is not
   negotiable for cosmetic convenience.

   Rules every primitive here follows:
     * Colour comes from CSS classes only (.ch-*, .is-<severity>), never from
       hardcoded hex. A re-theme or a light/dark flip must not need a JS edit.
     * Everything is drawn into a viewBox and scaled with preserveAspectRatio,
       so a panel can be any size — including the 4K wall screen.
     * Every chart carries a <title> or aria-label. A wall board that a screen
       reader cannot describe is a wall board that fails an accessibility review.
     * No chart invents data. Empty input renders an explicit empty state; it
       never draws a plausible-looking zero line.
   ===================================================================== */
'use strict';

const cn = (v) => (Number.isFinite(+v) ? +v : 0).toFixed(2);
const CH_SEV = ['critical', 'high', 'medium', 'low', 'info'];

function chEmpty(msg) {
  return h('div', { class: 'ch-empty' }, msg || 'no data yet');
}

/* ---- horizontal bars ------------------------------------------------
   rows: [{label, value, cls?, note?}]. The default reading for "how much of
   each" — a donut hides a long tail, and SOC distributions are all tail. */
function chBars(rows, o = {}) {
  rows = (rows || []).filter(r => r);
  if (!rows.length) return chEmpty(o.empty);
  const max = Math.max(1, ...rows.map(r => +r.value || 0));
  return h('div', { class: 'ch-bars' + (o.dense ? ' is-dense' : '') },
    rows.map(r => h('div', { class: 'ch-bar-row', title: r.title || `${r.label}: ${r.value}` },
      h('span', { class: 'ch-bar-l' }, String(r.label)),
      h('span', { class: 'ch-bar-t' },
        h('i', {
          class: 'ch-bar-f' + (r.cls ? ' is-' + r.cls : ''),
          style: `width:${((+r.value || 0) / max) * 100}%`,
        })),
      h('span', { class: 'ch-bar-n' }, r.note != null ? String(r.note) : String(r.value)))));
}

/* ---- stacked columns over time --------------------------------------
   cols: [{label, parts:[{cls, value}]}]. Used for the arrival timeline, where
   the SHAPE (a burst vs a steady trickle) is the signal an analyst reads. */
function chColumns(cols, o = {}) {
  cols = (cols || []).filter(c => c);
  if (!cols.length) return chEmpty(o.empty);
  const W = 100, H = o.h || 42, gap = 0.18;
  const totals = cols.map(c => (c.parts || []).reduce((s, p) => s + (+p.value || 0), 0));
  const max = Math.max(1, ...totals);
  const bw = W / cols.length;
  const bars = [];
  cols.forEach((c, i) => {
    let y = H;
    (c.parts || []).forEach(p => {
      const hgt = ((+p.value || 0) / max) * H;
      if (hgt <= 0) return;
      y -= hgt;
      bars.push(sv('rect', {
        class: 'ch-col' + (p.cls ? ' is-' + p.cls : ''),
        x: cn(i * bw + bw * gap / 2), y: cn(y),
        width: cn(bw * (1 - gap)), height: cn(hgt),
      }, sv('title', null, `${c.label}: ${p.value} ${p.cls || ''}`)));
    });
    if (!totals[i]) {
      // An explicit zero tick. Without it an empty hour is indistinguishable
      // from an hour the chart simply did not cover.
      bars.push(sv('rect', {
        class: 'ch-col is-zero',
        x: cn(i * bw + bw * gap / 2), y: cn(H - 0.6),
        width: cn(bw * (1 - gap)), height: '0.6',
      }, sv('title', null, `${c.label}: 0`)));
    }
  });
  const svg = sv('svg', {
    class: 'ch-svg', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none',
    role: 'img', 'aria-label': o.aria || 'timeline',
  }, bars);
  const ticks = o.ticks !== false ? h('div', { class: 'ch-ticks' },
    h('span', {}, cols[0].label),
    h('span', {}, cols[Math.floor(cols.length / 2)].label),
    h('span', {}, cols[cols.length - 1].label)) : null;
  return h('div', { class: 'ch-cols' }, svg, ticks);
}

/* ---- donut ----------------------------------------------------------
   slices: [{label, value, cls?}]. Only for parts-of-a-whole where the whole
   genuinely means something (compliance status, verdict mix). */
function chDonut(slices, o = {}) {
  slices = (slices || []).filter(s => s && +s.value > 0);
  if (!slices.length) return chEmpty(o.empty);
  const total = slices.reduce((s, x) => s + (+x.value || 0), 0);
  const R = 46, R2 = o.thin ? 34 : 30, C = 50;
  const paths = [];

  if (slices.length === 1) {
    // A full circle as an arc is degenerate (start == end, nothing renders).
    // Two concentric circles give the same ring honestly.
    paths.push(sv('path', {
      class: 'ch-slice' + (slices[0].cls ? ' is-' + slices[0].cls : ''),
      d: `M${C} ${C - R}A${R} ${R} 0 1 1 ${C - 0.01} ${C - R}Z`
       + `M${C} ${C - R2}A${R2} ${R2} 0 1 0 ${C - 0.01} ${C - R2}Z`,
      'fill-rule': 'evenodd',
    }, sv('title', null, `${slices[0].label}: ${slices[0].value}`)));
  } else {
    let a = -Math.PI / 2;
    slices.forEach(s => {
      const sweep = ((+s.value || 0) / total) * Math.PI * 2;
      const a1 = a + sweep;
      const big = sweep > Math.PI ? 1 : 0;
      const p = (ang, r) => [cn(C + r * Math.cos(ang)), cn(C + r * Math.sin(ang))];
      const [x0, y0] = p(a, R), [x1, y1] = p(a1, R);
      const [x2, y2] = p(a1, R2), [x3, y3] = p(a, R2);
      paths.push(sv('path', {
        class: 'ch-slice' + (s.cls ? ' is-' + s.cls : ''),
        d: `M${x0} ${y0}A${R} ${R} 0 ${big} 1 ${x1} ${y1}L${x2} ${y2}A${R2} ${R2} 0 ${big} 0 ${x3} ${y3}Z`,
      }, sv('title', null, `${s.label}: ${s.value}`)));
      a = a1;
    });
  }

  const svg = sv('svg', {
    class: 'ch-donut', viewBox: '0 0 100 100', role: 'img',
    'aria-label': o.aria || slices.map(s => `${s.label} ${s.value}`).join(', '),
  }, paths,
    o.center != null ? sv('text', { class: 'ch-dc', x: 50, y: 50 }, String(o.center)) : null,
    o.centerSub ? sv('text', { class: 'ch-ds', x: 50, y: 62 }, o.centerSub) : null);

  return h('div', { class: 'ch-donut-wrap' }, svg,
    o.legend === false ? null : h('div', { class: 'ch-legend' },
      slices.map(s => h('span', { class: 'ch-lg' },
        h('i', { class: s.cls ? 'is-' + s.cls : '' }),
        h('b', {}, String(s.value)), ' ', s.label))));
}

/* ---- matrix heatmap -------------------------------------------------
   Built for ATT&CK: columns are tactics (the kill-chain, left to right),
   cells are techniques shaded by volume. Reading order matches how an analyst
   already thinks about an intrusion. */
function chHeat(cols, o = {}) {
  cols = (cols || []).filter(c => c && (c.cells || []).length);
  if (!cols.length) return chEmpty(o.empty);
  const max = Math.max(1, ...cols.flatMap(c => c.cells.map(x => +x.value || 0)));
  return h('div', { class: 'ch-heat' },
    cols.map(c => h('div', { class: 'ch-heat-col' },
      h('div', { class: 'ch-heat-h' }, c.label),
      c.cells.map(x => {
        // Five steps rather than a continuous ramp: a reader can actually name
        // the level they are looking at, and it survives a colour-blind check.
        const step = Math.min(4, Math.floor(((+x.value || 0) / max) * 4.999));
        return h('div', {
          class: `ch-cell lv${step}` + (x.hot ? ' is-hot' : ''),
          title: `${x.label}${x.name ? ' — ' + x.name : ''}\n${x.value} finding(s)`
               + (x.tools ? '\ntools: ' + x.tools : ''),
          onclick: x.onclick || null,
        },
          h('b', {}, x.label),
          h('i', {}, String(x.value)),
          x.tools ? h('u', {}, x.tools) : null);
      }))));
}

/* ---- radial gauge ---------------------------------------------------
   A 270° arc. For single bounded percentages (compliance, CPU, memory). */
function chGauge(value, o = {}) {
  const v = Math.max(0, Math.min(100, +value || 0));
  const C = 50, R = 38, SPAN = Math.PI * 1.5, START = Math.PI * 0.75;
  const pt = (ang) => [cn(C + R * Math.cos(ang)), cn(C + R * Math.sin(ang))];
  const track = (() => {
    const [x0, y0] = pt(START), [x1, y1] = pt(START + SPAN);
    return `M${x0} ${y0}A${R} ${R} 0 1 1 ${x1} ${y1}`;
  })();
  const end = START + SPAN * (v / 100);
  const [fx0, fy0] = pt(START), [fx1, fy1] = pt(end);
  const fill = `M${fx0} ${fy0}A${R} ${R} 0 ${SPAN * (v / 100) > Math.PI ? 1 : 0} 1 ${fx1} ${fy1}`;
  return h('div', { class: 'ch-gauge-wrap' },
    sv('svg', {
      class: 'ch-gauge', viewBox: '0 0 100 100', role: 'img',
      'aria-label': `${o.label || 'value'}: ${Math.round(v)}%`,
    },
      sv('path', { class: 'ch-g-track', d: track, fill: 'none' }),
      sv('path', { class: 'ch-g-fill' + (o.cls ? ' is-' + o.cls : ''), d: fill, fill: 'none' }),
      sv('text', { class: 'ch-gv', x: 50, y: 52 }, o.text != null ? String(o.text) : Math.round(v) + '%'),
      o.sub ? sv('text', { class: 'ch-gs', x: 50, y: 66 }, o.sub) : null));
}

/* ---- scatter --------------------------------------------------------
   pts: [{x, y, cls?, label?}] in 0..100 on both axes. Exists for exactly one
   question — where do the composite score and the ML score DISAGREE — which is
   a scatter and nothing else. */
function chScatter(pts, o = {}) {
  pts = (pts || []).filter(p => p && Number.isFinite(+p.x) && Number.isFinite(+p.y));
  if (!pts.length) return chEmpty(o.empty);
  const W = 100, H = 100;
  const px = (v) => cn((v / 100) * W);
  const py = (v) => cn(H - (v / 100) * H);
  const grid = [25, 50, 75].flatMap(g => [
    sv('line', { class: 'ch-grid', x1: 0, y1: py(g), x2: W, y2: py(g) }),
    sv('line', { class: 'ch-grid', x1: px(g), y1: 0, x2: px(g), y2: H }),
  ]);
  return h('div', { class: 'ch-scatter-wrap' },
    sv('svg', {
      class: 'ch-scatter', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none',
      role: 'img', 'aria-label': o.aria || `${pts.length} points`,
    },
      grid,
      // The agreement line. Points far from it are where the two scorers differ,
      // which is the only reason to draw this chart.
      sv('line', { class: 'ch-diag', x1: 0, y1: py(0), x2: px(100), y2: py(100) }),
      pts.map(p => sv('circle', {
        class: 'ch-pt' + (p.cls ? ' is-' + p.cls : ''),
        cx: px(p.x), cy: py(p.y), r: 1.8,
        onclick: p.onclick || null,
      }, sv('title', null, p.label || `${p.x} / ${p.y}`)))),
    o.axes === false ? null : h('div', { class: 'ch-axes' },
      h('span', {}, o.xlabel || 'x'), h('span', {}, o.ylabel || 'y')));
}

/* ---- sparkline ------------------------------------------------------ */
function chSpark(values, o = {}) {
  const v = (values || []).map(x => +x || 0);
  if (v.length < 2) return h('span', { class: 'ch-spark is-flat' });
  const max = Math.max(...v), min = Math.min(...v), rng = (max - min) || 1;
  const W = 100, H = 24;
  const pts = v.map((y, i) => `${cn((i / (v.length - 1)) * W)},${cn(H - ((y - min) / rng) * H)}`);
  return sv('svg', {
    class: 'ch-spark' + (o.cls ? ' is-' + o.cls : ''), viewBox: `0 0 ${W} ${H}`,
    preserveAspectRatio: 'none', role: 'img', 'aria-label': o.aria || 'trend',
  },
    sv('polyline', { class: 'ch-spark-l', points: pts.join(' '), fill: 'none' }),
    sv('polygon', { class: 'ch-spark-a', points: `0,${H} ${pts.join(' ')} ${W},${H}` }));
}
