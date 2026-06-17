/* =====================================================================
   Storyline Mode — a guided, always-works attack→containment walkthrough.

   A linear state machine that drives the REAL screens (go / openFinding /
   the existing views) with a box-shadow "spotlight" overlay and a caption
   card. Forces deterministic fixtures (API._story) so it runs identically
   every time and never depends on live tool output. Two "the machine is
   reasoning" beats are animated: the SHAP waterfall builds bar-by-bar, and
   the multi-tool consensus reveals tool-by-tool. Pure vanilla JS; honours
   prefers-reduced-motion (renders final state instantly). Esc exits anytime.

   Globals used (all defined in earlier scripts): h, $, $$, ic, go,
   openFinding, closeDrawer, closePalette, toast, API.
   ===================================================================== */
'use strict';

const STORY_REDUCED = matchMedia('(prefers-reduced-motion: reduce)').matches;
let _storyIdx = -1, _storyActive = false, _storyEls = {}, _storySpotEl = null;
const _sdelay = ms => new Promise(r => setTimeout(r, STORY_REDUCED ? 0 : ms));

/* ---- the beats ------------------------------------------------------- */
const STORY = [
  { id: 'overview', route: 'overview', title: '~500 alerts → 1 decision',
    caption: 'Raw security tools would bury an analyst in ~500 alerts a day. VYREX fuses and ranks them into one decision that matters right now.',
    highlight: '#view .kpis', onEnter: animateFunnel },
  { id: 'triage', route: 'triage', title: 'The #1 ranked decision',
    caption: 'The highest-risk finding sits at the top of the decision queue — a known-exploited CVE on an internet-facing host. Open it.',
    highlight: '#view .card:first-child, #view .tbl tbody tr:first-child' },
  { id: 'finding', openDrawer: 10, title: 'Why the machine ranks it #1',
    caption: 'The 0–100 score is assembled factor by factor — each bar is a SHAP contribution. KEV and multi-tool consensus push it to the top.',
    highlight: '#drawer .cols2', onEnter: animateShap },
  { id: 'fusion', route: 'fusion', title: 'Three independent tools agree',
    caption: 'The endpoint agent, Trivy and Suricata each flagged the same issue. Agreement is the most intuitive trust signal — consensus saturates to 1.0.',
    highlight: '#view .consensus-reveal', onEnter: animateConsensus },
  { id: 'case', route: 'cases', title: 'Promote to an incident',
    caption: 'The analyst opens a case. It enters the investigation board and the attack chain is assembled from the linked findings.',
    highlight: '#view .kanban, #view .board, #view' },
  { id: 'contain', openDrawer: 10, scrollTo: '#drawer .gate', title: 'Contain it — safely',
    caption: 'Request host isolation → two-person approval → an Ed25519-signed command dispatches over the channel → the agent executes. Every step is auditable.',
    highlight: '#drawer .gate', onEnter: driveApprovalGate },
  { id: 'trust', route: 'trust', title: 'Nothing left the building',
    caption: 'The hash-chained audit verifies intact and tamper-evident. The egress matrix shows every service contained — zero bytes egressed.',
    highlight: '#view .tbl', onEnter: animateTrust },
];

/* ---- lifecycle ------------------------------------------------------- */
async function startStory() {
  if (_storyActive) return;
  _storyActive = true;
  API._story = true;                          // deterministic fixtures for the whole run
  API._set && API._set('demo');               // reflect it honestly in the LIVE/DEMO badge
  if (typeof closePalette === 'function') closePalette();
  if (typeof closeDrawer === 'function') closeDrawer();
  buildStoryOverlay();
  await storyGoto(0);
}
function endStory() {
  if (!_storyActive) return;
  _storyActive = false;
  API._story = false;                         // live data resumes on next navigation
  window.removeEventListener('resize', positionSpot);
  document.removeEventListener('scroll', positionSpot, true);
  document.removeEventListener('keydown', storyKey, true);
  if (_storyEls.ov) _storyEls.ov.remove();
  $$('.story-inject').forEach(e => e.remove());
  _storyEls = {}; _storyIdx = -1; _storySpotEl = null;
  if (typeof toast === 'function') toast('Storyline ended — live data resumed', true);
}
function buildStoryOverlay() {
  const spot = h('div', { class: 'story-spot', id: 'story-spot' });
  const cap = h('div', { class: 'story-cap', id: 'story-cap' });
  const ov = h('div', { class: 'story' + (STORY_REDUCED ? ' reduced' : ''), id: 'story' }, spot, cap);
  document.body.append(ov);
  _storyEls = { ov, spot, cap };
  window.addEventListener('resize', positionSpot);
  document.addEventListener('scroll', positionSpot, true);   // capture: reposition on any scroll
  document.addEventListener('keydown', storyKey, true);
}
function storyKey(e) {
  if (!_storyActive) return;
  if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); endStory(); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); storyNext(); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); storyPrev(); }
}
function storyNext() { if (!_storyActive) return; if (_storyIdx < STORY.length - 1) storyGoto(_storyIdx + 1); else endStory(); }
function storyPrev() { if (_storyActive && _storyIdx > 0) storyGoto(_storyIdx - 1); }

/* ---- step driver ----------------------------------------------------- */
async function storyGoto(i) {
  _storyIdx = i;
  const step = STORY[i];
  $$('.story-inject').forEach(e => e.remove());   // clear any injected visuals from a prior beat
  _storySpotEl = null;
  if (_storyEls.spot) _storyEls.spot.style.opacity = '0';

  if (step.openDrawer != null) {
    if (typeof openFinding === 'function') openFinding(step.openDrawer);
    await waitFor('#drawer.show', 4000);
    await waitFor(step.highlight || '#drawer .hero', 4000);
  } else if (step.route) {
    if (typeof closeDrawer === 'function') closeDrawer();
    go(step.route);
    await waitFor(step.highlight || '#view .panel', 4000);
  }
  if (!_storyActive || _storyIdx !== i) return;   // user advanced/exited while we waited

  if (step.scrollTo) { const t = $(step.scrollTo); if (t) { t.scrollIntoView({ block: 'center' }); await _sdelay(380); } }
  renderCaption(step, i);
  positionSpot();
  if (step.onEnter) { try { await step.onEnter({ step, i }); } catch (e) { /* never let an animation break the flow */ } }
  positionSpot();
}

/* ---- caption card ---------------------------------------------------- */
function renderCaption(step, i) {
  const cap = _storyEls.cap; if (!cap) return;
  cap.innerHTML = '';
  cap.append(
    h('div', { class: 'sc-top' },
      h('span', { class: 'sc-step mono' }, `${i + 1} / ${STORY.length}`),
      h('span', { class: 'sc-tag' }, 'Storyline'),
      h('span', { style: 'flex:1' }),
      h('button', { class: 'sc-x', title: 'Exit (Esc)', onclick: endStory, html: ic('x') })),
    h('div', { class: 'sc-title' }, step.title),
    h('div', { class: 'sc-body' }, step.caption),
    h('div', { class: 'sc-foot' },
      h('div', { class: 'sc-dots' }, STORY.map((_, k) => h('i', { class: 'sc-dot' + (k === i ? ' on' : k < i ? ' done' : '') }))),
      h('span', { style: 'flex:1' }),
      h('button', { class: 'btn', onclick: storyPrev, disabled: i === 0 ? 'disabled' : null }, 'Back'),
      h('button', { class: 'btn primary', onclick: storyNext }, i === STORY.length - 1 ? 'Finish' : 'Next ›')));
}

/* ---- spotlight (box-shadow cutout; pure CSS, no canvas) -------------- */
function positionSpot() {
  if (!_storyActive) return;
  const spot = _storyEls.spot, step = STORY[_storyIdx]; if (!spot || !step) return;
  const el = _storySpotEl || (step.highlight ? $(step.highlight) : null);
  if (!el) { spot.style.opacity = '0'; return; }
  const r = el.getBoundingClientRect();
  if (r.width < 2 || r.height < 2) { spot.style.opacity = '0'; return; }
  const pad = 8;
  spot.style.opacity = '1';
  spot.style.top = Math.max(4, r.top - pad) + 'px';
  spot.style.left = Math.max(4, r.left - pad) + 'px';
  spot.style.width = Math.min(window.innerWidth - 8, r.width + pad * 2) + 'px';
  spot.style.height = (r.height + pad * 2) + 'px';
}

/* ---- helpers --------------------------------------------------------- */
function waitFor(sel, timeout) {
  return new Promise(res => {
    if (!sel) return res(null);
    const start = Date.now(), t = timeout || 4000;
    (function poll() { const el = $(sel.split(',')[0].trim()); if (el) return res(el); if (Date.now() - start > t) return res(null); requestAnimationFrame(poll); })();
  });
}
function countUp(el, target, dur, prefix) {
  if (!el) return;
  prefix = prefix || '';
  if (STORY_REDUCED) { el.textContent = prefix + target; return; }
  const start = performance.now();
  (function tick(now) {
    const p = Math.min(1, (now - start) / dur), ease = 1 - Math.pow(1 - p, 3);
    el.textContent = prefix + Math.round(target * ease);
    if (p < 1) requestAnimationFrame(tick);
  })(start);
}

/* ---- beat 1: noise→signal funnel ------------------------------------ */
async function animateFunnel() {
  const view = $('#view'); if (!view) return;
  const funnel = h('div', { class: 'panel pad story-inject story-funnel' },
    h('div', { class: 'sf-side' },
      h('div', { class: 'sf-n mono muted', id: 'sf-raw' }, '0'),
      h('div', { class: 'sf-l faint' }, 'raw tool alerts / day'),
      h('div', { class: 'sf-dots' }, Array.from({ length: 48 }).map(() => h('i', {})))),
    h('div', { class: 'sf-arrow' }, h('span', { html: ic('chevron') })),
    h('div', { class: 'sf-side hot' },
      h('div', { class: 'sf-n mono', id: 'sf-one' }, '1'),
      h('div', { class: 'sf-l' }, 'ranked decision')));
  view.prepend(funnel);
  _storySpotEl = funnel; positionSpot();
  countUp($('#sf-raw'), 500, 1000, '~');
  const one = $('#sf-one'); if (one && !STORY_REDUCED) { one.classList.remove('sf-pulse'); void one.offsetWidth; one.classList.add('sf-pulse'); }
}

/* ---- beat 3: SHAP waterfall builds bar-by-bar ----------------------- */
async function animateShap() {
  const bars = $$('#drawer .sfbars .sfbar .tr i');
  const big = $('#drawer .hero .big');
  const target = big ? Math.round(parseFloat(big.textContent) || 0) : 0;
  if (!bars.length) return;
  if (STORY_REDUCED) { if (big) big.textContent = String(target); return; }
  const widths = bars.map(i => i.style.width || '0%');
  bars.forEach(i => { i.style.transition = 'none'; i.style.width = '0%'; });
  if (big) big.textContent = '0';
  void bars[0].offsetWidth;                       // force reflow so 0% is committed
  bars.forEach((i, k) => setTimeout(() => { i.style.transition = 'width .5s cubic-bezier(.2,.8,.2,1)'; i.style.width = widths[k]; }, 90 * k));
  countUp(big, target, 90 * bars.length + 520);
}

/* ---- beat 4: multi-tool consensus reveal ---------------------------- */
async function animateConsensus() {
  const w = $('#view .consensus-reveal'); if (!w) return;
  const tools = $$('.cr-tool', w), fill = $('.cr-fill', w), cw = $('.cr-w', w), cf = $('.cr-cf', w);
  const steps = [['10%', '0.0'], ['50%', '0.5'], ['100%', '1.0']];
  if (STORY_REDUCED) { tools.forEach(t => t.classList.add('on')); if (fill) fill.style.width = '100%'; if (cw) cw.textContent = '1.0'; if (cf) cf.classList.add('show'); return; }
  tools.forEach(t => t.classList.remove('on'));
  if (fill) { fill.style.transition = 'none'; fill.style.width = '0%'; }
  if (cw) cw.textContent = '0.0';
  if (cf) cf.classList.remove('show');
  await _sdelay(120);
  for (let k = 0; k < tools.length; k++) {
    await _sdelay(640);
    if (!_storyActive) return;
    tools[k].classList.add('on');
    if (fill) { fill.style.transition = 'width .55s cubic-bezier(.2,.8,.2,1)'; fill.style.width = steps[k][0]; }
    if (cw) cw.textContent = steps[k][1];
  }
  await _sdelay(520);
  if (cf) cf.classList.add('show');
}

/* ---- beat 6: drive the two-person approval gate --------------------- */
async function driveApprovalGate() {
  // the drawer loads some blocks (attribution graph) async ABOVE the gate, so settle first,
  // then scroll — and re-scroll after each click because the gate re-renders at a new height.
  // direct scrollTop on the drawer's scroll container — reliable everywhere (smooth-scroll
  // doesn't settle under headless virtual-time, and the gate sits near the bottom).
  const scroll = () => {
    const g = $('#drawer .gate'), db = $('#drawer .drawer-b');
    if (g && db) { const gr = g.getBoundingClientRect(), dr = db.getBoundingClientRect(); db.scrollTop += (gr.top - dr.top) - (db.clientHeight - gr.height) / 2; }
  };
  await _sdelay(750);
  scroll(); await _sdelay(450); positionSpot();
  const btn = txt => $$('#drawer .gate button').find(b => b.textContent.trim().toLowerCase().includes(txt));
  const tap = async (txt, wait) => { const b = btn(txt); if (b) b.click(); await _sdelay(wait); scroll(); positionSpot(); };
  await tap('approve', 1000);            // proposed → awaiting second approver
  await tap('simulate second', 1000);    // → authorized
  await tap('execute containment', 1300);// → executing → (auto, 900ms) contained
  await _sdelay(1000); scroll(); positionSpot();
}

/* ---- beat 7: trust — flash the contained egress rows ---------------- */
async function animateTrust() {
  const chips = $$('#view .tbl .chip.ok');
  if (STORY_REDUCED || !chips.length) return;
  chips.forEach((c, k) => setTimeout(() => { c.classList.remove('story-flash'); void c.offsetWidth; c.classList.add('story-flash'); }, k * 110));
}
