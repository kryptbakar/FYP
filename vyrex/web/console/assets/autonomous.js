/* =====================================================================
   VYREX — Autonomous Defense command center (Sentinel · Decoy · Mend · Forge).

   The agentic "self-driving SOC" surface: graded-autonomy response, deception
   tripwires, self-healing remediation, and continuous adversary emulation.
   Demo-driven + deterministic (works offline); every destructive path stays
   GOVERNED (signed, reversible, two-person for high blast-radius) — this is
   active defense, never hack-back. Honestly labelled as a governed simulation.

   Globals used (ui.js / views.js, loaded earlier): h, $, $$, bento, tile, chip,
   ic, toast, donut, n0, band, severity, eAsset.
   ===================================================================== */
'use strict';

const AUTODEF = {
  level: 'reversible',                 // advisory | reversible | full
  mttc: 0.8,                           // mean-time-to-contain (s)
  autoHandled: 47,
  timers: [],
  log: [
    { t: 'CONTAIN', title: 'xz/liblzma backdoor — sshd RCE', host: 'k8s-node-02', action: 'isolate_host', blast: 'med', secs: 0.7, when: '2m ago' },
    { t: 'CONTAIN', title: 'C2 beacon on tcp/4444 (Cobalt Strike)', host: 'web-prod-03', action: 'block_ip', blast: 'low', secs: 0.5, when: '9m ago' },
    { t: 'MONITOR', title: 'runc container escape attempt', host: 'k8s-node-02', action: 'watch', blast: 'low', secs: 0.4, when: '21m ago' },
    { t: 'CONTAIN', title: 'PwnKit local privilege escalation', host: 'mail-gw-01', action: 'kill_process', blast: 'low', secs: 0.6, when: '34m ago' },
    { t: 'DISMISS', title: 'nginx 1.18 outdated — no exploit path', host: 'ws-eng-22', action: 'none', blast: 'none', secs: 0.3, when: '51m ago' },
  ],
  decoys: [
    { name: 'AWS_SECRET_KEY (fake)', kind: 'credential', where: 'web-prod-03:/home/deploy/.aws', state: 'armed' },
    { name: 'domain-admin / B@ckup2024', kind: 'credential', where: 'Active Directory', state: 'armed' },
    { name: 'salaries_2026.xlsx', kind: 'canary file', where: 'mail-gw-01:/finance', state: 'armed' },
    { name: 'phantom Postgres :5433', kind: 'decoy service', where: 'db-core-01', state: 'armed' },
    { name: 'jump-box-07 (decoy host)', kind: 'decoy host', where: '10.4.9.99', state: 'armed' },
  ],
  mend: [
    { what: '/etc/passwd — unauthorized user "svc-x" added', host: 'web-prod-03', fix: 'Restore from FIM baseline', healed: false },
    { what: 'cron @reboot curl … | bash (persistence)', host: 'mail-gw-01', fix: 'Remove cron + kill process', healed: false },
    { what: 'nginx.conf — proxy_pass to attacker host', host: 'scan-target-01', fix: 'Roll back to known-good', healed: false },
  ],
  forge: [
    { tac: 'Initial Access', tech: 'T1190 Exploit public-facing app', result: null },
    { tac: 'Execution', tech: 'T1059 Command interpreter', result: null },
    { tac: 'Priv. Esc', tech: 'T1068 Exploitation for PrivEsc', result: null },
    { tac: 'Defense Evasion', tech: 'T1562 Impair defenses', result: null },
    { tac: 'C2', tech: 'T1071 App-layer protocol', result: null },
    { tac: 'Exfiltration', tech: 'T1041 Exfil over C2', result: null },
  ],
};

const LEVELS = {
  advisory:   { lb: 'Advisory',          d: 'Agent proposes only — every action waits for a human.' },
  reversible: { lb: 'Auto · reversible', d: 'Auto-executes reversible/low-blast actions in seconds; destructive ones escalate.' },
  full:       { lb: 'Full autonomy',     d: 'Agent acts on all containment; two-person only for irreversible changes.' },
};
const BLAST = { none: '', low: 'ok', med: 'warn', high: 'kev' };

function _at(fn, ms) { const id = setTimeout(fn, ms); AUTODEF.timers.push(id); return id; }

async function viewAutonomous(root) {
  if (window._viewCleanup) { try { window._viewCleanup(); } catch {} }
  AUTODEF.timers = [];
  window._viewCleanup = () => { AUTODEF.timers.forEach(clearTimeout); AUTODEF.timers = []; };
  root.innerHTML = '';

  // ---- hero banner ----
  root.append(h('div', { class: 'hero-banner fade' },
    h('div', { class: 'hb-main' },
      h('div', { class: 'hb-title' }, 'Autonomous Defense'),
      h('div', { class: 'hb-sub' }, 'The agent detects, decides, contains, heals and hardens — sub-second, signed, and fully governed. Active defense, never hack-back.'),
      h('div', { class: 'hb-ribbon' },
        chip('Sentinel · graded autonomy', 'consensus'),
        chip('Decoy · deception', 'intel'),
        chip('Mend · self-healing', 'ok'),
        chip('Forge · adversary emulation', 'warn'),
        chip('governed simulation', ''))),
    h('div', { class: 'hb-side' },
      h('div', { class: 'hb-metric' }, h('div', { class: 'v high' }, AUTODEF.mttc + 's'), h('div', { class: 'l' }, 'mean time to contain')),
      h('div', { class: 'hb-metric' }, h('div', { class: 'v' }, String(AUTODEF.autoHandled)), h('div', { class: 'l' }, 'auto-handled today')),
      h('button', { class: 'btn primary', onclick: simulateAttack, html: ic('target') + '<span style="margin-left:7px">Simulate live attack</span>' }))));

  // ---- Sentinel ----
  root.append(sentinelPanel());
  // ---- Decoy + Mend ----
  root.append(bento(
    tile({ span: 6, pad0: true, title: 'Decoy · deception grid', sub: '· honeytokens armed across the estate', cls: 'fade' }, decoyBody()),
    tile({ span: 6, pad0: true, title: 'Mend · self-healing', sub: '· restore tampered state to baseline', cls: 'fade' }, mendBody())));
  // ---- Forge ----
  root.append(forgePanel());
}

/* ---- SENTINEL ------------------------------------------------------- */
function sentinelPanel() {
  const dial = h('div', { class: 'autlevel' }, Object.entries(LEVELS).map(([k, v]) =>
    h('button', { class: 'al-opt' + (AUTODEF.level === k ? ' on' : ''), 'data-lvl': k,
      onclick: () => { AUTODEF.level = k; $$('.al-opt').forEach(b => b.classList.toggle('on', b.dataset.lvl === k));
        $('#al-desc').textContent = LEVELS[k].d; try { API.setDefensePolicy(k); } catch {} toast('Autonomy: ' + v.lb, true); } }, v.lb)));
  return h('div', { class: 'panel pad fade', style: 'margin-bottom:14px' },
    h('div', { class: 'row', style: 'gap:var(--s-3);flex-wrap:wrap;margin-bottom:var(--s-3)' },
      h('div', {}, h('div', { class: 'sec-label' }, 'Sentinel · autonomy policy'),
        h('div', { class: 'faint', id: 'al-desc', style: 'font-size:var(--t-xs);margin-top:3px' }, LEVELS[AUTODEF.level].d)),
      h('span', { class: 'spring', style: 'flex:1' }), dial),
    h('div', { class: 'sec-label', style: 'margin:6px 0 10px' }, 'Autonomous decision log'),
    h('div', { class: 'dlog', id: 'dlog' }, AUTODEF.log.map(decisionRow)));
}
function decisionRow(d) {
  const tone = d.t === 'CONTAIN' ? 'exploit' : d.t === 'MONITOR' ? 'warn' : 'mono';
  return h('div', { class: 'dlrow' },
    h('span', { class: 'chip ' + tone, style: 'min-width:78px;justify-content:center' }, d.t),
    h('div', { style: 'flex:1;min-width:0' }, h('div', { class: 'dl-t' }, d.title),
      h('div', { class: 'wrap', style: 'gap:6px;margin-top:3px' }, eAsset(d.host),
        d.action !== 'none' ? chip(d.action.replace(/_/g, ' '), 'mono') : null,
        d.blast !== 'none' ? chip('blast: ' + d.blast, BLAST[d.blast]) : null)),
    h('div', { style: 'text-align:right;flex:none' },
      h('div', { class: 'mono', style: 'font-size:var(--t-sm);color:var(--success-text)' }, d.secs + 's'),
      h('div', { class: 'faint mono', style: 'font-size:var(--t-3xs)' }, 'signed ✓ · ' + d.when)));
}
function simulateAttack() {
  const log = $('#dlog'); if (!log) return;
  try { API.defenseEvaluate(); } catch {}   // live: runs the real engine → real signed actions + audit
  const row = h('div', { class: 'dlrow live' },
    h('span', { class: 'chip warn', style: 'min-width:78px;justify-content:center' }, 'INCOMING'),
    h('div', { style: 'flex:1;min-width:0' }, h('div', { class: 'dl-t', id: 'sim-t' }, 'Suspicious credential access on web-prod-03…'),
      h('div', { class: 'wrap', style: 'gap:6px;margin-top:3px', id: 'sim-meta' }, eAsset('web-prod-03'), chip('detecting…', 'warn'))),
    h('div', { style: 'text-align:right;flex:none' }, h('div', { class: 'working', id: 'sim-clock' }, h('span', { class: 'd' }), 'live')));
  log.prepend(row);
  toast('⚠ Live attack detected — agent engaging', false);
  const meta = $('#sim-meta');
  _at(() => { if (!meta) return; meta.innerHTML = ''; meta.append(eAsset('web-prod-03'), chip('AI deciding…', 'intel'), chip('blast: low', 'ok')); }, 700);
  _at(() => { const t = $('#sim-t'); if (t) t.textContent = 'Decision: CONTAIN — isolate host + revoke token (reversible)'; }, 1500);
  _at(() => { if (meta) { meta.innerHTML = ''; meta.append(eAsset('web-prod-03'), chip('isolate host', 'mono'), chip('executing signed cmd…', 'warn')); } }, 2100);
  _at(() => {
    row.classList.remove('live'); row.classList.add('done');
    const t = $('#sim-t'); if (t) t.textContent = 'CONTAINED — host isolated, token revoked, Ed25519-signed';
    if (meta) { meta.innerHTML = ''; meta.append(eAsset('web-prod-03'), chip('isolate_host', 'mono'), chip('blast: low', 'ok'), chip('autonomous', 'consensus')); }
    const clk = $('#sim-clock'); if (clk) { clk.className = ''; clk.innerHTML = ''; clk.append(h('div', { class: 'mono', style: 'color:var(--success-text);font-size:var(--t-md)' }, '0.8s'), h('div', { class: 'faint mono', style: 'font-size:var(--t-3xs)' }, 'signed ✓ · just now')); }
    AUTODEF.autoHandled++; toast('✓ Threat contained autonomously in 0.8s — no human in the loop', true);
  }, 3200);
}

/* ---- DECOY ---------------------------------------------------------- */
function decoyBody() {
  const grid = h('div', { class: 'htgrid', id: 'htgrid' }, AUTODEF.decoys.map(htCard));
  const bar = h('div', { class: 'row', style: 'padding:12px 16px;border-top:1px solid var(--line);gap:var(--s-2)' },
    h('span', { class: 'faint', style: 'font-size:var(--t-2xs);flex:1' }, 'A real user never touches these. An attacker does → 100%-confidence tripwire → auto-isolate.'),
    h('button', { class: 'btn sm primary', onclick: tripHoneytoken, html: ic('target') + '<span style="margin-left:6px">Simulate intrusion</span>' }));
  return h('div', {}, grid, bar);
}
function htCard(d, i) {
  return h('div', { class: 'htoken' + (d.state === 'tripped' ? ' tripped' : ''), 'data-i': i },
    h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'ht-dot' }),
      h('span', { class: 'ht-k faint mono' }, d.kind), h('span', { class: 'spring', style: 'flex:1' }),
      chip(d.state === 'tripped' ? 'TRIPPED' : 'armed', d.state === 'tripped' ? 'kev' : 'ok')),
    h('div', { class: 'ht-n mono' }, d.name),
    h('div', { class: 'faint mono', style: 'font-size:var(--t-3xs);margin-top:3px' }, d.where));
}
function tripHoneytoken() {
  const armed = AUTODEF.decoys.map((d, i) => ({ d, i })).filter(x => x.d.state === 'armed');
  if (!armed.length) { AUTODEF.decoys.forEach(d => d.state = 'armed'); const g = $('#htgrid'); if (g) { g.innerHTML = ''; AUTODEF.decoys.forEach((d, i) => g.append(htCard(d, i))); } toast('Honeytokens re-armed', true); return; }
  const pick = armed[Math.floor(Math.random() * armed.length)];
  AUTODEF.decoys[pick.i].state = 'tripped';
  try { API.tripDecoy(pick.i + 1); } catch {}   // live: real tripwire → auto-isolate + audit
  const g = $('#htgrid'); if (g) { g.innerHTML = ''; AUTODEF.decoys.forEach((d, i) => g.append(htCard(d, i))); }
  toast('🚨 Honeytoken TRIPPED — ' + AUTODEF.decoys[pick.i].name + ' — attacker located', false);
  _at(() => toast('✓ Source auto-isolated · full attack path captured · 100% confidence', true), 1400);
}

/* ---- MEND ----------------------------------------------------------- */
function mendBody() {
  const list = h('div', { id: 'mendlist' }, AUTODEF.mend.map((m, i) => mendRow(m, i)));
  return list;
}
function mendRow(m, i) {
  return h('div', { class: 'mendrow' + (m.healed ? ' healed' : ''), 'data-i': i },
    h('span', { class: 'gl s-' + (m.healed ? 'low' : 'critical'), style: 'margin-top:5px;flex:none' }),
    h('div', { style: 'flex:1;min-width:0' }, h('div', { class: 'mr-w' }, m.what),
      h('div', { class: 'wrap', style: 'gap:6px;margin-top:3px' }, eAsset(m.host),
        chip(m.healed ? 'restored ✓' : m.fix, m.healed ? 'ok' : 'mono'))),
    m.healed ? h('span', { class: 'chip ok', style: 'flex:none' }, 'healed')
      : h('button', { class: 'btn sm', style: 'flex:none', onclick: () => heal(i) }, 'Heal'));
}
function heal(i) {
  const m = AUTODEF.mend[i]; if (!m || m.healed) return;
  try { API.defenseHeal(m.what, m.host, 'restore_baseline'); } catch {}   // live: real remediation + audit
  toast('Self-healing — ' + m.fix + '…', false);
  _at(() => { m.healed = true; const list = $('#mendlist'); if (list) { list.innerHTML = ''; AUTODEF.mend.forEach((x, j) => list.append(mendRow(x, j))); }
    toast('✓ ' + m.host + ' restored to baseline', true); }, 900);
}

/* ---- FORGE ---------------------------------------------------------- */
function forgePanel() {
  const grid = h('div', { class: 'basgrid', id: 'basgrid' }, AUTODEF.forge.map(basCell));
  return h('div', { class: 'panel pad fade', style: 'margin-top:14px' },
    h('div', { class: 'row', style: 'gap:var(--s-3);margin-bottom:var(--s-3);flex-wrap:wrap' },
      h('div', {}, h('div', { class: 'sec-label' }, 'Forge · continuous adversary emulation'),
        h('div', { class: 'faint', style: 'font-size:var(--t-xs);margin-top:3px' }, 'Safely attacks your own estate to find what would work — then auto-hardens the gaps.')),
      h('span', { class: 'spring', style: 'flex:1' }),
      h('button', { class: 'btn sm', id: 'forge-harden', hidden: true, onclick: forgeHarden }, 'Auto-harden gaps'),
      h('button', { class: 'btn sm primary', id: 'forge-run', onclick: runForge, html: ic('target') + '<span style="margin-left:6px">Run breach simulation</span>' })),
    grid);
}
function basCell(f, i) {
  const cls = f.result === 'blocked' ? 'blocked' : f.result === 'open' ? 'open' : '';
  return h('div', { class: 'bascell ' + cls, 'data-i': i },
    h('div', { class: 'bc-tac faint' }, f.tac),
    h('div', { class: 'bc-tech mono' }, f.tech),
    h('div', { class: 'bc-r' }, f.result === 'blocked' ? 'BLOCKED ✓' : f.result === 'open' ? 'WOULD SUCCEED' : '—'));
}
function runForge() {
  try { API.defenseEmulate(); } catch {}   // live: real BAS vs detection coverage
  AUTODEF.forge.forEach(f => f.result = null);
  const render = () => { const g = $('#basgrid'); if (g) { g.innerHTML = ''; AUTODEF.forge.forEach((f, i) => g.append(basCell(f, i))); } };
  render(); toast('Running breach & attack simulation…', false);
  AUTODEF.forge.forEach((f, i) => _at(() => {
    f.result = (i === 2 || i === 4) ? 'open' : 'blocked';   // a couple of gaps to dramatise
    render();
    if (i === AUTODEF.forge.length - 1) { const hb = $('#forge-harden'); if (hb) hb.hidden = false;
      toast('Simulation complete — 2 techniques would succeed', false); }
  }, 500 + i * 450));
}
function forgeHarden() {
  try { API.defenseHarden(); } catch {}   // live: auto-creates detection rules for the gaps
  AUTODEF.forge.forEach(f => f.result = 'blocked');
  const g = $('#basgrid'); if (g) { g.innerHTML = ''; AUTODEF.forge.forEach((f, i) => g.append(basCell(f, i))); }
  const hb = $('#forge-harden'); if (hb) hb.hidden = true;
  toast('✓ Gaps auto-hardened — full ATT&CK coverage restored', true);
}
