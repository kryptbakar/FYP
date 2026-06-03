/* =====================================================================
   UI primitives + components. Dependency-free; all charts are inline SVG/CSS.
   Severity is encoded by SHAPE + LABEL (color only reinforces) for WCAG.
   ===================================================================== */
'use strict';

/* ---- DOM builder ----------------------------------------------------- */
function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'html') e.innerHTML = v;
    else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const kid of kids.flat()) { if (kid == null || kid === false) continue; e.append(kid.nodeType ? kid : document.createTextNode(kid)); }
  return e;
}
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* ---- format + severity ---------------------------------------------- */
const SEVOF = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', INFO: 'info' };
const sevClass = s => SEVOF[(s || 'INFO').toUpperCase()] || 'info';
function band(score) { const n = +score; return n >= 80 ? 'critical' : n >= 60 ? 'high' : n >= 40 ? 'medium' : n >= 20 ? 'low' : 'info'; }
const SEVLABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };
const n1 = (v) => (v == null || v === '' ? '—' : (+v).toFixed(1));
const n0 = (v) => (v == null || v === '' ? '—' : Math.round(+v).toString());
const pct = (v) => (v == null ? '—' : Math.round(+v * 100) + '%');
const ago = (s) => { if (!s) return '—'; const d = (Date.now() - new Date(s)) / 36e5; return d < 1 ? `${Math.max(1, Math.round(d * 60))}m ago` : d < 24 ? `${Math.round(d)}h ago` : `${Math.round(d / 24)}d ago`; };

/* ATT&CK technique names — static reference data (air-gap clean; no lookup) */
const ATTACK = { T1190: 'Exploit Public-Facing Application', T1133: 'External Remote Services', T1566: 'Phishing', T1059: 'Command & Scripting Interpreter',
  T1203: 'Exploitation for Client Execution', T1068: 'Exploitation for Privilege Escalation', T1548: 'Abuse Elevation Control', T1562: 'Impair Defenses',
  T1070: 'Indicator Removal', T1071: 'Application Layer Protocol (C2)', 'T1071.001': 'Web Protocols (C2)', T1571: 'Non-Standard Port', T1090: 'Proxy',
  T1041: 'Exfiltration Over C2', T1048: 'Exfiltration Over Alternative Protocol', T1486: 'Data Encrypted for Impact', T1547: 'Boot/Logon Autostart', T1543: 'Create/Modify System Process' };
const attackName = (t) => t ? (ATTACK[t] || ATTACK[String(t).split('.')[0]] || 'technique') : '';

/* ---- icons (line, 1.6px) -------------------------------------------- */
const PATHS = {
  triage: 'M4 6h16M4 12h10M4 18h7', detail: 'M9 3v18M3 9h18M3 3h18v18H3z', shield: 'M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z',
  cases: 'M3 7h18v13H3zM8 7V4h8v3', fusion: 'M12 3v4M12 17v4M3 12h4M17 12h4M7.5 7.5l2.8 2.8M13.7 13.7l2.8 2.8M16.5 7.5l-2.8 2.8M10.3 13.7l-2.8 2.8',
  shieldcheck: 'M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Zm-3 9.5 2 2 4-4.5', lock: 'M6 10V7a6 6 0 0 1 12 0v3M5 10h14v11H5z',
  chevron: 'm9 6 6 6-6 6', x: 'M6 6l12 12M18 6 6 18', shield2: 'M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5z' };
const ic = (k) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="${PATHS[k]}"/></svg>`;

/* ---- atoms ----------------------------------------------------------- */
function severity(sev) {
  const c = sevClass(sev);
  return h('span', { class: 'sev ' + c }, h('span', { class: 'gl s-' + c }), SEVLABEL[c]);
}
const chip = (txt, cls = '') => h('span', { class: 'chip ' + cls }, txt);
function consensusChip(con) {
  if (!con || (con.n_tools || 0) < 2) return null;
  return chip(`${con.n_tools} tools agree`, 'consensus');
}
function toolChip(t, onclick) { const c = h('span', { class: 'chip tool', onclick }, t); return c; }

/* ---- SHAP waterfall (inline SVG/CSS, 0–100 x-domain) ----------------- */
function waterfall(rows) {
  const X = (v) => Math.max(0, Math.min(100, +v));
  const baseCum = +rows[0].cumulative, finalCum = +rows[rows.length - 1].cumulative;
  const axis = h('div', { class: 'axis' });
  [0, 25, 50, 75, 100].forEach(t => { axis.append(h('span', { style: `left:${t}%` }, String(t)), h('span', { class: 'tick', style: `left:${t}%` })); });
  const wrap = h('div', { class: 'wf' }, axis);
  let sum = 0;
  rows.forEach((r, i) => {
    const isBase = i === 0, isFinal = i === rows.length - 1;
    const track = h('div', { class: 'wftrack' }, h('div', { class: 'grid0', style: `left:${X(baseCum)}%` }));
    let cls, left, width, clab, ccls = '';
    if (isBase || isFinal) {
      left = 0; width = X(r.cumulative); cls = 'anchor'; clab = n1(r.cumulative);
    } else {
      const prev = +rows[i - 1].cumulative, cur = +r.cumulative; sum += +r.contribution;
      left = Math.min(X(prev), X(cur)); width = Math.abs(X(cur) - X(prev));
      const positive = (+r.contribution) >= 0;
      cls = positive ? ('pos' + (Math.abs(+r.contribution) >= 10 ? ' hi' : '')) : 'neg';
      ccls = positive ? 'pos' : 'neg'; clab = (positive ? '+' : '') + n1(r.contribution);
    }
    track.append(h('div', { class: 'wfbar ' + cls, style: `left:${left}%;width:${Math.max(width, 0.7)}%` }));
    const label = isBase ? 'base value' : isFinal ? 'final score' : `${r.feature}`;
    wrap.append(h('div', { class: 'wfr' + (isBase || isFinal ? ' anchor' : ''), title: isBase || isFinal ? '' : `${r.feature}: ${clab}` },
      h('div', { class: 'k' }, label), track, h('div', { class: 'c ' + ccls }, clab)));
  });
  const ok = Math.abs(baseCum + sum - finalCum) < 1.5;
  wrap.append(h('div', { class: 'check' }, `base ${n1(baseCum)} + Σ contributions ${sum >= 0 ? '+' : ''}${n1(sum)} = ${n1(finalCum)} ${ok ? '✓' : '≈'}`));
  return wrap;
}

/* ---- consensus panel ------------------------------------------------- */
function consensusPanel(con) {
  const w = con.weight || 0; const filled = w >= 1 ? 3 : w >= 0.5 ? 2 : con.n_tools >= 1 ? 1 : 0;
  const pips = h('span', { class: 'pips' }, [0, 1, 2].map(i => h('span', { class: 'pip' + (i < filled ? ' on' : '') })));
  const statement = con.n_tools > 1
    ? `${con.n_tools} independent tools corroborate · consensus weight ${w.toFixed(1)}`
    : `single-source detection · consensus weight ${w.toFixed(1)}`;
  return h('div', { class: 'stack', style: 'gap:10px' },
    h('div', { class: 'row' }, pips, h('span', { style: 'font-size:13px' }, statement)),
    h('div', { class: 'wrap' }, (con.tools || []).map(t => toolChip(t))),
    h('div', { class: 'faint mono', style: 'font-size:10.5px' }, 'dedup_key ' + (con.dedup_key || '—')));
}

/* ---- counterfactuals ------------------------------------------------- */
function counterfactuals(list) {
  return h('div', {}, (list || []).map(c => h('div', { class: 'cf' },
    h('span', {}, c.change),
    h('span', { class: 'd ' + ((c.delta || 0) < 0 ? 'down' : 'up') }, `${(c.delta || 0) < 0 ? '' : '+'}${n1(c.delta)} → ${n0(c.new_score)} (${SEVLABEL[band(c.new_score)]})`))));
}

/* ---- provenance (expandable raw signal) ------------------------------ */
function provenance(f) {
  const ev = f.evidence || {};
  const box = h('div', { class: 'prov' });
  const body = h('div', { class: 'prov-b' }, h('pre', {}, JSON.stringify(ev, null, 2)));
  const head = h('div', { class: 'prov-h', onclick: () => box.classList.toggle('open') },
    h('span', { html: ic('chevron'), style: 'width:13px;height:13px;color:var(--faint)' }),
    chip(f.source_tool || 'agent', 'tool'),
    h('span', { style: 'font-size:12px' }, ev.signal || f.raw_ref || 'raw signal'),
    h('span', { style: 'flex:1' }),
    h('span', { class: 'faint mono', style: 'font-size:10.5px' }, ev.observed_at ? ago(ev.observed_at) : ''));
  box.append(head, body); return box;
}

/* ---- two-person approval gate --------------------------------------- */
const DESTRUCTIVE = ['isolate_host', 'block_ip', 'kill_process', 'quarantine_file', 'disable_account'];
function approvalGate(action, opts) {
  opts = opts || {};
  const destructive = DESTRUCTIVE.includes(action.action);
  // local state machine
  let state = action.status || 'proposed';
  const approvals = new Set(action.approvals || []);
  const me = 'analyst';
  const el = h('div', { class: 'gate' });

  function steps() {
    const seq = destructive
      ? ['proposed', 'approved_by_you', 'awaiting_second_approver', 'authorized', 'executing', 'contained']
      : ['proposed', 'approved', 'executing', 'done'];
    const labels = { proposed: 'Proposed', approved_by_you: 'You approved', awaiting_second_approver: '2nd approver', authorized: 'Authorized', executing: 'Executing', contained: 'Contained', approved: 'Approved', done: 'Done' };
    const idx = seq.indexOf(state);
    const row = h('div', { class: 'gate-steps' });
    seq.forEach((s, i) => {
      row.append(h('div', { class: 'gstep ' + (i < idx ? 'done' : i === idx ? 'active' : '') },
        h('span', { class: 'n' }, i < idx ? '✓' : String(i + 1)), labels[s]));
      if (i < seq.length - 1) row.append(h('div', { class: 'arr' }));
    });
    return row;
  }
  function controls() {
    const c = h('div', { class: 'gate-b' });
    c.append(h('div', { class: 'blast' }, h('strong', {}, 'Blast radius: '),
      `${action.action.replace(/_/g, ' ')} → ${action.target || 'target'}. Containment-only, reversible, over the Ed25519-signed channel; every transition is appended to the hash-chained audit log.`));
    if (state === 'proposed') {
      c.append(h('div', { class: 'row' },
        h('button', { class: 'btn primary', onclick: () => approve(me) }, 'Approve'),
        h('button', { class: 'btn', onclick: () => opts.onclose && opts.onclose() }, 'Edit'),
        h('button', { class: 'btn danger', onclick: deny }, 'Deny')));
    } else if (destructive && state === 'awaiting_second_approver') {
      c.append(h('div', { class: 'working' }, h('span', { class: 'd' }), `Awaiting a second, distinct approver — you (${[...approvals][0]}) cannot satisfy both.`));
      c.append(h('div', { class: 'row' },
        h('button', { class: 'btn', onclick: () => approve('analyst-2', true) }, '(simulate second approver)'),
        h('button', { class: 'btn danger', onclick: deny }, 'Deny')));
    } else if (state === 'authorized') {
      c.append(h('button', { class: 'btn primary', onclick: execute }, 'Execute containment'));
    } else if (state === 'executing') {
      c.append(h('div', { class: 'working' }, h('span', { class: 'd' }), 'Executing over the signed channel…'));
    } else {
      c.append(h('div', { class: 'row' }, h('span', { class: 'chip ok' }, '✓ ' + state), h('span', { class: 'faint', style: 'font-size:11.5px' }, 'appended to the hash-chained audit log')));
    }
    return c;
  }
  async function approve(who, isSecond) {
    approvals.add(who);
    await API.approveAction(action.id, { analyst: who });
    if (!destructive) { state = 'approved'; render(); setTimeout(execute, 400); return; }
    if (approvals.size >= 2) state = 'authorized';
    else state = isSecond ? 'authorized' : 'awaiting_second_approver';
    render();
  }
  async function execute() {
    state = 'executing'; render();
    setTimeout(() => { state = destructive ? 'contained' : 'done'; render(); opts.onresolve && opts.onresolve(state); toast('Action ' + state + ' · audit entry written', true); }, 900);
  }
  async function deny() { await API.rejectAction(action.id, { analyst: me }); state = 'denied'; render(); opts.onresolve && opts.onresolve('denied'); }
  function render() {
    el.innerHTML = '';
    el.append(
      h('div', { class: 'gate-h' }, h('span', { html: ic('lock'), style: 'width:15px;height:15px;color:var(--accent)' }),
        h('strong', { style: 'font-size:13px' }, destructive ? 'Two-person approval required' : 'Approval'),
        h('span', { class: 'spring', style: 'flex:1' }), chip(action.action, 'mono')),
      steps(), controls());
  }
  render(); return el;
}

/* ---- misc ------------------------------------------------------------ */
function loading(label) { return h('div', { class: 'center' }, h('div', { class: 'spin' }), h('div', {}, label || 'Loading…')); }
let _toastT;
function toast(msg, ok) { const t = $('#toast'); t.className = 'toast show' + (ok ? ' ok' : ''); t.textContent = (ok ? '✓ ' : '') + msg; clearTimeout(_toastT); _toastT = setTimeout(() => t.classList.remove('show'), 3000); }
