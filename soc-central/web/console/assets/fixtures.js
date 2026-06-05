/* =====================================================================
   Embedded demo data. The console renders fully offline from these when /api
   is unreachable (the LIVE/DEMO indicator reflects which is in use). Shapes mirror
   the real FastAPI responses exactly, so views bind identically either way.
   ===================================================================== */
'use strict';

const FIX = (() => {
  const ranking = [
    { risk_rank: 1, id: 10, asset_id: 'web-prod-03', domain: 'application', title: 'CVE-2023-4911 (Looney Tunables) — local privilege escalation in glibc',
      severity: 'HIGH', cve_id: 'CVE-2023-4911', source_tool: 'agent', risk_score: '94.3', ml_risk_score: '94.3', kev: true, cvss_score: '7.8', epss: '0.71',
      attack: 'T1190', threat_intel: { indicator: '185.220.101.45', type: 'ip-dst', confidence: 90 },
      consensus: { tools: ['agent', 'trivy', 'suricata'], n_tools: 3, weight: 1.0, members: [10, 11, 7734], primary: 10, dedup_key: 'ce940f3478795574998a' } },
    { risk_rank: 2, id: 21, asset_id: 'web-prod-03', domain: 'network', title: 'Suspicious C2 egress on tcp/4444 to a known Cobalt Strike node',
      severity: 'CRITICAL', cve_id: null, source_tool: 'suricata', risk_score: '88.0', ml_risk_score: '88.0', kev: false, cvss_score: null, epss: null,
      attack: 'T1071.001', threat_intel: { indicator: '185.220.101.45', type: 'ip-dst', confidence: 90 },
      consensus: { tools: ['suricata', 'misp', 'agent'], n_tools: 3, weight: 1.0, members: [21, 22], primary: 21, dedup_key: 'a13be0c9' } },
    { risk_rank: 3, id: 33, asset_id: 'scan-target-01', domain: 'application', title: 'Apache Log4Shell (CVE-2021-44228) RCE exposed on an internet-facing service',
      severity: 'CRITICAL', cve_id: 'CVE-2021-44228', source_tool: 'nuclei', risk_score: '83.5', ml_risk_score: '83.5', kev: true, cvss_score: '10.0', epss: '0.94',
      attack: 'T1190', threat_intel: null, consensus: { tools: ['nuclei'], n_tools: 1, weight: 0.0, members: [33], primary: 33, dedup_key: '72d89492' } },
    { risk_rank: 4, id: 41, asset_id: 'db-core-01', domain: 'system', title: 'auditd not installed — host lacks tamper-evident audit logging (CIS 4.1.1)',
      severity: 'MEDIUM', cve_id: null, source_tool: 'wazuh', risk_score: '46.2', ml_risk_score: '46.2', kev: false, cvss_score: null, epss: null,
      attack: 'T1562', threat_intel: null, consensus: { tools: ['wazuh', 'agent'], n_tools: 2, weight: 0.5, members: [41, 42], primary: 41, dedup_key: 'bb19fd2' } },
    { risk_rank: 5, id: 55, asset_id: 'db-core-01', domain: 'application', title: 'CVE-2022-3715 — bash heap buffer overflow',
      severity: 'HIGH', cve_id: 'CVE-2022-3715', source_tool: 'trivy', risk_score: '41.0', ml_risk_score: '41.0', kev: false, cvss_score: '7.8', epss: '0.001',
      attack: null, threat_intel: null, consensus: { tools: ['trivy'], n_tools: 1, weight: 0.0, members: [55], primary: 55, dedup_key: 'f0a1b2' } },
    { risk_rank: 6, id: 60, asset_id: 'sensor-01', domain: 'network', title: 'Exposed Redis on tcp/6379 without authentication',
      severity: 'MEDIUM', cve_id: null, source_tool: 'agent', risk_score: '38.0', ml_risk_score: '38.0', kev: false, cvss_score: null, epss: null,
      attack: null, threat_intel: null, consensus: { tools: ['agent'], n_tools: 1, weight: 0.0, members: [60], primary: 60, dedup_key: 'c3d4e5' } },
  ];

  // lifecycle + derived exploit-availability signal (mirrors the live API fields)
  const CWE_DEMO = { 'CVE-2023-4911': 'CWE-787', 'CVE-2021-44228': 'CWE-502', 'CVE-2022-3715': 'CWE-787' };
  ranking.forEach(r => { r.triage_status = r.triage_status || 'open'; r.exploit_available = !!(r.kev || r.source_tool === 'nuclei');
    r.cwe = r.cwe || CWE_DEMO[r.cve_id] || null; r.cvss_predicted = r.cvss_predicted || false; });

  const explain = (id) => {
    const f = ranking.find(r => r.id === +id) || ranking[0];
    const comp = { cvss: 14.0, epss: 11.3, kev: 15.0, exposure: 8.2, threat_intel: f.threat_intel ? 9.0 : 0, consensus: (f.consensus.weight || 0) * 9, attack_ctx: f.attack ? 4.9 : 0, compliance_impact: 2.5, age: 4.0, criticality: 6.0 };
    const base = 48.1;
    const shap = { kev: 15.0, cvss: 12.8, consensus: 7.4 * (f.consensus.weight || 0) * 2, exposure: 6.4, epss: f.epss ? 5.2 : -1.8, threat_intel: f.threat_intel ? 8.5 : -1.1, attack_ctx: f.attack ? 2.9 : 0, age: 3.3, compliance_impact: 0.2, criticality: 0.2, attack_phase: 1.0 };
    const ordered = ['kev', 'cvss', 'consensus', 'exposure', 'epss', 'threat_intel', 'attack_ctx', 'age', 'compliance_impact', 'criticality', 'attack_phase'];
    let cum = base; const wf = [{ feature: 'base_value', contribution: base, cumulative: round(base) }];
    ordered.forEach(k => { cum += shap[k]; wf.push({ feature: k, contribution: round(shap[k], 2), cumulative: round(cum) }); });
    wf.push({ feature: 'ml_risk_score', contribution: 0, cumulative: round(+f.ml_risk_score) });
    return {
      finding: { id: f.id, title: f.title, domain: f.domain, severity: f.severity, risk_score: f.risk_score, ml_risk_score: f.ml_risk_score,
        risk_components: comp, model_version: 'xgb-20260602T093946Z', source_tool: f.source_tool, attack: f.attack, threat_intel: f.threat_intel, consensus: f.consensus,
        cve_id: f.cve_id, cvss_score: f.cvss_score, epss: f.epss, kev: f.kev, asset_id: f.asset_id },
      composite_components: comp, consensus: f.consensus,
      ml_explanation: { ml_risk_score: f.ml_risk_score, base_value: round(base), shap, waterfall: wf, model_version: 'xgb-20260602T093946Z',
        counterfactuals: [
          f.threat_intel ? { change: 'if there were no live MISP IOC match', new_score: round(+f.ml_risk_score - 12), delta: -12 } : null,
          (f.consensus.n_tools > 1) ? { change: 'if only one tool reported it (no corroboration)', new_score: round(+f.ml_risk_score - 21), delta: -21 } : null,
          f.kev ? { change: 'if not on the KEV list', new_score: round(+f.ml_risk_score - 20), delta: -20 } : null,
          { change: 'if the asset were not internet-exposed', new_score: round(+f.ml_risk_score - 18), delta: -18 },
        ].filter(Boolean) },
    };
  };

  const findingDetail = (id) => {
    const f = ranking.find(r => r.id === +id) || ranking[0];
    return { ...f, package_name: f.cve_id ? 'glibc' : null, raw_ref: f.source_tool === 'suricata' ? 'eve.json#alert.signature_id=2024897' : f.cve_id,
      exploit_refs: f.exploit_available ? [{ source: 'exploit-db', ref: 'EDB-51884', type: 'exploit' }, { source: 'metasploit', ref: 'exploit/linux/local/glibc_tunables_priv_esc', type: 'metasploit' }] : [],
      evidence: { source_tool: f.source_tool, signal: f.domain === 'network' ? 'ET MALWARE Cobalt Strike Beacon Observed' : `${f.cve_id} matched package inventory`, observed_at: '2026-06-02T09:38:58Z', port: f.domain === 'network' ? 4444 : null } };
  };

  function round(n, d = 1) { const p = 10 ** d; return Math.round(n * p) / p; }

  return {
    version: { service: 'soc-central-api', version: '1.0.0', environment: 'production' },
    ready: { status: 'ready', checks: { postgres: { ok: true }, opensearch: { ok: true }, nats: { ok: true } } },
    ranking, explain, findingDetail,
    stats: { assets: 7, kev_findings: 8, by_domain_severity: [
      { domain: 'application', severity: 'CRITICAL', count: 2 }, { domain: 'application', severity: 'HIGH', count: 11 }, { domain: 'application', severity: 'MEDIUM', count: 2 },
      { domain: 'network', severity: 'HIGH', count: 3 }, { domain: 'network', severity: 'MEDIUM', count: 2 }, { domain: 'network', severity: 'LOW', count: 2 },
      { domain: 'system', severity: 'MEDIUM', count: 12 }, { domain: 'system', severity: 'LOW', count: 6 } ],
      top_cves: [ { cve_id: 'CVE-2023-4911', cvss: '7.8', epss: '0.71', kev: true, occurrences: 6 }, { cve_id: 'CVE-2021-44228', cvss: '10.0', epss: '0.94', kev: true, occurrences: 2 } ] },
    assets: [
      { host_id: 'web-prod-03', hostname: 'web-prod-03', os: 'Debian GNU/Linux 12', ip: '10.4.2.13', exposure: 'internet', criticality: 1.0 },
      { host_id: 'scan-target-01', hostname: 'app-gw-02', os: 'Ubuntu 22.04 LTS', ip: '10.4.2.21', exposure: 'internet', criticality: 0.85 },
      { host_id: 'db-core-01', hostname: 'db-core-01', os: 'Debian GNU/Linux 12', ip: '10.4.9.2', exposure: 'internal', criticality: 0.9 },
      { host_id: 'sensor-01', hostname: 'cache-01', os: 'Debian GNU/Linux 12', ip: '10.4.9.7', exposure: 'internal', criticality: 0.5 } ],
    compSummary: { by_status: [ { status: 'pass', count: 22 }, { status: 'fail', count: 38 }, { status: 'not_applicable', count: 6 } ],
      per_asset: [ { asset_id: 'web-prod-03', pass: 5, fail: 5, partial: 0, not_applicable: 1, score_pct: '50.0' }, { asset_id: 'db-core-01', pass: 3, fail: 7, partial: 0, not_applicable: 1, score_pct: '30.0' } ] },
    compResults: [
      { asset_id: 'web-prod-03', rule_id: 'CIS 4.1.1', title: 'Ensure auditd is installed', status: 'fail' },
      { asset_id: 'web-prod-03', rule_id: 'CIS 5.2.1', title: 'Ensure permissions on SSH config are configured', status: 'pass' },
      { asset_id: 'db-core-01', rule_id: 'CIS 3.5.1', title: 'Ensure a firewall is configured', status: 'fail' },
      { asset_id: 'db-core-01', rule_id: 'CIS 1.4.1', title: 'Ensure automatic updates are enabled', status: 'partial' },
    ],
    compEvidence: [ { id: 18370, rule_id: 'CIS 4.1.1', asset_id: 'web-prod-03', status: 'fail', prev_hash: 'a1b2c3d4e5f6', hash: 'e39b4dc20b97e2125e1a', recorded_at: '2026-06-02T09:38:59Z' } ],
    chain: { ok: true, length: 19294, head_hash: 'e39b4dc20b97e2125e1a1849b4de29a0dfd76dbb6ccb12fbbf0b0c8b7a7f2df2' },
    // One threaded breach story: internet-facing exploit → C2 beacon → attempted lateral move.
    incidents: [
      { id: 1, asset_id: 'web-prod-03', title: 'Active C2 beacon on web-prod-03 (Cobalt Strike)', severity: 'critical', status: 'in_progress', assignee: 'hamza', created_by: 'soc-auto', sla_due: '2026-06-03T18:02:31Z', sla_breached: false, created_at: '2026-06-02T18:02:31Z', finding_count: 3 },
      { id: 2, asset_id: 'scan-target-01', title: 'Log4Shell exploitation on app-gw-02', severity: 'critical', status: 'contained', assignee: 'amina', created_by: 'soc-auto', sla_due: '2026-06-03T09:40:00Z', sla_breached: false, created_at: '2026-06-02T07:55:00Z', finding_count: 2 },
      { id: 3, asset_id: 'db-core-01', title: 'Lateral-movement attempt toward db-core-01', severity: 'high', status: 'open', assignee: null, created_by: 'soc-auto', sla_due: '2026-06-02T16:00:00Z', sla_breached: true, created_at: '2026-06-02T19:20:00Z', finding_count: 1 },
    ],
    actions: [
      { id: 1, incident_id: 1, action: 'isolate_host', target: 'web-prod-03', status: 'awaiting_second_approver', requested_by: 'hamza', approvals: ['hamza'], created_at: '2026-06-02T18:10:00Z' },
      { id: 2, incident_id: 2, action: 'isolate_host', target: 'app-gw-02', status: 'contained', requested_by: 'amina', approvals: ['amina', 'hamza'], created_at: '2026-06-02T08:05:00Z' },
      { id: 3, incident_id: 2, action: 'kill_process', target: 'app-gw-02', status: 'completed', requested_by: 'amina', approvals: ['amina', 'hamza'], created_at: '2026-06-02T08:09:00Z' },
    ],
    auditVerify: { ok: true, length: 12, head_hash: '7f3a9c2e1d8b4a60' },

    // Model card — mirrors GET /risk/model/metadata. States provenance + limitations honestly.
    modelCard: {
      model_version: 'xgb-20260602T093946Z',
      algorithm: 'XGBoost regressor (gradient-boosted trees)',
      explainer: 'TreeSHAP (exact per-feature attribution) + counterfactuals',
      primary_signal: 'composite weighted score (sums to 1.0)',
      composite_weights: { cvss: 0.18, epss: 0.16, kev: 0.15, exposure: 0.12, threat_intel: 0.10, consensus: 0.09, attack_ctx: 0.07, compliance_impact: 0.05, age: 0.04, criticality: 0.04 },
      features: ['cvss', 'epss', 'kev', 'exposure', 'threat_intel', 'consensus', 'attack_ctx', 'compliance_impact', 'age', 'criticality', 'attack_phase'],
      scope: { findings_scored_by_ml: 214, findings_scored_by_composite: 214, analyst_labels_captured: 11,
        feedback_by_action: [ { action: 'confirm_tp', n: 6 }, { action: 'mark_fp', n: 3 }, { action: 'escalate', n: 2 } ] },
      training: { label_source: 'composite priority score, plus analyst feedback weighted 5x', bootstrap: 'synthetic dataset until field labels accumulate', retrain_cadence: 'monthly (CronJob) and on demand' },
      limitations: [
        'Bootstrapped on synthetic data, so until enough analyst labels and real outcomes accumulate the ML score largely reproduces the composite formula — it is a re-ranker, not an independent oracle.',
        'Real-outcome labels (exploited / patched / dismissed) are the path to the model learning signal the formula does not already encode.' ],
      honest_status: 'feedback-adaptive re-ranker',
    },

    // Near-real-time detections feed — mirrors GET /detections/recent.
    recent: ranking.map((r, i) => ({ id: r.id, asset_id: r.asset_id, domain: r.domain, title: r.title, severity: r.severity,
      cve_id: r.cve_id, source_tool: r.source_tool, risk_score: r.risk_score, kev: r.kev, attack: r.attack, threat_intel: r.threat_intel,
      consensus: r.consensus, observed_at: new Date(Date.now() - (i * 7 + 2) * 60000).toISOString() })),

    // Multi-tool fusion clusters — mirrors GET /findings/clusters.
    clusters: ranking.filter(r => r.consensus && r.consensus.n_tools >= 2).map(r => ({
      dedup_key: r.consensus.dedup_key, n_tools: r.consensus.n_tools, tools: r.consensus.tools,
      top_risk_score: r.risk_score, severity: r.severity, primary_id: r.id, title: r.title, asset_id: r.asset_id })),

    // Response-action audit timeline — mirrors GET /response/audit/events (hash-chained lifecycle).
    auditEvents: [
      { seq: 12, action_id: 1, event: 'requested', actor: 'hamza', record: { action_type: 'network_isolate', target: 'web-prod-03' }, hash: '7f3a9c2e1d8b4a60', created_at: '2026-06-02T18:10:00Z' },
      { seq: 11, action_id: 1, event: 'approved', actor: 'hamza', record: { approvals: 1 }, hash: 'b21cc9e4f0a18d33', created_at: '2026-06-02T18:11:00Z' },
      { seq: 10, action_id: 3, event: 'completed', actor: 'agent', record: { output: 'process 4488 terminated' }, hash: 'c0ffee1234ab55de', created_at: '2026-06-02T08:09:40Z' },
      { seq: 9, action_id: 3, event: 'dispatched', actor: 'agent:app-gw-02', record: {}, hash: 'a9b8c7d6e5f40312', created_at: '2026-06-02T08:09:10Z' },
      { seq: 8, action_id: 2, event: 'completed', actor: 'agent', record: { output: 'iface eth0 isolated via nftables' }, hash: 'de1c0de900112233', created_at: '2026-06-02T08:06:20Z' },
      { seq: 7, action_id: 2, event: 'signed', actor: 'system', record: { pubkey: 'ed25519:9f12…c4' }, hash: '44aa55bb66cc77dd', created_at: '2026-06-02T08:05:40Z' },
      { seq: 6, action_id: 2, event: 'approved', actor: 'hamza', record: { approvals: 2 }, hash: '1122334455667788', created_at: '2026-06-02T08:05:30Z' },
      { seq: 5, action_id: 2, event: 'approved', actor: 'amina', record: { approvals: 1 }, hash: '8877665544332211', created_at: '2026-06-02T08:05:10Z' },
      { seq: 4, action_id: 2, event: 'requested', actor: 'amina', record: { action_type: 'network_isolate', target: 'app-gw-02' }, hash: '0f0e0d0c0b0a0908', created_at: '2026-06-02T08:05:00Z' },
    ],

    // Offline full-text log search — mirrors GET /logs/search (q + kind filter over telemetry).
    logSearch: (q, kind) => {
      const base = [
        { id: 'ev-7734', kind: 'ids_alert', agent_id: 'suricata-01', hostname: 'web-prod-03', ingested_at: '2026-06-02T18:01:55Z', payload: { signature: 'ET MALWARE Cobalt Strike Beacon Observed', src_ip: '10.4.2.13', dest_ip: '185.220.101.45', dest_port: 4444, severity: 1, proto: 'TCP' } },
        { id: 'ev-7720', kind: 'network_flow', agent_id: 'agent-web-prod-03', hostname: 'web-prod-03', ingested_at: '2026-06-02T18:01:40Z', payload: { direction: 'outbound', local_ip: '10.4.2.13', local_port: 51344, remote_ip: '185.220.101.45', remote_port: 4444 } },
        { id: 'ev-6611', kind: 'fim_event', agent_id: 'agent-web-prod-03', hostname: 'web-prod-03', ingested_at: '2026-06-02T17:58:02Z', payload: { path: '/tmp/.x/beacon', change: 'created', sha256: '9c1e…7a', size: 284160 } },
        { id: 'ev-5521', kind: 'runtime_alert', agent_id: 'falco-01', hostname: 'app-gw-02', ingested_at: '2026-06-02T07:54:31Z', payload: { rule: 'Shell spawned by Java process', proc: 'java→/bin/sh', fields: { 'fd.sip': '185.220.101.45' } } },
        { id: 'ev-5510', kind: 'ids_alert', agent_id: 'suricata-01', hostname: 'app-gw-02', ingested_at: '2026-06-02T07:54:10Z', payload: { signature: 'ET EXPLOIT Apache log4j RCE Attempt (jndi:ldap)', src_ip: '203.0.113.9', dest_ip: '10.4.2.21', dest_port: 443, severity: 1, proto: 'TCP' } },
        { id: 'ev-4400', kind: 'osquery_result', agent_id: 'agent-db-core-01', hostname: 'db-core-01', ingested_at: '2026-06-02T19:19:50Z', payload: { query_name: 'logged_in_users', user: 'svc-web', tty: 'pts/3', host: '10.4.2.13' } },
        { id: 'ev-4012', kind: 'traffic_metadata', agent_id: 'zeek-01', hostname: 'web-prod-03', ingested_at: '2026-06-02T18:00:12Z', payload: { 'id.resp_h': '185.220.101.45', service: 'ssl', 'ssl.server_name': 'updates.cdn-sync.net' } },
        { id: 'ev-3301', kind: 'scan_finding', agent_id: 'wazuh-01', hostname: 'db-core-01', ingested_at: '2026-06-02T06:00:00Z', payload: { policy: 'CIS Debian 12', check: 'auditd installed', result: 'failed' } },
      ];
      const ql = (q || '').toLowerCase();
      const hits = base.filter(h => (!kind || h.kind === kind) &&
        (!ql || JSON.stringify(h).toLowerCase().includes(ql)));
      return { total: hits.length, hits, available: true };
    },

    // Asset hub + per-asset filters (mirror /assets/{id}, /findings?asset_id, /compliance/results?asset_id).
    assetDetail: (id) => {
      const a = (FIX.assets || []).find(x => x.host_id === id) || { host_id: id, hostname: id, os: '—', ip: '—', criticality: 0.5 };
      const findings = ranking.filter(r => r.asset_id === id).map(r => ({ id: r.id, domain: r.domain, title: r.title, severity: r.severity, cve_id: r.cve_id, source_tool: r.source_tool, risk_score: r.risk_score, kev: r.kev, attack: r.attack }));
      const compliance = (FIX.compResults || []).filter(c => c.asset_id === id);
      return { asset: a, findings, compliance };
    },
    findingsBy: (id) => ranking.filter(r => r.asset_id === id),
    compResultsBy: (id) => (FIX.compResults || []).filter(c => c.asset_id === id),

    // Feedback impact loop (mirror /analysts/feedback-stats).
    feedbackStats: { total: 11,
      by_action: [ { action: 'confirm_tp', n: 6 }, { action: 'mark_fp', n: 3 }, { action: 'escalate', n: 2 } ],
      by_analyst: [ { analyst: 'hamza', n: 7 }, { analyst: 'amina', n: 4 } ],
      incorporated_in_models: ['xgb-20260602T093946Z', 'xgb-20260501T030010Z'] },

    // Detection catalog (mirror /detections) — derived from the ranked findings.
    detections: (() => { const m = {}; ranking.forEach(r => { const k = (r.source_tool || 'agent') + '|' + r.domain;
      m[k] = m[k] || { source_tool: r.source_tool || 'agent', domain: r.domain, hits: 0, kev_hits: 0, top_risk_score: 0 };
      m[k].hits++; if (r.kev) m[k].kev_hits++; m[k].top_risk_score = Math.max(m[k].top_risk_score, +r.risk_score); });
      return Object.values(m).sort((a, b) => b.hits - a.hits); })(),

    // Current user (mirror /whoami) — demo identity when no SSO proxy is in front.
    whoami: { authenticated: true, user: 'hamza', email: 'hamza@soc.local', roles: ['soc-analyst'], role: 'analyst', sso: 'keycloak / oauth2-proxy (demo)' },

    // Alerting inbox (mirror /notifications).
    notifications: [
      { id: 1, kind: 'critical_finding', severity: 'critical', title: 'Critical risk on web-prod-03', body: 'CVE-2023-4911 (Looney Tunables) — local privilege escalation in glibc', ref_type: 'finding', ref_id: '10', acknowledged: false, created_at: new Date(Date.now() - 9 * 60000).toISOString() },
      { id: 2, kind: 'critical_finding', severity: 'critical', title: 'Critical risk on web-prod-03', body: 'Suspicious C2 egress on tcp/4444 to a known Cobalt Strike node', ref_type: 'finding', ref_id: '21', acknowledged: false, created_at: new Date(Date.now() - 14 * 60000).toISOString() },
      { id: 3, kind: 'sla_breach', severity: 'high', title: 'SLA breached', body: 'Lateral-movement attempt toward db-core-01', ref_type: 'incident', ref_id: '3', acknowledged: false, created_at: new Date(Date.now() - 41 * 60000).toISOString() },
      { id: 4, kind: 'critical_finding', severity: 'critical', title: 'Critical risk on app-gw-02', body: 'Apache Log4Shell (CVE-2021-44228) RCE exposed on an internet-facing service', ref_type: 'finding', ref_id: '33', acknowledged: true, created_at: new Date(Date.now() - 70 * 60000).toISOString() },
    ],

    // Access audit (mirror /access/audit) — who viewed/changed what.
    accessAudit: [
      { seq: 42, actor: 'hamza', role: 'analyst', tenant: 'default', method: 'POST', path: '/findings/10/feedback', status: 200, created_at: new Date(Date.now() - 6 * 60000).toISOString() },
      { seq: 41, actor: 'hamza', role: 'analyst', tenant: 'default', method: 'PATCH', path: '/assets/db-core-01', status: 200, created_at: new Date(Date.now() - 22 * 60000).toISOString() },
      { seq: 40, actor: 'amina', role: 'admin', tenant: 'default', method: 'POST', path: '/actions/2/approve', status: 200, created_at: new Date(Date.now() - 95 * 60000).toISOString() },
      { seq: 39, actor: 'hamza', role: 'analyst', tenant: 'default', method: 'GET', path: '/whoami', status: 200, created_at: new Date(Date.now() - 130 * 60000).toISOString() },
    ],

    // Global search + entity pages.
    searchResults: (q) => {
      const ql = (q || '').toLowerCase();
      const findings = ranking.filter(r => `${r.title} ${r.cve_id || ''} ${r.asset_id}`.toLowerCase().includes(ql))
        .map(r => ({ id: r.id, asset_id: r.asset_id, title: r.title, severity: r.severity, cve_id: r.cve_id, source_tool: r.source_tool, risk_score: r.risk_score, kev: r.kev }));
      const assets = (FIX.assets || []).filter(a => `${a.host_id} ${a.hostname} ${a.ip}`.toLowerCase().includes(ql));
      const cves = [...new Set(ranking.filter(r => r.cve_id && r.cve_id.toLowerCase().includes(ql)).map(r => r.cve_id))]
        .map(c => { const r = ranking.find(x => x.cve_id === c); return { cve_id: c, cvss_score: r.cvss_score, kev: r.kev, cwe: r.cwe, occurrences: 1 }; });
      const iocs = (FIX.sightings || []).filter(s => s.indicator.toLowerCase().includes(ql)).map(s => ({ indicator: s.indicator, type: s.type }));
      return { query: q, findings, assets, cves, iocs, total: findings.length + assets.length + cves.length + iocs.length };
    },
    entityCve: (id) => { const r = ranking.find(x => x.cve_id === id) || {};
      return { cve_id: id, meta: { cve_id: id, cvss_score: r.cvss_score, cvss_severity: r.severity, cwe: r.cwe || 'CWE-787', description: 'Vulnerability ' + id + ' affecting the matched package.' },
        kev: r.kev ? { due_date: '2026-06-30', known_ransomware: 'Unknown' } : null, epss: r.epss ? { epss: r.epss, percentile: 0.9 } : null,
        exploits: r.exploit_available ? [{ source: 'exploit-db', ref: 'EDB-51884', type: 'exploit' }, { source: 'metasploit', ref: 'exploit/linux/local/glibc_tunables_priv_esc', type: 'metasploit' }] : [],
        findings: ranking.filter(x => x.cve_id === id).map(x => ({ id: x.id, asset_id: x.asset_id, title: x.title, severity: x.severity, source_tool: x.source_tool, risk_score: x.risk_score, triage_status: 'open' })),
        affected_assets: [...new Set(ranking.filter(x => x.cve_id === id).map(x => x.asset_id))] }; },
    entityIp: (ip) => { const fs = ranking.filter(r => r.threat_intel && r.threat_intel.indicator === ip);
      return { indicator: ip, sightings: (FIX.sightings || []).filter(s => s.indicator === ip),
        findings: fs.map(r => ({ id: r.id, asset_id: r.asset_id, title: r.title, severity: r.severity, source_tool: r.source_tool, risk_score: r.risk_score, attack: r.attack, threat_intel: r.threat_intel })),
        seen_on_assets: [...new Set(fs.map(r => r.asset_id))] }; },

    // Reports Center.
    reports: [
      { id: 2, type: 'executive', title: 'Executive Summary — 2026-06-05 08:00 UTC', generated_by: 'hamza', created_at: new Date(Date.now() - 60 * 60000).toISOString() },
      { id: 1, type: 'posture', title: 'Security Posture Report — 2026-06-04 18:00 UTC', generated_by: 'hamza', created_at: new Date(Date.now() - 14 * 3600000).toISOString() },
    ],
    reportDetail: (id) => ({ id: +id, type: 'posture', title: 'Security Posture Report (demo)', generated_by: 'hamza', created_at: new Date().toISOString(),
      content: { kpis: { assets: 7, open_findings: 40, kev: 8, exploit_available: 3, critical: 2, high: 14, avg_risk: 30.2 },
        risk_bands: { critical: 2, high: 14, medium: 18, low: 6 },
        top_risks: [{ risk_rank: 1, title: 'CVE-2023-4911 (Looney Tunables)', asset_id: 'web-prod-03', cve_id: 'CVE-2023-4911', severity: 'HIGH', risk: 94.3, kev: true },
          { risk_rank: 2, title: 'Suspicious C2 egress on tcp/4444', asset_id: 'web-prod-03', cve_id: null, severity: 'CRITICAL', risk: 88.0, kev: false }],
        by_tool: [{ tool: 'agent', n: 20 }, { tool: 'trivy', n: 8 }, { tool: 'nuclei', n: 6 }, { tool: 'wazuh', n: 4 }, { tool: 'suricata', n: 2 }] } }),
    generateReport: (type) => ({ id: Date.now(), type, title: type + ' report (demo) — just now', simulated: true,
      content: { kpis: { assets: 7, open_findings: 40, kev: 8, exploit_available: 3, critical: 2, high: 14, avg_risk: 30.2 }, risk_bands: { critical: 2, high: 14, medium: 18, low: 6 }, top_risks: [], by_tool: [] } }),

    // Organizations (mirror /tenants).
    tenants: [ { id: 'default', name: 'Default organization' }, { id: 'pitb', name: 'Punjab IT Board (demo)' } ],

    // Live hunt (Velociraptor) — fleet collection tasks + results.
    hunts: [
      { id: 1, name: 'Hunt: processes named "beacon"', artifact: 'processes', query: null, target: 'all', status: 'completed', created_by: 'hamza', created_at: new Date(Date.now() - 20 * 60000).toISOString(), result_count: 2 },
      { id: 2, name: 'Listening ports across the fleet', artifact: 'listening_ports', query: null, target: 'all', status: 'collecting', created_by: 'amina', created_at: new Date(Date.now() - 4 * 60000).toISOString(), result_count: 1 },
    ],
    huntDetail: (id) => ({ id: +id, name: 'Hunt: processes named "beacon"', artifact: 'processes', query: null, target: 'all', status: 'completed', created_by: 'hamza',
      results: [
        { id: 1, agent_id: 'agent-001', asset_id: 'web-prod-03', row_count: 2, collected_at: new Date(Date.now() - 19 * 60000).toISOString(),
          rows: [{ pid: 4488, ppid: 1, comm: 'beacon', cmdline: '/tmp/.x/beacon' }, { pid: 5012, ppid: 4488, comm: 'sh', cmdline: 'sh -i' }] },
        { id: 2, agent_id: 'agent-002', asset_id: 'db-core-01', row_count: 0, collected_at: new Date(Date.now() - 18 * 60000).toISOString(), rows: [] },
      ] }),
    createHunt: (b) => ({ id: Date.now(), name: b.name, artifact: b.artifact, query: b.query || null, target: b.target || 'all', status: 'queued', simulated: true }),

    // Case work (TheHive) — tasks + observables per incident.
    tasks: (incId) => ([
      { id: 1, title: 'Validate the detection / rule out false positive', status: 'done', assignee: 'hamza' },
      { id: 2, title: 'Scope: which hosts/users are affected', status: 'in_progress', assignee: 'hamza' },
      { id: 3, title: 'Contain — isolate affected host (two-person)', status: 'todo', assignee: null },
      { id: 4, title: 'Eradicate & recover; document timeline', status: 'todo', assignee: null },
    ]),
    observables: (incId) => ([
      { id: 1, type: 'host', value: 'web-prod-03', is_ioc: false, tlp: 'amber' },
      { id: 2, type: 'ip', value: '185.220.101.45', is_ioc: true, tlp: 'red' },
      { id: 3, type: 'cve', value: 'CVE-2023-4911', is_ioc: false, tlp: 'green' },
    ]),

    // SOAR (n8n/Shuffle) — playbooks + run history.
    playbooks: [
      { id: 'pb-critical-triage', name: 'Critical finding fast-triage', trigger: 'critical_finding', enabled: true,
        description: 'On a critical finding: raise an alert, open a case, and propose host containment for approval.',
        actions: [{ type: 'notify' }, { type: 'open_incident' }, { type: 'propose_containment', params: { action: 'network_isolate' } }] },
      { id: 'pb-c2-contain', name: 'Suspected C2 beacon containment', trigger: 'manual', enabled: true,
        description: 'On a C2/egress detection: alert, open a case, and propose isolating the source host.',
        actions: [{ type: 'notify' }, { type: 'open_incident' }, { type: 'propose_containment', params: { action: 'network_isolate' } }] },
      { id: 'pb-sla-escalate', name: 'SLA-breach escalation', trigger: 'sla_breach', enabled: true,
        description: 'On an SLA breach: raise a high-severity alert and notify the on-call owner.',
        actions: [{ type: 'notify' }] },
    ],
    playbookRuns: [
      { id: 12, playbook_id: 'pb-critical-triage', trigger_ref: 'finding:10', status: 'completed', run_by: 'hamza', created_at: new Date(Date.now() - 18 * 60000).toISOString(),
        steps: [{ action: 'notify', ok: true, detail: 'critical' }, { action: 'open_incident', ok: true, detail: '#7' }, { action: 'propose_containment', ok: true, detail: 'action #5 pending two-person approval' }] },
    ],
    runPlaybook: (id) => ({ run_id: Date.now(), playbook: id, trigger_ref: 'finding:10', incident_id: 7, simulated: true,
      steps: [{ action: 'notify', ok: true, detail: 'critical' }, { action: 'open_incident', ok: true, detail: '#7' }, { action: 'propose_containment', ok: true, detail: 'action #5 pending two-person approval' }] }),

    // Threat intel (OpenCTI knowledge graph + MISP sightings).
    intelGraph: (fid) => ({
      attribution: { indicator: '185.220.101.45', malware: 'Cobalt Strike', actor: 'TA-Phoenix', campaign: 'Operation Duskfall', technique: 'T1071.001', confidence: 90 },
      nodes: [
        { id: 'asset:web-prod-03', label: 'web-prod-03', type: 'asset' },
        { id: 'finding:' + fid, label: 'finding #' + fid, type: 'finding' },
        { id: 'ioc:185.220.101.45', label: '185.220.101.45', type: 'indicator' },
        { id: 'ttp:T1071.001', label: 'T1071.001', type: 'technique' },
        { id: 'mal:Cobalt Strike', label: 'Cobalt Strike', type: 'malware' },
        { id: 'actor:TA-Phoenix', label: 'TA-Phoenix', type: 'actor' },
        { id: 'camp:Operation Duskfall', label: 'Operation Duskfall', type: 'campaign' },
      ],
      edges: [
        { from: 'finding:' + fid, to: 'asset:web-prod-03', label: 'affects' },
        { from: 'finding:' + fid, to: 'ioc:185.220.101.45', label: 'observed' },
        { from: 'finding:' + fid, to: 'ttp:T1071.001', label: 'maps to' },
        { from: 'ioc:185.220.101.45', to: 'mal:Cobalt Strike', label: 'indicates' },
        { from: 'mal:Cobalt Strike', to: 'actor:TA-Phoenix', label: 'used by' },
        { from: 'actor:TA-Phoenix', to: 'camp:Operation Duskfall', label: 'part of' },
      ],
    }),
    attribution: { actors: [{ name: 'TA-Phoenix', findings: 2 }], malware: [{ name: 'Cobalt Strike', findings: 2 }, { name: 'Log4Shell', findings: 1 }] },
    sightings: [
      { id: 1, indicator: '185.220.101.45', type: 'ip-dst', finding_id: 21, asset_id: 'web-prod-03', source: 'misp', seen_at: new Date(Date.now() - 12 * 60000).toISOString() },
    ],
  };
})();
