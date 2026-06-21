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
    { risk_rank: 7, id: 70, asset_id: 'k8s-node-02', domain: 'application', title: 'CVE-2024-3094 — xz/liblzma backdoor enabling sshd remote code execution',
      severity: 'CRITICAL', cve_id: 'CVE-2024-3094', source_tool: 'trivy', risk_score: '96.5', ml_risk_score: '96.5', kev: true, cvss_score: '10.0', epss: '0.90',
      attack: 'T1190', threat_intel: { indicator: '45.137.21.9', type: 'ip-dst', confidence: 95 },
      consensus: { tools: ['trivy', 'agent', 'misp'], n_tools: 3, weight: 1.0, members: [70, 71], primary: 70, dedup_key: 'd71aa0934c' } },
    { risk_rank: 8, id: 81, asset_id: 'mail-gw-01', domain: 'system', title: 'CVE-2021-4034 (PwnKit) — local privilege escalation via polkit pkexec',
      severity: 'CRITICAL', cve_id: 'CVE-2021-4034', source_tool: 'wazuh', risk_score: '84.0', ml_risk_score: '84.0', kev: true, cvss_score: '7.8', epss: '0.50',
      attack: 'T1068', threat_intel: null, consensus: { tools: ['wazuh', 'agent'], n_tools: 2, weight: 0.5, members: [81, 82], primary: 81, dedup_key: 'a90c1f22' } },
    { risk_rank: 9, id: 72, asset_id: 'scan-target-01', domain: 'network', title: 'CVE-2023-44487 — HTTP/2 Rapid Reset, actively exploited for DDoS',
      severity: 'HIGH', cve_id: 'CVE-2023-44487', source_tool: 'suricata', risk_score: '79.4', ml_risk_score: '79.4', kev: true, cvss_score: '7.5', epss: '0.86',
      attack: 'T1071', threat_intel: null, consensus: { tools: ['suricata', 'zeek'], n_tools: 2, weight: 0.5, members: [72, 73], primary: 72, dedup_key: 'b1c2d3e4' } },
    { risk_rank: 10, id: 110, asset_id: 'k8s-node-02', domain: 'system', title: 'CVE-2024-21626 — runc container escape via leaked file descriptor',
      severity: 'HIGH', cve_id: 'CVE-2024-21626', source_tool: 'trivy', risk_score: '76.0', ml_risk_score: '76.0', kev: false, cvss_score: '8.6', epss: '0.08',
      attack: 'T1068', threat_intel: null, consensus: { tools: ['trivy', 'falco'], n_tools: 2, weight: 0.5, members: [110, 111], primary: 110, dedup_key: 'f5061728' } },
    { risk_rank: 11, id: 88, asset_id: 'vpn-edge-01', domain: 'network', title: 'Falco — interactive shell spawned inside a container (reverse-shell pattern)',
      severity: 'HIGH', cve_id: null, source_tool: 'falco', risk_score: '72.0', ml_risk_score: '72.0', kev: false, cvss_score: null, epss: null,
      attack: 'T1059', threat_intel: { indicator: '193.42.33.18', type: 'ip-dst', confidence: 80 },
      consensus: { tools: ['falco', 'suricata'], n_tools: 2, weight: 0.5, members: [88, 89], primary: 88, dedup_key: '0a9b8c7d' } },
    { risk_rank: 12, id: 150, asset_id: 'scan-target-01', domain: 'application', title: 'CVE-2024-1086 — nf_tables use-after-free local privilege escalation',
      severity: 'HIGH', cve_id: 'CVE-2024-1086', source_tool: 'agent', risk_score: '71.0', ml_risk_score: '71.0', kev: true, cvss_score: '7.8', epss: '0.30',
      attack: 'T1068', threat_intel: null, consensus: { tools: ['agent', 'trivy'], n_tools: 2, weight: 0.5, members: [150, 151], primary: 150, dedup_key: 'cc44ab21' } },
    { risk_rank: 13, id: 95, asset_id: 'db-core-01', domain: 'application', title: 'CVE-2022-0847 (Dirty Pipe) — arbitrary file overwrite leading to root',
      severity: 'HIGH', cve_id: 'CVE-2022-0847', source_tool: 'trivy', risk_score: '66.5', ml_risk_score: '66.5', kev: true, cvss_score: '7.8', epss: '0.42',
      attack: 'T1068', threat_intel: null, consensus: { tools: ['trivy'], n_tools: 1, weight: 0.0, members: [95], primary: 95, dedup_key: 'e3f4a5b6' } },
    { risk_rank: 14, id: 121, asset_id: 'sensor-01', domain: 'network', title: 'Zeek — periodic beaconing to a newly-registered domain (60s interval)',
      severity: 'MEDIUM', cve_id: null, source_tool: 'zeek', risk_score: '49.0', ml_risk_score: '49.0', kev: false, cvss_score: null, epss: null,
      attack: 'T1071.001', threat_intel: { indicator: 'cdn-update.live', type: 'domain', confidence: 70 },
      consensus: { tools: ['zeek'], n_tools: 1, weight: 0.0, members: [121], primary: 121, dedup_key: '7788aa99' } },
    { risk_rank: 15, id: 130, asset_id: 'mail-gw-01', domain: 'application', title: 'Nuclei — phishing credential-harvester kit served from web root',
      severity: 'MEDIUM', cve_id: null, source_tool: 'nuclei', risk_score: '44.0', ml_risk_score: '44.0', kev: false, cvss_score: null, epss: null,
      attack: 'T1566', threat_intel: null, consensus: { tools: ['nuclei'], n_tools: 1, weight: 0.0, members: [130], primary: 130, dedup_key: '11bb22cc' } },
    { risk_rank: 16, id: 142, asset_id: 'ws-eng-22', domain: 'system', title: 'SSH password authentication enabled — hardening gap (CIS 5.2.x)',
      severity: 'LOW', cve_id: null, source_tool: 'wazuh', risk_score: '24.0', ml_risk_score: '24.0', kev: false, cvss_score: null, epss: null,
      attack: null, threat_intel: null, consensus: { tools: ['wazuh'], n_tools: 1, weight: 0.0, members: [142], primary: 142, dedup_key: '33dd44ee' } },
    { risk_rank: 17, id: 160, asset_id: 'ws-eng-22', domain: 'application', title: 'Outdated nginx 1.18.0 — several fixed CVEs available in 1.24',
      severity: 'LOW', cve_id: null, source_tool: 'trivy', risk_score: '28.0', ml_risk_score: '28.0', kev: false, cvss_score: null, epss: null,
      attack: null, threat_intel: null, consensus: { tools: ['trivy'], n_tools: 1, weight: 0.0, members: [160], primary: 160, dedup_key: '55ff66aa' } },
  ];

  // lifecycle + derived exploit-availability signal (mirrors the live API fields)
  const CWE_DEMO = { 'CVE-2023-4911': 'CWE-787', 'CVE-2021-44228': 'CWE-502', 'CVE-2022-3715': 'CWE-787',
    'CVE-2024-3094': 'CWE-94', 'CVE-2021-4034': 'CWE-269', 'CVE-2024-21626': 'CWE-269',
    'CVE-2024-1086': 'CWE-416', 'CVE-2022-0847': 'CWE-787', 'CVE-2023-44487': 'CWE-400' };
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
    version: { service: 'vyrex-api', version: '1.0.0', environment: 'production' },
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
      { host_id: 'sensor-01', hostname: 'cache-01', os: 'Debian GNU/Linux 12', ip: '10.4.9.7', exposure: 'internal', criticality: 0.5 },
      { host_id: 'k8s-node-02', hostname: 'k8s-node-02', os: 'Ubuntu 22.04 LTS', ip: '10.4.5.32', exposure: 'internal', criticality: 0.95 },
      { host_id: 'mail-gw-01', hostname: 'mail-gw-01', os: 'Debian GNU/Linux 12', ip: '10.4.2.40', exposure: 'internet', criticality: 0.8 },
      { host_id: 'vpn-edge-01', hostname: 'vpn-edge-01', os: 'Alpine 3.19', ip: '10.4.2.5', exposure: 'internet', criticality: 0.9 },
      { host_id: 'ws-eng-22', hostname: 'ws-eng-22', os: 'Windows 11 Pro', ip: '10.4.20.22', exposure: 'internal', criticality: 0.4 } ],
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

    // ATT&CK coverage matrix.
    attackCoverage: { tactics: ['initial-access', 'execution', 'privilege-escalation', 'defense-evasion', 'command-and-control'],
      techniques: [
        { technique: 'T1190', tactic: 'initial-access', name: 'Exploit Public-Facing Application', findings: 6, tools: ['agent', 'nuclei', 'trivy'], tool_count: 3, top_risk: 94.3 },
        { technique: 'T1059', tactic: 'execution', name: 'Command & Scripting Interpreter', findings: 1, tools: ['falco'], tool_count: 1, top_risk: 60 },
        { technique: 'T1068', tactic: 'privilege-escalation', name: 'Exploitation for Privilege Escalation', findings: 2, tools: ['agent', 'trivy'], tool_count: 2, top_risk: 72 },
        { technique: 'T1562', tactic: 'defense-evasion', name: 'Impair Defenses', findings: 2, tools: ['wazuh', 'agent'], tool_count: 2, top_risk: 46 },
        { technique: 'T1071.001', tactic: 'command-and-control', name: 'Web Protocols (C2)', findings: 2, tools: ['suricata', 'misp'], tool_count: 2, top_risk: 88 },
      ], covered: 5, total_known: 20 },
    postureTrends: (() => { const out = []; for (let i = 6; i >= 0; i--) { const d = new Date(Date.now() - i * 86400000);
      out.push({ snap_date: d.toISOString().slice(0, 10), open_findings: 38 + (6 - i), kev: 7 + (i % 2), critical: 2, high: 12 + (6 - i), exploit_available: 3, avg_risk: 28 + (6 - i) * 0.6, compliance_pct: 33 + (6 - i) }); } return out; })(),

    // Detection rules (management).
    detectionRules: [
      { id: 1, name: 'C2 beacon to non-standard port (tcp/4444)', source: 'suricata', technique: 'T1071.001', severity: 'critical', logic: 'alert tcp any any -> any 4444 (msg:"C2 beacon"; sid:9000001;)', enabled: true, hits: 14, created_by: 'system' },
      { id: 2, name: 'Looney Tunables local privilege escalation', source: 'sigma', technique: 'T1068', severity: 'high', logic: 'process.args contains "GLIBC_TUNABLES" and exit_code = 0', enabled: true, hits: 6, created_by: 'system' },
      { id: 4, name: 'auditd not running (tamper-evident logging off)', source: 'domain', technique: 'T1562', severity: 'medium', logic: 'service.auditd.active = false', enabled: true, hits: 8, created_by: 'system' },
      { id: 5, name: 'Apache Log4Shell JNDI exploit attempt', source: 'suricata', technique: 'T1190', severity: 'critical', logic: 'content:"jndi:ldap"; http.uri;', enabled: true, hits: 2, created_by: 'system' },
      { id: 3, name: 'Reverse shell spawned (bash -i /dev/tcp)', source: 'yara', technique: 'T1059', severity: 'high', logic: '$a = "bash -i >& /dev/tcp/"', enabled: false, hits: 3, created_by: 'system' },
    ],
    ruleStats: { n: 5, enabled: 4, hits: 33, by_source: [{ source: 'suricata', n: 2 }, { source: 'sigma', n: 1 }, { source: 'yara', n: 1 }, { source: 'domain', n: 1 }] },

    // Alerting (channels / rules / deliveries).
    alertChannels: [
      { id: 1, name: 'SOC webhook (SIRP intake)', type: 'webhook', target: 'http://sirp.soc.local/hooks/vyrex', enabled: true },
      { id: 2, name: 'On-call email', type: 'email', target: 'soc-oncall@org.local', enabled: true },
    ],
    alertRules: [
      { id: 1, name: 'Critical findings → SIRP', min_severity: 'critical', kind: 'critical_finding', channel_id: 1, channel_name: 'SOC webhook (SIRP intake)', enabled: true },
      { id: 2, name: 'SLA breaches → on-call', min_severity: 'high', kind: 'sla_breach', channel_id: 2, channel_name: 'On-call email', enabled: true },
    ],
    alertDeliveries: [
      { id: 3, channel_name: 'SOC webhook (SIRP intake)', subject: 'Critical risk on web-prod-03', status: 'delivered', detail: 'HTTP 200', created_at: new Date(Date.now() - 9 * 60000).toISOString() },
      { id: 2, channel_name: 'On-call email', subject: 'SLA breached — db-core-01', status: 'queued', detail: 'email transport not configured at this site', created_at: new Date(Date.now() - 41 * 60000).toISOString() },
    ],

    // Demo-mode login (offline): the 3 seed users, password "vyrex".
    login: (u, p) => { const roles = { admin: 'admin', analyst: 'analyst', viewer: 'viewer' };
      if (p === 'vyrex' && roles[u]) return { token: 'demo-' + u, user: u, role: roles[u] };
      return { error: 'invalid username or password' }; },

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

    // Analyst toolkit (ARIS-derived) — demo fallbacks for the two server-backed tools.
    nodeVitals: {
      os: { system: 'Linux', node: 'vyrex-api', release: '6.1.0', machine: 'x86_64', python: '3.11.9',
        boot_time: '2026-06-17 09:00:00 UTC', uptime: '3h 12m', note: 'VYREX appliance node (demo data — /api unreachable)' },
      cpu: { logical: 8, total_pct: 18.4, per_core: [12, 28, 9, 41, 16, 22, 7, 33], load1: 0.6, load5: 0.5, load15: 0.4 },
      ram: { total: 16 * 2 ** 30, used: 6.1 * 2 ** 30, percent: 38.1, total_h: '16.0 GB', used_h: '6.1 GB', swap_percent: 3.0, swap_total_h: '2.0 GB' },
      disk: { total: 256 * 2 ** 30, used: 70 * 2 ** 30, free: 186 * 2 ** 30, percent: 27.3, total_h: '256.0 GB', used_h: '70.0 GB', free_h: '186.0 GB' },
      captured: new Date().toISOString(),
    },
    agentStatus: { engine: 'ollama', reachable: false, url: 'http://ollama:11434', model: 'llama3.2:3b', models_available: [], model_ready: false },
    agentRuns: [
      { id: 2, model: 'llama3.2:3b', considered: 8, escalated: 3, summary: 'Three known-exploited findings on internet-facing hosts dominate the queue; the rest are low-EPSS noise.', decisions: [], created_at: new Date(Date.now() - 9 * 60000).toISOString() },
    ],
    agentTriage: {
      model: 'llama3.2:3b', considered: 6, escalated: 2,
      summary: 'CVE-2023-4911 (KEV, 3-tool consensus) on web-prod-03 is the clear top priority; Log4Shell on an internet-facing service is second. The bash overflow is low EPSS — monitor.',
      decisions: [
        { id: 10, title: 'CVE-2023-4911 (Looney Tunables) — local privilege escalation in glibc', asset_id: 'web-prod-03', severity: 'HIGH', decision: 'ESCALATE', reason: 'KEV + 3 independent tools agree + internet-exposed asset — open an incident now.' },
        { id: 33, title: 'Apache Log4Shell (CVE-2021-44228) RCE', asset_id: 'scan-target-01', severity: 'CRITICAL', decision: 'ESCALATE', reason: 'KEV, CVSS 10, EPSS 0.94 on an internet-facing service — emergency patch.' },
        { id: 55, title: 'CVE-2022-3715 — bash heap buffer overflow', asset_id: 'db-core-01', severity: 'HIGH', decision: 'MONITOR', reason: 'EPSS 0.001, single tool, not exposed — patch in the normal cycle.' },
      ],
    },
    agentInvestigate: {
      model: 'llama3.2:3b', considered: 2, run_id: 3,
      incident: { id: 2, title: 'Correlated activity on scan-target-01', severity: 'CRITICAL' },
      result: {
        narrative: 'Initial access via an unpatched glibc privilege-escalation flaw on scan-target-01, followed by Log4Shell remote code execution on the same internet-facing host — a single attack chain across two corroborated findings.',
        timeline: [
          { step: 'Initial Access', detail: 'CVE-2023-4911 (Looney Tunables) in libc6 on scan-target-01 (#5072)' },
          { step: 'Execution', detail: 'Apache Log4Shell RCE detected by nuclei on scan-target-01 (#5075)' },
        ],
        killchain: [
          { tactic: 'Initial Access', technique: 'T1190', evidence: '#5072 glibc' },
          { tactic: 'Execution', technique: 'T1190', evidence: '#5075 Log4Shell' },
        ],
        recommendations: ['Isolate scan-target-01 (propose containment — two-person approval).', 'Pull web/proxy logs around the Log4Shell hit to confirm exploitation.', 'Patch glibc + the Log4j component on the host.'],
        entities: { assets: ['scan-target-01'], techniques: ['T1190'], tools: ['trivy', 'nuclei'], iocs: [], findings: 2 },
      },
    },
    automationStatus: {
      engine: 'n8n', reachable: false, base_url: 'http://n8n:5678', webhook_url: 'http://n8n:5678/webhook/vyrex',
      api_key_configured: false, channel: { id: 4, name: 'n8n automation', target: 'http://n8n:5678/webhook/vyrex-alert', enabled: true },
      workflows: [
        { id: 'vyrexAutoTriage1', name: 'Auto-triage loop', trigger: 'every 15 min', kind: 'schedule', does: 'pull ranking → correlate → dispatch alerts' },
        { id: 'vyrexCriticalRsp', name: 'Critical finding responder', trigger: 'webhook /webhook/vyrex', kind: 'webhook', does: 'branch on severity → correlate → dispatch → respond' },
        { id: 'vyrexAlertIntake', name: 'Alert intake', trigger: 'webhook /webhook/vyrex-alert', kind: 'webhook', does: 'receive dispatched alerts; escalate criticals; fan out' },
        { id: 'vyrexSlaEscal01', name: 'SLA-breach escalation', trigger: 'hourly', kind: 'schedule', does: 'count SLA breaches → escalate + executive report' },
        { id: 'vyrexIocRespond1', name: 'Live-IOC responder', trigger: 'every 20 min', kind: 'schedule', does: 'high-risk findings with a live MISP IOC → correlate + dispatch' },
        { id: 'vyrexDailyReport', name: 'Daily posture report', trigger: 'daily 08:00', kind: 'schedule', does: 'generate report → notify' },
      ],
      executions: [],
      deliveries: [
        { channel_name: 'n8n automation', subject: 'Critical: CVE-2023-4911 on web-prod-03', status: 'delivered', detail: 'HTTP 200', created_at: new Date(Date.now() - 6 * 60000).toISOString() },
        { channel_name: 'n8n automation', subject: 'VYREX test alert', status: 'delivered', detail: 'HTTP 200', created_at: new Date(Date.now() - 22 * 60000).toISOString() },
      ],
      handoffs: [
        { id: 8, playbook_id: 'pb-n8n-automation', trigger_ref: 'finding:11', status: 'completed', created_at: new Date(Date.now() - 8 * 60000).toISOString() },
      ],
    },
    portScan: (target, mode) => ({
      target: target || '127.0.0.1', resolved_ip: target || '127.0.0.1', mode: mode || 'quick', scanned: 22,
      open: [
        { port: 22, service: 'ssh', risk: 'MEDIUM', banner: 'SSH-2.0-OpenSSH_9.2' },
        { port: 80, service: 'http', risk: 'MEDIUM', banner: 'HTTP/1.1 200 OK' },
        { port: 443, service: 'https', risk: 'LOW', banner: '' },
        { port: 5432, service: 'postgresql', risk: 'HIGH', banner: '' },
      ],
      assessment: { posture: 'HIGH', summary: '4 open port(s) (demo): 0 critical, 1 high. Posture HIGH. Reduce surface to required services.',
        notes: ['Port 5432 (postgresql) is HIGH — ensure auth, patching and firewalling; should not be internet-facing.'] },
    }),
  };
})();
