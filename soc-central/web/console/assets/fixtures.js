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
    assets: [ { host_id: 'web-prod-03', hostname: 'web-prod-03', os: 'Debian GNU/Linux', ip: '10.4.2.13', exposure: 'internet', criticality: 1.0 },
      { host_id: 'db-core-01', hostname: 'db-core-01', os: 'Debian GNU/Linux', ip: '10.4.9.2', exposure: 'internal', criticality: 1.0 } ],
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
    incidents: [ { id: 1, title: 'Active C2 beacon on web-prod-03', severity: 'critical', status: 'open', assignee: 'hamza', created_by: 'hamza', sla_due: '2026-06-03T18:02:31Z', sla_breached: false, created_at: '2026-06-02T18:02:31Z', finding_count: 2 } ],
    actions: [ { id: 1, incident_id: 1, action: 'isolate_host', target: 'web-prod-03', status: 'awaiting_second_approver', requested_by: 'hamza', approvals: ['hamza'], created_at: '2026-06-02T18:10:00Z' } ],
    auditVerify: { ok: true, length: 12, head_hash: '7f3a9c2e1d8b4a60' },
  };
})();
