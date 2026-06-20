/* =====================================================================
   Analyst Toolkit engines — capabilities ported from the A.R.I.S. dashboard,
   reimplemented as DETERMINISTIC, OFFLINE, EXPLAINABLE rule engines so they fit
   VYREX's air-gap thesis (A.R.I.S. used a cloud-pulled RSS + a local Ollama LLM;
   we use rules + bundled data — nothing is fetched, nothing leaves the box).
   An optional local LLM (e.g. Ollama) could later enrich the prose; these engines
   are the always-available baseline. Pure functions on the global scope.
   ===================================================================== */
'use strict';

/* ---- Phishing / email analyzer -------------------------------------- */
function tkEmail(text) {
  text = text || '';
  const grab = re => ((text.match(re) || [])[1] || '').trim();
  const from = grab(/^From:\s*(.+)$/im);
  const subject = grab(/^Subject:\s*(.+)$/im);
  const replyTo = grab(/^Reply-To:\s*(.+)$/im);
  const returnPath = grab(/^Return-Path:\s*(.+)$/im);

  const iocs = []; let score = 0;
  const add = (tag, detail, w, kind) => { iocs.push({ tag, detail, kind }); score += w; };
  const addr = s => (s.match(/@([\w.-]+)/) || [])[1] || '';

  const links = (text.match(/https?:\/\/[^\s>"')]+/gi) || []);
  if (links.length) add('LINKS', links.length + ' embedded URL(s)', 1.4, 'net');
  if (/(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly)/i.test(text)) add('SHORTENER', 'URL shortener hides destination', 2, 'crit');
  if (/(attachment|\.exe|\.zip|\.scr|\.docm|\.xlsm|\.iso|\.img|\.html?\b|\.js\b)/i.test(text)) add('ATTACHMENT', 'suspicious attachment / file type', 2, 'crit');
  if (/(urgent|immediate|verify|suspend|locked|within \d+\s*(hours|minutes)|act now|final notice|expire)/i.test(text)) add('URGENCY', 'pressure / urgency language', 1.5, 'net');
  if (/(password|credential|login|sign[- ]?in|confirm your|update your (account|payment)|ssn|otp|one[- ]time code|bank)/i.test(text)) add('CREDENTIALS', 'credential / sensitive-data solicitation', 2, 'crit');
  const ips = text.match(/\b\d{1,3}(\.\d{1,3}){3}\b/g);
  if (ips) add('IP-LITERAL', ips.length + ' raw IP address(es)', 1, 'code');
  if (replyTo && from && addr(replyTo) && addr(replyTo).toLowerCase() !== addr(from).toLowerCase()) add('REPLY-MISMATCH', `reply-to (${addr(replyTo)}) ≠ from (${addr(from)})`, 2, 'crit');
  if (returnPath && from && addr(returnPath) && addr(returnPath).toLowerCase() !== addr(from).toLowerCase()) add('PATH-MISMATCH', 'return-path ≠ from (spoofing)', 1.5, 'crit');
  const fdom = addr(from);
  if (/-/.test(fdom) && /(secure|account|verify|update|support|login|service|billing)/i.test(fdom)) add('LOOKALIKE', `sender domain looks impersonated (${fdom})`, 1.5, 'net');
  if (/dear (customer|user|sir|madam|account holder)/i.test(text)) add('GENERIC-GREETING', 'impersonal greeting', 0.5, 'code');
  if (/(invoice|payment|wire|transfer|gift card|crypto|btc)/i.test(text)) add('FINANCIAL-LURE', 'financial / payment lure', 1, 'net');

  score = Math.min(10, Math.round(score * 10) / 10);
  const level = score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW';
  const confidence = iocs.length >= 4 ? 'High' : iocs.length >= 2 ? 'Medium' : 'Low';
  const recommendation = level === 'HIGH'
    ? 'Do not interact. Report to the SOC, quarantine the message, block the sender domain and all embedded URLs, and check whether anyone already clicked.'
    : level === 'MEDIUM'
      ? 'Treat with caution. Verify the sender through a known, independent channel before acting — do not click links or open attachments.'
      : 'Few indicators. Remain cautious and verify any unexpected request, but no strong phishing signal detected.';
  return { from, subject, replyTo, score, level, confidence, iocs, recommendation, links: links.slice(0, 12) };
}

/* ---- Log analyzer --------------------------------------------------- */
const TK_LOGRULES = [
  { re: /(union\s+select|or\s+1=1|';--|<script>|\.\.\/\.\.\/|\/etc\/passwd|cmd\.exe|powershell\s+-enc|base64\s+-d)/i, type: 'Exploit attempt (injection / RCE)', sev: 'CRITICAL', tip: 'Likely web/command exploit — review WAF logs, isolate the target, and patch the affected service.' },
  { re: /(malware|trojan|ransom|\bc2\b|beacon|cobalt\s?strike|mimikatz|reverse shell|meterpreter)/i, type: 'Malware / C2 indicator', sev: 'CRITICAL', tip: 'Isolate the host immediately and begin incident response — this is an active compromise signal.' },
  { re: /(failed password|authentication failure|invalid user|failed login|login failed|access denied)/i, type: 'Failed authentication', sev: 'HIGH', tip: 'Possible brute force — correlate by source IP/volume, enable lockout + MFA, block offending IPs.' },
  { re: /(port ?scan|nmap|masscan|syn flood|too many connections|connection refused.*repeated)/i, type: 'Reconnaissance / scan', sev: 'HIGH', tip: 'Block the scanning source and review which services are externally reachable.' },
  { re: /(useradd|adduser|net user .*\/add|new user created|net localgroup administrators .*\/add)/i, type: 'Account creation / persistence', sev: 'HIGH', tip: 'Verify the new account is authorised — attackers create accounts for persistence.' },
  { re: /(audit.*(disabled|cleared)|log.*cleared|defender.*disabled|firewall.*disabled|stopped the .* service)/i, type: 'Defense evasion', sev: 'HIGH', tip: 'A security control was tampered with — investigate who/what disabled it and when.' },
  { re: /(sudo:.*COMMAND|session opened for user root|elevated|privilege|uac bypass|runas)/i, type: 'Privileged access', sev: 'MEDIUM', tip: 'Confirm the privileged session was expected and authorised.' },
  { re: /(segfault|kernel:.*oom|out of memory|disk full|no space left)/i, type: 'System instability', sev: 'MEDIUM', tip: 'Investigate the failing/OOM process; instability can mask or accompany an attack.' },
  { re: /(accepted password|session opened|login succeeded|authentication succeeded)/i, type: 'Successful login', sev: 'LOW', tip: 'Baseline event — note source and time for correlation.' },
];
function tkLog(text) {
  const lines = (text || '').split(/\r?\n/).filter(l => l.trim());
  const findings = [];
  for (const l of lines) {
    for (const r of TK_LOGRULES) {
      if (r.re.test(l)) { findings.push({ line: l.trim().slice(0, 220), type: r.type, sev: r.sev, tip: r.tip }); break; }
    }
  }
  const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const flagged = findings.filter(f => f.sev !== 'LOW');
  const severity = findings.length ? findings.reduce((m, f) => order[f.sev] > order[m] ? f.sev : m, 'LOW') : 'LOW';
  const counts = {}; findings.forEach(f => counts[f.sev] = (counts[f.sev] || 0) + 1);
  const recommendations = [...new Set(flagged.map(f => f.tip))].slice(0, 6);
  const score = Math.min(100, findings.reduce((a, f) => a + order[f.sev] * 9, 0));
  const summary = flagged.length
    ? `${flagged.length} suspicious event(s) across ${lines.length} log line(s) — highest severity ${severity}.`
    : `No known-bad patterns found in ${lines.length} log line(s). Continue monitoring.`;
  return { lines: lines.length, findings, severity, score, counts, recommendations, summary };
}

/* ---- IR playbook (NIST SP 800-61) ----------------------------------- */
const TK_IRTYPES = [
  { re: /(ransom|encrypt|\.locked|readme.*decrypt|files.*encrypted)/i, name: 'Ransomware', sev: 'CRITICAL' },
  { re: /(exfil|data\s*(leak|theft|breach)|large.*(upload|transfer)|dns tunnel)/i, name: 'Data Exfiltration', sev: 'CRITICAL' },
  { re: /(malware|trojan|\bc2\b|beacon|implant|backdoor|rootkit)/i, name: 'Malware Infection', sev: 'CRITICAL' },
  { re: /(brute|failed\s+(password|login)|failed\s+\w*\s*logins?|multiple failed|credential stuffing|password spray|account lockout)/i, name: 'Brute Force / Credential Attack', sev: 'HIGH' },
  { re: /(phish|spoof|malicious.*(link|attachment)|business email compromise|\bbec\b)/i, name: 'Phishing', sev: 'HIGH' },
  { re: /(privilege|sudo|admin.*granted|uac bypass|token theft|escalat|root login|uid[- ]?0|new\s+\w*\s*(root|admin|uid-0)\s+account)/i, name: 'Privilege Escalation', sev: 'HIGH' },
  { re: /(insider|unauthorized.*access|after hours|disgruntled)/i, name: 'Insider Threat', sev: 'HIGH' },
  { re: /(ddos|denial of service|flood|amplif)/i, name: 'Denial of Service', sev: 'HIGH' },
  { re: /(scan|recon|nmap|enumerat|probe)/i, name: 'Reconnaissance / Port Scan', sev: 'MEDIUM' },
];
function tkPlaybook(alert) {
  const t = TK_IRTYPES.find(x => x.re.test(alert || '')) || { name: 'Unclassified Security Incident', sev: 'MEDIUM' };
  const tail = {
    'Ransomware': ['Disconnect affected hosts from the network (do NOT power off — preserve memory).', 'Identify the ransomware family and check for a known decryptor.', 'Locate and protect backups; verify they are offline and intact.'],
    'Data Exfiltration': ['Identify the destination and protocol; block it at the egress firewall.', 'Determine the data classification and volume that left.', 'Preserve netflow/proxy logs for the exfiltration window.'],
    'Malware Infection': ['Isolate the host and capture volatile memory before remediation.', 'Hash the malicious artifact and sweep the fleet for the same IOC.', 'Identify the initial access vector (email, web, removable media).'],
    'Brute Force / Credential Attack': ['Block the source IP(s) and force-reset targeted credentials.', 'Enable/verify account lockout and MFA on the targeted service.', 'Check for any successful login from the attacking source.'],
    'Phishing': ['Pull the message from all mailboxes that received it.', 'Block the sender domain and the embedded URLs/attachments.', 'Identify and reset credentials for anyone who clicked or replied.'],
    'Privilege Escalation': ['Revoke the escalated session/token and disable the abused path.', 'Review what the elevated context accessed or changed.', 'Audit for new accounts, scheduled tasks, or persistence.'],
    'Insider Threat': ['Preserve evidence quietly; involve HR/Legal before acting.', 'Review the user\'s recent access against their role.', 'Disable access if active misuse is confirmed.'],
    'Denial of Service': ['Engage upstream/ISP filtering and rate-limit at the edge.', 'Scale or shed load on the targeted service.', 'Distinguish volumetric vs application-layer attack.'],
    'Reconnaissance / Port Scan': ['Block the scanning source and review exposed services.', 'Confirm no follow-on exploitation occurred.', 'Reduce the external attack surface to only required ports.'],
  }[t.name] || ['Scope the affected systems, users and data.', 'Determine the initial access vector.', 'Decide containment vs. continued monitoring for intelligence.'];

  return {
    classification: t.name,
    severity: t.sev,
    immediate: [
      'Acknowledge the alert and open a tracked incident case (assign an owner).',
      'Confirm the alert is a true positive — pull the raw events behind it.',
      'Identify the affected host(s), account(s) and entry point.',
      tail[0],
    ],
    containment: [
      'Contain the blast radius — isolate hosts / disable accounts as appropriate.',
      tail[1],
      'Preserve volatile evidence (memory, network connections) before changes.',
      'Snapshot affected systems for forensics; do not wipe yet.',
    ],
    investigation: [
      'Collect: relevant logs, the triggering artifact, netflow, and host timeline.',
      tail[2],
      'Determine scope: is this one host or lateral movement across many?',
      'Map observed activity to MITRE ATT&CK techniques.',
      'Answer: how did they get in, what did they touch, are they still active?',
    ],
    escalation: [
      `Notify the SOC lead immediately (severity ${t.sev}).`,
      t.sev === 'CRITICAL' ? 'Escalate to CISO / IR retainer and Legal within 1 hour.' : 'Escalate to the on-call IR analyst; brief management on a regular cadence.',
      'Engage Legal/Comms if regulated data or a breach threshold is involved.',
    ],
    lessons: [
      'What control would have prevented or detected this earlier?',
      'Were the detection and response times within SLA?',
      'What detection rule, hardening, or training change comes out of this?',
    ],
  };
}

/* ---- CVE explainer (deterministic, from existing CVE data) ---------- */
function tkCveExplain(d) {
  d = d || {};
  const id = d.cve_id || d.id || 'this CVE';
  const sev = (d.severity || '').toUpperCase() || 'UNKNOWN';
  const score = d.cvss_score != null ? d.cvss_score : (d.cvss != null ? d.cvss : null);
  const cwe = d.cwe || '';
  const desc = d.description || d.summary || '';
  const cweLabel = (typeof cweName === 'function' && cwe) ? cweName(cwe) : '';
  const exploited = d.exploit_available || d.kev || /exploit/i.test(JSON.stringify(d.exploit_refs || ''));
  const what = desc
    ? desc
    : `${id} is a disclosed vulnerability${cweLabel ? ` involving ${cweLabel.toLowerCase()} (${cwe})` : ''}.`;
  const how = cweLabel
    ? `The weakness class is ${cwe} — ${cweLabel}. An attacker abuses this by supplying crafted input or conditions that the affected software fails to handle safely, leading to the impact described above.`
    : 'An attacker triggers the flaw by interacting with the vulnerable component in a way its developers did not anticipate, causing unintended behaviour.';
  const who = `Any system running the affected software/version is exposed. ${sev === 'CRITICAL' || sev === 'HIGH' ? 'Internet-facing and unpatched instances are at the highest risk and should be treated as urgent.' : 'Exposure depends on configuration and reachability; prioritise by asset criticality.'}`;
  const fix = `Apply the vendor patch or upgrade to a fixed version as the primary remediation. Until patched: restrict network access to the component, apply vendor/WAF mitigations, and increase monitoring on the affected hosts.${exploited ? ' Public exploitation is known — patch on an emergency timeline.' : ''}`;
  const risk = `${sev}${score != null ? ` · CVSS ${(+score).toFixed(1)}` : ''}${exploited ? ' · known exploited' : ''}. ${sev === 'CRITICAL' ? 'Top-priority remediation.' : sev === 'HIGH' ? 'High-priority remediation.' : sev === 'MEDIUM' ? 'Schedule remediation in the normal cycle.' : 'Remediate per standard cadence.'}`;
  return { id, severity: sev, score, cwe, exploited: !!exploited, sections: { what, how, who, fix, risk } };
}

/* ---- Security assistant (offline knowledge base) -------------------- */
const TK_KB = [
  { re: /(what is|explain).*(this|vyrex|platform)|^vyrex/i, a: 'VYREX is an air-gapped SOC & vulnerability-intelligence platform: it ingests findings from multiple tools, fuses and de-duplicates them, scores risk with an explainable composite + XGBoost re-ranker (with SHAP), and drives triage, casework, hunting and signed response — all without anything leaving the building.' },
  { re: /\bcvss\b/i, a: 'CVSS (Common Vulnerability Scoring System) rates vulnerability severity 0–10: 0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0–10 Critical. It is built from attack vector, complexity, privileges required, user interaction, and the impact to confidentiality/integrity/availability. Treat it as a starting prioritisation signal, not the whole story — combine it with exploitability (KEV/EPSS) and asset criticality.' },
  { re: /\bkev\b|known exploited/i, a: 'KEV is CISA\'s Known Exploited Vulnerabilities catalog — CVEs with confirmed in-the-wild exploitation. A KEV flag should override raw CVSS for prioritisation: patch KEV items first regardless of score, because real-world exploitation is proven.' },
  { re: /\bepss\b/i, a: 'EPSS (Exploit Prediction Scoring System) estimates the probability a CVE will be exploited in the next 30 days (0–1). Use it to prioritise the large middle band of vulnerabilities where CVSS alone does not discriminate well.' },
  { re: /att&?ck|mitre/i, a: 'MITRE ATT&CK is a knowledge base of adversary tactics (the "why" — e.g. Initial Access, Persistence, Exfiltration) and techniques (the "how" — e.g. T1190 Exploit Public-Facing Application). Mapping detections to ATT&CK lets you measure coverage and reason about an attack chain rather than isolated alerts.' },
  { re: /phish/i, a: 'Phishing red flags: urgency/threats, mismatched or look-alike sender domains, reply-to ≠ from, link shorteners or links whose text ≠ destination, unexpected attachments, and requests for credentials or payment. Verify out-of-band, never click to "confirm", and report to the SOC. The Phishing Analyzer tool here scores raw email content for exactly these indicators.' },
  { re: /ransom/i, a: 'On suspected ransomware: isolate affected hosts from the network but do NOT power them off (preserve memory), protect/verify offline backups, identify the family and check for a decryptor, and begin formal IR. Containment speed limits blast radius more than anything else.' },
  { re: /brute|credential stuffing|password spray/i, a: 'For brute-force / credential attacks: block the source, force-reset targeted credentials, verify lockout + MFA are enforced, and crucially check whether any attempt succeeded. Correlate by source IP and volume to distinguish noise from a targeted campaign.' },
  { re: /incident response|\bir\b|playbook/i, a: 'NIST SP 800-61 frames IR in phases: Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity. The IR Playbook tool here generates a phased, incident-type-specific checklist (immediate / containment / investigation / escalation / lessons learned) from a pasted alert.' },
  { re: /port|nmap|scan/i, a: 'Open ports are attack surface. The riskiest exposures are remote-admin and cleartext services (Telnet 23, VNC 5900, RDP 3389, SMB 445, databases like MySQL 3306 / PostgreSQL 5432 / MongoDB 27017 / Redis 6379). Expose only what is required, put management behind a VPN/jump host, and patch + authenticate everything reachable. The Port Scanner tool scans localhost/private ranges only.' },
  { re: /air[- ]?gap/i, a: 'Air-gapped means the platform has no path to the public internet — no CDN, no telemetry, no cloud AI. VYREX is built this way on purpose: it is a selling point for sovereign/regulated/defence buyers because the system physically cannot exfiltrate data. Every analysis tool here runs locally and deterministically for that reason.' },
];
function tkAssistant(q) {
  q = (q || '').trim();
  if (!q) return { answer: 'Ask me about CVSS, KEV, EPSS, ATT&CK, phishing, ransomware, incident response, port exposure, or how VYREX works.', refs: [] };
  const hit = TK_KB.find(k => k.re.test(q));
  if (hit) return { answer: hit.a, refs: [] };
  return {
    answer: 'I don\'t have a curated answer for that in the offline knowledge base. This assistant is deterministic and runs fully air-gapped — it covers core SOC concepts (CVSS, KEV, EPSS, ATT&CK, phishing, ransomware, IR, port exposure). An optional local LLM could be attached to broaden it without breaking the air gap.',
    refs: [],
  };
}

/* ---- Threat news (bundled, offline; threat level derived) ----------- */
const TK_NEWS = [
  { title: 'Critical RCE in widely-used reverse proxy actively exploited', source: 'Advisory feed', severity: 'CRITICAL', published: '2026-06-16', summary: 'A pre-auth remote code execution flaw is under mass exploitation. Patch immediately; treat any unpatched internet-facing instance as compromised.', tags: ['RCE', 'KEV', 'T1190'] },
  { title: 'Ransomware crew shifts to data-extortion-only model', source: 'Threat intel', severity: 'HIGH', published: '2026-06-15', summary: 'Group drops encryption in favour of pure exfiltration + extortion, shortening dwell time. Prioritise egress monitoring and DLP on crown-jewel data.', tags: ['Ransomware', 'Exfiltration', 'T1048'] },
  { title: 'Phishing kit abuses look-alike domains with valid TLS', source: 'Threat intel', severity: 'HIGH', published: '2026-06-14', summary: 'Kit auto-provisions certificates so phishing pages show a padlock. Reinforce that TLS ≠ trust; rely on sender/domain verification and reporting.', tags: ['Phishing', 'T1566'] },
  { title: 'New CVSS 9.8 deserialization bug in a popular app framework', source: 'NVD-style advisory', severity: 'CRITICAL', published: '2026-06-13', summary: 'Untrusted deserialization (CWE-502) yields RCE. A fixed release is available; inventory affected services and patch on an emergency timeline.', tags: ['CWE-502', 'Patch'] },
  { title: 'Botnet scans for exposed databases and Redis instances', source: 'Sensor telemetry', severity: 'MEDIUM', published: '2026-06-12', summary: 'Opportunistic scanning for 3306/5432/6379/27017 with default creds. Ensure datastores are never internet-facing and require authentication.', tags: ['Recon', 'T1046'] },
  { title: 'Guidance: rotate long-lived service tokens after recent disclosures', source: 'Best practice', severity: 'LOW', published: '2026-06-11', summary: 'Routine hardening reminder — shorten token lifetimes and prefer workload identity over static secrets.', tags: ['Hardening'] },
];
function tkNews() {
  const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const level = TK_NEWS.reduce((m, n) => order[n.severity] > order[m] ? n.severity : m, 'LOW');
  return { threat_level: level, items: TK_NEWS, note: 'Bundled offline feed — air-gapped build does not fetch live RSS. Attach an outbound-allowed collector to refresh.' };
}
