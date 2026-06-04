/* =====================================================================
   Same-origin API client (fetch '/api/...' via the nginx reverse proxy — no CORS).
   Every call falls back to embedded fixtures when /api is unreachable, so the
   console renders fully offline. `API.mode` drives the LIVE/DEMO indicator.
   ===================================================================== */
'use strict';

const API = {
  mode: 'connecting',           // 'live' | 'demo' | 'connecting'
  _onmode: null,

  async _get(path, fallback) {
    try {
      const r = await fetch('/api' + path, { headers: { Accept: 'application/json' } });
      if (!r.ok) throw new Error(r.status);
      this._set('live');
      return await r.json();
    } catch {
      this._set('demo');
      return typeof fallback === 'function' ? fallback() : fallback;
    }
  },
  async _post(path, body, simulated) {
    if (this.mode === 'demo') return simulated;
    try {
      const r = await fetch('/api' + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error(r.status);
      this._set('live');
      return r.status === 204 ? simulated : await r.json();
    } catch {
      this._set('demo');
      return simulated;
    }
  },
  async _send(method, path, body, simulated) {
    if (this.mode === 'demo') return simulated;
    try {
      const r = await fetch('/api' + path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!r.ok) throw new Error(r.status);
      this._set('live');
      return r.status === 204 ? simulated : await r.json();
    } catch {
      this._set('demo');
      return simulated;
    }
  },
  _set(m) { if (this.mode !== m) { this.mode = m; this._onmode && this._onmode(m); } },

  // reads
  version: () => API._get('/version', () => FIX.version),
  ready: () => API._get('/health/ready', () => FIX.ready),
  ranking: () => API._get('/risk/ranking?limit=150', () => FIX.ranking),
  explain: (id) => API._get(`/findings/${id}/explain`, () => FIX.explain(id)),
  finding: (id) => API._get(`/findings/${id}`, () => FIX.findingDetail(id)),
  stats: () => API._get('/stats/summary', () => FIX.stats),
  assets: () => API._get('/assets', () => FIX.assets),
  compSummary: () => API._get('/compliance/summary', () => FIX.compSummary),
  compResults: () => API._get('/compliance/results?limit=300', () => FIX.compResults),
  compEvidence: () => API._get('/compliance/evidence?limit=60', () => FIX.compEvidence),
  chain: () => API._get('/compliance/evidence/verify', () => FIX.chain),
  incidents: () => API._get('/incidents?limit=200', () => FIX.incidents),
  actions: () => API._get('/actions', () => FIX.actions),
  auditVerify: () => API._get('/response/audit/verify', () => FIX.auditVerify),

  // surfaced backend intelligence (Sprint-1 exposure work)
  modelCard: () => API._get('/risk/model/metadata', () => FIX.modelCard),
  recent: (n = 30) => API._get(`/detections/recent?limit=${n}`, () => FIX.recent),
  clusters: () => API._get('/fusion/clusters', () => FIX.clusters),
  auditEvents: (n = 40) => API._get(`/response/audit/events?limit=${n}`, () => FIX.auditEvents),
  logs: (q = '', kind = '', minutes = 1440) =>
    API._get(`/logs/search?q=${encodeURIComponent(q)}${kind ? '&kind=' + encodeURIComponent(kind) : ''}&minutes=${minutes}&size=80`,
      () => FIX.logSearch(q, kind)),
  asset: (id) => API._get(`/assets/${encodeURIComponent(id)}`, () => FIX.assetDetail(id)),
  findingsBy: (assetId) => API._get(`/findings?asset_id=${encodeURIComponent(assetId)}&limit=200`, () => FIX.findingsBy(assetId)),
  compResultsBy: (assetId) => API._get(`/compliance/results?asset_id=${encodeURIComponent(assetId)}&limit=200`, () => FIX.compResultsBy(assetId)),
  feedbackStats: () => API._get('/analysts/feedback-stats', () => FIX.feedbackStats),
  detections: () => API._get('/detections', () => FIX.detections),
  whoami: () => API._get('/whoami', () => FIX.whoami),
  patchAsset: (id, criticality) =>
    API._send('PATCH', `/assets/${encodeURIComponent(id)}`, { criticality }, { host_id: id, criticality, simulated: true }),
  notifications: () => API._get('/notifications', () => FIX.notifications),
  notificationsRefresh: () => API._post('/notifications/refresh', {}, { created: 0, simulated: true }),
  ackNotification: (id) => API._post(`/notifications/${id}/ack`, {}, { id, acknowledged: true, simulated: true }),
  accessAudit: (n = 50) => API._get(`/access/audit?limit=${n}`, () => FIX.accessAudit),
  tenants: () => API._get('/tenants', () => FIX.tenants),
  triage: (id, body) => API._post(`/findings/${id}/triage`, body, { id, triage_status: body.status, simulated: true }),
  correlate: (body) => API._post('/incidents/correlate', body || { min_score: 60, window_hours: 24 }, { correlated_groups: 1, created: [{ incident_id: 99, findings: 3 }], simulated: true }),
  // casework (TheHive)
  tasks: (incId) => API._get(`/incidents/${incId}/tasks`, () => FIX.tasks(incId)),
  addTask: (incId, body) => API._post(`/incidents/${incId}/tasks`, body, { id: Date.now(), title: body.title, status: 'todo', simulated: true }),
  patchTask: (taskId, body) => API._send('PATCH', `/tasks/${taskId}`, body, { id: taskId, status: body.status, simulated: true }),
  observables: (incId) => API._get(`/incidents/${incId}/observables`, () => FIX.observables(incId)),
  addObservable: (incId, body) => API._post(`/incidents/${incId}/observables`, body, { id: Date.now(), ...body, simulated: true }),
  autoObservables: (incId) => API._post(`/incidents/${incId}/observables/auto`, {}, { seeded: 3, simulated: true }),
  // SOAR (n8n/Shuffle)
  playbooks: () => API._get('/playbooks', () => FIX.playbooks),
  playbookRuns: () => API._get('/playbook-runs', () => FIX.playbookRuns),
  runPlaybook: (id, body) => API._post(`/playbooks/${id}/run`, body || {}, FIX.runPlaybook(id)),
  // threat intel (OpenCTI / MISP)
  intelGraph: (fid) => API._get(`/findings/${fid}/intel-graph`, () => FIX.intelGraph(fid)),
  attribution: () => API._get('/intel/attribution', () => FIX.attribution),
  sightings: () => API._get('/intel/sightings', () => FIX.sightings),
  // live hunt (Velociraptor)
  hunts: () => API._get('/hunts', () => FIX.hunts),
  hunt: (id) => API._get(`/hunts/${id}`, () => FIX.huntDetail(id)),
  createHunt: (body) => API._post('/hunts', body, FIX.createHunt(body)),

  // writes
  feedback: (id, body) => API._post(`/findings/${id}/feedback`, body, { ok: true, simulated: true }),
  requestAction: (incidentId, body) => API._post(`/incidents/${incidentId}/actions`, body, { id: Date.now(), status: 'proposed', simulated: true }),
  approveAction: (actionId, body) => API._post(`/actions/${actionId}/approve`, body || {}, { ok: true, simulated: true }),
  rejectAction: (actionId, body) => API._post(`/actions/${actionId}/reject`, body || {}, { ok: true, simulated: true }),
};
