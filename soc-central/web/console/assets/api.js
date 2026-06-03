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

  // writes
  feedback: (id, body) => API._post(`/findings/${id}/feedback`, body, { ok: true, simulated: true }),
  requestAction: (incidentId, body) => API._post(`/incidents/${incidentId}/actions`, body, { id: Date.now(), status: 'proposed', simulated: true }),
  approveAction: (actionId, body) => API._post(`/actions/${actionId}/approve`, body || {}, { ok: true, simulated: true }),
  rejectAction: (actionId, body) => API._post(`/actions/${actionId}/reject`, body || {}, { ok: true, simulated: true }),
};
