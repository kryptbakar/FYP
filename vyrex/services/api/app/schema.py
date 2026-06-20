"""Incident-management + active-response schema, ensured at API startup.

The API owns this slice of the schema (enrichment owns findings/compliance,
risk-engine owns explanations). All idempotent.
"""
from __future__ import annotations

import logging

import psycopg

from .config import settings

log = logging.getLogger("api.schema")

DDL = """
CREATE TABLE IF NOT EXISTS incidents (
    id          bigserial PRIMARY KEY,
    title       text NOT NULL,
    description text,
    severity    text DEFAULT 'medium',
    status      text DEFAULT 'open',        -- open | in_progress | resolved | closed
    assignee    text,
    created_by  text,
    sla_due     timestamptz,
    created_at  timestamptz DEFAULT now(),
    updated_at  timestamptz DEFAULT now(),
    resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS incident_findings (
    incident_id bigint REFERENCES incidents(id) ON DELETE CASCADE,
    finding_id  bigint,
    linked_at   timestamptz DEFAULT now(),
    PRIMARY KEY (incident_id, finding_id)
);

CREATE TABLE IF NOT EXISTS response_actions (
    id            bigserial PRIMARY KEY,
    incident_id   bigint REFERENCES incidents(id) ON DELETE SET NULL,
    agent_id      text NOT NULL,
    action_type   text NOT NULL,            -- process_kill | network_isolate | file_quarantine | user_disable
    params        jsonb DEFAULT '{}',
    status        text DEFAULT 'pending_approval',
    -- pending_approval -> approved -> dispatched -> completed | failed ; or rejected
    requested_by  text NOT NULL,
    approvals     jsonb DEFAULT '[]',        -- [{approver, at}]
    rejected_by   text,
    nonce         text,
    signed_payload text,                     -- exact canonical bytes the agent verifies
    signature     text,                      -- base64 Ed25519 signature
    signing_pubkey text,
    result        jsonb,
    created_at    timestamptz DEFAULT now(),
    approved_at   timestamptz,
    dispatched_at timestamptz,
    completed_at  timestamptz
);
CREATE INDEX IF NOT EXISTS response_actions_agent ON response_actions (agent_id, status);

-- Append-only, hash-chained audit of every action lifecycle event (D-026).
CREATE TABLE IF NOT EXISTS action_audit (
    seq        bigserial PRIMARY KEY,
    action_id  bigint,
    event      text NOT NULL,               -- requested|approved|rejected|signed|dispatched|completed|failed|verify_failed
    actor      text,
    record     jsonb NOT NULL,              -- exact content that is hashed
    prev_hash  text NOT NULL,
    hash       text NOT NULL,
    created_at timestamptz DEFAULT now()
);

-- Notifications / alerting: rule-driven alerts an analyst should see (critical detections,
-- SLA breaches). Generated from the live findings/incidents on demand (no extra worker).
CREATE TABLE IF NOT EXISTS notifications (
    id           bigserial PRIMARY KEY,
    dedup_key    text UNIQUE,                -- so re-runs don't duplicate the same alert
    kind         text NOT NULL,             -- critical_finding | sla_breach | system
    severity     text DEFAULT 'info',
    title        text NOT NULL,
    body         text,
    ref_type     text,                      -- finding | incident
    ref_id       text,
    acknowledged bool DEFAULT false,
    created_at   timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notifications_ack ON notifications (acknowledged, created_at DESC);

-- Access audit: who viewed/changed what (distinct from the action hash-chain, which is
-- about destructive response actions). Closes the "audit access, not just actions" gap.
CREATE TABLE IF NOT EXISTS access_audit (
    seq        bigserial PRIMARY KEY,
    actor      text,
    role       text,
    tenant     text,
    method     text,
    path       text,
    status     int,
    created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS access_audit_time ON access_audit (created_at DESC);

-- Multi-tenancy foundation (modelled, non-breaking): every record defaults to the
-- 'default' org; reads scope by the X-Tenant context when provided. Full enforcement
-- across enrichment-owned tables is the documented next step.
CREATE TABLE IF NOT EXISTS tenants (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    created_at  timestamptz DEFAULT now()
);
INSERT INTO tenants (id, name) VALUES ('default', 'Default organization')
    ON CONFLICT (id) DO NOTHING;
ALTER TABLE incidents     ADD COLUMN IF NOT EXISTS tenant text DEFAULT 'default';
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS tenant text DEFAULT 'default';

-- Alert correlation (agentic-soc-platform pattern): a deterministic correlation key groups
-- related findings (same asset + technique, same time bucket) into one auto-created incident.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_uid text;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS auto_created boolean DEFAULT false;
CREATE UNIQUE INDEX IF NOT EXISTS incidents_correlation_uid ON incidents (correlation_uid)
    WHERE correlation_uid IS NOT NULL;

-- Case work (TheHive pattern): tasks/checklists + observables (IOCs) attached to an incident.
CREATE TABLE IF NOT EXISTS case_tasks (
    id           bigserial PRIMARY KEY,
    incident_id  bigint REFERENCES incidents(id) ON DELETE CASCADE,
    title        text NOT NULL,
    status       text DEFAULT 'todo',       -- todo | in_progress | done
    assignee     text,
    created_at   timestamptz DEFAULT now(),
    completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS case_tasks_incident ON case_tasks (incident_id);

CREATE TABLE IF NOT EXISTS case_observables (
    id           bigserial PRIMARY KEY,
    incident_id  bigint REFERENCES incidents(id) ON DELETE CASCADE,
    type         text NOT NULL,             -- ip | domain | url | hash | cve | host
    value        text NOT NULL,
    is_ioc       boolean DEFAULT false,
    tlp          text DEFAULT 'amber',
    note         text,
    added_at     timestamptz DEFAULT now(),
    UNIQUE (incident_id, type, value)
);

-- IOC sightings (MISP pattern): record where/when an indicator was actually observed.
CREATE TABLE IF NOT EXISTS ioc_sightings (
    id         bigserial PRIMARY KEY,
    indicator  text NOT NULL,
    type       text,
    finding_id bigint,
    asset_id   text,
    source     text,
    seen_at    timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ioc_sightings_indicator ON ioc_sightings (indicator, seen_at DESC);

-- SOAR playbooks (n8n/Shuffle pattern): a named sequence of containment-safe actions, with
-- an audit of every run. Actions are local-only (notify / open_incident / propose_containment)
-- so automation stays air-gap clean and analyst-controlled.
CREATE TABLE IF NOT EXISTS playbooks (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    description text,
    trigger     text DEFAULT 'manual',      -- manual | critical_finding | sla_breach
    actions     jsonb DEFAULT '[]',         -- [{type, params}]
    enabled     boolean DEFAULT true,
    created_at  timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS playbook_runs (
    id           bigserial PRIMARY KEY,
    playbook_id  text REFERENCES playbooks(id) ON DELETE CASCADE,
    trigger_ref  text,                       -- e.g. finding:10 / incident:3 / manual
    status       text DEFAULT 'completed',   -- completed | failed
    steps        jsonb DEFAULT '[]',         -- per-action result
    run_by       text,
    created_at   timestamptz DEFAULT now()
);

-- Local users + sessions for the console login gate (complements the K3s SSO path). Real
-- pbkdf2 password hashing; sessions are opaque bearer tokens. Seeded by auth.seed_users().
CREATE TABLE IF NOT EXISTS users (
    username      text PRIMARY KEY,
    password_hash text NOT NULL,
    salt          text NOT NULL,
    role          text DEFAULT 'viewer',   -- admin | analyst | viewer
    created_at    timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions (
    token      text PRIMARY KEY,
    username   text,
    role       text,
    created_at timestamptz DEFAULT now()
);

-- Alerting: notification channels (webhook/email/slack), routing rules, and a delivery log.
-- Closes the "alerts exist in-app but never leave the building" gap. Webhook delivery is real
-- (an internal POST, air-gap-friendly); email/slack are recorded as queued until a transport
-- is wired at the site.
CREATE TABLE IF NOT EXISTS alert_channels (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL,
    type       text DEFAULT 'webhook',     -- webhook | email | slack
    target     text NOT NULL,              -- URL / email / slack webhook
    enabled    boolean DEFAULT true,
    created_at timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS alert_rules (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL,
    min_severity text DEFAULT 'high',       -- critical | high | medium
    kind         text,                      -- critical_finding | sla_breach | any
    channel_id   bigint REFERENCES alert_channels(id) ON DELETE CASCADE,
    enabled      boolean DEFAULT true,
    created_at   timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS alert_deliveries (
    id           bigserial PRIMARY KEY,
    channel_id   bigint,
    channel_name text,
    subject      text,
    status       text,                      -- delivered | failed | queued
    detail       text,
    created_at   timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alert_deliveries_time ON alert_deliveries (created_at DESC);

-- Agentic AI analyst runs (air-gapped LLM triage). Records the model, shift summary, and per-finding
-- decisions+reasoning so the console can show the agent's work. Governed: the agent only proposes.
CREATE TABLE IF NOT EXISTS agent_runs (
    id          bigserial PRIMARY KEY,
    kind        text DEFAULT 'triage',      -- triage | investigation
    model       text,
    summary     text,
    considered  int DEFAULT 0,
    escalated   int DEFAULT 0,
    ref_id      text,                        -- incident id for investigations
    decisions   jsonb,                       -- triage decisions OR investigation result
    created_at  timestamptz DEFAULT now()
);
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS kind text DEFAULT 'triage';
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS ref_id text;
CREATE INDEX IF NOT EXISTS agent_runs_time ON agent_runs (created_at DESC);

-- Seed an n8n automation alert channel + a routing rule, so dispatched alerts also flow into
-- the n8n automation engine (not just playbook hand-offs). Idempotent (guarded by target/name).
INSERT INTO alert_channels (name, type, target)
  SELECT 'n8n automation', 'webhook', 'http://n8n:5678/webhook/vyrex-alert'
  WHERE NOT EXISTS (SELECT 1 FROM alert_channels WHERE target = 'http://n8n:5678/webhook/vyrex-alert');
INSERT INTO alert_rules (name, min_severity, kind, channel_id)
  SELECT 'Route high/critical to n8n', 'high', 'any', c.id
  FROM alert_channels c
  WHERE c.target = 'http://n8n:5678/webhook/vyrex-alert'
    AND NOT EXISTS (SELECT 1 FROM alert_rules WHERE name = 'Route high/critical to n8n');

-- Detection rules (Sigma/Suricata/YARA/domain) as manageable content: enable/tune/track
-- hits, not just a read-only catalog. The detections-as-content surface every SIEM has.
CREATE TABLE IF NOT EXISTS detection_rules (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    source      text DEFAULT 'sigma',     -- sigma | suricata | yara | domain
    technique   text,                     -- ATT&CK technique id
    severity    text DEFAULT 'medium',
    logic       text,                     -- query / condition / signature
    enabled     boolean DEFAULT true,
    hits        int DEFAULT 0,
    created_by  text,
    created_at  timestamptz DEFAULT now()
);
INSERT INTO detection_rules (name, source, technique, severity, logic, hits) VALUES
  ('C2 beacon to non-standard port (tcp/4444)', 'suricata', 'T1071.001', 'critical', 'alert tcp any any -> any 4444 (msg:"C2 beacon"; sid:9000001;)', 14),
  ('Looney Tunables local privilege escalation', 'sigma', 'T1068', 'high', 'process.args contains "GLIBC_TUNABLES" and exit_code = 0', 6),
  ('Reverse shell spawned (bash -i /dev/tcp)', 'yara', 'T1059', 'high', '$a = "bash -i >& /dev/tcp/"', 3),
  ('auditd not running (tamper-evident logging off)', 'domain', 'T1562', 'medium', 'service.auditd.active = false', 8),
  ('Apache Log4Shell JNDI exploit attempt', 'suricata', 'T1190', 'critical', 'content:"jndi:ldap"; http.uri; sid:9000002;', 2)
ON CONFLICT (name) DO NOTHING;

-- Generated reports (posture / compliance / executive) — point-in-time snapshots an analyst
-- or stakeholder can export. Content is a self-contained jsonb so a report is reproducible.
CREATE TABLE IF NOT EXISTS reports (
    id           bigserial PRIMARY KEY,
    type         text NOT NULL,            -- posture | compliance | executive
    title        text NOT NULL,
    content      jsonb NOT NULL,
    generated_by text,
    created_at   timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reports_created ON reports (created_at DESC);

-- Daily posture snapshots — so the platform can show real trends, not a single point.
CREATE TABLE IF NOT EXISTS posture_snapshots (
    snap_date    date PRIMARY KEY,
    open_findings int, kev int, critical int, high int,
    exploit_available int, avg_risk numeric, compliance_pct numeric,
    created_at   timestamptz DEFAULT now()
);

-- Live hunting (Velociraptor pattern): an analyst defines a read-only artifact to collect
-- across the fleet; agents poll, collect, and return rows. Collection-only (never executes
-- destructive actions), so it needs no two-person gate — but is still agent-token auth'd.
CREATE TABLE IF NOT EXISTS hunts (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL,
    artifact    text NOT NULL,            -- processes | listening_ports | file_search | osquery
    query       text,                     -- osquery SQL, or a file glob, depending on artifact
    target      text DEFAULT 'all',       -- 'all' or a specific agent/host id
    status      text DEFAULT 'queued',    -- queued | collecting | completed
    created_by  text,
    created_at  timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS hunt_results (
    id           bigserial PRIMARY KEY,
    hunt_id      bigint REFERENCES hunts(id) ON DELETE CASCADE,
    agent_id     text,
    asset_id     text,
    rows         jsonb,
    row_count    int,
    collected_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hunt_results_hunt ON hunt_results (hunt_id);

-- Seed three default playbooks (idempotent).
INSERT INTO playbooks (id, name, description, trigger, actions) VALUES
  ('pb-critical-triage', 'Critical finding fast-triage',
   'On a critical finding: raise an alert, open a case, and propose host containment for approval.',
   'critical_finding',
   '[{"type":"notify","params":{"severity":"critical"}},{"type":"open_incident","params":{}},{"type":"propose_containment","params":{"action":"network_isolate"}}]'),
  ('pb-c2-contain', 'Suspected C2 beacon containment',
   'On a C2/egress detection: alert, open a case, and propose isolating the source host.',
   'manual',
   '[{"type":"notify","params":{"severity":"critical"}},{"type":"open_incident","params":{}},{"type":"propose_containment","params":{"action":"network_isolate"}}]'),
  ('pb-sla-escalate', 'SLA-breach escalation',
   'On an SLA breach: raise a high-severity alert and notify the on-call owner.',
   'sla_breach',
   '[{"type":"notify","params":{"severity":"high"}}]'),
  ('pb-n8n-automation', 'Hand off to n8n automation',
   'Open a case, then hand the finding to the n8n automation engine to run the full automated-analyst workflow (enrich → correlate → alert → report).',
   'manual',
   '[{"type":"notify","params":{"severity":"high"}},{"type":"open_incident","params":{}},{"type":"webhook","params":{}}]')
ON CONFLICT (id) DO NOTHING;
"""

# Finding lifecycle / risk-acceptance (DefectDojo pattern). findings is owned by the
# enrichment service, so these are applied in a separate guarded step that no-ops if the
# table doesn't exist yet (cold start) instead of aborting the core schema.
FINDINGS_AUGMENT = """
ALTER TABLE findings ADD COLUMN IF NOT EXISTS triage_status text DEFAULT 'open';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS triage_note text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS triaged_by text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS triaged_at timestamptz;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_accepted_until date;
"""


def ensure_schema() -> None:
    try:
        with psycopg.connect(settings.postgres_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(DDL)
        log.info("incident/response schema ready")
    except Exception as e:  # don't crash the API if the DB is briefly unavailable at boot
        log.warning("schema ensure deferred: %s", e)
    # findings table belongs to enrichment; augment it best-effort (separate txn).
    try:
        with psycopg.connect(settings.postgres_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(FINDINGS_AUGMENT)
        log.info("findings lifecycle columns ready")
    except Exception as e:
        log.info("findings augment deferred (table not present yet): %s", e)
