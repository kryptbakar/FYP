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
