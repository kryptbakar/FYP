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
"""


def ensure_schema() -> None:
    try:
        with psycopg.connect(settings.postgres_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(DDL)
        log.info("incident/response schema ready")
    except Exception as e:  # don't crash the API if the DB is briefly unavailable at boot
        log.warning("schema ensure deferred: %s", e)
