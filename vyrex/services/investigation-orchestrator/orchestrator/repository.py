"""Database access for the orchestrator.

Synchronous psycopg, matching services/enrichment and ml/ (only services/api is async).
The orchestrator is a worker loop, not a web server, so there is nothing to gain from
async here and a great deal of complexity to avoid.

The orchestrator connects DIRECTLY to Postgres rather than through the VYREX API. That
is how every other backend service works, and it sidesteps the fact that the repo has no
service-principal auth — only a shared agent bearer token that bypasses RBAC entirely.
It should be granted write on the orchestration tables and read on findings/assets, and
nothing at all on response_actions, users or sessions.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

log = logging.getLogger("orchestrator.db")


def connect(dsn: str) -> psycopg.Connection:
    # autocommit for ordinary single statements; claim_next_job opens an explicit
    # transaction where atomicity actually matters.
    return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)


# --------------------------------------------------------------------------- work intake

def claim_next_job(pg: psycopg.Connection, max_attempts: int) -> dict | None:
    """Atomically take ownership of one pending outbox row.

    `FOR UPDATE SKIP LOCKED` is what makes this safe to run in more than one process:
    each worker takes a different row instead of two workers racing for the same one and
    one of them blocking. Marking the row 'sent' inside the same transaction means a
    crash after the claim cannot lose the job — it is either still pending, or claimed
    and recorded.

    Rows past `max_attempts` are parked as 'failed' instead of spinning forever; nothing
    else in this repo has a dead-letter path, and an infinitely-retried poison message is
    a silent outage.
    """
    with pg.transaction():
        with pg.cursor() as cur:
            cur.execute(
                """SELECT * FROM investigation_outbox
                    WHERE status = 'pending'
                    ORDER BY created_at
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1"""
            )
            row = cur.fetchone()
            if not row:
                return None
            if (row["attempts"] or 0) >= max_attempts:
                cur.execute(
                    "UPDATE investigation_outbox SET status='failed', "
                    "last_error='exceeded max attempts' WHERE id=%s",
                    (row["id"],),
                )
                log.warning("outbox %s parked as failed after %s attempts",
                            row["id"], row["attempts"])
                return None
            cur.execute(
                "UPDATE investigation_outbox SET status='sent', attempts = attempts + 1, "
                "sent_at = now() WHERE id=%s",
                (row["id"],),
            )
            return row


def find_orphaned(pg: psycopg.Connection) -> list[dict]:
    """Investigations left in 'running' by a worker that died mid-graph.

    Without this they are lost forever: `claim_next_job` already marked their outbox row
    'sent', so nothing re-delivers them, and the investigation sits in 'running'
    indefinitely. The checkpointer can resume the graph, but only if something notices
    the run needs resuming — that is what this is for.

    Safe because the orchestrator runs single-instance (ORCH_CONCURRENCY=1 by default on
    this hardware): at startup, any 'running' row is necessarily stale, because this
    process is the only thing that could have been running it. Scaling to multiple
    workers would need a lease column (worker id + heartbeat) so a live run on another
    worker is not stolen; noted rather than built, since one worker is the deliberate
    configuration here.
    """
    with pg.cursor() as cur:
        cur.execute(
            "SELECT investigation_id, subject_type, subject_id, started_at "
            "FROM investigations WHERE status='running' ORDER BY started_at"
        )
        return cur.fetchall()


def release_job(pg: psycopg.Connection, outbox_id: int, error: str) -> None:
    """Hand a job back for retry after a transient failure."""
    with pg.cursor() as cur:
        cur.execute(
            "UPDATE investigation_outbox SET status='pending', last_error=%s WHERE id=%s",
            (error[:500], outbox_id),
        )


def ensure_investigation(pg: psycopg.Connection, payload: dict, event_key: str) -> str | None:
    """Return the investigation_id for a job, creating one for automatic triggers.

    Manual requests already created their row in the same transaction as the outbox
    entry, so this finds it. Automatic triggers come from the risk engine, which writes
    only the outbox row — so the investigation is created here, keyed on event_key so a
    redelivery cannot produce a second one.
    """
    with pg.cursor() as cur:
        cur.execute(
            "SELECT investigation_id FROM investigations WHERE idempotency_key = %s", (event_key,)
        )
        row = cur.fetchone()
        if row:
            return row["investigation_id"]

        import uuid
        inv_id = str(uuid.uuid4())
        try:
            cur.execute(
                """INSERT INTO investigations
                     (investigation_id, subject_type, subject_id, trigger_type, status,
                      idempotency_key, trigger_score_snapshot, trigger_policy_version)
                   VALUES (%s,%s,%s,%s,'queued',%s,%s,%s)
                RETURNING investigation_id""",
                (inv_id, payload.get("subject_type", "finding"), payload["subject_id"],
                 payload.get("trigger_type", "automatic"), event_key,
                 payload.get("trigger_score_snapshot"), payload.get("trigger_policy_version")),
            )
            return cur.fetchone()["investigation_id"]
        except psycopg.errors.UniqueViolation:
            # An active run already exists for this subject (the partial unique index).
            # Not an error: the work is already accounted for, so drop this delivery.
            log.info("subject %s already has an active investigation; skipping duplicate",
                     payload.get("subject_id"))
            return None


# ------------------------------------------------------------------------ investigation

def start(pg: psycopg.Connection, inv_id: str, *, graph_version: str, prompt_version: str,
          model_name: str | None, contract_version: str) -> None:
    with pg.cursor() as cur:
        cur.execute(
            """UPDATE investigations
                  SET status='running', started_at=now(), graph_version=%s,
                      prompt_version=%s, model_name=%s, contract_version=%s
                WHERE investigation_id=%s""",
            (graph_version, prompt_version, model_name, contract_version, inv_id),
        )


def finish(pg: psycopg.Connection, inv_id: str, status: str, error: str | None = None) -> None:
    with pg.cursor() as cur:
        cur.execute(
            """UPDATE investigations
                  SET status=%s, finished_at=now(), error=%s,
                      duration_ms = CASE WHEN started_at IS NOT NULL
                                    THEN EXTRACT(MILLISECONDS FROM (now() - started_at))::int
                                       + EXTRACT(EPOCH FROM (now() - started_at))::int * 1000
                                    ELSE NULL END
                WHERE investigation_id=%s""",
            (status, (error or None), inv_id),
        )


def load_subject(pg: psycopg.Connection, subject_type: str, subject_id: int) -> dict | None:
    """The finding/incident under investigation, plus the context the nodes reason over."""
    with pg.cursor() as cur:
        if subject_type == "finding":
            cur.execute("SELECT * FROM findings WHERE id=%s", (subject_id,))
        else:
            cur.execute("SELECT * FROM incidents WHERE id=%s", (subject_id,))
        return cur.fetchone()


def load_asset(pg: psycopg.Connection, host_id: str) -> dict | None:
    with pg.cursor() as cur:
        cur.execute("SELECT * FROM assets WHERE host_id=%s", (host_id,))
        return cur.fetchone()


def load_explanation(pg: psycopg.Connection, finding_id: int) -> dict | None:
    """SHAP factors already computed by the risk engine — reuse, don't recompute."""
    with pg.cursor() as cur:
        cur.execute("SELECT * FROM finding_explanations WHERE finding_id=%s", (finding_id,))
        return cur.fetchone()


# ------------------------------------------------------------------------------- writes

def upsert_step(pg: psycopg.Connection, inv_id: str, node: str, status: str, *,
                attempt: int = 1, reason: str | None = None, output: Any = None,
                evidence_ids: list[str] | None = None, duration_ms: int | None = None,
                started: bool = False, finished: bool = False) -> None:
    """Record a node's execution. Idempotent on (investigation, node, attempt).

    Every node writes a row even when it is skipped, because 'the historical branch
    found nothing' and 'the historical branch crashed' must stay distinguishable — a
    single result blob destroys that distinction, which is the core defect of agent_runs.
    """
    with pg.cursor() as cur:
        cur.execute(
            """INSERT INTO investigation_steps
                 (investigation_id, node, attempt, status, reason, output, evidence_ids,
                  duration_ms, started_at, finished_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,
                       CASE WHEN %s THEN now() END, CASE WHEN %s THEN now() END)
               ON CONFLICT (investigation_id, node, attempt) DO UPDATE SET
                 status=EXCLUDED.status,
                 reason=COALESCE(EXCLUDED.reason, investigation_steps.reason),
                 output=COALESCE(EXCLUDED.output, investigation_steps.output),
                 evidence_ids=COALESCE(EXCLUDED.evidence_ids, investigation_steps.evidence_ids),
                 duration_ms=COALESCE(EXCLUDED.duration_ms, investigation_steps.duration_ms),
                 finished_at=COALESCE(EXCLUDED.finished_at, investigation_steps.finished_at)""",
            (inv_id, node, attempt, status, reason,
             Jsonb(output) if output is not None else None,
             Jsonb(evidence_ids) if evidence_ids is not None else None,
             duration_ms, started, finished),
        )


def save_evidence(pg: psycopg.Connection, inv_id: str, items: list[dict]) -> int:
    """Persist frozen evidence. ON CONFLICT DO NOTHING so a resumed node is harmless."""
    if not items:
        return 0
    n = 0
    with pg.cursor() as cur:
        for e in items:
            cur.execute(
                """INSERT INTO investigation_evidence
                     (investigation_id, citation_id, source_type, source_reference,
                      structured_payload, content_hash, source_tool, tlp, observed_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (investigation_id, citation_id) DO NOTHING""",
                (inv_id, e["citation_id"], e["source_type"], e.get("source_reference"),
                 Jsonb(e["structured_payload"]), e["content_hash"],
                 e.get("source_tool"), e.get("tlp", "TLP:AMBER"), e.get("observed_at")),
            )
            n += cur.rowcount
    return n


def save_report(pg: psycopg.Connection, inv_id: str, report: dict,
                unresolved: list[str] | None = None) -> None:
    with pg.cursor() as cur:
        cur.execute(
            """INSERT INTO triage_reports
                 (investigation_id, recommended_severity, recommended_disposition, confidence,
                  summary, rationale_claims, recommended_next_steps, missing_evidence,
                  completeness, unresolved_citations, graph_version, prompt_version,
                  model_name, contract_version)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (investigation_id) DO UPDATE SET
                 recommended_severity=EXCLUDED.recommended_severity,
                 recommended_disposition=EXCLUDED.recommended_disposition,
                 confidence=EXCLUDED.confidence, summary=EXCLUDED.summary,
                 rationale_claims=EXCLUDED.rationale_claims,
                 recommended_next_steps=EXCLUDED.recommended_next_steps,
                 missing_evidence=EXCLUDED.missing_evidence,
                 completeness=EXCLUDED.completeness,
                 unresolved_citations=EXCLUDED.unresolved_citations""",
            (inv_id, report["recommended_severity"], report["recommended_disposition"],
             report["confidence"], report["summary"],
             Jsonb(report.get("rationale_claims", [])),
             Jsonb(report.get("recommended_next_steps", [])),
             Jsonb(report.get("missing_evidence", [])),
             report.get("completeness", "complete"),
             Jsonb(unresolved or []),
             report.get("graph_version"), report.get("prompt_version"),
             report.get("model_name"), report.get("contract_version")),
        )
