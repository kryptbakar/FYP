"""Investigation orchestration — the async job API.

Replaces the fire-and-forget `/agent/*` pattern, which could not work: nginx caps a
proxied response at 30s (`web/console/nginx.conf`) while an LLM investigation runs
180-240s, so the console's own reverse proxy would kill the request before the answer
existed. Every endpoint here returns immediately; work happens out of band.

    POST /investigations            -> 202 {investigation_id, status}
    GET  /investigations/{id}       -> status + timings
    GET  /investigations/{id}/steps -> per-node execution trace
    GET  /investigations/{id}/report-> the verdict, once there is one

Creation writes the investigation row AND its outbox row in ONE transaction
(`db.transaction`). That is what makes an automatic trigger exactly-once: an event can
never announce work that rolled back, and work can never commit without its event.

The taxonomy (ESCALATE | MONITOR | DISMISS | INSUFFICIENT_EVIDENCE) is owned by
services/investigation-orchestrator/orchestrator/models/contracts.py. It is mirrored as
literals here rather than imported because the two services are packaged separately;
if you change it there, change it here.
"""
from __future__ import annotations

import json
import uuid
from typing import Annotated, Literal

import psycopg
from fastapi import APIRouter, Header, HTTPException, Response
from pydantic import BaseModel, Field

from .. import db, ratelimit
from ..config import settings

router = APIRouter(tags=["investigations"])

DISPOSITIONS = ("ESCALATE", "MONITOR", "DISMISS", "INSUFFICIENT_EVIDENCE")
ACTIVE = ("queued", "running")


class InvestigationIn(BaseModel):
    subject_type: Literal["finding", "incident"] = "finding"
    subject_id: int
    # Lets a caller retry safely: the same key returns the same investigation instead of
    # starting a second one. Automatic triggers reuse the outbox event_key here.
    idempotency_key: str | None = None


class ReviewIn(BaseModel):
    action: Literal["accept", "reject", "override"]
    note: str | None = None
    # Only meaningful for 'override' — what the analyst decided instead. Captured as
    # training signal: these become the real labels the ML layer currently lacks.
    severity: str | None = None
    disposition: str | None = Field(default=None, description="|".join(DISPOSITIONS))


async def _get(inv_id: str) -> dict:
    row = await db.fetch_one(
        "SELECT * FROM investigations WHERE investigation_id = %s", (inv_id,)
    )
    if not row:
        raise HTTPException(status_code=404, detail="investigation not found")
    return row


async def _active_for(subject_type: str, subject_id: int) -> dict | None:
    return await db.fetch_one(
        "SELECT * FROM investigations WHERE subject_type=%s AND subject_id=%s "
        "AND status = ANY(%s) ORDER BY created_at DESC LIMIT 1",
        (subject_type, subject_id, list(ACTIVE)),
    )


@router.post("/investigations", status_code=202,
             summary="Request an investigation (returns immediately; poll for the result)")
async def create_investigation(
    body: InvestigationIn,
    response: Response,
    x_analyst: Annotated[str | None, Header()] = None,
) -> dict:
    """202 Accepted, always fast. The graph runs out of band.

    Idempotent by design. Asking twice for the same subject returns the run already in
    flight rather than starting a competing one — enforced by a partial unique index, so
    two concurrent callers cannot both win the race.
    """
    subject = await db.fetch_one(
        "SELECT id FROM findings WHERE id=%s" if body.subject_type == "finding"
        else "SELECT id FROM incidents WHERE id=%s",
        (body.subject_id,),
    )
    if not subject:
        raise HTTPException(status_code=404, detail=f"{body.subject_type} {body.subject_id} not found")

    existing = await _active_for(body.subject_type, body.subject_id)
    if existing is None:
        # Admission control, only on genuinely NEW work. A caller polling an in-flight
        # subject gets the existing run below without spending any allowance — otherwise
        # the idempotent path would punish the well-behaved client.
        #
        # This endpoint returns in milliseconds but commits the orchestrator to ~2 minutes
        # of serial inference, so the cost is invisible at the edge. See app/ratelimit.py.
        depth = await db.fetch_one(
            "SELECT count(*) AS n FROM investigation_outbox WHERE status <> 'sent'")
        try:
            ratelimit.check_queue_depth(int((depth or {}).get("n", 0)),
                                        settings.investigation_max_queue)
            ratelimit.check_window(x_analyst or "anonymous",
                                   settings.investigation_rate_limit,
                                   settings.investigation_rate_window_s)
        except ratelimit.RateLimited as e:
            raise HTTPException(status_code=429, detail=e.detail,
                                headers={"Retry-After": str(e.retry_after)}) from e

    if existing:
        response.status_code = 200
        return {"investigation_id": existing["investigation_id"], "status": existing["status"],
                "existing": True, "detail": "an investigation for this subject is already in flight"}

    inv_id = str(uuid.uuid4())
    key = body.idempotency_key or f"manual:{body.subject_type}:{body.subject_id}:{inv_id}"
    payload = {"subject_type": body.subject_type, "subject_id": body.subject_id,
               "trigger_type": "manual", "requested_by": x_analyst}
    try:
        async with db.transaction() as conn:
            await db.tx_execute(
                conn,
                """INSERT INTO investigations
                     (investigation_id, subject_type, subject_id, trigger_type,
                      status, idempotency_key, requested_by)
                   VALUES (%s,%s,%s,'manual','queued',%s,%s)""",
                (inv_id, body.subject_type, body.subject_id, key, x_analyst),
            )
            # Same transaction: the orchestrator can never see a request whose
            # investigation row did not commit.
            await db.tx_execute(
                conn,
                """INSERT INTO investigation_outbox
                     (event_key, subject_type, subject_id, trigger_type, payload)
                   VALUES (%s,%s,%s,'manual',%s)
                   ON CONFLICT (event_key) DO NOTHING""",
                (key, body.subject_type, body.subject_id, json.dumps(payload)),
            )
    except psycopg.errors.UniqueViolation:
        # Lost a race against a concurrent request; hand back the winner.
        existing = await _active_for(body.subject_type, body.subject_id)
        if existing:
            response.status_code = 200
            return {"investigation_id": existing["investigation_id"], "status": existing["status"],
                    "existing": True, "detail": "raced with a concurrent request"}
        raise
    return {"investigation_id": inv_id, "status": "queued"}


@router.get("/investigations", summary="List investigations (newest first)")
async def list_investigations(status: str | None = None, limit: int = 50) -> list[dict]:
    if status:
        return await db.fetch(
            "SELECT * FROM investigations WHERE status=%s ORDER BY created_at DESC LIMIT %s",
            (status, limit))
    return await db.fetch(
        "SELECT * FROM investigations ORDER BY created_at DESC LIMIT %s", (limit,))


@router.get("/investigations/{investigation_id}", summary="One investigation's status")
async def get_investigation(investigation_id: str) -> dict:
    return await _get(investigation_id)


@router.get("/investigations/{investigation_id}/steps",
            summary="Per-node execution trace (what ran, what was skipped, and why)")
async def get_steps(investigation_id: str) -> list[dict]:
    await _get(investigation_id)
    return await db.fetch(
        "SELECT * FROM investigation_steps WHERE investigation_id=%s "
        "ORDER BY started_at NULLS LAST, id", (investigation_id,))


@router.get("/investigations/{investigation_id}/evidence",
            summary="The frozen facts the report is allowed to cite")
async def get_evidence(investigation_id: str) -> list[dict]:
    await _get(investigation_id)
    return await db.fetch(
        "SELECT * FROM investigation_evidence WHERE investigation_id=%s ORDER BY citation_id",
        (investigation_id,))


@router.get("/investigations/{investigation_id}/report", summary="The verdict, once there is one")
async def get_report(investigation_id: str) -> dict:
    inv = await _get(investigation_id)
    row = await db.fetch_one(
        "SELECT * FROM triage_reports WHERE investigation_id=%s", (investigation_id,))
    if not row:
        # Not an error — the caller is polling and the answer isn't ready. Saying so
        # explicitly beats a 404, which reads as "wrong id".
        raise HTTPException(status_code=409,
                            detail=f"no report yet; investigation is '{inv['status']}'")
    return row


@router.post("/investigations/{investigation_id}/cancel", summary="Cancel a queued/running run")
async def cancel(investigation_id: str, x_analyst: Annotated[str | None, Header()] = None) -> dict:
    inv = await _get(investigation_id)
    if inv["status"] not in ACTIVE:
        raise HTTPException(status_code=409,
                            detail=f"cannot cancel an investigation that is '{inv['status']}'")
    await db.execute(
        "UPDATE investigations SET status='cancelled', finished_at=now() WHERE investigation_id=%s",
        (investigation_id,))
    return {"investigation_id": investigation_id, "status": "cancelled"}


@router.post("/investigations/{investigation_id}/retry",
             summary="Re-run a finished investigation (creates a new one)")
async def retry(investigation_id: str, response: Response,
                x_analyst: Annotated[str | None, Header()] = None) -> dict:
    inv = await _get(investigation_id)
    if inv["status"] in ACTIVE:
        raise HTTPException(status_code=409, detail="that investigation is still in flight")
    return await create_investigation(
        InvestigationIn(subject_type=inv["subject_type"], subject_id=inv["subject_id"]),
        response, x_analyst)


@router.post("/investigations/{investigation_id}/review",
             summary="Analyst accepts, rejects or overrides the verdict")
async def review(investigation_id: str, body: ReviewIn,
                 x_analyst: Annotated[str | None, Header()] = None) -> dict:
    """Analyst judgement on a report.

    Deliberately recorded even when the analyst simply accepts: an accepted verdict is
    as much a label as a corrected one, and the evaluation needs both.
    """
    await _get(investigation_id)
    if body.disposition and body.disposition not in DISPOSITIONS:
        raise HTTPException(status_code=422,
                            detail=f"disposition must be one of {DISPOSITIONS}")
    row = await db.execute(
        """UPDATE triage_reports
              SET analyst_action=%s, analyst_note=%s, analyst_severity=%s,
                  analyst_disposition=%s, reviewed_by=%s, reviewed_at=now()
            WHERE investigation_id=%s
        RETURNING investigation_id, analyst_action, reviewed_by, reviewed_at""",
        (body.action, body.note, body.severity, body.disposition, x_analyst, investigation_id))
    if not row:
        raise HTTPException(status_code=409, detail="there is no report to review yet")
    return row


@router.get("/findings/{finding_id}/investigations", summary="Investigations for one finding")
async def for_finding(finding_id: int) -> list[dict]:
    return await db.fetch(
        "SELECT * FROM investigations WHERE subject_type='finding' AND subject_id=%s "
        "ORDER BY created_at DESC", (finding_id,))


@router.get("/incidents/{incident_id}/investigations", summary="Investigations for one incident")
async def for_incident(incident_id: int) -> list[dict]:
    return await db.fetch(
        "SELECT * FROM investigations WHERE subject_type='incident' AND subject_id=%s "
        "ORDER BY created_at DESC", (incident_id,))


@router.get("/orchestrator/status", summary="Is the orchestration pipeline healthy?")
async def orchestrator_status() -> dict:
    """Queue depth and outcome counts.

    `pending_outbox` is the number that matters operationally: if it grows without
    bound the relay or the orchestrator has stopped consuming, and investigations are
    being requested but never run — a failure that is otherwise silent.
    """
    by_status = await db.fetch(
        "SELECT status, count(*) AS n FROM investigations GROUP BY status")
    outbox = await db.fetch(
        "SELECT status, count(*) AS n FROM investigation_outbox GROUP BY status")
    oldest = await db.fetch_one(
        "SELECT min(created_at) AS oldest FROM investigation_outbox WHERE status='pending'")
    return {
        "investigations": {r["status"]: r["n"] for r in by_status},
        "outbox": {r["status"]: r["n"] for r in outbox},
        "pending_outbox": next((r["n"] for r in outbox if r["status"] == "pending"), 0),
        "oldest_pending": (oldest or {}).get("oldest"),
    }
