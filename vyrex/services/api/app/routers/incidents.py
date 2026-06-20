"""Incident management: lifecycle, assignment, SLA, linked evidence (findings)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Header, Query
from pydantic import BaseModel

from .. import db

router = APIRouter(prefix="/incidents", tags=["incidents"])

# SLA target (hours to resolve) by severity.
SLA_HOURS = {"critical": 4, "high": 24, "medium": 72, "low": 168, "info": 336}


class IncidentIn(BaseModel):
    title: str
    description: str | None = None
    severity: str = "medium"
    assignee: str | None = None
    finding_ids: list[int] = []


class IncidentPatch(BaseModel):
    status: str | None = None       # open | in_progress | resolved | closed
    assignee: str | None = None
    severity: str | None = None


class LinkIn(BaseModel):
    finding_ids: list[int]


@router.post("", summary="Open an incident (optionally from findings)")
async def create(inc: IncidentIn, x_analyst: Annotated[str | None, Header()] = None) -> dict:
    hours = SLA_HOURS.get(inc.severity.lower(), 72)
    row = await db.execute(
        """
        INSERT INTO incidents (title, description, severity, assignee, created_by, sla_due)
        VALUES (%(t)s, %(d)s, %(sev)s, %(asg)s, %(by)s, now() + (%(h)s || ' hours')::interval)
        RETURNING id, title, severity, status, assignee, sla_due, created_at
        """,
        {"t": inc.title, "d": inc.description, "sev": inc.severity, "asg": inc.assignee,
         "by": x_analyst or "analyst", "h": hours},
    )
    for fid in inc.finding_ids:
        await db.execute(
            "INSERT INTO incident_findings (incident_id, finding_id) VALUES (%(i)s,%(f)s) ON CONFLICT DO NOTHING",
            {"i": row["id"], "f": fid},
        )
    row["linked_findings"] = len(inc.finding_ids)
    return row


@router.get("", summary="List incidents")
async def list_incidents(
    status: str | None = None, assignee: str | None = None, severity: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict]:
    clauses, params = [], {"limit": limit}
    for col, val in (("status", status), ("assignee", assignee), ("severity", severity)):
        if val:
            clauses.append(f"i.{col} = %({col})s"); params[col] = val
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return await db.fetch(
        f"""
        SELECT i.id, i.title, i.severity, i.status, i.assignee, i.created_by,
               i.sla_due, (i.status NOT IN ('resolved','closed') AND now() > i.sla_due) AS sla_breached,
               i.created_at, i.resolved_at,
               COALESCE(i.auto_created, false) AS auto_created, i.correlation_uid,
               (SELECT count(*) FROM incident_findings f WHERE f.incident_id = i.id) AS finding_count
        FROM incidents i {where}
        ORDER BY (i.status NOT IN ('resolved','closed')) DESC, i.sla_due
        LIMIT %(limit)s
        """,
        params,
    )


@router.get("/{incident_id}", summary="Incident detail + linked findings")
async def get_incident(incident_id: int) -> dict:
    inc = await db.fetch_one("SELECT * FROM incidents WHERE id = %(id)s", {"id": incident_id})
    if not inc:
        return {}
    inc["findings"] = await db.fetch(
        """SELECT fd.id, fd.domain, fd.title, fd.severity, fd.risk_score, fd.cve_id, fd.kev
           FROM incident_findings link JOIN findings fd ON fd.id = link.finding_id
           WHERE link.incident_id = %(id)s ORDER BY fd.risk_score DESC NULLS LAST""",
        {"id": incident_id},
    )
    inc["actions"] = await db.fetch(
        "SELECT id, action_type, agent_id, status, requested_by FROM response_actions "
        "WHERE incident_id = %(id)s ORDER BY created_at DESC",
        {"id": incident_id},
    )
    return inc


@router.patch("/{incident_id}", summary="Update status / assignee / severity")
async def patch_incident(incident_id: int, p: IncidentPatch) -> dict:
    sets, params = ["updated_at = now()"], {"id": incident_id}
    if p.status:
        sets.append("status = %(status)s"); params["status"] = p.status
        if p.status == "resolved":
            sets.append("resolved_at = now()")
    if p.assignee is not None:
        sets.append("assignee = %(assignee)s"); params["assignee"] = p.assignee
    if p.severity:
        sets.append("severity = %(severity)s"); params["severity"] = p.severity
    return await db.execute(
        f"UPDATE incidents SET {', '.join(sets)} WHERE id = %(id)s RETURNING id, status, assignee, severity, updated_at",
        params,
    ) or {}


@router.post("/{incident_id}/findings", summary="Link findings (evidence) to an incident")
async def link_findings(incident_id: int, body: LinkIn) -> dict:
    for fid in body.finding_ids:
        await db.execute(
            "INSERT INTO incident_findings (incident_id, finding_id) VALUES (%(i)s,%(f)s) ON CONFLICT DO NOTHING",
            {"i": incident_id, "f": fid},
        )
    return {"incident_id": incident_id, "linked": body.finding_ids}
