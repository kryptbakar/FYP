"""Alerting / notifications — the analyst's alert inbox.

Rules turn live state into alerts an analyst must see: a *critical* finding, or an incident
that has *breached SLA*. Generation is idempotent (deduped), so /refresh can be called on
every console load without piling up duplicates. No extra worker — it derives from the
findings/incidents already in the DB.
"""
from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Query

from .. import db

router = APIRouter(tags=["notifications"])

CRITICAL_THRESHOLD = 80.0


@router.post("/notifications/refresh", summary="(Re)generate alerts from current findings & incidents")
async def refresh() -> dict:
    created = 0
    # Rule 1: critical-risk findings.
    crits = await db.fetch(
        "SELECT id, title, asset_id, risk_score FROM findings "
        "WHERE risk_score >= %(t)s ORDER BY risk_score DESC LIMIT 100",
        {"t": CRITICAL_THRESHOLD},
    )
    for f in crits:
        row = await db.execute(
            """INSERT INTO notifications (dedup_key, kind, severity, title, body, ref_type, ref_id)
               VALUES (%(k)s,'critical_finding','critical',%(title)s,%(body)s,'finding',%(rid)s)
               ON CONFLICT (dedup_key) DO NOTHING RETURNING id""",
            {"k": f"crit:{f['id']}", "title": f"Critical risk on {f['asset_id']}",
             "body": f["title"], "rid": str(f["id"])},
        )
        created += 1 if row else 0
    # Rule 2: SLA-breached incidents.
    breaches = await db.fetch(
        "SELECT id, title FROM incidents WHERE sla_due < now() "
        "AND status NOT IN ('resolved','closed') LIMIT 100"
    )
    for i in breaches:
        row = await db.execute(
            """INSERT INTO notifications (dedup_key, kind, severity, title, body, ref_type, ref_id)
               VALUES (%(k)s,'sla_breach','high',%(title)s,%(body)s,'incident',%(rid)s)
               ON CONFLICT (dedup_key) DO NOTHING RETURNING id""",
            {"k": f"sla:{i['id']}", "title": "SLA breached", "body": i["title"], "rid": str(i["id"])},
        )
        created += 1 if row else 0
    return {"created": created}


@router.get("/notifications", summary="List alerts (unacknowledged first)")
async def list_notifications(
    unacked: Annotated[bool, Query(description="only unacknowledged")] = False,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict]:
    where = "WHERE NOT acknowledged" if unacked else ""
    return await db.fetch(
        f"SELECT id, kind, severity, title, body, ref_type, ref_id, acknowledged, created_at "
        f"FROM notifications {where} ORDER BY acknowledged, created_at DESC LIMIT %(l)s",
        {"l": limit},
    )


@router.post("/notifications/{notification_id}/ack", summary="Acknowledge an alert")
async def ack(notification_id: int) -> dict:
    row = await db.execute(
        "UPDATE notifications SET acknowledged = true WHERE id = %(id)s RETURNING id, acknowledged",
        {"id": notification_id},
    )
    return row or {}
