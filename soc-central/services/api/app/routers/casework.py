"""Case work — tasks/checklists and observables on an incident (TheHive pattern).

A real investigation isn't just a status: it's a checklist of tasks an analyst works
through, and a set of observables (IOCs/entities) gathered while doing so. Observables can
be auto-seeded from the incident's linked findings (CVE, host, live IOC) so the analyst
starts with context instead of a blank page.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import db

router = APIRouter(tags=["casework"])

TASK_STATES = {"todo", "in_progress", "done"}


# ------------------------------------------------------------------- tasks ----
class TaskIn(BaseModel):
    title: str
    assignee: str | None = None


class TaskPatch(BaseModel):
    status: str | None = None
    assignee: str | None = None


@router.get("/incidents/{incident_id}/tasks", summary="List case tasks")
async def list_tasks(incident_id: int) -> list[dict]:
    return await db.fetch(
        "SELECT id, title, status, assignee, created_at, completed_at FROM case_tasks "
        "WHERE incident_id=%(i)s ORDER BY (status='done'), created_at",
        {"i": incident_id},
    )


@router.post("/incidents/{incident_id}/tasks", summary="Add a case task")
async def add_task(incident_id: int, t: TaskIn) -> dict:
    return await db.execute(
        "INSERT INTO case_tasks (incident_id, title, assignee) VALUES (%(i)s,%(t)s,%(a)s) "
        "RETURNING id, title, status, assignee, created_at",
        {"i": incident_id, "t": t.title, "a": t.assignee},
    ) or {}


@router.patch("/tasks/{task_id}", summary="Update a case task (status/assignee)")
async def patch_task(task_id: int, p: TaskPatch) -> dict:
    if p.status and p.status not in TASK_STATES:
        raise HTTPException(400, f"invalid status; allowed: {sorted(TASK_STATES)}")
    done = ", completed_at = now()" if p.status == "done" else ""
    sets, params = [], {"id": task_id}
    if p.status:
        sets.append("status=%(s)s"); params["s"] = p.status
    if p.assignee is not None:
        sets.append("assignee=%(a)s"); params["a"] = p.assignee
    if not sets:
        raise HTTPException(400, "nothing to update")
    row = await db.execute(
        f"UPDATE case_tasks SET {', '.join(sets)}{done} WHERE id=%(id)s "
        "RETURNING id, title, status, assignee, completed_at",
        params,
    )
    if not row:
        raise HTTPException(404, "task not found")
    return row


# -------------------------------------------------------------- observables ----
class ObservableIn(BaseModel):
    type: str
    value: str
    is_ioc: bool = False
    tlp: str = "amber"
    note: str | None = None


@router.get("/incidents/{incident_id}/observables", summary="List case observables")
async def list_observables(incident_id: int) -> list[dict]:
    return await db.fetch(
        "SELECT id, type, value, is_ioc, tlp, note, added_at FROM case_observables "
        "WHERE incident_id=%(i)s ORDER BY is_ioc DESC, added_at",
        {"i": incident_id},
    )


@router.post("/incidents/{incident_id}/observables", summary="Add a case observable")
async def add_observable(incident_id: int, o: ObservableIn) -> dict:
    return await db.execute(
        "INSERT INTO case_observables (incident_id, type, value, is_ioc, tlp, note) "
        "VALUES (%(i)s,%(t)s,%(v)s,%(ioc)s,%(tlp)s,%(n)s) "
        "ON CONFLICT (incident_id, type, value) DO UPDATE SET is_ioc=EXCLUDED.is_ioc "
        "RETURNING id, type, value, is_ioc, tlp",
        {"i": incident_id, "t": o.type, "v": o.value, "ioc": o.is_ioc, "tlp": o.tlp, "n": o.note},
    ) or {}


@router.post("/incidents/{incident_id}/observables/auto", summary="Auto-seed observables from linked findings")
async def auto_observables(incident_id: int) -> dict:
    """Pull entities out of the incident's linked findings: CVE, affected host, and any live
    MISP indicator — so the case starts pre-populated with what to investigate."""
    findings = await db.fetch(
        """SELECT fd.cve_id, fd.asset_id, fd.threat_intel
           FROM incident_findings link JOIN findings fd ON fd.id = link.finding_id
           WHERE link.incident_id = %(i)s""",
        {"i": incident_id},
    )
    seeded = 0
    for f in findings:
        obs: list[tuple[str, str, bool]] = []
        if f.get("asset_id"):
            obs.append(("host", f["asset_id"], False))
        if f.get("cve_id"):
            obs.append(("cve", f["cve_id"], False))
        ti = f.get("threat_intel") or {}
        if isinstance(ti, dict) and ti.get("indicator"):
            obs.append((ti.get("type", "ip") or "ip", ti["indicator"], True))
        for typ, val, ioc in obs:
            row = await db.execute(
                "INSERT INTO case_observables (incident_id, type, value, is_ioc) "
                "VALUES (%(i)s,%(t)s,%(v)s,%(ioc)s) ON CONFLICT (incident_id, type, value) DO NOTHING "
                "RETURNING id",
                {"i": incident_id, "t": typ, "v": val, "ioc": ioc},
            )
            seeded += 1 if row else 0
    return {"seeded": seeded}
