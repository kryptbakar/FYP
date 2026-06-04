"""SOAR playbooks (n8n / Shuffle pattern) — analyst-controlled automation.

A playbook is a named sequence of *containment-safe, local-only* actions. Running one is
recorded as an audited run. Actions deliberately stop at *proposing* containment (which then
needs the existing two-person approval) — automation accelerates the SOC without ever
auto-executing a destructive action, which keeps it defensible and air-gap clean.
"""
from __future__ import annotations

import json
import uuid
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import audit, db

router = APIRouter(tags=["soar"])


@router.get("/playbooks", summary="List SOAR playbooks")
async def list_playbooks() -> list[dict]:
    return await db.fetch(
        "SELECT id, name, description, trigger, actions, enabled, created_at FROM playbooks ORDER BY id"
    )


@router.get("/playbook-runs", summary="Recent playbook runs")
async def list_runs(limit: int = 30) -> list[dict]:
    return await db.fetch(
        "SELECT id, playbook_id, trigger_ref, status, steps, run_by, created_at "
        "FROM playbook_runs ORDER BY id DESC LIMIT %(l)s",
        {"l": limit},
    )


class RunIn(BaseModel):
    finding_id: int | None = None
    incident_id: int | None = None


async def _finding(fid: int) -> dict | None:
    return await db.fetch_one(
        "SELECT id, asset_id, title, severity, cve_id, threat_intel FROM findings WHERE id=%(id)s",
        {"id": fid},
    )


@router.post("/playbooks/{playbook_id}/run", summary="Run a playbook (records an audited run)")
async def run_playbook(playbook_id: str, r: RunIn,
                       x_analyst: Annotated[str | None, Header()] = None) -> dict:
    pb = await db.fetch_one("SELECT * FROM playbooks WHERE id=%(id)s", {"id": playbook_id})
    if not pb:
        raise HTTPException(404, "playbook not found")
    actor = x_analyst or "soc-auto"
    finding = await _finding(r.finding_id) if r.finding_id else None
    trigger_ref = (f"finding:{r.finding_id}" if r.finding_id
                   else f"incident:{r.incident_id}" if r.incident_id else "manual")
    incident_id = r.incident_id
    steps: list[dict] = []

    for action in (pb.get("actions") or []):
        kind = action.get("type")
        params = action.get("params") or {}
        try:
            if kind == "notify":
                title = f"Playbook '{pb['name']}'" + (f" — {finding['title'][:60]}" if finding else "")
                await db.execute(
                    """INSERT INTO notifications (dedup_key, kind, severity, title, body, ref_type, ref_id)
                       VALUES (%(k)s,'system',%(sev)s,%(t)s,%(b)s,'finding',%(rid)s)
                       ON CONFLICT (dedup_key) DO NOTHING""",
                    {"k": f"pb:{playbook_id}:{trigger_ref}:{len(steps)}",
                     "sev": params.get("severity", "high"), "t": title,
                     "b": pb.get("description"), "rid": str(r.finding_id or "")},
                )
                steps.append({"action": "notify", "ok": True, "detail": params.get("severity", "high")})

            elif kind == "open_incident":
                if incident_id:
                    steps.append({"action": "open_incident", "ok": True, "detail": f"existing #{incident_id}"})
                else:
                    title = ("Auto: " + finding["title"][:70]) if finding else f"Playbook {pb['name']}"
                    sev = (finding.get("severity") or "high").lower() if finding else "high"
                    inc = await db.execute(
                        "INSERT INTO incidents (title, severity, status, created_by, auto_created, sla_due) "
                        "VALUES (%(t)s,%(s)s,'open',%(by)s,true, now() + interval '24 hours') RETURNING id",
                        {"t": title, "s": sev, "by": actor},
                    )
                    incident_id = inc["id"] if inc else None
                    if incident_id and r.finding_id:
                        await db.execute(
                            "INSERT INTO incident_findings (incident_id, finding_id) VALUES (%(i)s,%(f)s) "
                            "ON CONFLICT DO NOTHING", {"i": incident_id, "f": r.finding_id})
                    steps.append({"action": "open_incident", "ok": True, "detail": f"#{incident_id}"})

            elif kind == "propose_containment":
                if not (finding and finding.get("asset_id")):
                    steps.append({"action": "propose_containment", "ok": False, "detail": "no target host"})
                    continue
                act = await db.execute(
                    """INSERT INTO response_actions (incident_id, agent_id, action_type, params, requested_by, nonce)
                       VALUES (%(i)s,%(ag)s,%(t)s,%(p)s,%(by)s,%(n)s) RETURNING id""",
                    {"i": incident_id, "ag": finding["asset_id"],
                     "t": params.get("action", "network_isolate"),
                     "p": json.dumps({"reason": f"playbook {playbook_id}"}),
                     "by": actor, "n": uuid.uuid4().hex},
                )
                if act:
                    audit.append(act["id"], "requested", actor,
                                 {"playbook": playbook_id, "agent_id": finding["asset_id"]})
                    steps.append({"action": "propose_containment", "ok": True,
                                  "detail": f"action #{act['id']} pending two-person approval"})
            else:
                steps.append({"action": kind, "ok": False, "detail": "unknown action"})
        except Exception as e:  # one bad step shouldn't abort the run
            steps.append({"action": kind, "ok": False, "detail": str(e)[:120]})

    run = await db.execute(
        "INSERT INTO playbook_runs (playbook_id, trigger_ref, status, steps, run_by) "
        "VALUES (%(p)s,%(tr)s,%(st)s,%(steps)s,%(by)s) RETURNING id, created_at",
        {"p": playbook_id, "tr": trigger_ref,
         "st": "completed" if all(s["ok"] for s in steps) else "failed",
         "steps": json.dumps(steps), "by": actor},
    )
    return {"run_id": (run or {}).get("id"), "playbook": playbook_id, "trigger_ref": trigger_ref,
            "incident_id": incident_id, "steps": steps}
