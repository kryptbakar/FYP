"""Active response — the signed, two-person-approved containment command channel.

Reimplements Velociraptor's active-response *model* (not its code): request → two-person
approval → Ed25519-signed command → agent verifies + executes → result, with every step
in a hash-chained audit log. Containment only (kill/isolate/quarantine/disable); no patching.

Security properties:
- **Two-person rule** (D-027): destructive actions need >=2 *distinct* approvers, and the
  requester may not approve their own request (separation of duties).
- **Signed commands** (D-028): the server signs the exact bytes the agent verifies, so a
  command can't be forged or altered in transit.
- **Tamper-evident audit** (D-026): every lifecycle event is hash-chained.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import audit, db, signing
from ..config import settings

router = APIRouter(tags=["response"])

DESTRUCTIVE = {"process_kill", "network_isolate", "file_quarantine", "user_disable"}


class ActionIn(BaseModel):
    agent_id: str
    action_type: str
    params: dict = {}


class Approval(BaseModel):
    approver: str
    reason: str | None = None


class ResultIn(BaseModel):
    status: str            # completed | failed | verify_failed
    output: str | None = None


def _require_agent(authorization: str | None) -> None:
    """Authenticate an agent call by the shared bearer token."""
    token = settings.ingest_agent_token
    if token and authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid agent token")


# ----------------------------------------------------- request / approve ----
@router.post("/incidents/{incident_id}/actions", summary="Request a containment action")
async def request_action(incident_id: int, a: ActionIn,
                         x_analyst: Annotated[str | None, Header()] = None) -> dict:
    if a.action_type not in DESTRUCTIVE:
        raise HTTPException(400, f"unknown action_type; allowed: {sorted(DESTRUCTIVE)}")
    requester = x_analyst or "analyst"
    row = await db.execute(
        """INSERT INTO response_actions (incident_id, agent_id, action_type, params, requested_by, nonce)
           VALUES (%(i)s,%(ag)s,%(t)s,%(p)s,%(by)s,%(n)s)
           RETURNING id, agent_id, action_type, params, status, requested_by, created_at""",
        {"i": incident_id, "ag": a.agent_id, "t": a.action_type,
         "p": __import__("json").dumps(a.params), "by": requester, "n": uuid.uuid4().hex},
    )
    audit.append(row["id"], "requested", requester,
                 {"agent_id": a.agent_id, "action_type": a.action_type, "params": a.params})
    row["note"] = f"pending_approval — needs {settings.two_person_min} distinct approvers (not the requester)"
    return row


@router.post("/actions/{action_id}/approve", summary="Approve (two-person rule)")
async def approve(action_id: int, ap: Approval) -> dict:
    act = await db.fetch_one("SELECT * FROM response_actions WHERE id=%(id)s", {"id": action_id})
    if not act:
        raise HTTPException(404, "action not found")
    if act["status"] != "pending_approval":
        raise HTTPException(409, f"action is '{act['status']}', not pending_approval")
    if ap.approver == act["requested_by"]:
        raise HTTPException(403, "separation of duties: the requester cannot approve their own action")
    approvers = [x["approver"] for x in (act["approvals"] or [])]
    if ap.approver in approvers:
        raise HTTPException(409, "this approver already approved")

    approvals = (act["approvals"] or []) + [{"approver": ap.approver, "at": datetime.now(timezone.utc).isoformat()}]
    await db.execute("UPDATE response_actions SET approvals=%(a)s WHERE id=%(id)s",
                     {"a": __import__("json").dumps(approvals), "id": action_id})
    audit.append(action_id, "approved", ap.approver, {"approvals": len(approvals)})

    if len(approvals) < settings.two_person_min:
        return {"id": action_id, "status": "pending_approval",
                "approvals": len(approvals), "needed": settings.two_person_min}

    # Quorum reached → sign the command.
    if not signing.signing_available():
        raise HTTPException(500, "command signing key unavailable")
    payload = {
        "action_id": action_id, "agent_id": act["agent_id"], "action_type": act["action_type"],
        "params": act["params"] or {}, "nonce": act["nonce"],
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    signed_payload, sig, pub = signing.sign_command(payload)
    await db.execute(
        """UPDATE response_actions SET status='approved', approved_at=now(),
               signed_payload=%(sp)s, signature=%(sig)s, signing_pubkey=%(pub)s WHERE id=%(id)s""",
        {"sp": signed_payload, "sig": sig, "pub": pub, "id": action_id},
    )
    audit.append(action_id, "signed", "system", {"approvals": len(approvals), "pubkey": pub})
    return {"id": action_id, "status": "approved", "approvals": len(approvals), "signed": True}


@router.post("/actions/{action_id}/reject", summary="Reject an action")
async def reject(action_id: int, ap: Approval) -> dict:
    res = await db.execute(
        "UPDATE response_actions SET status='rejected', rejected_by=%(by)s "
        "WHERE id=%(id)s AND status='pending_approval' RETURNING id, status",
        {"by": ap.approver, "id": action_id},
    )
    if not res:
        raise HTTPException(409, "action not pending_approval")
    audit.append(action_id, "rejected", ap.approver, {"reason": ap.reason})
    return res


@router.get("/actions", summary="List response actions")
async def list_actions(status: str | None = None, agent_id: str | None = None) -> list[dict]:
    clauses, params = [], {}
    if status:
        clauses.append("status=%(s)s"); params["s"] = status
    if agent_id:
        clauses.append("agent_id=%(a)s"); params["a"] = agent_id
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return await db.fetch(
        f"SELECT id, incident_id, agent_id, action_type, params, status, requested_by, approvals, "
        f"created_at, dispatched_at, completed_at, result FROM response_actions {where} ORDER BY created_at DESC",
        params,
    )


# --------------------------------------------------- agent command channel ---
@router.get("/v1/agents/{agent_id}/commands", summary="Agent polls for signed commands")
async def poll_commands(agent_id: str, authorization: Annotated[str | None, Header()] = None) -> list[dict]:
    _require_agent(authorization)
    cmds = await db.fetch(
        "SELECT id, signed_payload, signature, signing_pubkey FROM response_actions "
        "WHERE agent_id=%(a)s AND status='approved' ORDER BY approved_at",
        {"a": agent_id},
    )
    for c in cmds:
        await db.execute(
            "UPDATE response_actions SET status='dispatched', dispatched_at=now() WHERE id=%(id)s",
            {"id": c["id"]},
        )
        audit.append(c["id"], "dispatched", f"agent:{agent_id}", {})
    return cmds


@router.post("/v1/commands/{action_id}/result", summary="Agent reports command result")
async def command_result(action_id: int, r: ResultIn,
                         authorization: Annotated[str | None, Header()] = None) -> dict:
    _require_agent(authorization)
    status = "completed" if r.status == "completed" else ("failed" if r.status == "failed" else "verify_failed")
    await db.execute(
        "UPDATE response_actions SET status=%(s)s, completed_at=now(), result=%(res)s WHERE id=%(id)s",
        {"s": status, "res": __import__("json").dumps({"status": r.status, "output": r.output}), "id": action_id},
    )
    audit.append(action_id, status, "agent", {"output": (r.output or "")[:500]})
    return {"id": action_id, "status": status}


@router.get("/response/audit/verify", summary="Verify the action audit hash-chain")
async def verify_audit() -> dict:
    return audit.verify()
