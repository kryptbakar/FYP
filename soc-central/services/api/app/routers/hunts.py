"""Live hunting across the fleet (Velociraptor pattern).

An analyst defines a *read-only* artifact to collect (running processes, listening ports, a
file search, or an osquery query); agents poll for hunts addressed to them, collect rows, and
return them. This is collection-only — it never runs a destructive action — so unlike the
active-response channel it needs no two-person approval, but it is still agent-token
authenticated. The whole server side (define -> dispatch -> collect -> view) runs without any
endpoint; a real endpoint just fills in richer rows.
"""
from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import db
from ..config import settings

router = APIRouter(tags=["hunt"])

ARTIFACTS = {"processes", "listening_ports", "file_search", "osquery"}


def _require_agent(authorization: str | None) -> None:
    token = settings.ingest_agent_token
    if token and authorization != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="invalid agent token")


class HuntIn(BaseModel):
    name: str
    artifact: str
    query: str | None = None
    target: str = "all"


@router.post("/hunts", summary="Define & queue a live hunt across the fleet")
async def create_hunt(h: HuntIn, x_analyst: Annotated[str | None, Header()] = None) -> dict:
    if h.artifact not in ARTIFACTS:
        raise HTTPException(400, f"unknown artifact; allowed: {sorted(ARTIFACTS)}")
    return await db.execute(
        "INSERT INTO hunts (name, artifact, query, target, created_by) "
        "VALUES (%(n)s,%(a)s,%(q)s,%(t)s,%(by)s) "
        "RETURNING id, name, artifact, query, target, status, created_at",
        {"n": h.name, "a": h.artifact, "q": h.query, "t": h.target, "by": x_analyst or "analyst"},
    ) or {}


@router.get("/hunts", summary="List hunts")
async def list_hunts() -> list[dict]:
    return await db.fetch(
        """SELECT h.id, h.name, h.artifact, h.query, h.target, h.status, h.created_by, h.created_at,
                  (SELECT count(*) FROM hunt_results r WHERE r.hunt_id = h.id) AS result_count
           FROM hunts h ORDER BY h.id DESC"""
    )


@router.get("/hunts/{hunt_id}", summary="Hunt detail + collected results")
async def get_hunt(hunt_id: int) -> dict:
    hunt = await db.fetch_one("SELECT * FROM hunts WHERE id=%(id)s", {"id": hunt_id})
    if not hunt:
        return {}
    hunt["results"] = await db.fetch(
        "SELECT id, agent_id, asset_id, rows, row_count, collected_at FROM hunt_results "
        "WHERE hunt_id=%(id)s ORDER BY collected_at DESC",
        {"id": hunt_id},
    )
    return hunt


# --------------------------------------------------------- agent hunt channel ---
@router.get("/v1/agents/{agent_id}/hunts", summary="Agent polls for queued hunts addressed to it")
async def poll_hunts(agent_id: str, authorization: Annotated[str | None, Header()] = None) -> list[dict]:
    _require_agent(authorization)
    hunts = await db.fetch(
        "SELECT id, artifact, query, target FROM hunts "
        "WHERE status IN ('queued','collecting') AND (target='all' OR target=%(a)s) ORDER BY id",
        {"a": agent_id},
    )
    for h in hunts:
        await db.execute("UPDATE hunts SET status='collecting' WHERE id=%(id)s AND status='queued'",
                         {"id": h["id"]})
    return hunts


class ResultIn(BaseModel):
    asset_id: str | None = None
    rows: list[dict] = []


@router.post("/v1/hunts/{hunt_id}/results", summary="Agent submits collected hunt rows")
async def submit_results(hunt_id: int, r: ResultIn, agent_id: Annotated[str | None, Header()] = None,
                         authorization: Annotated[str | None, Header()] = None) -> dict:
    _require_agent(authorization)
    row = await db.execute(
        "INSERT INTO hunt_results (hunt_id, agent_id, asset_id, rows, row_count) "
        "VALUES (%(h)s,%(ag)s,%(as)s,%(rows)s,%(n)s) RETURNING id",
        {"h": hunt_id, "ag": agent_id, "as": r.asset_id or agent_id,
         "rows": json.dumps(r.rows), "n": len(r.rows)},
    )
    await db.execute("UPDATE hunts SET status='completed' WHERE id=%(id)s", {"id": hunt_id})
    return {"result_id": (row or {}).get("id"), "hunt_id": hunt_id, "rows": len(r.rows)}
