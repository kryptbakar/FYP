"""Detection-rules management — detections as manageable content (Sigma/Suricata/YARA/domain).

A read-only catalog isn't enough for a real platform: analysts author rules, enable/disable
them, tune severity, and watch hit counts. This is the detections-as-content surface every
SIEM/EDR ships.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import db

router = APIRouter(tags=["detections"])

SOURCES = {"sigma", "suricata", "yara", "domain"}


class RuleIn(BaseModel):
    name: str
    source: str = "sigma"
    technique: str | None = None
    severity: str = "medium"
    logic: str | None = None


class RulePatch(BaseModel):
    enabled: bool | None = None
    severity: str | None = None
    logic: str | None = None


@router.get("/detection-rules", summary="List detection rules")
async def list_rules() -> list[dict]:
    return await db.fetch(
        "SELECT id, name, source, technique, severity, logic, enabled, hits, created_by, created_at "
        "FROM detection_rules ORDER BY enabled DESC, hits DESC, id")


@router.get("/detection-rules/stats", summary="Detection rule rollup")
async def rule_stats() -> dict:
    total = await db.fetch_one("SELECT count(*) AS n, count(*) FILTER (WHERE enabled) AS enabled, "
                               "coalesce(sum(hits),0) AS hits FROM detection_rules")
    by_source = await db.fetch("SELECT source, count(*) AS n FROM detection_rules GROUP BY source ORDER BY n DESC")
    return {**(total or {}), "by_source": by_source}


@router.post("/detection-rules", summary="Author a detection rule")
async def create_rule(r: RuleIn, x_analyst: Annotated[str | None, Header()] = None) -> dict:
    if r.source not in SOURCES:
        raise HTTPException(400, f"unknown source; allowed: {sorted(SOURCES)}")
    return await db.execute(
        "INSERT INTO detection_rules (name, source, technique, severity, logic, created_by) "
        "VALUES (%(n)s,%(s)s,%(t)s,%(sev)s,%(l)s,%(by)s) "
        "ON CONFLICT (name) DO NOTHING RETURNING id, name, source, technique, severity, enabled",
        {"n": r.name, "s": r.source, "t": r.technique, "sev": r.severity, "l": r.logic, "by": x_analyst or "analyst"},
    ) or {"error": "a rule with that name already exists"}


@router.patch("/detection-rules/{rule_id}", summary="Enable / disable / tune a rule")
async def patch_rule(rule_id: int, p: RulePatch) -> dict:
    sets, params = [], {"id": rule_id}
    if p.enabled is not None:
        sets.append("enabled=%(e)s"); params["e"] = p.enabled
    if p.severity is not None:
        sets.append("severity=%(sev)s"); params["sev"] = p.severity
    if p.logic is not None:
        sets.append("logic=%(l)s"); params["l"] = p.logic
    if not sets:
        raise HTTPException(400, "nothing to update")
    row = await db.execute(
        f"UPDATE detection_rules SET {', '.join(sets)} WHERE id=%(id)s RETURNING id, name, enabled, severity",
        params)
    if not row:
        raise HTTPException(404, "rule not found")
    return row
