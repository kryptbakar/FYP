"""Reports Center — generate, store, and retrieve posture / compliance / executive reports.

Regulated and enterprise buyers expect to pull (and schedule) signed, exportable reports for
their own auditors. Each report is computed from the live data and stored as a self-contained
jsonb snapshot, so it's reproducible and exportable (the console adds PDF/CSV on top).
"""
from __future__ import annotations

import json
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import db

router = APIRouter(tags=["reports"])

REPORT_TYPES = {"posture", "compliance", "executive"}


def _jsonable(o):
    """DB numerics come back as Decimal and dates as date/datetime — make them JSON-safe."""
    if isinstance(o, Decimal):
        return float(o)
    if isinstance(o, (date, datetime)):
        return o.isoformat()
    return str(o)


async def _band_counts() -> dict:
    rows = await db.fetch(
        """SELECT CASE WHEN risk_score>=80 THEN 'critical' WHEN risk_score>=60 THEN 'high'
                       WHEN risk_score>=40 THEN 'medium' WHEN risk_score>=20 THEN 'low' ELSE 'info' END AS band,
                  count(*) AS n
           FROM findings WHERE risk_score IS NOT NULL GROUP BY 1"""
    )
    return {r["band"]: r["n"] for r in rows}


async def _posture_content() -> dict:
    assets = await db.fetch_one("SELECT count(*) AS n FROM assets")
    fcount = await db.fetch_one("SELECT count(*) AS n FROM findings WHERE risk_score IS NOT NULL")
    kev = await db.fetch_one("SELECT count(*) AS n FROM findings WHERE kev")
    expl = await db.fetch_one("SELECT count(*) AS n FROM findings WHERE COALESCE(exploit_available,false)")
    avg = await db.fetch_one("SELECT round(avg(risk_score),1) AS v FROM findings WHERE risk_score IS NOT NULL")
    bands = await _band_counts()
    top = await db.fetch(
        "SELECT risk_rank, title, asset_id, cve_id, severity, round(risk_score,1) AS risk, kev "
        "FROM findings WHERE risk_score IS NOT NULL ORDER BY risk_score DESC LIMIT 15")
    by_tool = await db.fetch(
        "SELECT COALESCE(source_tool,'agent') AS tool, count(*) AS n FROM findings GROUP BY 1 ORDER BY 2 DESC")
    return {
        "kpis": {"assets": (assets or {}).get("n", 0), "open_findings": (fcount or {}).get("n", 0),
                 "kev": (kev or {}).get("n", 0), "exploit_available": (expl or {}).get("n", 0),
                 "critical": bands.get("critical", 0), "high": bands.get("high", 0),
                 "avg_risk": float((avg or {}).get("v") or 0)},
        "risk_bands": bands, "top_risks": top, "by_tool": by_tool,
    }


async def _compliance_content() -> dict:
    by_status = await db.fetch("SELECT status, count(*) AS n FROM compliance_results GROUP BY status")
    bs = {r["status"]: r["n"] for r in by_status}
    graded = (bs.get("pass", 0) + bs.get("fail", 0) + bs.get("partial", 0)) or 1
    failing = await db.fetch(
        "SELECT rule_id, benchmark, title, asset_id FROM compliance_results WHERE status='fail' "
        "ORDER BY asset_id, rule_id LIMIT 100")
    from .. import audit  # reuse the hash-chain verifier
    try:
        chain = audit.verify()
    except Exception:
        chain = {"ok": None}
    return {"summary": {**bs, "score_pct": round(bs.get("pass", 0) / graded * 100, 1)},
            "failing_controls": failing, "evidence_chain": chain}


async def _executive_content() -> dict:
    posture = await _posture_content()
    incidents = await db.fetch("SELECT status, sla_due FROM incidents")
    open_inc = sum(1 for i in incidents if (i.get("status") or "") not in ("resolved", "closed"))
    breaches = sum(1 for i in incidents
                   if (i.get("status") or "") not in ("resolved", "closed")
                   and i.get("sla_due") and i["sla_due"] < datetime.now(timezone.utc))
    comp = await _compliance_content()
    k = posture["kpis"]
    posture_score = max(0, 100 - k["critical"] * 8 - k["high"] * 2)
    return {"posture_score": posture_score, "open_incidents": open_inc, "sla_breaches": breaches,
            "kpis": k, "top_risks": posture["top_risks"][:5],
            "compliance_score": comp["summary"]["score_pct"]}


class ReportIn(BaseModel):
    type: str


@router.post("/reports", summary="Generate a report (posture | compliance | executive)")
async def generate(r: ReportIn, x_analyst: Annotated[str | None, Header()] = None) -> dict:
    if r.type not in REPORT_TYPES:
        raise HTTPException(400, f"unknown type; allowed: {sorted(REPORT_TYPES)}")
    content = (await _posture_content() if r.type == "posture"
               else await _compliance_content() if r.type == "compliance"
               else await _executive_content())
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = {"posture": "Security Posture Report", "compliance": "Compliance Report",
             "executive": "Executive Summary"}[r.type] + f" — {stamp}"
    row = await db.execute(
        "INSERT INTO reports (type, title, content, generated_by) VALUES (%(t)s,%(ti)s,%(c)s,%(by)s) "
        "RETURNING id, type, title, created_at",
        {"t": r.type, "ti": title, "c": json.dumps(content, default=_jsonable), "by": x_analyst or "analyst"},
    )
    return {**(row or {}), "content": content}


@router.get("/reports", summary="List generated reports")
async def list_reports(limit: int = 50) -> list[dict]:
    return await db.fetch(
        "SELECT id, type, title, generated_by, created_at FROM reports ORDER BY id DESC LIMIT %(l)s",
        {"l": limit})


@router.get("/reports/{report_id}", summary="Get a report's content")
async def get_report(report_id: int) -> dict:
    return await db.fetch_one("SELECT id, type, title, content, generated_by, created_at FROM reports WHERE id=%(id)s",
                              {"id": report_id}) or {}
