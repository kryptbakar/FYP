"""Risk ranking, per-finding XAI explanation, and analyst feedback capture.

These back the analyst console's "what should I fix first, and why?" view and the
feedback that drives model retraining (Phase 5 loop).
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel

from .. import db

router = APIRouter(tags=["risk"])


@router.get("/risk/ranking", summary="Findings ranked by composite risk")
async def ranking(limit: Annotated[int, Query(ge=1, le=500)] = 25) -> list[dict]:
    return await db.fetch(
        """
        SELECT risk_rank, id, asset_id, domain, title, severity, cve_id, source_tool,
               risk_score, ml_risk_score, kev, cvss_score, epss,
               attack, threat_intel, consensus
        FROM findings
        WHERE risk_score IS NOT NULL
        ORDER BY risk_score DESC
        LIMIT %(limit)s
        """,
        {"limit": limit},
    )


@router.get("/findings/{finding_id}/explain", summary="XAI: composite breakdown + SHAP waterfall + consensus")
async def explain(finding_id: int) -> dict:
    finding = await db.fetch_one(
        "SELECT id, title, domain, severity, risk_score, ml_risk_score, risk_components, model_version, "
        "source_tool, attack, threat_intel, consensus "
        "FROM findings WHERE id = %(id)s",
        {"id": finding_id},
    )
    if not finding:
        return {}
    explanation = await db.fetch_one(
        "SELECT ml_risk_score, base_value, shap, top_factors, counterfactuals, waterfall, model_version "
        "FROM finding_explanations WHERE finding_id = %(id)s",
        {"id": finding_id},
    )
    return {
        "finding": finding,
        "composite_components": finding.get("risk_components"),
        "consensus": finding.get("consensus"),
        "ml_explanation": explanation or {"note": "no ML explanation yet — run the risk-engine `train` then `score`"},
    }


class Feedback(BaseModel):
    analyst: str = "analyst"
    action: str            # accept | dismiss | escalate | deprioritize | relabel
    label_priority: float | None = None  # optional 0..100 training label
    comment: str | None = None


@router.post("/findings/{finding_id}/feedback", summary="Capture analyst feedback (feeds retraining)")
async def add_feedback(finding_id: int, fb: Feedback) -> dict:
    row = await db.execute(
        """
        INSERT INTO analyst_feedback (finding_id, analyst, action, label_priority, comment)
        VALUES (%(fid)s, %(analyst)s, %(action)s, %(label)s, %(comment)s)
        RETURNING id, finding_id, action, label_priority, created_at
        """,
        {"fid": finding_id, "analyst": fb.analyst, "action": fb.action,
         "label": fb.label_priority, "comment": fb.comment},
    )
    return row or {}


@router.get("/findings/{finding_id}/feedback", summary="List analyst feedback for a finding")
async def list_feedback(finding_id: int) -> list[dict]:
    return await db.fetch(
        "SELECT id, analyst, action, label_priority, comment, created_at "
        "FROM analyst_feedback WHERE finding_id = %(id)s ORDER BY created_at DESC",
        {"id": finding_id},
    )
