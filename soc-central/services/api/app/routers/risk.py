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
async def ranking(
    limit: Annotated[int, Query(ge=1, le=500)] = 25,
    include_closed: Annotated[bool, Query(description="include triaged-away findings")] = False,
) -> list[dict]:
    # exploit_available: a derived 'a working exploit exists' signal (KEV = exploited in the
    # wild; a Nuclei detection means a weaponised template fired). A full Exploit-DB mirror is
    # the richer follow-on, but this surfaces the signal the references emphasise today.
    closed = "" if include_closed else (
        "AND COALESCE(triage_status,'open') NOT IN "
        "('false_positive','risk_accepted','mitigated','resolved')"
    )
    return await db.fetch(
        f"""
        SELECT risk_rank, id, asset_id, domain, title, severity, cve_id, source_tool,
               risk_score, ml_risk_score, kev, cvss_score, epss,
               attack, threat_intel, consensus,
               COALESCE(triage_status,'open') AS triage_status,
               COALESCE(exploit_available, kev OR source_tool = 'nuclei') AS exploit_available,
               cwe, COALESCE(cvss_predicted, false) AS cvss_predicted
        FROM findings
        WHERE risk_score IS NOT NULL {closed}
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


# The composite weights are the *primary, defensible* signal (ml/scoring.py). They sum to 1.0.
# The ML layer is a feedback-adaptive re-ranker over these same factors — surfaced here, with
# its training provenance and limitations stated openly, so the model is a glass box not a
# black box (see the Model view in the console).
COMPOSITE_WEIGHTS = {
    "cvss": 0.18, "epss": 0.16, "kev": 0.15, "exposure": 0.12, "threat_intel": 0.10,
    "consensus": 0.09, "attack_ctx": 0.07, "compliance_impact": 0.05, "age": 0.04, "criticality": 0.04,
}


@router.get("/risk/model/metadata", summary="Model card: version, scope, training provenance, limitations")
async def model_metadata() -> dict:
    """Transparency endpoint for the risk model. Reports the version actually in use,
    the volume of findings scored and analyst labels captured, the composite weights
    (the primary signal), and an explicit statement of how the ML layer is trained and
    where its current limitations lie. Everything is derived from the live DB."""
    ver = await db.fetch_one(
        "SELECT model_version FROM finding_explanations WHERE model_version IS NOT NULL "
        "ORDER BY created_at DESC NULLS LAST LIMIT 1"
    )
    scored = await db.fetch_one("SELECT count(*) AS n FROM findings WHERE ml_risk_score IS NOT NULL")
    composite = await db.fetch_one("SELECT count(*) AS n FROM findings WHERE risk_score IS NOT NULL")
    fb = await db.fetch_one("SELECT count(*) AS n FROM analyst_feedback")
    fb_actions = await db.fetch(
        "SELECT action, count(*) AS n FROM analyst_feedback GROUP BY action ORDER BY n DESC"
    )
    n_feedback = (fb or {}).get("n", 0)
    return {
        "model_version": (ver or {}).get("model_version") or "untrained",
        "algorithm": "XGBoost regressor (gradient-boosted trees)",
        "explainer": "TreeSHAP (exact per-feature attribution) + counterfactuals",
        "primary_signal": "composite weighted score (sums to 1.0)",
        "composite_weights": COMPOSITE_WEIGHTS,
        "features": list(COMPOSITE_WEIGHTS.keys()) + ["attack_phase"],
        "scope": {
            "findings_scored_by_ml": (scored or {}).get("n", 0),
            "findings_scored_by_composite": (composite or {}).get("n", 0),
            "analyst_labels_captured": n_feedback,
            "feedback_by_action": fb_actions,
        },
        "training": {
            "label_source": "composite priority score, plus analyst feedback weighted 5x",
            "bootstrap": "synthetic dataset until field labels accumulate",
            "retrain_cadence": "monthly (CronJob) and on demand",
        },
        "limitations": [
            "Bootstrapped on synthetic data, so until enough analyst labels and real outcomes "
            "accumulate the ML score largely reproduces the composite formula — it is a "
            "re-ranker, not an independent oracle.",
            "Real-outcome labels (exploited / patched / dismissed) are the path to the model "
            "learning signal the formula does not already encode.",
        ],
        "honest_status": (
            "feedback-adaptive re-ranker"
            if n_feedback > 0 else
            "tracking the composite score (no analyst labels yet)"
        ),
    }
