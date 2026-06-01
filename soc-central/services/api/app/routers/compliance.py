"""Compliance endpoints: results, per-asset score, and audit-chain verification.

The verify endpoint recomputes the hash chain in the API process and reports any
tampering — the auditor's "is this evidence trustworthy?" check.
"""
from __future__ import annotations

import hashlib
import json
from typing import Annotated

from fastapi import APIRouter, Query

from .. import db

router = APIRouter(prefix="/compliance", tags=["compliance"])

GENESIS = "0" * 64


def _canonical(record) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _record_hash(prev_hash: str, record) -> str:
    return hashlib.sha256((prev_hash + _canonical(record)).encode("utf-8")).hexdigest()


@router.get("/results", summary="Compliance results (filterable)")
async def results(
    asset_id: str | None = None,
    status: Annotated[str | None, Query(description="pass|fail|partial|not_applicable")] = None,
    benchmark: str | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[dict]:
    clauses, params = [], {}
    if asset_id:
        clauses.append("asset_id = %(asset_id)s"); params["asset_id"] = asset_id
    if status:
        clauses.append("status = %(status)s"); params["status"] = status
    if benchmark:
        clauses.append("benchmark ILIKE %(benchmark)s"); params["benchmark"] = f"%{benchmark}%"
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params["limit"] = limit
    return await db.fetch(
        f"""
        SELECT id, asset_id, rule_id, benchmark, title, severity, status, rationale,
               remediation, evidence, evidence_hash, evaluated_at
        FROM compliance_results {where}
        ORDER BY (status='fail') DESC, severity DESC, rule_id
        LIMIT %(limit)s
        """,
        params,
    )


@router.get("/summary", summary="Compliance posture rollup + per-asset score")
async def summary() -> dict:
    by_status = await db.fetch("SELECT status, count(*) AS count FROM compliance_results GROUP BY status ORDER BY 1")
    per_asset = await db.fetch(
        """
        SELECT asset_id,
               count(*) FILTER (WHERE status='pass')           AS pass,
               count(*) FILTER (WHERE status='fail')           AS fail,
               count(*) FILTER (WHERE status='partial')        AS partial,
               count(*) FILTER (WHERE status='not_applicable') AS not_applicable,
               round(100.0 * count(*) FILTER (WHERE status='pass')
                     / NULLIF(count(*) FILTER (WHERE status IN ('pass','fail','partial')), 0), 1) AS score_pct
        FROM compliance_results GROUP BY asset_id ORDER BY score_pct NULLS LAST
        """
    )
    return {"by_status": by_status, "per_asset": per_asset}


@router.get("/evidence/verify", summary="Verify the hash-chained evidence log")
async def verify() -> dict:
    rows = await db.fetch("SELECT seq, record, prev_hash, hash FROM compliance_evidence ORDER BY seq")
    expected_prev = GENESIS
    for r in rows:
        if r["prev_hash"] != expected_prev:
            return {"ok": False, "length": len(rows), "broken_at": r["seq"],
                    "reason": "prev_hash mismatch"}
        if _record_hash(expected_prev, r["record"]) != r["hash"]:
            return {"ok": False, "length": len(rows), "broken_at": r["seq"],
                    "reason": "record tampered (hash mismatch)"}
        expected_prev = r["hash"]
    return {"ok": True, "length": len(rows), "head_hash": expected_prev}


@router.get("/evidence", summary="Recent evidence records (audit log tail)")
async def evidence(limit: Annotated[int, Query(ge=1, le=500)] = 20) -> list[dict]:
    return await db.fetch(
        "SELECT seq, run_id, asset_id, rule_id, prev_hash, hash, created_at "
        "FROM compliance_evidence ORDER BY seq DESC LIMIT %(limit)s",
        {"limit": limit},
    )
