"""Read endpoints over the assessment output (assets, findings, summary).

These back the analyst console (Phase 7) and let us inspect Phase 3 output now.
Read-only; mutations (triage, status changes) arrive with incident management.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from .. import db

router = APIRouter(tags=["assessment"])


@router.get("/assets", summary="List monitored assets")
async def list_assets() -> list[dict]:
    return await db.fetch(
        "SELECT host_id, hostname, os, ip, criticality, first_seen, last_seen "
        "FROM assets ORDER BY last_seen DESC NULLS LAST"
    )


@router.get("/assets/{host_id}", summary="Asset detail + its findings & compliance rollup")
async def get_asset(host_id: str) -> dict:
    """The host hub: asset metadata plus a rollup of its findings (by severity) and
    compliance posture, so the console can render a single host page."""
    asset = await db.fetch_one(
        "SELECT host_id, hostname, os, ip, criticality, first_seen, last_seen "
        "FROM assets WHERE host_id = %(id)s",
        {"id": host_id},
    )
    if not asset:
        return {}
    findings = await db.fetch(
        "SELECT id, domain, title, severity, cve_id, source_tool, risk_score, kev, attack "
        "FROM findings WHERE asset_id = %(id)s ORDER BY risk_score DESC NULLS LAST LIMIT 100",
        {"id": host_id},
    )
    compliance = await db.fetch(
        "SELECT rule_id, benchmark, title, status FROM compliance_results "
        "WHERE asset_id = %(id)s ORDER BY (status='fail') DESC, rule_id LIMIT 100",
        {"id": host_id},
    )
    return {"asset": asset, "findings": findings, "compliance": compliance}


class AssetPatch(BaseModel):
    criticality: float = Field(ge=0.0, le=1.0)


@router.patch("/assets/{host_id}", summary="Update asset business criticality (drives risk scoring)")
async def patch_asset(host_id: str, body: AssetPatch) -> dict:
    """Lets the customer tune the platform to their business: criticality feeds the
    composite risk score (the next scoring run picks it up)."""
    row = await db.execute(
        "UPDATE assets SET criticality = %(c)s WHERE host_id = %(id)s "
        "RETURNING host_id, hostname, criticality",
        {"c": body.criticality, "id": host_id},
    )
    return row or {}


@router.get("/findings", summary="List findings (filterable)")
async def list_findings(
    domain: Annotated[str | None, Query(description="application|system|network")] = None,
    severity: str | None = None,
    asset_id: str | None = None,
    cve: Annotated[str | None, Query(description="filter by CVE id")] = None,
    kev: Annotated[bool | None, Query(description="only KEV-listed findings")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict]:
    clauses, params = [], {}
    if domain:
        clauses.append("domain = %(domain)s"); params["domain"] = domain
    if severity:
        clauses.append("upper(severity) = upper(%(severity)s)"); params["severity"] = severity
    if asset_id:
        clauses.append("asset_id = %(asset_id)s"); params["asset_id"] = asset_id
    if cve:
        clauses.append("cve_id = %(cve)s"); params["cve"] = cve
    if kev is not None:
        clauses.append("kev = %(kev)s"); params["kev"] = kev
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params["limit"], params["offset"] = limit, offset
    return await db.fetch(
        f"""
        SELECT id, asset_id, domain, rule_id, title, severity, cve_id, source_tool, package_name,
               package_version, port, proto, cvss_score, cvss_severity, epss, epss_percentile,
               kev, kev_due_date, risk_score, ml_risk_score, risk_rank, status, first_seen, last_seen
        FROM findings {where}
        ORDER BY risk_score DESC NULLS LAST, (cvss_score IS NULL), cvss_score DESC
        LIMIT %(limit)s OFFSET %(offset)s
        """,
        params,
    )


@router.get("/findings/{finding_id}", summary="Finding detail (with evidence)")
async def get_finding(finding_id: int) -> dict:
    row = await db.fetch_one(
        "SELECT * FROM findings WHERE id = %(id)s", {"id": finding_id}
    )
    return row or {}


@router.get("/stats/summary", summary="Findings rollup for dashboards")
async def stats_summary() -> dict:
    by_domain = await db.fetch(
        "SELECT domain, severity, count(*) AS count FROM findings GROUP BY domain, severity ORDER BY 1,2"
    )
    kev = await db.fetch("SELECT count(*) AS count FROM findings WHERE kev")
    assets = await db.fetch("SELECT count(*) AS count FROM assets")
    top_cves = await db.fetch(
        """
        SELECT cve_id, max(cvss_score) AS cvss, max(epss) AS epss, bool_or(kev) AS kev,
               count(*) AS occurrences
        FROM findings WHERE cve_id IS NOT NULL
        GROUP BY cve_id ORDER BY cvss DESC NULLS LAST LIMIT 10
        """
    )
    return {
        "assets": (assets[0]["count"] if assets else 0),
        "kev_findings": (kev[0]["count"] if kev else 0),
        "by_domain_severity": by_domain,
        "top_cves": top_cves,
    }
