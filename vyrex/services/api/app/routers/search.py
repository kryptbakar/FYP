"""Global search + entity pages.

A SOC platform lives or dies on "type anything, find everything, pivot to the entity." This
router gives the console a single search across findings / assets / CVEs / IOCs, and entity
endpoints that aggregate everything known about a CVE or an IP so an analyst can pivot from a
chip to a full context page.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from .. import db

router = APIRouter(tags=["search"])


@router.get("/search", summary="Global search across findings, assets, CVEs, IOCs")
async def search(q: Annotated[str, Query(min_length=1)],
                 limit: Annotated[int, Query(ge=1, le=50)] = 15) -> dict:
    like = f"%{q}%"
    findings = await db.fetch(
        """SELECT id, asset_id, title, severity, cve_id, source_tool, risk_score, kev
           FROM findings
           WHERE title ILIKE %(q)s OR cve_id ILIKE %(q)s OR asset_id ILIKE %(q)s
           ORDER BY risk_score DESC NULLS LAST LIMIT %(l)s""",
        {"q": like, "l": limit},
    )
    assets = await db.fetch(
        "SELECT host_id, hostname, os, ip, criticality FROM assets "
        "WHERE host_id ILIKE %(q)s OR hostname ILIKE %(q)s OR ip ILIKE %(q)s LIMIT %(l)s",
        {"q": like, "l": limit},
    )
    cves = await db.fetch(
        """SELECT cve_id, max(cvss_score) AS cvss_score, bool_or(kev) AS kev,
                  max(cwe) AS cwe, count(*) AS occurrences
           FROM findings WHERE cve_id ILIKE %(q)s
           GROUP BY cve_id ORDER BY cvss_score DESC NULLS LAST LIMIT %(l)s""",
        {"q": like, "l": limit},
    )
    iocs = await db.fetch(
        "SELECT DISTINCT indicator, type FROM ioc_sightings WHERE indicator ILIKE %(q)s LIMIT %(l)s",
        {"q": like, "l": limit},
    )
    return {"query": q, "findings": findings, "assets": assets, "cves": cves, "iocs": iocs,
            "total": len(findings) + len(assets) + len(cves) + len(iocs)}


@router.get("/entity/cve/{cve_id}", summary="Everything known about a CVE")
async def entity_cve(cve_id: str) -> dict:
    meta = await db.fetch_one(
        "SELECT cve_id, cvss_score, cvss_severity, cvss_vector, cwe, description, published, last_modified "
        "FROM nvd_cve WHERE cve_id = %(c)s",
        {"c": cve_id},
    )
    kev = await db.fetch_one("SELECT cve_id, due_date, known_ransomware FROM kev WHERE cve_id = %(c)s", {"c": cve_id})
    epss = await db.fetch_one("SELECT epss, percentile FROM epss WHERE cve_id = %(c)s", {"c": cve_id})
    exploits = await db.fetch(
        "SELECT source, ref, type, title FROM exploit_refs WHERE cve_id = %(c)s", {"c": cve_id})
    findings = await db.fetch(
        "SELECT id, asset_id, title, severity, source_tool, risk_score, COALESCE(triage_status,'open') AS triage_status "
        "FROM findings WHERE cve_id = %(c)s ORDER BY risk_score DESC NULLS LAST",
        {"c": cve_id},
    )
    return {"cve_id": cve_id, "meta": meta or {}, "kev": kev, "epss": epss,
            "exploits": exploits, "findings": findings,
            "affected_assets": sorted({f["asset_id"] for f in findings})}


@router.get("/entity/ip/{ip}", summary="Everything known about an IP / indicator")
async def entity_ip(ip: str) -> dict:
    sightings = await db.fetch(
        "SELECT id, type, finding_id, asset_id, source, seen_at FROM ioc_sightings "
        "WHERE indicator = %(i)s ORDER BY seen_at DESC",
        {"i": ip},
    )
    findings = await db.fetch(
        "SELECT id, asset_id, title, severity, source_tool, risk_score, attack, threat_intel "
        "FROM findings WHERE threat_intel->>'indicator' = %(i)s ORDER BY risk_score DESC NULLS LAST",
        {"i": ip},
    )
    return {"indicator": ip, "sightings": sightings, "findings": findings,
            "seen_on_assets": sorted({s["asset_id"] for s in sightings if s.get("asset_id")}
                                     | {f["asset_id"] for f in findings})}
