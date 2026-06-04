"""Threat intelligence — attribution + a knowledge graph (OpenCTI pattern) and sightings (MISP).

OpenCTI's value is the *graph*: an indicator links to malware, which links to a threat actor
and the ATT&CK techniques they use. We don't ship a STIX database, but we can assemble the
same relationship chain for a finding from its own enrichment plus a small, air-gap-local
knowledge base — turning a flat "live IOC" flag into "who, what, and how".
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel

from .. import db

router = APIRouter(tags=["intel"])

# Small local knowledge base (air-gap clean). Maps an indicator or ATT&CK technique to the
# malware/actor/campaign it is associated with. In a full deployment this is sourced from a
# mirrored OpenCTI/MISP export; here it is a curated reference set.
INDICATOR_KB: dict[str, dict] = {
    "185.220.101.45": {"malware": "Cobalt Strike", "actor": "TA-Phoenix", "campaign": "Operation Duskfall"},
}
MALWARE_KB: dict[str, dict] = {
    "Cobalt Strike": {"actor": "TA-Phoenix", "type": "C2 framework",
                      "techniques": ["T1071.001", "T1059"]},
    "Log4Shell": {"actor": "opportunistic", "type": "exploit", "techniques": ["T1190"]},
}
TECHNIQUE_MALWARE = {"T1071.001": "Cobalt Strike", "T1071": "Cobalt Strike", "T1190": "Log4Shell"}


def _attribute(finding: dict) -> dict:
    """Best-effort attribution for a finding from its IOC / technique."""
    ti = finding.get("threat_intel") or {}
    ind = ti.get("indicator") if isinstance(ti, dict) else None
    attack = finding.get("attack")
    malware = actor = campaign = None
    if ind and ind in INDICATOR_KB:
        kb = INDICATOR_KB[ind]; malware, actor, campaign = kb.get("malware"), kb.get("actor"), kb.get("campaign")
    if not malware and attack:
        malware = TECHNIQUE_MALWARE.get(attack) or TECHNIQUE_MALWARE.get(str(attack).split(".")[0])
    if malware and not actor:
        actor = (MALWARE_KB.get(malware) or {}).get("actor")
    return {"indicator": ind, "malware": malware, "actor": actor, "campaign": campaign,
            "technique": attack, "confidence": ti.get("confidence") if isinstance(ti, dict) else None}


@router.get("/findings/{finding_id}/intel-graph", summary="Knowledge graph for a finding (entities + relations)")
async def intel_graph(finding_id: int) -> dict:
    f = await db.fetch_one(
        "SELECT id, asset_id, title, cve_id, attack, threat_intel FROM findings WHERE id=%(id)s",
        {"id": finding_id},
    )
    if not f:
        return {"nodes": [], "edges": []}
    a = _attribute(f)
    nodes, edges = [], []

    def node(nid, label, typ):
        if not any(n["id"] == nid for n in nodes):
            nodes.append({"id": nid, "label": label, "type": typ})

    node(f"asset:{f['asset_id']}", f["asset_id"], "asset")
    node(f"finding:{f['id']}", f"finding #{f['id']}", "finding")
    edges.append({"from": f"finding:{f['id']}", "to": f"asset:{f['asset_id']}", "label": "affects"})
    if f.get("cve_id"):
        node(f"cve:{f['cve_id']}", f["cve_id"], "cve")
        edges.append({"from": f"finding:{f['id']}", "to": f"cve:{f['cve_id']}", "label": "is"})
    if a["technique"]:
        node(f"ttp:{a['technique']}", a["technique"], "technique")
        edges.append({"from": f"finding:{f['id']}", "to": f"ttp:{a['technique']}", "label": "maps to"})
    if a["indicator"]:
        node(f"ioc:{a['indicator']}", a["indicator"], "indicator")
        edges.append({"from": f"finding:{f['id']}", "to": f"ioc:{a['indicator']}", "label": "observed"})
    if a["malware"]:
        node(f"mal:{a['malware']}", a["malware"], "malware")
        src = f"ioc:{a['indicator']}" if a["indicator"] else f"ttp:{a['technique']}" if a["technique"] else f"finding:{f['id']}"
        edges.append({"from": src, "to": f"mal:{a['malware']}", "label": "indicates"})
    if a["actor"]:
        node(f"actor:{a['actor']}", a["actor"], "actor")
        if a["malware"]:
            edges.append({"from": f"mal:{a['malware']}", "to": f"actor:{a['actor']}", "label": "used by"})
    if a["campaign"]:
        node(f"camp:{a['campaign']}", a["campaign"], "campaign")
        if a["actor"]:
            edges.append({"from": f"actor:{a['actor']}", "to": f"camp:{a['campaign']}", "label": "part of"})
    return {"attribution": a, "nodes": nodes, "edges": edges}


@router.get("/intel/attribution", summary="Attribution rollup across active findings")
async def attribution_rollup(limit: Annotated[int, Query(ge=1, le=500)] = 200) -> dict:
    rows = await db.fetch(
        "SELECT id, attack, threat_intel FROM findings WHERE threat_intel IS NOT NULL "
        "OR attack IS NOT NULL ORDER BY risk_score DESC NULLS LAST LIMIT %(l)s", {"l": limit})
    actors: dict[str, int] = {}
    malware: dict[str, int] = {}
    for r in rows:
        a = _attribute(r)
        if a["actor"]:
            actors[a["actor"]] = actors.get(a["actor"], 0) + 1
        if a["malware"]:
            malware[a["malware"]] = malware.get(a["malware"], 0) + 1
    return {"actors": [{"name": k, "findings": v} for k, v in sorted(actors.items(), key=lambda x: -x[1])],
            "malware": [{"name": k, "findings": v} for k, v in sorted(malware.items(), key=lambda x: -x[1])]}


# --------------------------------------------------------------- sightings ----
class SightingIn(BaseModel):
    indicator: str
    type: str | None = None
    finding_id: int | None = None
    asset_id: str | None = None
    source: str | None = None


@router.get("/intel/sightings", summary="Recent IOC sightings")
async def sightings(limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict]:
    return await db.fetch(
        "SELECT id, indicator, type, finding_id, asset_id, source, seen_at "
        "FROM ioc_sightings ORDER BY seen_at DESC LIMIT %(l)s", {"l": limit})


@router.post("/intel/sightings", summary="Record an IOC sighting")
async def add_sighting(s: SightingIn) -> dict:
    return await db.execute(
        "INSERT INTO ioc_sightings (indicator, type, finding_id, asset_id, source) "
        "VALUES (%(i)s,%(t)s,%(f)s,%(a)s,%(s)s) RETURNING id, indicator, seen_at",
        {"i": s.indicator, "t": s.type, "f": s.finding_id, "a": s.asset_id, "s": s.source or "analyst"},
    ) or {}
