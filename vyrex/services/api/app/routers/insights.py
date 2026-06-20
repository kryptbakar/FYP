"""Surfaces backend intelligence the console previously could not reach.

These are read-only endpoints over data the platform already produces but did not
expose: a near-real-time detections feed, full-text log search over the OpenSearch
telemetry index, the human-readable response-action audit timeline (the hash-chained
lifecycle, not just a verify boolean), and the multi-tool fusion clusters.

Design rule (matches app/db.py): a query against a store/table that does not exist yet
returns empty rather than 500, so every view degrades gracefully on a cold stack.
"""
from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from typing import Annotated

from fastapi import APIRouter, Query

from .. import db
from ..config import settings

router = APIRouter(tags=["insights"])


# ----------------------------------------------------------- detections feed ---
@router.get("/detections/recent", summary="Most recent findings (near-real-time feed)")
async def recent_detections(limit: Annotated[int, Query(ge=1, le=200)] = 30) -> list[dict]:
    """Newest scored findings, most-recent first. Backs the live detections ticker;
    the console polls this on a short interval (the platform is batch-enriched, so this
    is near-real-time, not a websocket — labelled as such in the UI)."""
    return await db.fetch(
        """
        SELECT id, asset_id, domain, title, severity, cve_id, source_tool,
               risk_score, kev, attack, threat_intel, consensus,
               COALESCE(last_seen, first_seen) AS observed_at
        FROM findings
        WHERE risk_score IS NOT NULL
        ORDER BY COALESCE(last_seen, first_seen) DESC NULLS LAST, id DESC
        LIMIT %(limit)s
        """,
        {"limit": limit},
    )


# ----------------------------------------------------------------- log search ---
def _os_search(query: str, kind: str | None, minutes: int, size: int) -> dict:
    must: list[dict] = []
    if query:
        must.append({"query_string": {"query": query, "default_field": "*"}})
    if kind:
        must.append({"term": {"kind": kind}})
    body = {
        "size": size,
        "sort": [{"ingested_at": {"order": "desc"}}],
        "query": {"bool": {
            "must": must or [{"match_all": {}}],
            "filter": [{"range": {"ingested_at": {"gte": f"now-{minutes}m"}}}],
        }},
    }
    url = f"{settings.opensearch_url}/telemetry-v1/_search"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 (internal, air-gapped)
        return json.loads(resp.read().decode())


@router.get("/logs/search", summary="Full-text search over raw telemetry (OpenSearch)")
async def logs_search(
    q: Annotated[str, Query(description="Lucene query string; blank = match all")] = "",
    kind: Annotated[str | None, Query(description="telemetry kind, e.g. ids_alert")] = None,
    minutes: Annotated[int, Query(ge=1, le=43200)] = 1440,
    size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict:
    """Search the unified telemetry index. Returns normalised hits (host, kind, time,
    payload). Unreachable / missing index degrades to an empty result set."""
    try:
        raw = await asyncio.to_thread(_os_search, q, kind, minutes, size)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return {"total": 0, "hits": [], "available": False}
    hits_raw = (raw.get("hits") or {}).get("hits") or []
    total = ((raw.get("hits") or {}).get("total") or {}).get("value", len(hits_raw))
    hits = []
    for h in hits_raw:
        src = h.get("_source") or {}
        host = src.get("host") or {}
        hits.append({
            "id": h.get("_id"),
            "kind": src.get("kind"),
            "agent_id": src.get("agent_id"),
            "hostname": host.get("hostname") or host.get("host_id"),
            "ingested_at": src.get("ingested_at"),
            "collected_at": src.get("collected_at"),
            "payload": src.get("payload") or {},
        })
    return {"total": total, "hits": hits, "available": True}


# -------------------------------------------------------- response-action audit ---
@router.get("/response/actions/{action_id}/audit", summary="Hash-chained lifecycle for one action")
async def action_audit(action_id: int) -> list[dict]:
    """The full, human-readable signed lifecycle of a containment action
    (requested -> approved -> signed -> dispatched -> completed), straight from the
    tamper-evident chain."""
    return await db.fetch(
        "SELECT seq, action_id, event, actor, record, prev_hash, hash, created_at "
        "FROM action_audit WHERE action_id = %(id)s ORDER BY seq",
        {"id": action_id},
    )


@router.get("/response/audit/events", summary="Recent response-action audit events (all actions)")
async def audit_events(limit: Annotated[int, Query(ge=1, le=200)] = 40) -> list[dict]:
    """Tail of the global action-audit chain for the Trust Center timeline."""
    return await db.fetch(
        "SELECT seq, action_id, event, actor, record, hash, created_at "
        "FROM action_audit ORDER BY seq DESC LIMIT %(limit)s",
        {"limit": limit},
    )


# --------------------------------------------------------------- fusion clusters ---
@router.get("/fusion/clusters", summary="Multi-tool fusion clusters (>=2 corroborating tools)")
async def clusters(limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict]:
    """Findings that independent tools agreed on, grouped by dedup_key. This is the
    consensus signal made browsable: which issues multiple tools corroborate."""
    return await db.fetch(
        """
        SELECT dedup_key,
               count(DISTINCT source_tool) AS n_tools,
               array_agg(DISTINCT source_tool) AS tools,
               max(risk_score) AS top_risk_score,
               max(severity) AS severity,
               (array_agg(id ORDER BY risk_score DESC NULLS LAST))[1] AS primary_id,
               (array_agg(title ORDER BY risk_score DESC NULLS LAST))[1] AS title,
               (array_agg(asset_id ORDER BY risk_score DESC NULLS LAST))[1] AS asset_id
        FROM findings
        WHERE dedup_key IS NOT NULL AND risk_score IS NOT NULL
        GROUP BY dedup_key
        HAVING count(DISTINCT source_tool) >= 2
        ORDER BY top_risk_score DESC NULLS LAST
        LIMIT %(limit)s
        """,
        {"limit": limit},
    )


# ------------------------------------------------------------ feedback stats ---
@router.get("/analysts/feedback-stats", summary="Analyst feedback volume & label impact")
async def feedback_stats() -> dict:
    """Closes the loop visibly: how much feedback analysts have given, by action and by
    analyst, plus the model versions it has been folded into."""
    by_action = await db.fetch(
        "SELECT action, count(*) AS n FROM analyst_feedback GROUP BY action ORDER BY n DESC"
    )
    by_analyst = await db.fetch(
        "SELECT analyst, count(*) AS n FROM analyst_feedback GROUP BY analyst ORDER BY n DESC LIMIT 20"
    )
    total = await db.fetch_one("SELECT count(*) AS n FROM analyst_feedback")
    models = await db.fetch(
        "SELECT DISTINCT model_version FROM finding_explanations "
        "WHERE model_version IS NOT NULL ORDER BY model_version DESC LIMIT 5"
    )
    return {
        "total": (total or {}).get("n", 0),
        "by_action": by_action,
        "by_analyst": by_analyst,
        "incorporated_in_models": [m["model_version"] for m in models],
    }


# --------------------------------------------------------- detections catalog ---
@router.get("/detections", summary="Detection catalog — sources & rules with hit counts")
async def detections() -> list[dict]:
    """Read-only inventory of what is detecting: each source tool / rule and how many
    findings it has produced. The seed of a detections-as-content surface."""
    return await db.fetch(
        """
        SELECT COALESCE(source_tool, 'agent') AS source_tool,
               domain,
               count(*) AS hits,
               count(*) FILTER (WHERE kev) AS kev_hits,
               max(risk_score) AS top_risk_score
        FROM findings
        GROUP BY COALESCE(source_tool, 'agent'), domain
        ORDER BY hits DESC
        """
    )
