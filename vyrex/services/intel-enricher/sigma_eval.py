"""Sigma evaluator — compile vendor-neutral Sigma rules to OpenSearch queries and run
them against the log store; hits become findings (source_tool=sigma).

Uses **pySigma** + the OpenSearch backend to compile each rule. If pySigma is unavailable
or a rule can't be converted, it falls back to the rule's `x_opensearch_query` field so
detection still runs (D-039). The mirrored SigmaHQ rule set loads from `rules/`.
"""
from __future__ import annotations

import logging
from pathlib import Path

import httpx
import yaml

import db

log = logging.getLogger("intel.sigma")
RULES_DIR = Path(__file__).parent / "rules"
_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}


def _compile(text: str):
    try:
        from sigma.backends.opensearch import OpensearchLuceneBackend
        from sigma.collection import SigmaCollection

        queries = OpensearchLuceneBackend().convert(SigmaCollection.from_yaml(text))
        return list(queries), "pysigma"
    except Exception as e:  # noqa: BLE001
        log.warning("pySigma compile unavailable (%s); using x_opensearch_query fallback", e)
        return None, "fallback"


def _technique(tags: list[str]) -> str | None:
    for t in tags or []:
        if t.lower().startswith("attack.t"):
            return t.split(".", 1)[1].upper()
    return None


def run(pg, os_url: str) -> int:
    created = 0
    for rf in sorted(RULES_DIR.glob("*.yml")):
        text = rf.read_text()
        meta = yaml.safe_load(text)
        queries, mode = _compile(text)
        if not queries:
            fb = meta.get("x_opensearch_query")
            if not fb:
                continue
            queries = [fb]
        level = (meta.get("level") or "medium").upper()
        sev = level if level in _LEVELS else "MEDIUM"
        sev = "INFO" if sev == "INFORMATIONAL" else sev
        tech = _technique(meta.get("tags", []))
        rid = f"sigma.{str(meta.get('id', rf.stem))[:8]}"

        for q in queries:
            body = {"size": 0, "query": {"query_string": {"query": q}},
                    "aggs": {"by_host": {"terms": {"field": "host.host_id", "size": 100}}}}
            r = httpx.post(f"{os_url}/telemetry-v1/_search", json=body, timeout=20)
            if r.status_code >= 300:
                log.warning("sigma query failed (%s): %s", q, r.text[:160])
                continue
            data = r.json()
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            buckets = data.get("aggregations", {}).get("by_host", {}).get("buckets", [])
            log.info("sigma '%s' (%s) -> %d hit(s) across %d host(s)", meta.get("title"), mode, total, len(buckets))
            for b in buckets:
                asset, cnt = b["key"], b["doc_count"]
                db.ensure_asset(pg, asset)
                db.upsert_finding(pg, {
                    "asset_id": asset, "domain": "network", "rule_id": rid,
                    "title": f"Sigma: {meta.get('title')}",
                    "description": meta.get("description"), "severity": sev,
                    "source_tool": "sigma", "raw_ref": str(meta.get("id")),
                    "dedup_key": db.fp(asset, "sigma", rid),
                    "fingerprint": db.fp("sigma", asset, "network", rid),
                    "attack": tech, "threat_intel": None,
                    "evidence": {"sigma_query": q, "mode": mode, "matches": cnt, "level": level},
                })
                created += 1
    log.info("sigma: %d detection finding(s)", created)
    return created
