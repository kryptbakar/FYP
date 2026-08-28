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
            # Sub-aggregate the PEER the rule matched, not just the host. Previously we
            # recorded only host + the query string, so a Sigma hit could never be tied
            # to the connection it fired on - and therefore could never cluster with the
            # MISP IOC hit or the agent rule about that same connection.
            # payload.remote_ip is `text` with a .keyword subfield; remote_port is `long`.
            body = {"size": 0, "query": {"query_string": {"query": q}},
                    "aggs": {"by_host": {
                        "terms": {"field": "host.host_id", "size": 100},
                        "aggs": {"by_peer": {
                            "terms": {"field": "payload.remote_ip.keyword", "size": 10},
                            "aggs": {"by_port": {
                                "terms": {"field": "payload.remote_port", "size": 10}}}}}}}}
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
                # One finding per distinct peer the rule matched on this host. A rule with
                # no network peer (host/process rules) yields no peer buckets and falls
                # back to a single host-level finding, exactly as before.
                peers = [(p["key"],
                          (p.get("by_port", {}).get("buckets") or [{}])[0].get("key"),
                          p["doc_count"])
                         for p in (b.get("by_peer", {}).get("buckets") or [])]
                for ip, port, pcnt in (peers or [(None, None, cnt)]):
                    db.upsert_finding(pg, {
                        "asset_id": asset, "domain": "network", "rule_id": rid,
                        "title": f"Sigma: {meta.get('title')}"
                                 + (f" ({ip}:{port})" if ip else ""),
                        "description": meta.get("description"), "severity": sev,
                        "source_tool": "sigma", "raw_ref": str(meta.get("id")),
                        "dedup_key": db.fp(asset, "sigma", rid),
                        "observable_key": db.observable_key(asset, ip, port),
                        "port": port,
                        # Peer in the fingerprint so two peers on one host stay two rows.
                        "fingerprint": db.fp("sigma", asset, "network", rid, ip, port),
                        "attack": tech, "threat_intel": None,
                        "evidence": {"sigma_query": q, "mode": mode, "matches": pcnt,
                                     "level": level, "remote_ip": ip, "remote_port": port},
                    })
                    created += 1
    log.info("sigma: %d detection finding(s)", created)
    return created
