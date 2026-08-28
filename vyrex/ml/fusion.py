"""AI Fusion Engine front-end: cross-tool deduplication + consensus weighting.

This is the *new* part of the upgraded ml/ layer (Phase F) and a core original
contribution. Findings arrive from many independent tools (the Go agent, Suricata,
Zeek, Wazuh, Trivy, Nuclei, MISP, Sigma, …). When several of them describe the SAME
underlying issue on the SAME asset, that corroboration is itself a strong signal —
analysts trust a finding far more when three independent tools agree on it.

We exploit the `dedup_key` every producer already stamps (see ml/FUSION.md for the
per-tool key rules). Findings that share a dedup_key are one *cluster*. For each
cluster we record WHICH tools contributed (an explainability signal surfaced in the
console) and derive a `consensus` weight in 0..1 that feeds both the composite score
and the XGBoost model. We never delete the individual rows — analysts still need each
tool's raw evidence — we annotate every member with its cluster's `consensus` jsonb.
"""
from __future__ import annotations

import logging
from collections import defaultdict

log = logging.getLogger("ml.fusion")


def cluster_key(f: dict) -> str:
    """The fusion grouping key, in priority order.

    1. `observable_key` — the THING OBSERVED (this host talked to 185.220.101.45:4444).
       Different tools inspecting the same connection derive the same observable, which
       is what makes cross-tool corroboration possible at all.
    2. `dedup_key` — the RULE THAT FIRED. Correct for vulnerability findings, where the
       same CVE on the same asset is one issue whichever scanner reported it, but it
       cannot cluster across tool families because each family builds it differently.
    3. `solo:<id>` — a key-less finding is its own cluster, never lost.

    Ordering matters: keying on the rule first was the bug. A MISP IOC hit, a Sigma
    detection and an agent rule about ONE connection produced three unrelated dedup_keys,
    so `n_tools` was 1 for all three and the engine reported "0 corroborated by >1 tool"
    on the exact scenario ml/FUSION.md used as its worked example.
    """
    return f.get("observable_key") or f.get("dedup_key") or f"solo:{f['id']}"


def consensus_weight(n_tools: int) -> float:
    """Map the count of *distinct* corroborating tools to a 0..1 confidence boost.
    1 tool → 0.0 (no corroboration), 2 → 0.5, 3+ → 1.0. Deliberately saturating: the
    jump from one to two independent tools is the most informative."""
    return max(0.0, min(1.0, (n_tools - 1) / 2.0))


def build_clusters(findings: list[dict]) -> dict[int, dict]:
    """Group findings by cluster_key and compute each cluster's consensus record.

    Returns a map: finding_id -> consensus dict, where the dict is shared by every
    member of the cluster:
        {tools: [...], n_tools, weight, threat_intel, attack, members: [ids], primary}
    `primary` is the highest-severity member id — the row the console leads with.
    """
    clusters: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        clusters[cluster_key(f)].append(f)

    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    by_id: dict[int, dict] = {}
    multi = 0
    for key, members in clusters.items():
        tools = sorted({m.get("source_tool") or "agent" for m in members})
        n = len(tools)
        if n > 1:
            multi += 1
        # Threat-intel / ATT&CK context corroborate across the cluster: if ANY member
        # carries a MISP IOC hit or an ATT&CK technique, the whole cluster inherits it.
        has_intel = any(m.get("threat_intel") for m in members)
        attack = next((m.get("attack") for m in members if m.get("attack")), None)
        primary = max(members, key=lambda m: (sev_rank.get((m.get("severity") or "").lower(), 0), m["id"]))
        record = {
            "tools": tools,
            "n_tools": n,
            "weight": round(consensus_weight(n), 3),
            "threat_intel": has_intel,
            "attack": attack,
            "members": sorted(m["id"] for m in members),
            "primary": primary["id"],
            "dedup_key": None if key.startswith("solo:") else key,
        }
        for m in members:
            by_id[m["id"]] = record
    log.info("fused %d findings into %d clusters (%d multi-tool / corroborated)",
             len(findings), len(clusters), multi)
    return by_id
