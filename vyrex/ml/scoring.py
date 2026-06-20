"""Composite risk score — the transparent, explainable baseline.

A weighted sum of ten normalized factors (each 0..1) → 0..100. Every factor's
contribution is recorded so a finding's score is fully defensible in a viva:
"this is HIGH because KEV(+15), CVSS(+16) and a live MISP IOC(+10) dominate". The ML
model (train.py) layers on top to learn non-linear interactions the linear score
misses; SHAP then explains the ML delta. Weights live here and are the "adaptive
weighting" knob.

Phase F added the three fusion factors (threat_intel, attack_ctx, consensus) and
rebalanced the original seven down to make room — the weights still sum to 1.0.
"""
from __future__ import annotations

# Ten named factors. The first seven are the Phase-5 core; the last three are the
# Phase-F fusion signals (live threat intel, ATT&CK context, multi-tool consensus).
# Weights sum to 1.0.
WEIGHTS: dict[str, float] = {
    "cvss": 0.18,              # technical severity (CVSS base / 10)
    "epss": 0.16,              # probability of exploitation (FIRST EPSS)
    "kev": 0.15,               # known exploited in the wild (CISA KEV) — strong signal
    "exposure": 0.12,          # how network-exposed the asset is
    "threat_intel": 0.10,      # live IOC corroboration (MISP) — real-world activity
    "consensus": 0.09,         # independent tools agree on this finding (fusion)
    "attack_ctx": 0.07,        # mapped to a MITRE ATT&CK technique (OpenCTI/Sigma)
    "compliance_impact": 0.05, # weak hardening posture amplifies risk
    "age": 0.04,               # longer-known-unpatched = larger exposure window
    "criticality": 0.04,       # business criticality of the asset
}

COMPOSITE_FACTORS = list(WEIGHTS.keys())


def composite(features: dict[str, float]) -> tuple[float, dict[str, float]]:
    """Return (score 0..100, per-factor contribution in points)."""
    components: dict[str, float] = {}
    total = 0.0
    for factor, w in WEIGHTS.items():
        v = max(0.0, min(1.0, float(features.get(factor, 0.0))))
        contrib = 100.0 * w * v
        components[factor] = round(contrib, 2)
        total += contrib
    return round(total, 2), components


def band(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"
