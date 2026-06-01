"""Composite risk score — the transparent, explainable baseline.

A weighted sum of seven normalized factors (each 0..1) → 0..100. Every factor's
contribution is recorded so a finding's score is fully defensible in a viva:
"this is HIGH because KEV(+18) and CVSS(+19) dominate". The ML model (train.py)
layers on top to learn non-linear interactions the linear score misses; SHAP then
explains the ML delta. Weights live here and are the "adaptive weighting" knob.
"""
from __future__ import annotations

# Seven named factors from the brief. Weights sum to 1.0.
WEIGHTS: dict[str, float] = {
    "cvss": 0.22,              # technical severity (CVSS base / 10)
    "epss": 0.20,              # probability of exploitation (FIRST EPSS)
    "kev": 0.18,               # known exploited in the wild (CISA KEV) — strong signal
    "exposure": 0.15,          # how network-exposed the asset is
    "compliance_impact": 0.09, # weak hardening posture amplifies risk
    "age": 0.08,               # longer-known-unpatched = larger exposure window
    "criticality": 0.08,       # business criticality of the asset
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
