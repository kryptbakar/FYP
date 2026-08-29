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


def composite(features: dict[str, float],
              applicable: dict[str, bool] | None = None) -> tuple[float, dict[str, float | None]]:
    """Return (score 0..100, per-factor contribution in points).

    `applicable` marks factors that are UNDEFINED for this finding (see
    `features.applicability`). Those consume no weight and are reported as None
    rather than 0.0, and the remaining factors are renormalised over the weight
    actually in play. Omit it and every factor is treated as applicable, which is
    the pre-2026-08-29 behaviour and what the evaluation harnesses still use.

    WHY RENORMALISE. The ten weights sum to 1.0 only if all ten questions can be
    asked of the same finding, and in practice they never can: the factor sets are
    close to disjoint by finding type. A package vulnerability has CVSS/EPSS/KEV but
    cannot match a network IOC; an IP indicator has threat-intel and consensus but
    has no CVE, so EPSS and KEV are meaningless for it. Charging each type for the
    other's evidence caps BOTH below the band thresholds:

        CVE-2024-3094  CVSS 10, on KEV, internet-facing  -> 54.7  ("medium")
        Cobalt Strike C2, 3 tools agreeing, live IOC     -> 57.5  ("high")

    Both were at their structural ceiling, so "0 critical, 0 high across 63
    findings" was a property of the SCORING, not of the estate. It is also why an
    automatic trigger at 60/80 could never fire.

    Components are scaled by the same divisor, so they still sum to the score and
    the XAI waterfall continues to add up.
    """
    applicable = applicable or {}
    raw: dict[str, float | None] = {}
    total = 0.0
    live_weight = 0.0
    for factor, w in WEIGHTS.items():
        if applicable.get(factor, True) is False:
            raw[factor] = None                      # renders as "—", never as 0.0
            continue
        v = max(0.0, min(1.0, float(features.get(factor, 0.0))))
        contrib = 100.0 * w * v
        raw[factor] = contrib
        total += contrib
        live_weight += w

    if live_weight <= 0:
        # Every factor undefined. Not reachable today (exposure/age/criticality are
        # always applicable) but returning 0/0 would be a crash, and a silent 0.0
        # would look like a confident "no risk" rather than "nothing to say".
        return 0.0, {k: None for k in WEIGHTS}

    components = {k: (None if v is None else round(v / live_weight, 2))
                  for k, v in raw.items()}
    return round(min(100.0, total / live_weight), 2), components


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
