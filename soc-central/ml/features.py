"""Feature engineering — turn a finding + its asset context into a model vector.

Eight features (all normalized 0..1). The first seven feed the linear composite
(scoring.py); `attack_phase` is the extra ML-only signal that makes the model
"attack-phase aware" (adapted from the Attack-Phase-Aware reference) — it lets the
model learn that, e.g., a C2-egress finding deserves more weight than its CVSS alone.
"""
from __future__ import annotations

from datetime import datetime, timezone

FEATURES = ["cvss", "epss", "kev", "exposure", "compliance_impact", "age", "criticality", "attack_phase"]

# Coarse Lockheed-Martin kill-chain ordinal (1..7) per finding type, normalized /7.
_PHASE = {"recon": 1, "delivery": 2, "exploitation": 4, "installation": 5, "c2": 6, "actions": 7, "hardening": 3}

# Fallback CVSS-from-severity when a finding has no numeric CVSS (system/network rules).
_SEV = {"CRITICAL": 0.95, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1, "UNKNOWN": 0.4}


def _num(x, default=0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def attack_phase(domain: str, rule_id: str | None) -> float:
    rid = (rule_id or "").lower()
    if domain == "network" and "egress" in rid:
        return _PHASE["c2"] / 7
    if domain == "network" and "exposed" in rid:
        return _PHASE["delivery"] / 7
    if domain == "application":
        return _PHASE["exploitation"] / 7
    if domain == "system":
        return _PHASE["hardening"] / 7
    return _PHASE["recon"] / 7


def age_norm(published, first_seen, now: datetime | None = None) -> float:
    """Days since the CVE was published (or the finding first seen), capped at 1y."""
    now = now or datetime.now(timezone.utc)
    ref = published or first_seen
    if not ref:
        return 0.2
    if isinstance(ref, str):
        try:
            ref = datetime.fromisoformat(ref.replace("Z", "+00:00"))
        except ValueError:
            return 0.2
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    days = (now - ref).days
    return max(0.0, min(1.0, days / 365.0))


def build(finding: dict, ctx: "Context") -> dict[str, float]:
    """finding: a findings row dict. ctx: per-asset context (exposure/compliance/criticality/cve dates)."""
    asset = finding.get("asset_id")
    cvss = _num(finding.get("cvss_score")) / 10.0 if finding.get("cvss_score") is not None \
        else _SEV.get((finding.get("severity") or "UNKNOWN").upper(), 0.4)
    return {
        "cvss": max(0.0, min(1.0, cvss)),
        "epss": max(0.0, min(1.0, _num(finding.get("epss")))),
        "kev": 1.0 if finding.get("kev") else 0.0,
        "exposure": ctx.exposure.get(asset, 0.2),
        "compliance_impact": ctx.compliance_impact.get(asset, 0.5),
        "age": age_norm(ctx.cve_published.get(finding.get("cve_id")), finding.get("first_seen")),
        "criticality": ctx.criticality.get(asset, 0.5),
        "attack_phase": attack_phase(finding.get("domain"), finding.get("rule_id")),
    }


def to_vector(fd: dict[str, float]) -> list[float]:
    return [fd[f] for f in FEATURES]


class Context:
    """Per-asset context, assembled once per scoring run (see db.load_context)."""

    def __init__(self, exposure: dict, compliance_impact: dict, criticality: dict, cve_published: dict):
        self.exposure = exposure
        self.compliance_impact = compliance_impact
        self.criticality = criticality
        self.cve_published = cve_published
