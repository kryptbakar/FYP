"""Unit tests for the composite risk score — the primary, defensible signal.

These pin the properties we defend in a viva: the weights sum to 1.0, every factor
is clamped to 0..1, the score is the sum of the per-factor contributions, and the
risk bands fall on the documented thresholds.
"""
from scoring import WEIGHTS, band, composite


def test_weights_sum_to_one():
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


def test_all_factors_present():
    for f in ("cvss", "epss", "kev", "exposure", "threat_intel",
              "consensus", "attack_ctx", "compliance_impact", "age", "criticality"):
        assert f in WEIGHTS


def test_max_score_is_100():
    score, comp = composite({k: 1.0 for k in WEIGHTS})
    assert round(score) == 100
    assert abs(sum(comp.values()) - score) < 0.5


def test_zero_score():
    score, comp = composite({})
    assert score == 0.0
    assert all(v == 0.0 for v in comp.values())


def test_factor_values_are_clamped():
    # cvss=5.0 must clamp to 1.0 -> contributes exactly its weight * 100
    score, comp = composite({"cvss": 5.0})
    assert comp["cvss"] == round(100 * WEIGHTS["cvss"], 2)
    assert score == comp["cvss"]


def test_negative_values_clamp_to_zero():
    score, comp = composite({"kev": -3.0})
    assert comp["kev"] == 0.0
    assert score == 0.0


def test_band_thresholds():
    assert band(85) == "critical"
    assert band(80) == "critical"
    assert band(65) == "high"
    assert band(45) == "medium"
    assert band(25) == "low"
    assert band(5) == "info"
