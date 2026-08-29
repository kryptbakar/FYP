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


# ---------------------------------------------------------- applicability ---
# A factor that CANNOT be evidenced by a given kind of finding must not consume
# weight. Scoring it 0 charges the finding for failing to be a different kind of
# finding, and it is what produced "0 critical, 0 high" across 63 findings that
# included an actively exploited CVSS-10 backdoor.

def test_inapplicable_factor_is_none_not_zero():
    """None and 0.0 are different claims: "cannot be asked" vs "asked, answer no".
    They must not render as the same thing in the XAI panel."""
    _, comp = composite({k: 1.0 for k in WEIGHTS}, {"kev": False})
    assert comp["kev"] is None
    assert comp["cvss"] is not None


def test_inapplicable_factor_does_not_cost_the_finding():
    """THE property. A perfect finding is still 100 when a factor cannot apply."""
    score, _ = composite({k: 1.0 for k in WEIGHTS}, {"kev": False, "epss": False})
    assert round(score) == 100


def test_components_still_sum_to_the_score():
    """The XAI waterfall must keep adding up after renormalisation, or the
    explanation stops being an explanation."""
    feats = {"cvss": 1.0, "kev": 1.0, "exposure": 0.5, "age": 0.3, "criticality": 0.8}
    score, comp = composite(feats, {"epss": False, "threat_intel": False})
    assert abs(sum(v for v in comp.values() if v is not None) - score) < 0.5


def test_renormalisation_lifts_a_structurally_capped_finding():
    """The real case, with real numbers: CVE-2024-3094 — CVSS 10, on the CISA KEV
    list, internet-facing — scored 54.7 ("medium") because threat_intel could never
    apply to a package finding. It is HIGH once that dead weight is removed."""
    feats = {"cvss": 1.0, "kev": 1.0, "exposure": 1.0, "epss": 0.0,
             "attack_ctx": 0.7, "compliance_impact": 0.5, "age": 0.02,
             "criticality": 0.55, "consensus": 0.0}
    capped, _ = composite(feats)
    lifted, _ = composite(feats, {"threat_intel": False})
    assert band(capped) == "medium"
    assert band(lifted) == "high"
    assert lifted > capped


def test_a_real_negative_still_costs_the_finding():
    """The guard against turning this into a score-inflation knob. `consensus: 0`
    means one tool reported it — evidence we HAVE, and it must keep hurting."""
    feats = {k: 1.0 for k in WEIGHTS}
    both_applicable_one_zero, _ = composite({**feats, "consensus": 0.0})
    all_present, _ = composite(feats)
    assert both_applicable_one_zero < all_present
    # ...and marking it inapplicable would be the bug, so prove they differ.
    if_wrongly_excluded, _ = composite({**feats, "consensus": 0.0}, {"consensus": False})
    assert if_wrongly_excluded > both_applicable_one_zero


def test_default_is_unchanged_behaviour():
    """Callers that pass no applicability map (evaluate.py, dataset.py) must score
    exactly as before, or the evaluation harnesses silently change meaning."""
    feats = {"cvss": 0.8, "kev": 1.0, "exposure": 0.4}
    assert composite(feats)[0] == composite(feats, {})[0]


def test_all_factors_inapplicable_does_not_divide_by_zero():
    score, comp = composite({k: 1.0 for k in WEIGHTS}, {k: False for k in WEIGHTS})
    assert score == 0.0
    assert all(v is None for v in comp.values())
