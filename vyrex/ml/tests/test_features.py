"""Unit tests for feature engineering — every normalization we rely on at score time."""
from datetime import datetime, timedelta, timezone

import pytest

import features
from features import Context, age_norm, attack_ctx, attack_phase, build, to_vector


def _ctx(**kw):
    return Context(
        exposure=kw.get("exposure", {}),
        compliance_impact=kw.get("compliance_impact", {}),
        criticality=kw.get("criticality", {}),
        cve_published=kw.get("cve_published", {}),
    )


def test_feature_order_matches_vector():
    fd = build({"severity": "HIGH"}, _ctx())
    vec = to_vector(fd)
    assert len(vec) == len(features.FEATURES)
    assert vec == [fd[f] for f in features.FEATURES]


def test_cvss_numeric_normalized_and_clamped():
    assert build({"cvss_score": 9.8}, _ctx())["cvss"] == pytest.approx(0.98)
    assert build({"cvss_score": 15}, _ctx())["cvss"] == 1.0   # clamped
    assert build({"cvss_score": -3}, _ctx())["cvss"] == 0.0


def test_cvss_falls_back_to_severity_band():
    assert build({"severity": "CRITICAL"}, _ctx())["cvss"] == 0.95
    assert build({"severity": "info"}, _ctx())["cvss"] == 0.1
    assert build({}, _ctx())["cvss"] == 0.4  # UNKNOWN default


def test_kev_and_intel_flags_binary():
    fd = build({"kev": True, "threat_intel": {"ioc": "1.2.3.4"}}, _ctx())
    assert fd["kev"] == 1.0 and fd["threat_intel"] == 1.0
    fd = build({}, _ctx())
    assert fd["kev"] == 0.0 and fd["threat_intel"] == 0.0


def test_attack_ctx_grading():
    assert attack_ctx(None) == 0.0
    assert attack_ctx("T1041") == 1.0            # exfiltration tops the scale
    assert attack_ctx("T1071.001") == 0.9        # sub-technique inherits parent grade
    assert attack_ctx("T9999") == 0.5            # mapped-but-unranked still counts


def test_attack_phase_by_domain_and_rule():
    assert attack_phase("network", "egress-c2-beacon") == 6 / 7
    assert attack_phase("network", "exposed-smb") == 2 / 7
    assert attack_phase("application", None) == 4 / 7
    assert attack_phase("system", None) == 3 / 7
    assert attack_phase("other", None) == 1 / 7


def test_age_norm_caps_and_defaults():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert age_norm(None, None, now) == 0.2                       # unknown → mild default
    assert age_norm(now - timedelta(days=730), None, now) == 1.0  # capped at 1y
    assert abs(age_norm(now - timedelta(days=36, hours=12), None, now) - 36 / 365) < 0.01
    assert age_norm("not-a-date", None, now) == 0.2               # unparsable → default
    naive = (now - timedelta(days=100)).replace(tzinfo=None)
    assert abs(age_norm(naive, None, now) - 100 / 365) < 0.01     # naive dt assumed UTC


def test_asset_context_defaults():
    fd = build({"asset_id": "h-unknown"}, _ctx())
    assert fd["exposure"] == 0.2
    assert fd["compliance_impact"] == 0.5
    assert fd["criticality"] == 0.5


def test_consensus_passthrough_clamped():
    assert build({"_consensus": 0.5}, _ctx())["consensus"] == 0.5
    assert build({"_consensus": 3}, _ctx())["consensus"] == 1.0
    assert build({"_consensus": "junk"}, _ctx())["consensus"] == 0.0
