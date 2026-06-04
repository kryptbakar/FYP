"""Tests for the model-card weights and asset-criticality validation."""
import pytest
from pydantic import ValidationError

from app.routers.findings import AssetPatch
from app.routers.risk import COMPOSITE_WEIGHTS


def test_model_card_weights_sum_to_one():
    assert abs(sum(COMPOSITE_WEIGHTS.values()) - 1.0) < 1e-9


def test_model_card_exposes_core_factors():
    for k in ("cvss", "epss", "kev", "consensus", "threat_intel"):
        assert k in COMPOSITE_WEIGHTS


def test_asset_patch_accepts_valid_criticality():
    assert AssetPatch(criticality=0.5).criticality == 0.5
    assert AssetPatch(criticality=0.0).criticality == 0.0
    assert AssetPatch(criticality=1.0).criticality == 1.0


def test_asset_patch_rejects_out_of_range():
    with pytest.raises(ValidationError):
        AssetPatch(criticality=1.5)
    with pytest.raises(ValidationError):
        AssetPatch(criticality=-0.1)
