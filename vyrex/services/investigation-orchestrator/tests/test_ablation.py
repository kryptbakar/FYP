"""Ablation slicing — withholding one specialist's evidence from synthesis.

EVALUATION-PROTOCOL §4 requires ablations (without historical / intel / asset context) to
show which specialists earn their place. Because each evidence record carries a citation
prefix identifying the branch that produced it, an ablation is a filter rather than graph
surgery — and the remaining set is byte-identical to a real run without that branch.

These tests pin the slicing itself. Whether a dropped branch *changes the verdict* is a
question for the benchmark against a real model, not for a unit test.
"""
from __future__ import annotations

import pytest

from orchestrator.benchmark import ABLATIONS, ablate
from orchestrator.models.contracts import Evidence, SourceType


def _ev(cid: str) -> Evidence:
    return Evidence.create(cid, SourceType.FINDING, "findings:1", {"id": 1})


@pytest.fixture
def evidence():
    # One record per branch, matching the graph's real prefix scheme.
    return [_ev(c) for c in ("F1", "X1", "A1", "A2", "T1", "C1", "H1")]


def test_no_ablation_returns_everything(evidence):
    assert len(ablate(evidence, None)) == len(evidence)


def test_dropping_asset_removes_every_asset_record(evidence):
    """A2 (compliance) is part of the asset branch and must go with A1 — dropping only
    the first record would leave a half-ablated branch and quietly invalidate the run."""
    out = ablate(evidence, "asset")
    assert [e.citation_id for e in out] == ["F1", "X1", "T1", "C1", "H1"]


@pytest.mark.parametrize("name,gone", [
    ("attack", "X1"), ("intel", "T1"), ("fusion", "C1"), ("historical", "H1"),
])
def test_each_ablation_drops_only_its_own_branch(evidence, name, gone):
    out = {e.citation_id for e in ablate(evidence, name)}
    assert gone not in out
    assert "F1" in out, "the finding snapshot is never ablated - it is the subject itself"
    assert len(out) == len(evidence) - 1


def test_the_subject_snapshot_survives_every_ablation(evidence):
    """F1 is the finding under investigation. Removing it would not be an ablation, it
    would be a different experiment with no subject."""
    for name in ABLATIONS:
        assert any(e.citation_id == "F1" for e in ablate(evidence, name))


def test_ablation_names_map_to_distinct_prefixes():
    """Two ablations sharing a prefix would silently drop each other's evidence and make
    every result attributable to the wrong branch."""
    assert len(set(ABLATIONS.values())) == len(ABLATIONS)


def test_unknown_ablation_is_a_hard_error_not_a_silent_no_op():
    """A typo must not quietly produce a full-evidence run reported as an ablation —
    that would look like 'this branch changes nothing' and be entirely wrong."""
    with pytest.raises(KeyError):
        ablate([_ev("F1")], "nonexistent")
