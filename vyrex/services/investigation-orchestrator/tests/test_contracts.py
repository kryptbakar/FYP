"""The three invariants the contracts are supposed to make unbreakable.

If these can be violated, a demo can show a confident, well-cited, complete-looking
report that is none of those things — which is the exact failure mode the whole
evidence-grounded design exists to prevent.
"""
from __future__ import annotations

import pathlib
import sys

import pytest
from pydantic import ValidationError

# The package is named `orchestrator`, not `app`, on purpose: services/api already owns
# the top-level name `app`, and its conftest puts services/api on sys.path first — so a
# second `app` package makes the two suites uncollectable in one pytest run.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from orchestrator.models import (  # noqa: E402
    CONTRACT_VERSION,
    BranchOutput,
    Claim,
    Completeness,
    Disposition,
    Evidence,
    InvestigationState,
    InvestigationStatus,
    NodeStatus,
    Severity,
    SourceType,
    SubjectType,
    SynthesisOutput,
    TriageReport,
    TriggerType,
    derive_confidence,
    unresolved_citations,
)


def _evidence(cid: str = "E1") -> Evidence:
    return Evidence.create(
        cid, SourceType.FINDING, "findings:12",
        {"id": 12, "cve_id": "CVE-2023-4911", "risk_score": 54.45},
        source_tool="trivy",
    )


def _report(claims: list[Claim] | None = None, **kw) -> TriageReport:
    base = dict(
        recommended_severity=Severity.HIGH,
        recommended_disposition=Disposition.ESCALATE,
        confidence=0.7,
        summary="Exposed service with a KEV-listed CVE.",
        rationale_claims=claims if claims is not None else [Claim(text="KEV listed", citation_ids=["E1"])],
        graph_version="0.1.0",
        prompt_version="0.1.0",
        model_name="llama3.2:3b",
    )
    base.update(kw)
    return TriageReport(**base)


# --- invariant 1: no uncited claims --------------------------------------------------

def test_claim_cannot_be_built_without_a_citation():
    with pytest.raises(ValidationError):
        Claim(text="the asset is internet facing", citation_ids=[])


def test_claim_rejects_blank_citation_ids():
    """A whitespace id would pass a naive min_length check and resolve to nothing."""
    with pytest.raises(ValidationError):
        Claim(text="something", citation_ids=["  ", ""])


def test_unresolved_citations_catches_an_invented_reference():
    report = _report([Claim(text="seen in MISP", citation_ids=["E1", "E7"])])
    assert unresolved_citations(report, [_evidence("E1")]) == ["E7"]


def test_unresolved_citations_empty_when_everything_resolves():
    report = _report([Claim(text="KEV listed", citation_ids=["E1"])])
    assert unresolved_citations(report, [_evidence("E1")]) == []


def test_unresolved_citations_does_not_duplicate_ids():
    report = _report([
        Claim(text="a", citation_ids=["E9"]),
        Claim(text="b", citation_ids=["E9"]),
    ])
    assert unresolved_citations(report, []) == ["E9"]


# --- invariant 2: the model cannot assert its own confidence -------------------------

def test_synthesis_output_has_no_confidence_field():
    assert "confidence" not in SynthesisOutput.model_fields


def test_synthesis_output_rejects_a_smuggled_confidence():
    """extra='forbid' — a model that volunteers confidence fails schema validation
    rather than having the value silently accepted."""
    with pytest.raises(ValidationError):
        SynthesisOutput(
            recommended_severity=Severity.HIGH,
            recommended_disposition=Disposition.ESCALATE,
            summary="x",
            confidence=0.99,
        )


def test_synthesis_output_rejects_versions_it_must_not_control():
    with pytest.raises(ValidationError):
        SynthesisOutput(
            recommended_severity=Severity.LOW,
            recommended_disposition=Disposition.MONITOR,
            summary="x",
            graph_version="tampered",
        )


@pytest.mark.parametrize(
    "expected,succeeded,count,corroborated,lo,hi",
    [
        (4, 4, 10, True, 0.99, 1.0),    # everything landed
        (4, 0, 0, False, 0.0, 0.01),    # nothing landed
        (4, 2, 2, False, 0.3, 0.5),     # half the branches, thin evidence
    ],
)
def test_derive_confidence_tracks_coverage(expected, succeeded, count, corroborated, lo, hi):
    c = derive_confidence(
        branches_expected=expected, branches_succeeded=succeeded,
        evidence_count=count, corroborated=corroborated,
    )
    assert lo <= c <= hi


def test_confidence_rises_with_branch_coverage():
    weak = derive_confidence(branches_expected=4, branches_succeeded=1, evidence_count=3)
    strong = derive_confidence(branches_expected=4, branches_succeeded=4, evidence_count=3)
    assert strong > weak


def test_abstention_is_capped():
    """Declining to decide must never read as high certainty."""
    c = derive_confidence(
        branches_expected=4, branches_succeeded=4, evidence_count=10,
        corroborated=True, abstained=True,
    )
    assert c <= 0.5


def test_confidence_is_zero_when_nothing_was_planned():
    assert derive_confidence(branches_expected=0, branches_succeeded=0, evidence_count=0) == 0.0


# --- invariant 3: evidence is a frozen, verifiable snapshot --------------------------

def test_content_hash_is_order_independent():
    a = Evidence.hash_payload({"x": 1, "y": 2})
    b = Evidence.hash_payload({"y": 2, "x": 1})
    assert a == b


def test_content_hash_changes_with_content():
    assert Evidence.hash_payload({"score": 54.45}) != Evidence.hash_payload({"score": 54.46})


def test_evidence_verifies_its_own_payload():
    assert _evidence().verify() is True


def test_evidence_is_immutable():
    """Frozen so a later node cannot quietly edit a fact the report already cited."""
    with pytest.raises(ValidationError):
        _evidence().citation_id = "E2"


# --- state / round-trip ---------------------------------------------------------------

def test_state_round_trips_through_json():
    """LangGraph checkpoints to Postgres — anything that cannot round-trip cannot resume."""
    state = InvestigationState(
        investigation_id="inv-1",
        subject_type=SubjectType.FINDING,
        subject_id=12,
        trigger_type=TriggerType.AUTOMATIC,
        trigger_score_snapshot=54.45,
        trigger_policy_version="2026-08-manual-only-v1",
        evidence=[_evidence()],
        branch_outputs={"attack": BranchOutput(node="attack", status=NodeStatus.SUCCEEDED)},
        report=_report(),
    )
    restored = InvestigationState.model_validate_json(state.model_dump_json())
    assert restored.investigation_id == "inv-1"
    assert restored.evidence[0].content_hash == state.evidence[0].content_hash
    assert restored.report.recommended_disposition is Disposition.ESCALATE
    assert restored.branch_outputs["attack"].status is NodeStatus.SUCCEEDED


def test_skipped_branch_is_recorded_not_dropped():
    """'no historical matches' and 'the query failed' must stay distinguishable."""
    b = BranchOutput(node="historical", status=NodeStatus.SKIPPED, reason="no prior findings")
    assert b.contributed is False and b.reason


def test_partial_completeness_is_representable():
    assert _report(completeness=Completeness.PARTIAL).completeness is Completeness.PARTIAL


def test_abstained_reports_are_flagged():
    r = _report(recommended_disposition=Disposition.INSUFFICIENT_EVIDENCE)
    assert r.abstained is True


def test_confidence_is_bounded_by_the_schema():
    with pytest.raises(ValidationError):
        _report(confidence=1.4)


def test_report_stamps_the_contract_version():
    assert _report().contract_version == CONTRACT_VERSION


def test_state_defaults_to_queued():
    s = InvestigationState(
        investigation_id="inv-2", subject_type=SubjectType.INCIDENT,
        subject_id=1, trigger_type=TriggerType.MANUAL,
    )
    assert s.status is InvestigationStatus.QUEUED and s.report is None


# --- invariant 4: a decision must be justified ---------------------------------------
# Added after benchmarking showed models will happily return a disposition with zero
# claims. Abstention needs no claims; a DECISION does.

@pytest.mark.parametrize("disposition", [
    Disposition.ESCALATE, Disposition.MONITOR, Disposition.DISMISS])
def test_deciding_without_citing_anything_is_rejected(disposition):
    """A confident verdict with no cited evidence is an assertion, not a verdict."""
    with pytest.raises(ValidationError) as e:
        SynthesisOutput(
            recommended_severity=Severity.HIGH,
            recommended_disposition=disposition,
            summary="Trust me.",
            rationale_claims=[],
        )
    assert "at least one cited claim" in str(e.value)


def test_abstaining_without_claims_is_allowed():
    """'I cannot tell from this' needs no supporting evidence - missing_evidence carries
    the reasoning instead. Requiring claims here would force fabrication."""
    out = SynthesisOutput(
        recommended_severity=Severity.INFO,
        recommended_disposition=Disposition.INSUFFICIENT_EVIDENCE,
        summary="Not enough to decide.",
        rationale_claims=[],
        missing_evidence=["no corroboration from any second tool"],
    )
    assert out.rationale_claims == []


def test_deciding_with_a_cited_claim_is_allowed():
    out = SynthesisOutput(
        recommended_severity=Severity.HIGH,
        recommended_disposition=Disposition.ESCALATE,
        summary="Escalate.",
        rationale_claims=[Claim(text="KEV-listed and reachable", citation_ids=["F1"])],
    )
    assert out.recommended_disposition is Disposition.ESCALATE