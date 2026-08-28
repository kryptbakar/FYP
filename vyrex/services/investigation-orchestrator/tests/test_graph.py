"""Graph behaviour: routing, failure isolation, citation validation, confidence.

Runs the REAL compiled LangGraph against a fake repository and a deterministic LLM, so
these exercise the actual wiring — parallel fan-out, the reducers that let branches
accumulate evidence without overwriting each other, and the validator — rather than
re-implementing them in a mock.

No database, no model, no network: fast enough to run on every commit, which is the point.
The properties pinned here are the ones whose failure is invisible in a demo — a fabricated
citation shown as sourced, a crashed branch silently dropped, confidence that does not fall
when coverage falls.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from orchestrator.graph import build_graph  # noqa: E402
from orchestrator.llm import FakeLLM  # noqa: E402
from orchestrator.models import Disposition  # noqa: E402


class FakeRepo:
    """In-memory stand-in for the repository, recording what the graph persisted."""

    def __init__(self, *, subject=None, asset=None, explanation=None, cluster=None,
                 historical=None, intel=None, compliance=None, attack=None,
                 raise_in=None):
        self._subject = subject
        self._asset = asset
        self._explanation = explanation
        self._cluster = cluster or []
        self._historical = historical or []
        self._intel = intel or []
        self._compliance = compliance or {}
        self._attack = attack or {}
        self.raise_in = raise_in          # node name that should blow up
        self.steps: dict[str, dict] = {}
        self.evidence: list[dict] = []
        self.report: dict | None = None
        self.unresolved: list[str] | None = None

    # -- reads -------------------------------------------------------------------------
    def load_subject(self, pg, subject_type, subject_id):
        return self._subject

    def load_asset(self, pg, host_id):
        if self.raise_in == "asset_context":
            raise RuntimeError("asset query exploded")
        return self._asset

    def load_explanation(self, pg, fid):
        return self._explanation

    def load_fusion_cluster(self, pg, fid):
        if self.raise_in == "fusion_context":
            raise RuntimeError("fusion query exploded")
        return self._cluster

    def load_historical(self, pg, finding, limit=10):
        if self.raise_in == "historical_context":
            raise RuntimeError("historical query exploded")
        return self._historical

    def load_intel_sightings(self, pg, asset_id, limit=10):
        return self._intel

    def load_compliance(self, pg, asset_id):
        return self._compliance

    def load_attack_context(self, pg, technique):
        return self._attack

    # -- writes ------------------------------------------------------------------------
    def upsert_step(self, pg, inv, node, status, **kw):
        cur = self.steps.setdefault(node, {})
        cur["status"] = status
        cur.update({k: v for k, v in kw.items() if v is not None})

    def save_evidence(self, pg, inv, items):
        self.evidence.extend(items)
        return len(items)

    def save_report(self, pg, inv, report, unresolved=None):
        self.report = report
        self.unresolved = unresolved


class Settings:
    graph_version = "test"
    prompt_version = "test"


FINDING = {
    "id": 42, "title": "Suspicious outbound to 4444", "severity": "HIGH",
    "cve_id": None, "risk_score": 47.3, "kev": False, "attack": "T1071.001",
    "asset_id": "lab-vm-01", "source_tool": "misp", "threat_intel": None,
}


def run_graph(repo: FakeRepo, llm=None, subject_type="finding"):
    graph = build_graph({"repo": repo, "pg": None, "llm": llm or FakeLLM(),
                         "settings": Settings()})
    return graph.invoke({
        "investigation_id": "inv-test", "subject_type": subject_type, "subject_id": 42,
        "evidence": [], "branch_outputs": {}, "errors": [],
    })


# --- happy path -----------------------------------------------------------------------

def test_full_run_collects_evidence_from_every_applicable_branch():
    repo = FakeRepo(subject=FINDING, asset={"host_id": "lab-vm-01", "hostname": "lab-vm-01",
                                            "os": "linux", "ip": "10.0.0.5", "criticality": 0.7},
                    explanation={"ml_risk_score": 69.2, "top_factors": [{"feature": "kev"}]},
                    cluster=[{"id": 43, "source_tool": "sigma", "severity": "HIGH",
                              "title": "Sigma hit", "rule_id": "r", "attack": "T1571",
                              "risk_score": 40, "has_intel": False}],
                    historical=[{"id": 9, "asset_id": "h", "title": "old", "severity": "LOW",
                                 "cve_id": None, "attack": None, "triage_status": "dismissed",
                                 "risk_score": 10, "first_seen": None, "relation": "same_asset"}],
                    compliance={"failed": 7, "passed": 3, "total": 10},
                    attack={"findings": 20, "assets": 2, "high_sev": 5})
    out = run_graph(repo)

    assert repo.steps["load_subject"]["status"] == "succeeded"
    for node in ("asset_context", "attack_context", "fusion_context", "historical_context"):
        assert repo.steps[node]["status"] == "succeeded", node
    assert repo.steps["validate"]["status"] == "succeeded"
    # Prefixes keep parallel branches from colliding on an id.
    cids = {e["citation_id"] for e in repo.evidence}
    assert {"F1", "X1", "A1", "A2", "T1", "C1", "H1"} <= cids
    assert repo.report["recommended_disposition"] in {d.value for d in Disposition}


# --- failure isolation -----------------------------------------------------------------

@pytest.mark.parametrize("broken", ["asset_context", "fusion_context", "historical_context"])
def test_one_branch_raising_does_not_kill_the_investigation(broken):
    """A degraded investigation is a result; a lost one is an outage."""
    repo = FakeRepo(subject=FINDING, asset={"host_id": "lab-vm-01"},
                    cluster=[{"id": 43, "source_tool": "sigma", "severity": "HIGH",
                              "title": "t", "rule_id": "r", "attack": None,
                              "risk_score": 1, "has_intel": False}],
                    historical=[{"id": 9, "asset_id": "h", "title": "t", "severity": "LOW",
                                 "cve_id": None, "attack": None, "triage_status": None,
                                 "risk_score": 1, "first_seen": None, "relation": "same_asset"}],
                    attack={"findings": 1, "assets": 1, "high_sev": 0},
                    raise_in=broken)
    out = run_graph(repo)

    assert repo.steps[broken]["status"] == "failed"
    assert repo.steps[broken].get("reason")          # why, not just that
    assert repo.report is not None                   # still produced a verdict
    assert repo.steps["validate"]["status"] == "succeeded"


def test_missing_subject_abstains_without_calling_the_model():
    """No evidence means no basis for a verdict - and no reason to spend 90s finding out."""
    llm = FakeLLM()
    repo = FakeRepo(subject=None)
    run_graph(repo, llm)

    assert repo.steps["load_subject"]["status"] == "failed"
    assert llm.calls == 0
    assert repo.report["recommended_disposition"] == Disposition.INSUFFICIENT_EVIDENCE.value
    assert repo.report["completeness"] == "partial"


# --- the citation contract --------------------------------------------------------------

class FabricatingLLM:
    """Returns a confident verdict citing evidence that does not exist."""

    name = "fabricator"
    calls = 0

    def complete(self, system, user):
        self.calls += 1
        return json.dumps({
            "recommended_severity": "CRITICAL",
            "recommended_disposition": "ESCALATE",
            "summary": "Definitely malicious.",
            "rationale_claims": [{"text": "Confirmed by threat intel.",
                                  "citation_ids": ["Z9"]}],
            "recommended_next_steps": [], "missing_evidence": [],
        })


def test_fabricated_citation_is_dropped_and_the_report_downgraded():
    """A fabricated citation looks MORE rigorous than a missing one. It must not survive."""
    repo = FakeRepo(subject=FINDING, asset={"host_id": "lab-vm-01"},
                    attack={"findings": 1, "assets": 1, "high_sev": 0})
    run_graph(repo, FabricatingLLM())

    assert repo.unresolved == ["Z9"]
    assert repo.report["rationale_claims"] == []          # unsupported claim removed
    assert repo.report["completeness"] == "partial"       # and the report says so


class PartlyGroundedLLM:
    """Cites one real id and one invented one in the same claim."""

    name = "partly-grounded"
    calls = 0

    def complete(self, system, user):
        self.calls += 1
        return json.dumps({
            "recommended_severity": "HIGH",
            "recommended_disposition": "ESCALATE",
            "summary": "Escalate.",
            "rationale_claims": [{"text": "Grounded in the finding.",
                                  "citation_ids": ["F1", "Z9"]}],
            "recommended_next_steps": [], "missing_evidence": [],
        })


def test_partly_valid_claim_keeps_only_the_resolvable_citations():
    repo = FakeRepo(subject=FINDING, attack={"findings": 1, "assets": 1, "high_sev": 0})
    run_graph(repo, PartlyGroundedLLM())

    assert repo.report["rationale_claims"][0]["citation_ids"] == ["F1"]
    assert repo.unresolved == ["Z9"]
    assert repo.report["completeness"] == "partial"


# --- confidence is derived, never asserted by the model ---------------------------------

def test_confidence_falls_when_a_branch_fails():
    full = FakeRepo(subject=FINDING, asset={"host_id": "lab-vm-01"},
                    cluster=[{"id": 43, "source_tool": "sigma", "severity": "HIGH",
                              "title": "t", "rule_id": "r", "attack": None,
                              "risk_score": 1, "has_intel": False}],
                    attack={"findings": 1, "assets": 1, "high_sev": 0})
    run_graph(full)

    degraded = FakeRepo(subject=FINDING, asset={"host_id": "lab-vm-01"},
                        cluster=[{"id": 43, "source_tool": "sigma", "severity": "HIGH",
                                  "title": "t", "rule_id": "r", "attack": None,
                                  "risk_score": 1, "has_intel": False}],
                        attack={"findings": 1, "assets": 1, "high_sev": 0},
                        raise_in="fusion_context")
    run_graph(degraded)

    assert degraded.report["confidence"] < full.report["confidence"], (
        "coverage fell, so confidence must fall")


def test_model_cannot_smuggle_its_own_confidence():
    """SynthesisOutput forbids extras; a volunteered confidence fails validation, and the
    graph abstains rather than adopting the model's self-assessment."""

    class OverconfidentLLM:
        name = "overconfident"
        calls = 0

        def complete(self, system, user):
            self.calls += 1
            return json.dumps({
                "recommended_severity": "CRITICAL",
                "recommended_disposition": "ESCALATE",
                "summary": "Certain.",
                "confidence": 0.99,
                "rationale_claims": [], "recommended_next_steps": [], "missing_evidence": [],
            })

    repo = FakeRepo(subject=FINDING, attack={"findings": 1, "assets": 1, "high_sev": 0})
    run_graph(repo, OverconfidentLLM())
    assert repo.report["confidence"] <= 0.5
    assert repo.report["recommended_disposition"] == Disposition.INSUFFICIENT_EVIDENCE.value


def test_unavailable_model_abstains_rather_than_failing():
    """Ollama being down is a degraded investigation, not a crashed one."""

    class DeadLLM:
        name = "dead"

        def complete(self, system, user):
            raise __import__("orchestrator.llm", fromlist=["LLMUnavailable"]).LLMUnavailable(
                "connection refused")

    repo = FakeRepo(subject=FINDING, attack={"findings": 1, "assets": 1, "high_sev": 0})
    run_graph(repo, DeadLLM())

    assert repo.steps["synthesize"]["status"] == "failed"
    assert repo.report["recommended_disposition"] == Disposition.INSUFFICIENT_EVIDENCE.value
    assert "model" in " ".join(repo.report["missing_evidence"]).lower()


# --- routing ------------------------------------------------------------------------------

def test_router_skips_attack_branch_when_no_technique_is_mapped():
    repo = FakeRepo(subject={**FINDING, "attack": None},
                    asset={"host_id": "lab-vm-01"})
    run_graph(repo)
    assert "attack_context" not in repo.steps


def test_router_skips_historical_for_incidents():
    """Historical similarity is defined over findings, not incidents."""
    repo = FakeRepo(subject={"id": 7, "title": "inc", "severity": "HIGH", "asset_id": None,
                             "attack": None})
    run_graph(repo, subject_type="incident")
    assert "historical_context" not in repo.steps


def test_branch_with_no_data_is_skipped_not_failed():
    """'Found nothing' and 'crashed' must stay distinguishable."""
    repo = FakeRepo(subject=FINDING, asset={"host_id": "lab-vm-01"},
                    cluster=[], historical=[],
                    attack={"findings": 1, "assets": 1, "high_sev": 0})
    run_graph(repo)
    assert repo.steps["fusion_context"]["status"] == "skipped"
    assert repo.steps["fusion_context"]["reason"]
