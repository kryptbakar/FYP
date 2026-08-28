"""Frozen contracts for the investigation orchestrator.

These types are the interface between the graph, the database, the API and the console.
Freezing them BEFORE the nodes are written is deliberate: the nodes, the tables, the REST
surface and the console all encode these field names, and changing one later means
changing all four at once.

Three design rules are enforced here rather than left to convention, because each one
protects against a failure that would otherwise be invisible in a demo:

1. EVERY FACTUAL CLAIM MUST CITE. `Claim.citation_ids` has min_length=1, so a claim with
   no evidence cannot be constructed at all. `unresolved_citations()` then checks the ids
   actually resolve — a model can happily invent "E7".

2. THE MODEL DOES NOT SET ITS OWN CONFIDENCE. `SynthesisOutput` is what the LLM is
   allowed to return and deliberately has no confidence field; `derive_confidence()`
   computes it from evidence coverage and branch completion. A self-reported "0.95" is
   a fluent sentence, not a measurement.

3. MISSING EVIDENCE IS REPRESENTED, NOT OMITTED. A branch that failed appears as a
   SKIPPED/FAILED `BranchOutput` and its gap is listed in `missing_evidence`, so a
   partial investigation reads as partial instead of quietly looking complete.

Everything is JSON-serialisable: LangGraph checkpoints the state to Postgres between
nodes, so a value that cannot round-trip through JSON cannot be resumed after a restart.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Bump on any breaking change to the shapes below. Persisted on every report so a stored
# investigation can always be read back by the contract that produced it.
CONTRACT_VERSION = "1.0.0"


# --------------------------------------------------------------------------- taxonomies

class Disposition(str, Enum):
    """The canonical verdict set. Used by the graph, the API, the console and the
    evaluation harness — one vocabulary, so macro-F1 means the same thing everywhere."""

    ESCALATE = "ESCALATE"
    MONITOR = "MONITOR"
    DISMISS = "DISMISS"
    # Not a failure: refusing to guess without evidence is a correct outcome, and the
    # evaluation scores abstention quality explicitly.
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SubjectType(str, Enum):
    FINDING = "finding"
    INCIDENT = "incident"


class TriggerType(str, Enum):
    MANUAL = "manual"
    AUTOMATIC = "automatic"


class InvestigationStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"      # finished, but at least one evidence branch did not land
    FAILED = "failed"
    CANCELLED = "cancelled"


class NodeStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    SKIPPED = "skipped"      # router decided it was not applicable — not an error
    FAILED = "failed"


class SourceType(str, Enum):
    """Where a piece of evidence came from. Deliberately granular: the evaluation
    measures retrieval recall per source, and the console groups the inspector by it."""

    FINDING = "finding"
    ASSET = "asset"
    EXPLANATION = "explanation"          # SHAP factors from finding_explanations
    FUSION_CLUSTER = "fusion_cluster"    # multi-tool corroboration
    ATTACK_MAPPING = "attack_mapping"    # MITRE ATT&CK technique
    THREAT_INTEL = "threat_intel"        # IOC match / sighting
    HISTORICAL_FINDING = "historical_finding"
    COMPLIANCE = "compliance"


class TLP(str, Enum):
    """Traffic Light Protocol. Intel carries handling restrictions; a report that
    aggregates AMBER+STRICT evidence must not be shared more widely than its sources."""

    CLEAR = "TLP:CLEAR"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    AMBER_STRICT = "TLP:AMBER+STRICT"
    RED = "TLP:RED"


class Completeness(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------- evidence

class Evidence(BaseModel):
    """One frozen, addressable fact.

    Evidence is a SNAPSHOT, not a pointer. A report written today must still be readable
    in six months even though the underlying finding has been rescored, retriaged or
    deleted — so the payload is copied in and hashed, and `source_reference` is kept only
    for provenance, not for re-reading at render time.
    """

    model_config = ConfigDict(frozen=True)

    citation_id: str = Field(description="Stable within one investigation, e.g. 'E3'")
    source_type: SourceType
    source_reference: str = Field(description="Provenance, e.g. 'findings:12'")
    structured_payload: dict = Field(description="The frozen snapshot itself")
    content_hash: str = Field(description="sha256 of the canonical payload")
    observed_at: datetime | None = Field(
        default=None, description="When the fact was true in the world (not when we read it)"
    )
    collected_at: datetime = Field(default_factory=_utcnow)
    source_tool: str | None = None
    tlp: TLP = TLP.AMBER

    @staticmethod
    def hash_payload(payload: dict) -> str:
        """Canonical JSON → sha256. Sorted keys and no insignificant whitespace, so an
        identical fact hashes identically regardless of dict ordering."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        citation_id: str,
        source_type: SourceType,
        source_reference: str,
        payload: dict,
        *,
        observed_at: datetime | None = None,
        source_tool: str | None = None,
        tlp: TLP = TLP.AMBER,
    ) -> "Evidence":
        return cls(
            citation_id=citation_id,
            source_type=source_type,
            source_reference=source_reference,
            structured_payload=payload,
            content_hash=cls.hash_payload(payload),
            observed_at=observed_at,
            source_tool=source_tool,
            tlp=tlp,
        )

    def verify(self) -> bool:
        """Re-hash the payload — detects tampering or an in-place mutation."""
        return self.hash_payload(self.structured_payload) == self.content_hash


# ------------------------------------------------------------------------ node results

class BranchOutput(BaseModel):
    """What one specialist node produced. Persisted per node so the console can show the
    graph as it actually executed, including the branches that did not run and why."""

    node: str
    status: NodeStatus
    evidence_ids: list[str] = Field(default_factory=list)
    summary: str | None = None
    # Why a node was skipped or failed. Required reading for the analyst: "no historical
    # matches" and "the history query timed out" look identical in a report otherwise.
    reason: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
    attempt: int = 1

    @property
    def contributed(self) -> bool:
        return self.status is NodeStatus.SUCCEEDED


# ---------------------------------------------------------------------------- synthesis

class Claim(BaseModel):
    """A single factual assertion plus the evidence that supports it.

    `min_length=1` is the enforcement point for "no uncited claims" — an unsupported
    claim raises at construction rather than reaching a report.
    """

    text: str = Field(min_length=1)
    citation_ids: list[str] = Field(min_length=1)

    @field_validator("citation_ids")
    @classmethod
    def _no_blank_ids(cls, v: list[str]) -> list[str]:
        cleaned = [c.strip() for c in v if c and c.strip()]
        if not cleaned:
            raise ValueError("a claim must cite at least one non-empty citation_id")
        return cleaned


class SynthesisOutput(BaseModel):
    """EXACTLY what the LLM is permitted to return — the JSON schema handed to Ollama.

    Note what is absent: confidence, every *_version field, and completeness. Those are
    computed from observed execution, not asserted by the model. Keeping the model's
    output surface this small is also what makes one bounded repair attempt realistic.
    """

    model_config = ConfigDict(extra="forbid")   # unknown keys are a schema violation

    recommended_severity: Severity
    recommended_disposition: Disposition
    summary: str = Field(min_length=1)
    rationale_claims: list[Claim] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class TriageReport(BaseModel):
    """The persisted, analyst-facing verdict: model output plus everything we derived."""

    recommended_severity: Severity
    recommended_disposition: Disposition
    confidence: float = Field(ge=0.0, le=1.0, description="DERIVED — see derive_confidence()")
    summary: str
    rationale_claims: list[Claim] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    completeness: Completeness = Completeness.COMPLETE

    graph_version: str
    prompt_version: str
    model_name: str
    model_digest: str | None = None
    contract_version: str = CONTRACT_VERSION
    created_at: datetime = Field(default_factory=_utcnow)

    @property
    def abstained(self) -> bool:
        return self.recommended_disposition is Disposition.INSUFFICIENT_EVIDENCE


# ------------------------------------------------------------------------------- state

class InvestigationState(BaseModel):
    """The LangGraph state object, checkpointed to Postgres between nodes.

    Must stay JSON round-trippable — anything that cannot be serialised cannot be resumed
    after an orchestrator restart, which is the whole point of checkpointing.
    """

    investigation_id: str
    subject_type: SubjectType
    subject_id: int
    trigger_type: TriggerType

    # Why this investigation exists, captured at request time. Without the snapshot an
    # automatic trigger is unexplainable later, because the score has since moved on.
    trigger_score_snapshot: float | None = None
    trigger_policy_version: str | None = None

    finding_snapshot: dict = Field(default_factory=dict)
    routing_plan: list[str] = Field(default_factory=list)
    branch_outputs: dict[str, BranchOutput] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    report: TriageReport | None = None
    errors: list[str] = Field(default_factory=list)

    status: InvestigationStatus = InvestigationStatus.QUEUED
    graph_version: str = "0.1.0"
    prompt_version: str = "0.1.0"
    model_name: str | None = None
    model_digest: str | None = None
    contract_version: str = CONTRACT_VERSION
    requested_by: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)

    def evidence_index(self) -> dict[str, Evidence]:
        return {e.citation_id: e for e in self.evidence}


# -------------------------------------------------------------------------- validation

def unresolved_citations(report: TriageReport, evidence: list[Evidence]) -> list[str]:
    """Citation ids referenced by claims that no evidence record provides.

    This is the citation validator's core check. A non-empty result means the model
    invented a reference, and the report must be downgraded rather than shown as-is —
    a fabricated citation is more dangerous than a missing one, because it looks rigorous.
    """
    known = {e.citation_id for e in evidence}
    missing: list[str] = []
    for claim in report.rationale_claims:
        for cid in claim.citation_ids:
            if cid not in known and cid not in missing:
                missing.append(cid)
    return missing


def derive_confidence(
    *,
    branches_expected: int,
    branches_succeeded: int,
    evidence_count: int,
    corroborated: bool = False,
    abstained: bool = False,
) -> float:
    """Confidence from observed execution, never from the model's self-report.

    Deliberately simple and explainable — in a viva this has to be defensible line by
    line, and a fitted function over 36 findings would not be:

      coverage  (0.6) — fraction of planned evidence branches that actually succeeded
      evidence  (0.3) — saturating at 5 records, so volume helps but cannot dominate
      corroboration (0.1) — independent tools agreeing on the same finding

    Abstention caps at 0.5: declining to decide is a valid answer, but it is not a
    confident one, and the number must not read as certainty about uncertainty.
    """
    if branches_expected <= 0:
        return 0.0
    coverage = max(0.0, min(1.0, branches_succeeded / branches_expected))
    volume = max(0.0, min(1.0, evidence_count / 5.0))
    score = 0.6 * coverage + 0.3 * volume + (0.1 if corroborated else 0.0)
    if abstained:
        score = min(score, 0.5)
    return round(max(0.0, min(1.0, score)), 3)
