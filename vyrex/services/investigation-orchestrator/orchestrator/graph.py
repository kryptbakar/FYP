"""The investigation graph.

Phase 1 topology — one deterministic router, one evidence node, one LLM synthesis node,
one deterministic validator:

    START -> load_evidence -> route -+-> synthesize -> validate -> END
                                     |                    ^
                                     +--> (abstain) ------+

The Phase 2 specialists (ATT&CK, Intel, Historical, Asset) slot in between `route` and
`synthesize` as parallel branches. The shape is already here so adding them does not
require rewiring: each will append to `evidence` and write its own `branch_outputs`
entry, and `validate` already handles a partial evidence set.

Design rules this file enforces, rather than hopes for:

* Evidence is collected BEFORE the model is consulted, and the model is shown only that
  evidence. It cannot cite what it was never given.
* The model's output is validated against `SynthesisOutput`, which has no confidence
  field. Confidence is computed here from branch coverage.
* Any claim citing an id the evidence set does not contain is dropped, and the report is
  downgraded to partial. A fabricated citation looks *more* rigorous than a missing one,
  which is exactly why it has to be caught mechanically.
"""
from __future__ import annotations

import logging
import time
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from . import llm as llm_mod
from .models import (
    CONTRACT_VERSION,
    Completeness,
    Disposition,
    Evidence,
    Severity,
    SourceType,
    derive_confidence,
    unresolved_citations,
)

log = logging.getLogger("orchestrator.graph")

# MEASURED 2026-08-28, llama3.2:3b, finding 3371 (MISP IOC on lab-vm-01):
# the model abstained citing "the model's top factors and contribution values are not
# provided" - but E2 contained exactly that (5 weighted SHAP factors + ml_risk_score
# 69.24). The evidence pipeline was correct; the 3B model misread its own context and
# hallucinated an absence. Schema compliance and citation discipline were fine (zero
# unresolved citations), so the failure is comprehension, not format.
#
# Do not "fix" this by inflating the prompt. It is the exact quality gap the Phase 0
# model benchmark exists to measure (llama3.2:3b vs Qwen3 4B), and a benchmark is how
# the choice gets made - not prompt-tinkering against a single case.
SYSTEM = (
    "You are VYREX, a senior SOC analyst performing triage in an air-gapped environment. "
    "You are given a numbered EVIDENCE list and nothing else. Every factual claim you make "
    "must cite at least one evidence id (e.g. E1). Do not state anything the evidence does "
    "not support, and do not invent evidence ids. If the evidence is insufficient to decide, "
    "return disposition INSUFFICIENT_EVIDENCE and say what is missing. You may PROPOSE "
    "containment but must never claim to have executed anything: containment requires "
    "two-person approval in VYREX. Reply with ONLY the JSON object."
)

# The branches whose success determines confidence. Phase 2 extends this list; the
# denominator moving is intentional, because confidence should fall when a source that
# was supposed to contribute did not.
EXPECTED_BRANCHES = ("load_evidence", "synthesize")


class InvState(TypedDict, total=False):
    """The graph's state schema.

    Declared rather than a bare `dict`: with an untyped state LangGraph does not know
    which keys exist, so a node returning a partial update drops everything it did not
    mention — `investigation_id` vanished after the first node and the router raised
    KeyError. With the keys declared, updates merge.

    Every field is JSON-serialisable because this is checkpointed to Postgres between
    nodes; anything that cannot round-trip cannot be resumed after a restart.
    """

    investigation_id: str
    subject_type: str
    subject_id: int
    evidence: list[dict]
    branch_outputs: dict[str, str]
    errors: list[str]
    synthesis: dict
    report: dict
    unresolved: list[str]


def _ev(state: InvState) -> list[Evidence]:
    return [e if isinstance(e, Evidence) else Evidence(**e) for e in state.get("evidence", [])]


def _render(evidence: list[Evidence]) -> str:
    lines = []
    for e in evidence:
        payload = {k: v for k, v in e.structured_payload.items() if v not in (None, "", [], {})}
        lines.append(f"{e.citation_id}: [{e.source_type.value}] {payload}")
    return "\n".join(lines)


def build_graph(deps: dict[str, Any], checkpointer=None):
    """Compile the graph. `deps` carries the repository handle, the LLM and settings.

    Passed in rather than imported so tests can inject a FakeLLM and an in-memory
    checkpointer without patching module globals.
    """
    repo, pg, llm, settings = deps["repo"], deps["pg"], deps["llm"], deps["settings"]

    def _step(state, node, status, **kw):
        repo.upsert_step(pg, state["investigation_id"], node, status, **kw)

    # -- 1. Evidence -------------------------------------------------------------------
    def load_evidence(state: InvState) -> dict:
        t0 = time.time()
        _step(state, "load_evidence", "running", started=True)
        inv, sid = state["investigation_id"], state["subject_id"]
        items: list[Evidence] = []
        n = 0

        subject = repo.load_subject(pg, state["subject_type"], sid)
        if not subject:
            _step(state, "load_evidence", "failed", reason=f"subject {sid} no longer exists",
                  finished=True)
            return {"branch_outputs": {**state.get("branch_outputs", {}),
                                       "load_evidence": "failed"},
                    "errors": state.get("errors", []) + [f"subject {sid} not found"]}

        n += 1
        items.append(Evidence.create(
            f"E{n}", SourceType.FINDING, f"{state['subject_type']}s:{sid}",
            {k: str(v) if v is not None else None for k, v in subject.items()
             if k in ("id", "title", "severity", "cve_id", "risk_score", "kev", "cvss_score",
                      "epss", "attack", "asset_id", "source_tool", "description",
                      "exploit_available", "triage_status")},
            source_tool=subject.get("source_tool")))

        # Reuse the SHAP attribution the risk engine already computed. Recomputing it
        # here would be both slower and a second source of truth for the same number.
        exp = repo.load_explanation(pg, sid) if state["subject_type"] == "finding" else None
        if exp:
            n += 1
            items.append(Evidence.create(
                f"E{n}", SourceType.EXPLANATION, f"finding_explanations:{sid}",
                {"ml_risk_score": str(exp.get("ml_risk_score")),
                 "top_factors": exp.get("top_factors"),
                 "model_version": exp.get("model_version")},
                source_tool="risk-engine"))

        if subject.get("asset_id"):
            asset = repo.load_asset(pg, subject["asset_id"])
            if asset:
                n += 1
                items.append(Evidence.create(
                    f"E{n}", SourceType.ASSET, f"assets:{asset['host_id']}",
                    {k: str(v) for k, v in asset.items()
                     if k in ("host_id", "hostname", "os", "ip", "criticality")}))

        if subject.get("threat_intel"):
            n += 1
            items.append(Evidence.create(
                f"E{n}", SourceType.THREAT_INTEL, f"findings:{sid}:threat_intel",
                dict(subject["threat_intel"]), source_tool="misp"))

        repo.save_evidence(pg, inv, [e.model_dump(mode="json") for e in items])
        _step(state, "load_evidence", "succeeded",
              evidence_ids=[e.citation_id for e in items],
              output={"collected": len(items)},
              duration_ms=int((time.time() - t0) * 1000), finished=True)
        return {"evidence": [e.model_dump(mode="json") for e in items],
                "branch_outputs": {**state.get("branch_outputs", {}),
                                   "load_evidence": "succeeded"}}

    # -- 2. Router (deterministic) ------------------------------------------------------
    def route(state: InvState) -> str:
        """Enough evidence to ask the model? Otherwise abstain without spending 90s on it."""
        ok = state.get("branch_outputs", {}).get("load_evidence") == "succeeded"
        n = len(state.get("evidence", []))
        decision = "synthesize" if (ok and n) else "abstain"
        repo.upsert_step(pg, state["investigation_id"], "route", "succeeded",
                         reason=f"{n} evidence record(s) -> {decision}",
                         output={"decision": decision, "evidence_count": n},
                         started=True, finished=True)
        return decision

    # -- 3. Synthesis (the only LLM step) ----------------------------------------------
    def synthesize(state: InvState) -> dict:
        t0 = time.time()
        _step(state, "synthesize", "running", started=True)
        evidence = _ev(state)
        prompt = (
            f"EVIDENCE:\n{_render(evidence)}\n\n"
            f"Assess this {state['subject_type']} and return the JSON verdict."
        )
        out, err = llm_mod.synthesize(llm, SYSTEM, prompt)
        ms = int((time.time() - t0) * 1000)
        if out is None:
            # Not a crash: abstain with the reason recorded, so the console can show
            # WHY there is no verdict rather than an empty panel.
            _step(state, "synthesize", "failed", reason=err, duration_ms=ms, finished=True)
            return {"branch_outputs": {**state.get("branch_outputs", {}),
                                       "synthesize": "failed"},
                    "errors": state.get("errors", []) + [err or "synthesis failed"]}
        _step(state, "synthesize", "succeeded", output=out.model_dump(mode="json"),
              duration_ms=ms, finished=True)
        return {"synthesis": out.model_dump(mode="json"),
                "branch_outputs": {**state.get("branch_outputs", {}),
                                   "synthesize": "succeeded"}}

    def abstain(state: InvState) -> dict:
        repo.upsert_step(pg, state["investigation_id"], "synthesize", "skipped",
                         reason="insufficient evidence to consult the model",
                         started=True, finished=True)
        return {"branch_outputs": {**state.get("branch_outputs", {}),
                                   "synthesize": "skipped"}}

    # -- 4. Validator (deterministic) ---------------------------------------------------
    def validate(state: InvState) -> dict:
        t0 = time.time()
        _step(state, "validate", "running", started=True)
        evidence = _ev(state)
        syn = state.get("synthesis")
        branches = state.get("branch_outputs", {})
        succeeded = sum(1 for b in EXPECTED_BRANCHES if branches.get(b) == "succeeded")

        if not syn:
            report = {
                "recommended_severity": Severity.INFO.value,
                "recommended_disposition": Disposition.INSUFFICIENT_EVIDENCE.value,
                "summary": "No verdict: " + "; ".join(state.get("errors", [])
                                                      or ["synthesis did not run"]),
                "rationale_claims": [], "recommended_next_steps": [],
                "missing_evidence": ["model synthesis unavailable"],
                "completeness": Completeness.PARTIAL.value,
            }
            unresolved: list[str] = []
        else:
            # Drop claims citing evidence that does not exist, then note it. Keeping an
            # unresolvable citation would present a fabrication as sourced.
            known = {e.citation_id for e in evidence}
            kept, dropped = [], []
            for c in syn.get("rationale_claims", []):
                valid = [cid for cid in c.get("citation_ids", []) if cid in known]
                if valid:
                    kept.append({"text": c["text"], "citation_ids": valid})
                else:
                    dropped.append(c)
            unresolved = sorted({cid for c in syn.get("rationale_claims", [])
                                 for cid in c.get("citation_ids", []) if cid not in known})
            report = {
                "recommended_severity": syn["recommended_severity"],
                "recommended_disposition": syn["recommended_disposition"],
                "summary": syn["summary"],
                "rationale_claims": kept,
                "recommended_next_steps": syn.get("recommended_next_steps", []),
                "missing_evidence": syn.get("missing_evidence", []),
                "completeness": (Completeness.PARTIAL if (dropped or unresolved
                                 or succeeded < len(EXPECTED_BRANCHES))
                                 else Completeness.COMPLETE).value,
            }
            if dropped:
                log.warning("dropped %d claim(s) citing unknown evidence: %s",
                            len(dropped), unresolved)

        abstained = report["recommended_disposition"] == Disposition.INSUFFICIENT_EVIDENCE.value
        report["confidence"] = derive_confidence(
            branches_expected=len(EXPECTED_BRANCHES), branches_succeeded=succeeded,
            evidence_count=len(evidence),
            corroborated=any(e.source_type == SourceType.THREAT_INTEL for e in evidence),
            abstained=abstained)
        report.update(graph_version=settings.graph_version, prompt_version=settings.prompt_version,
                      model_name=llm.name, contract_version=CONTRACT_VERSION)

        repo.save_report(pg, state["investigation_id"], report, unresolved)
        _step(state, "validate", "succeeded",
              output={"unresolved_citations": unresolved,
                      "completeness": report["completeness"],
                      "confidence": report["confidence"]},
              duration_ms=int((time.time() - t0) * 1000), finished=True)
        return {"report": report, "unresolved": unresolved,
                "branch_outputs": {**branches, "validate": "succeeded"}}

    g = StateGraph(InvState)
    g.add_node("load_evidence", load_evidence)
    g.add_node("synthesize", synthesize)
    g.add_node("abstain", abstain)
    g.add_node("validate", validate)
    g.add_edge(START, "load_evidence")
    g.add_conditional_edges("load_evidence", route,
                            {"synthesize": "synthesize", "abstain": "abstain"})
    g.add_edge("synthesize", "validate")
    g.add_edge("abstain", "validate")
    g.add_edge("validate", END)
    return g.compile(checkpointer=checkpointer)
