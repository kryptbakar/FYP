"""The investigation graph.

    START -> load_subject -> route -+-> asset_context  -+
                                    +-> attack_context -+
                                    +-> intel_context  -+-> synthesize -> validate -> END
                                    +-> fusion_context -+
                                    +-> historical     -+

One deterministic router, five specialist evidence nodes running in parallel, one LLM
synthesis step, one deterministic validator.

WHAT IS AND IS NOT AN "AGENT" HERE
----------------------------------
Only `synthesize` consults a model. The five specialists are plain SQL retrieval, and the
router and validator are branching logic. That is a deliberate design position, not a
shortcut: everything feeding the model is code that can be read, unit-tested and defended
line by line, so "the model decided" is never the explanation for a verdict. Optional LLM
assistance inside Intel/Historical is a later, feature-flagged experiment that has to earn
its place against this baseline.

Design rules this file enforces rather than hopes for:

* Evidence is collected BEFORE the model is consulted, and the model sees only that
  evidence. It cannot cite what it was never given.
* Branches are independent. One failing is a degraded investigation, not a failed one —
  it records why, and confidence falls because coverage fell.
* `SynthesisOutput` has no confidence field; confidence is derived here from branch
  coverage. A model's self-reported certainty is a fluent sentence, not a measurement.
* A claim citing an id the evidence set does not contain is dropped and the report
  downgraded. A fabricated citation looks MORE rigorous than a missing one, which is
  exactly why it must be caught mechanically.

CITATION ID SCHEME
------------------
Each branch owns a prefix (F/X/A/T/I/C/H). Parallel branches therefore never collide on
an id without needing to coordinate, and the prefix tells the analyst where a citation
came from before they click it.
"""
from __future__ import annotations

import logging
import operator
import time
from typing import Annotated, Any, TypedDict

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
)

log = logging.getLogger("orchestrator.graph")

# MEASURED 2026-08-28, llama3.2:3b, finding 3371 (MISP IOC on lab-vm-01): the model
# abstained citing "the model's top factors and contribution values are not provided" —
# but that evidence record contained five weighted SHAP factors and ml_risk_score 69.24.
# The pipeline was correct; the 3B model misread its own context. Schema compliance and
# citation discipline were fine, so the failure is comprehension, not format.
#
# Do not "fix" this by inflating the prompt. It is the exact quality gap the Phase 0 model
# benchmark exists to measure (llama3.2:3b vs Qwen3 4B), and a benchmark is how the choice
# gets made — not prompt-tinkering against a single case.
#
# RE-MEASURED 2026-08-28 after the Phase 2 split, finding 4289, 9 evidence records from
# five specialists (was 4 from one node): 128.4s, zero unresolved citations, completeness
# 'complete', and the reasoning improved markedly — it now names which branches were and
# were not persuasive ("the IOC match and threat intel are consistent, but the asset's
# compliance and historical findings do not provide sufficient context").
#
# It nonetheless still returned INSUFFICIENT_EVIDENCE on a finding with three-tool
# corroboration and a Cobalt Strike C2 IOC, where an analyst would escalate, and made no
# cited claims at all. So: richer evidence bought better-articulated reasoning, not a
# better verdict. That is a model-capability ceiling rather than an evidence problem, and
# it is the strongest argument yet for running the benchmark before tuning anything else.
SYSTEM = (
    "You are VYREX, a senior SOC analyst performing triage in an air-gapped environment. "
    "You are given a numbered EVIDENCE list and nothing else. Every factual claim you make "
    "must cite at least one evidence id (e.g. F1, A1, C2). Do not state anything the "
    "evidence does not support, and do not invent evidence ids. If the evidence is "
    "insufficient to decide, return disposition INSUFFICIENT_EVIDENCE and say what is "
    "missing. You may PROPOSE containment but must never claim to have executed anything: "
    "containment requires two-person approval in VYREX. Reply with ONLY the JSON object."
)

SPECIALISTS = ("asset_context", "attack_context", "intel_context",
               "fusion_context", "historical_context")
# Confidence denominator: the subject snapshot, whichever specialists the router selected,
# and synthesis. Computed per-run rather than fixed, so skipping an inapplicable branch
# does not look like a failed one.
CORE_BRANCHES = ("load_subject", "synthesize")


def _merge(a: dict | None, b: dict | None) -> dict:
    """Reducer for dict state written by parallel branches (last write per key wins)."""
    return {**(a or {}), **(b or {})}


class InvState(TypedDict, total=False):
    """The graph's state schema.

    Declared, not a bare `dict`: with an untyped state LangGraph drops keys a node did not
    return, so `investigation_id` vanished after the first node and the router raised
    KeyError.

    `evidence`, `errors` and `branch_outputs` carry reducers because the specialists run in
    PARALLEL — without them the branches would overwrite each other's contributions and
    only the last one to finish would survive.

    Everything is JSON-serialisable: this is checkpointed to Postgres between nodes, and
    anything that cannot round-trip cannot be resumed after a restart.
    """

    investigation_id: str
    subject_type: str
    subject_id: int
    subject: dict
    plan: list[str]
    evidence: Annotated[list[dict], operator.add]
    branch_outputs: Annotated[dict[str, str], _merge]
    errors: Annotated[list[str], operator.add]
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


def _pack(items: list[Evidence]) -> list[dict]:
    return [e.model_dump(mode="json") for e in items]


def build_graph(deps: dict[str, Any], checkpointer=None):
    """Compile the graph. `deps` carries the repository, connection, LLM and settings.

    Injected rather than imported so tests can supply a FakeLLM and an in-memory
    checkpointer without patching module globals.
    """
    repo, pg, llm, settings = deps["repo"], deps["pg"], deps["llm"], deps["settings"]

    def _step(inv, node, status, **kw):
        repo.upsert_step(pg, inv, node, status, **kw)

    def specialist(name: str, prefix: str):
        """Wrap a specialist body with the bookkeeping every branch needs.

        Uniform handling of timing, step rows, evidence persistence and failure isolation,
        so a new node is a query plus a mapping — and so one branch raising can never take
        the investigation down with it.
        """
        def decorate(fn):
            def run(state: InvState) -> dict:
                inv = state["investigation_id"]
                t0 = time.time()
                _step(inv, name, "running", started=True)
                try:
                    items, reason = fn(state, prefix)
                except Exception as e:  # noqa: BLE001
                    log.exception("%s failed", name)
                    _step(inv, name, "failed", reason=f"{type(e).__name__}: {e}",
                          duration_ms=int((time.time() - t0) * 1000), finished=True)
                    return {"branch_outputs": {name: "failed"},
                            "errors": [f"{name}: {type(e).__name__}"]}
                ms = int((time.time() - t0) * 1000)
                if not items:
                    # "Found nothing" is a real result and must stay distinguishable from
                    # "crashed" — that distinction is what agent_runs' single blob destroyed.
                    _step(inv, name, "skipped", reason=reason or "no data",
                          duration_ms=ms, finished=True)
                    return {"branch_outputs": {name: "skipped"}}
                repo.save_evidence(pg, inv, _pack(items))
                _step(inv, name, "succeeded", evidence_ids=[e.citation_id for e in items],
                      output={"collected": len(items)}, duration_ms=ms, finished=True)
                return {"evidence": _pack(items), "branch_outputs": {name: "succeeded"}}
            return run
        return decorate

    # -- subject snapshot ---------------------------------------------------------------
    def load_subject(state: InvState) -> dict:
        inv, sid = state["investigation_id"], state["subject_id"]
        t0 = time.time()
        _step(inv, "load_subject", "running", started=True)
        subject = repo.load_subject(pg, state["subject_type"], sid)
        if not subject:
            _step(inv, "load_subject", "failed", reason=f"subject {sid} no longer exists",
                  finished=True)
            return {"branch_outputs": {"load_subject": "failed"},
                    "errors": [f"subject {sid} not found"]}

        items = [Evidence.create(
            "F1", SourceType.FINDING, f"{state['subject_type']}s:{sid}",
            {k: str(v) if v is not None else None for k, v in subject.items()
             if k in ("id", "title", "severity", "cve_id", "risk_score", "kev", "cvss_score",
                      "epss", "attack", "asset_id", "source_tool", "description",
                      "exploit_available", "triage_status", "port")},
            source_tool=subject.get("source_tool"))]

        # Reuse the SHAP attribution the risk engine already computed rather than
        # recomputing it — slower, and a second source of truth for the same number.
        exp = repo.load_explanation(pg, sid) if state["subject_type"] == "finding" else None
        if exp:
            items.append(Evidence.create(
                "X1", SourceType.EXPLANATION, f"finding_explanations:{sid}",
                {"ml_risk_score": str(exp.get("ml_risk_score")),
                 "top_factors": exp.get("top_factors"),
                 "model_version": exp.get("model_version")},
                source_tool="risk-engine"))

        repo.save_evidence(pg, inv, _pack(items))
        _step(inv, "load_subject", "succeeded", evidence_ids=[e.citation_id for e in items],
              output={"collected": len(items)},
              duration_ms=int((time.time() - t0) * 1000), finished=True)
        return {"subject": {k: str(v) if v is not None else None for k, v in subject.items()},
                "evidence": _pack(items), "branch_outputs": {"load_subject": "succeeded"}}

    # -- specialists --------------------------------------------------------------------
    @specialist("asset_context", "A")
    def asset_context(state, p):
        subj = state.get("subject") or {}
        host = subj.get("asset_id")
        if not host:
            return [], "finding is not attached to an asset"
        asset = repo.load_asset(pg, host)
        if not asset:
            return [], f"asset {host} not in inventory"
        out = [Evidence.create(f"{p}1", SourceType.ASSET, f"assets:{host}",
                               {k: str(v) for k, v in asset.items()
                                if k in ("host_id", "hostname", "os", "ip", "criticality")})]
        comp = repo.load_compliance(pg, host)
        if comp and comp.get("total"):
            out.append(Evidence.create(
                f"{p}2", SourceType.COMPLIANCE, f"compliance_results:{host}",
                {"failed": comp["failed"], "passed": comp["passed"], "total": comp["total"],
                 "note": "a weak control posture amplifies any finding on this host"}))
        return out, None

    @specialist("attack_context", "T")
    def attack_context(state, p):
        tech = (state.get("subject") or {}).get("attack")
        if not tech:
            return [], "finding has no ATT&CK technique mapped"
        ctx = repo.load_attack_context(pg, tech)
        return [Evidence.create(
            f"{p}1", SourceType.ATTACK_MAPPING, f"attack:{tech}",
            {"technique": tech, "findings_with_technique": ctx.get("findings"),
             "assets_affected": ctx.get("assets"), "high_severity": ctx.get("high_sev"),
             "note": "prevalence across the estate; widespread use reads differently "
                     "from a single host"})], None

    @specialist("intel_context", "I")
    def intel_context(state, p):
        subj = state.get("subject") or {}
        out: list[Evidence] = []
        raw = repo.load_subject(pg, state["subject_type"], state["subject_id"]) or {}
        if raw.get("threat_intel"):
            out.append(Evidence.create(
                f"{p}1", SourceType.THREAT_INTEL, f"findings:{state['subject_id']}:threat_intel",
                dict(raw["threat_intel"]), source_tool="misp"))
        host = subj.get("asset_id")
        if host:
            others = [s for s in repo.load_intel_sightings(pg, host)
                      if s["id"] != state["subject_id"]]
            if others:
                out.append(Evidence.create(
                    f"{p}2", SourceType.THREAT_INTEL, f"intel_sightings:{host}",
                    {"other_intel_hits_on_this_asset": len(others),
                     "indicators": [o["indicator"] for o in others[:5] if o["indicator"]],
                     "note": "a pattern of hits on one asset is stronger than an "
                             "isolated match"}))
        return out, "no threat-intel context for this finding or asset"

    @specialist("fusion_context", "C")
    def fusion_context(state, p):
        """Multi-tool corroboration — only meaningful since the observable_key fix.

        Before 2026-08-28 this branch would have returned nothing on real data: findings
        clustered on the rule that fired, so tools never agreed. See ml/FUSION.md.
        """
        siblings = repo.load_fusion_cluster(pg, state["subject_id"])
        if not siblings:
            return [], "no other tool reported this observable"
        tools = sorted({s["source_tool"] for s in siblings if s["source_tool"]})
        return [Evidence.create(
            f"{p}1", SourceType.FUSION_CLUSTER, f"fusion:{state['subject_id']}",
            {"corroborating_tools": tools, "distinct_tools": len(tools),
             "sibling_findings": [{"id": s["id"], "tool": s["source_tool"],
                                   "severity": s["severity"], "title": (s["title"] or "")[:80]}
                                  for s in siblings[:6]],
             "note": "independent tools describing the SAME observable; corroboration "
                     "raises confidence that this is real, not noise"})], None

    @specialist("historical_context", "H")
    def historical_context(state, p):
        """Prior similar findings and how they were triaged.

        Expect this to skip often on a small corpus. That is the honest outcome — the
        report says so and confidence drops, rather than the absence being invisible.
        """
        raw = repo.load_subject(pg, state["subject_type"], state["subject_id"]) or {}
        if state["subject_type"] != "finding":
            return [], "historical similarity is only defined for findings"
        similar = repo.load_historical(pg, raw)
        if not similar:
            return [], "no comparable prior findings"
        triaged = [s for s in similar if s.get("triage_status")]
        return [Evidence.create(
            f"{p}1", SourceType.HISTORICAL_FINDING, f"historical:{state['subject_id']}",
            {"similar_findings": len(similar),
             "previously_triaged": len(triaged),
             "prior_decisions": [{"id": s["id"], "relation": s["relation"],
                                  "triage_status": s["triage_status"],
                                  "asset": s["asset_id"]} for s in triaged[:5]],
             "examples": [{"id": s["id"], "relation": s["relation"],
                           "title": (s["title"] or "")[:70]} for s in similar[:5]],
             "note": "how comparable findings were handled before"})], None

    # -- router (deterministic) ----------------------------------------------------------
    def route(state: InvState) -> list[str]:
        """Which specialists apply. Returns a list, so LangGraph fans out in parallel.

        Cheap checks against the subject snapshot: running a branch that provably has no
        input wastes a query and produces a 'skipped' row that says nothing useful.
        """
        inv = state["investigation_id"]
        if state.get("branch_outputs", {}).get("load_subject") != "succeeded":
            _step(inv, "route", "succeeded", reason="subject unavailable -> abstain",
                  output={"plan": []}, started=True, finished=True)
            return ["abstain"]

        subj = state.get("subject") or {}
        plan = ["fusion_context"]                       # always: corroboration or its absence
        if subj.get("asset_id"):
            plan.append("asset_context")
        if subj.get("attack"):
            plan.append("attack_context")
        plan.append("intel_context")                    # decides internally; cheap
        if state["subject_type"] == "finding":
            plan.append("historical_context")

        _step(inv, "route", "succeeded",
              reason=f"{len(plan)} specialist branch(es) selected",
              output={"plan": plan}, started=True, finished=True)
        return plan

    # -- synthesis (the only LLM step) ---------------------------------------------------
    def synthesize(state: InvState) -> dict:
        inv = state["investigation_id"]
        t0 = time.time()
        _step(inv, "synthesize", "running", started=True)
        evidence = _ev(state)
        if not evidence:
            _step(inv, "synthesize", "skipped", reason="no evidence to reason over",
                  finished=True)
            return {"branch_outputs": {"synthesize": "skipped"}}
        prompt = (f"EVIDENCE:\n{_render(evidence)}\n\n"
                  f"Assess this {state['subject_type']} and return the JSON verdict.")
        out, err = llm_mod.synthesize(llm, SYSTEM, prompt)
        ms = int((time.time() - t0) * 1000)
        if out is None:
            _step(inv, "synthesize", "failed", reason=err, duration_ms=ms, finished=True)
            return {"branch_outputs": {"synthesize": "failed"},
                    "errors": [err or "synthesis failed"]}
        _step(inv, "synthesize", "succeeded", output=out.model_dump(mode="json"),
              duration_ms=ms, finished=True)
        return {"synthesis": out.model_dump(mode="json"),
                "branch_outputs": {"synthesize": "succeeded"}}

    def abstain(state: InvState) -> dict:
        _step(state["investigation_id"], "synthesize", "skipped",
              reason="insufficient evidence to consult the model", started=True, finished=True)
        return {"branch_outputs": {"synthesize": "skipped"}}

    # -- validator (deterministic) -------------------------------------------------------
    def validate(state: InvState) -> dict:
        inv = state["investigation_id"]
        t0 = time.time()
        _step(inv, "validate", "running", started=True)
        evidence = _ev(state)
        syn = state.get("synthesis")
        branches = state.get("branch_outputs", {})
        planned = list(CORE_BRANCHES) + [b for b in SPECIALISTS if b in branches]
        succeeded = sum(1 for b in planned if branches.get(b) == "succeeded")

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
            known = {e.citation_id for e in evidence}
            kept, dropped = [], []
            for c in syn.get("rationale_claims", []):
                valid = [cid for cid in c.get("citation_ids", []) if cid in known]
                (kept if valid else dropped).append(
                    {"text": c["text"], "citation_ids": valid} if valid else c)
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
                                 or succeeded < len(planned))
                                 else Completeness.COMPLETE).value,
            }
            if dropped:
                log.warning("dropped %d claim(s) citing unknown evidence: %s",
                            len(dropped), unresolved)

        abstained = report["recommended_disposition"] == Disposition.INSUFFICIENT_EVIDENCE.value
        report["confidence"] = derive_confidence(
            branches_expected=len(planned), branches_succeeded=succeeded,
            evidence_count=len(evidence),
            corroborated=any(e.source_type == SourceType.FUSION_CLUSTER for e in evidence),
            abstained=abstained)
        report.update(graph_version=settings.graph_version,
                      prompt_version=settings.prompt_version,
                      model_name=llm.name, contract_version=CONTRACT_VERSION)

        repo.save_report(pg, inv, report, unresolved)
        _step(inv, "validate", "succeeded",
              output={"unresolved_citations": unresolved,
                      "completeness": report["completeness"],
                      "confidence": report["confidence"],
                      "branches": {b: branches.get(b) for b in planned}},
              duration_ms=int((time.time() - t0) * 1000), finished=True)
        return {"report": report, "unresolved": unresolved,
                "branch_outputs": {"validate": "succeeded"}}

    g = StateGraph(InvState)
    g.add_node("load_subject", load_subject)
    g.add_node("asset_context", asset_context)
    g.add_node("attack_context", attack_context)
    g.add_node("intel_context", intel_context)
    g.add_node("fusion_context", fusion_context)
    g.add_node("historical_context", historical_context)
    g.add_node("synthesize", synthesize)
    g.add_node("abstain", abstain)
    g.add_node("validate", validate)

    g.add_edge(START, "load_subject")
    g.add_conditional_edges("load_subject", route,
                            {**{s: s for s in SPECIALISTS}, "abstain": "abstain"})
    # Fan-in: LangGraph waits for every selected specialist before synthesising, so the
    # model always sees the complete evidence set rather than a race-dependent subset.
    for s in SPECIALISTS:
        g.add_edge(s, "synthesize")
    g.add_edge("synthesize", "validate")
    g.add_edge("abstain", "validate")
    g.add_edge("validate", END)
    return g.compile(checkpointer=checkpointer)
