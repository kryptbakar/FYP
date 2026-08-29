"""Model benchmark for the synthesis step.

    python -m orchestrator.benchmark --models llama3.2:3b,qwen3:4b --repeats 2

WHAT THIS MEASURES — AND WHAT IT DOES NOT
-----------------------------------------
It measures model BEHAVIOUR on VYREX's real prompt and real evidence:

  schema_valid     did it produce output matching SynthesisOutput at all
  needed_repair    did it take a second attempt to get there
  citation_valid   did every id it cited actually exist in the evidence
  uncited          did it reach a verdict while citing nothing
  abstain_rate     how often it declined to decide
  latency          p50 / p95 wall clock, CPU-only
  determinism      same input twice at temperature 0 -> same verdict?

It does NOT measure accuracy. That needs ground-truth labels, which this project does not
yet have (0 rows in analyst_feedback), and inventing them here — or scoring the model
against another model's opinion — would be exactly the circular evaluation that
docs/METHODOLOGY.md §4.1 already calls out in the ML layer. Accuracy is Phase 4, after
blinded labelling.

Everything above is objective and needs no labels, which is precisely why it is worth
running now: it is enough to CHOOSE a model, which is the decision actually blocked.

The prompt and evidence are the real ones — the same SYSTEM text and the same repository
queries the specialists use — so the only variable is the model.
"""
from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime, timezone

from . import llm as llm_mod
from . import repository as repo
from .config import settings
from .graph import SYSTEM, _render
from .llm import OllamaClient
from .models import Disposition, Evidence, SourceType


def collect_evidence(pg, finding_id: int) -> list[Evidence]:
    """Assemble the same evidence set the specialists would, for one finding.

    Deliberately independent of graph.py's node closures: a benchmark that imports the
    graph's internals breaks whenever the graph is refactored, and the point here is a
    stable yardstick across model comparisons over time.
    """
    out: list[Evidence] = []
    f = repo.load_subject(pg, "finding", finding_id)
    if not f:
        return out
    out.append(Evidence.create(
        "F1", SourceType.FINDING, f"findings:{finding_id}",
        {k: str(v) if v is not None else None for k, v in f.items()
         if k in ("id", "title", "severity", "cve_id", "risk_score", "kev", "cvss_score",
                  "epss", "attack", "asset_id", "source_tool", "description",
                  "exploit_available", "triage_status", "port")}))

    exp = repo.load_explanation(pg, finding_id)
    if exp:
        out.append(Evidence.create(
            "X1", SourceType.EXPLANATION, f"finding_explanations:{finding_id}",
            {"ml_risk_score": str(exp.get("ml_risk_score")),
             "top_factors": exp.get("top_factors")}))

    if f.get("asset_id"):
        a = repo.load_asset(pg, f["asset_id"])
        if a:
            # Mirrors graph.asset_context: exposure and criticality are ranks 3 and 4 in
            # the rubric's precedence, so the benchmark must show the model the same
            # business context the real graph does, or it is measuring a different task.
            out.append(Evidence.create(
                "A1", SourceType.ASSET, f"assets:{a['host_id']}",
                {k: str(v) for k, v in a.items()
                 if k in ("host_id", "hostname", "os", "ip", "criticality",
                          "internet_exposed", "environment", "data_sensitivity",
                          "business_service", "owner_team", "criticality_rationale")
                 and v is not None}))
        c = repo.load_compliance(pg, f["asset_id"])
        if c and c.get("total"):
            out.append(Evidence.create(
                "A2", SourceType.COMPLIANCE, f"compliance_results:{f['asset_id']}",
                {"failed": c["failed"], "passed": c["passed"], "total": c["total"]}))

    if f.get("attack"):
        ctx = repo.load_attack_context(pg, f["attack"])
        out.append(Evidence.create(
            "T1", SourceType.ATTACK_MAPPING, f"attack:{f['attack']}",
            {"technique": f["attack"], "findings_with_technique": ctx.get("findings"),
             "assets_affected": ctx.get("assets")}))

    if f.get("threat_intel"):
        out.append(Evidence.create(
            "I1", SourceType.THREAT_INTEL, f"findings:{finding_id}:threat_intel",
            dict(f["threat_intel"])))

    sib = repo.load_fusion_cluster(pg, finding_id)
    if sib:
        tools = sorted({s["source_tool"] for s in sib if s["source_tool"]})
        out.append(Evidence.create(
            "C1", SourceType.FUSION_CLUSTER, f"fusion:{finding_id}",
            {"corroborating_tools": tools, "distinct_tools": len(tools)}))

    hist = repo.load_historical(pg, f)
    if hist:
        out.append(Evidence.create(
            "H1", SourceType.HISTORICAL_FINDING, f"historical:{finding_id}",
            {"similar_findings": len(hist),
             "previously_triaged": len([h for h in hist if h.get("triage_status")])}))
    return out


def pick_cases(pg, limit: int) -> list[int]:
    """A spread of cases, not just the easy ones.

    Ordered so corroborated and intel-backed findings come first: those are where a model
    has the most to work with, and therefore where declining to decide is most revealing.
    """
    with pg.cursor() as cur:
        cur.execute(
            """SELECT id FROM findings
                ORDER BY (observable_key IS NOT NULL) DESC,
                         (threat_intel IS NOT NULL) DESC,
                         risk_score DESC NULLS LAST
                LIMIT %s""", (limit,))
        return [r["id"] for r in cur.fetchall()]


def run_case(llm, evidence: list[Evidence], subject_type: str = "finding") -> dict:
    prompt = (f"EVIDENCE:\n{_render(evidence)}\n\n"
              f"Assess this {subject_type} and return the JSON verdict.")
    known = {e.citation_id for e in evidence}
    t0 = time.time()
    calls_before = getattr(llm, "calls", None)
    out, err = llm_mod.synthesize(llm, SYSTEM, prompt)
    elapsed = time.time() - t0

    rec = {"latency_s": round(elapsed, 1), "schema_valid": out is not None, "error": err}
    if out is None:
        return rec

    cited = [cid for c in out.rationale_claims for cid in c.citation_ids]
    bad = [c for c in cited if c not in known]
    rec.update({
        "disposition": out.recommended_disposition.value,
        "severity": out.recommended_severity.value,
        "claims": len(out.rationale_claims),
        "cited": len(cited),
        "unresolved": bad,
        "citation_valid": (not bad) and bool(cited),
        "uncited": len(cited) == 0,
        "abstained": out.recommended_disposition is Disposition.INSUFFICIENT_EVIDENCE,
        "summary": out.summary[:160],
    })
    if calls_before is not None:
        rec["needed_repair"] = getattr(llm, "calls", 0) - calls_before > 1
    return rec


# Ablations. Each evidence record carries a citation prefix that identifies which
# specialist produced it, so a branch can be removed by dropping its prefix — no graph
# surgery, and the remaining evidence is byte-identical to a real run without that branch.
# This is what answers "does this specialist earn its place?" (EVALUATION-PROTOCOL §4).
ABLATIONS = {
    "asset": "A",        # asset + compliance context
    "attack": "X",       # ATT&CK / SHAP explanation
    "intel": "T",        # threat intel
    "fusion": "C",       # multi-tool corroboration
    "historical": "H",   # prior triage of similar findings
}


def ablate(evidence: list, drop: str | None) -> list:
    """Remove one specialist's evidence by citation prefix.

    NOTE what this does and does not measure. It ablates the EVIDENCE, not the retrieval:
    the specialist still ran, and its cost is unchanged. So it answers "does this evidence
    change the verdict?" and not "is this branch worth its latency" — the latter is
    already answered by B6 in BENCHMARKS.md, where every specialist costs tens of ms.
    """
    if not drop:
        return evidence
    prefix = ABLATIONS[drop]
    return [e for e in evidence if not e.citation_id.startswith(prefix)]


def benchmark(models: list[str], n_cases: int, repeats: int, drop: str | None = None) -> dict:
    pg = repo.connect(settings.postgres_dsn)
    case_ids = pick_cases(pg, n_cases)
    evidence = {cid: collect_evidence(pg, cid) for cid in case_ids}
    evidence = {k: ablate(v, drop) for k, v in evidence.items() if v}
    label = f" [ablation: -{drop}]" if drop else ""
    print(f"benchmark: {len(evidence)} case(s) x {len(models)} model(s) x {repeats} repeat(s){label}")
    print(f"evidence per case: {sorted({len(v) for v in evidence.values()})} records\n")

    results: dict[str, list[dict]] = {}
    for model in models:
        llm = OllamaClient(settings.ollama_url, model, settings.llm_timeout_s)
        rows: list[dict] = []
        for cid, ev in evidence.items():
            for r in range(repeats):
                rec = run_case(llm, ev)
                rec.update(finding_id=cid, model=model, run=r + 1)
                rows.append(rec)
                print(f"  {model:14} finding {cid:>5} run {r+1}: "
                      f"{rec.get('disposition', 'INVALID'):22} "
                      f"{rec['latency_s']:>6.1f}s "
                      f"cites={rec.get('cited', 0)} "
                      f"{'BAD-CITES' if rec.get('unresolved') else ''}")
        results[model] = rows
    pg.close()
    return results


def summarise(results: dict[str, list[dict]]) -> str:
    lines = ["", "## Model benchmark — synthesis step", "",
             f"_Measured {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}, CPU-only, "
             "temperature 0._", "",
             "**Behaviour only — not accuracy.** Accuracy requires ground-truth labels "
             "(analyst_feedback is empty); scoring a model against another model's opinion "
             "would repeat the circular evaluation documented in METHODOLOGY.md §4.1.", "",
             "| model | n | schema valid | citations valid | uncited verdicts | abstained | "
             "p50 s | p95 s | deterministic |",
             "|---|---|---|---|---|---|---|---|---|"]
    for model, rows in results.items():
        n = len(rows)
        ok = [r for r in rows if r["schema_valid"]]
        lat = sorted(r["latency_s"] for r in rows)
        p50 = statistics.median(lat) if lat else 0
        p95 = lat[max(0, int(len(lat) * 0.95) - 1)] if lat else 0
        # Determinism: at temperature 0 the same case must yield the same disposition.
        by_case: dict[int, set] = {}
        for r in ok:
            by_case.setdefault(r["finding_id"], set()).add(r.get("disposition"))
        repeated = {k: v for k, v in by_case.items() if len(v) > 0}
        stable = all(len(v) == 1 for v in repeated.values()) if repeated else True
        lines.append(
            f"| `{model}` | {n} | {len(ok)}/{n} | "
            f"{sum(1 for r in ok if r.get('citation_valid'))}/{len(ok) or 1} | "
            f"{sum(1 for r in ok if r.get('uncited'))}/{len(ok) or 1} | "
            f"{sum(1 for r in ok if r.get('abstained'))}/{len(ok) or 1} | "
            f"{p50:.1f} | {p95:.1f} | {'yes' if stable else 'NO'} |")
    lines += ["", "### Per-case dispositions", "",
              "| finding | " + " | ".join(f"`{m}`" for m in results) + " |",
              "|---|" + "---|" * len(results)]
    cases = sorted({r["finding_id"] for rows in results.values() for r in rows})
    for cid in cases:
        cells = []
        for model, rows in results.items():
            ds = [r.get("disposition", "INVALID") for r in rows if r["finding_id"] == cid]
            cells.append("/".join(sorted(set(ds))) or "-")
        lines.append(f"| {cid} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Benchmark models on the synthesis step")
    ap.add_argument("--models", default="llama3.2:3b",
                    help="comma-separated Ollama model tags")
    ap.add_argument("--cases", type=int, default=5)
    ap.add_argument("--repeats", type=int, default=1,
                    help="runs per case; >=2 measures determinism")
    ap.add_argument("--out", default=None, help="write the markdown report here")
    ap.add_argument("--drop", choices=sorted(ABLATIONS), default=None,
                    help="ablation: withhold one specialist's evidence from synthesis")
    a = ap.parse_args()

    results = benchmark([m.strip() for m in a.models.split(",") if m.strip()],
                        a.cases, a.repeats, a.drop)
    report = summarise(results)
    print(report)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"\nwrote {a.out}")
    print("\nraw:", json.dumps(results, default=str)[:400], "...")


if __name__ == "__main__":
    main()
