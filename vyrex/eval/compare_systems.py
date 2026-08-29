"""Compare the three systems the evaluation protocol requires.

[docs/EVALUATION-PROTOCOL.md](../docs/EVALUATION-PROTOCOL.md) §1 is explicit about why all
three are needed:

    A  score + SHAP only          today's console: composite score, factor waterfall
    B  one-shot LLM               the deprecated /agent/triage: a verdict, no evidence
    C  investigation graph        cited verdict, per-node trace, inspectable evidence

    "B matters. Without it, any advantage of C could simply be 'an LLM helps' rather
     than '**this** design helps', and the entire contribution of the graph would be
     unevidenced."

That is the contribution claim, so this harness exists to make it falsifiable. If C does
not beat B, that is the result and it goes in the thesis.

    python eval/compare_systems.py --labels eval/labels/labels-<stamp>.csv

Like `score_labels.py`, it refuses to report accuracy without labels and prints the
label-free comparisons instead.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys
from collections import Counter

import psycopg
from psycopg.rows import dict_row

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from score_labels import (  # noqa: E402
    DISPOSITIONS,
    dsn,
    load_labels,
    macro_f1,
    per_class_f1,
    weighted_severity_agreement,
)

# System A turns the composite score into a disposition. The thresholds are the console's
# own risk bands (band() in ui.js), NOT numbers tuned here — inventing a favourable cut
# would make the baseline artificially weak and the comparison worthless.
#
# A cannot express INSUFFICIENT_EVIDENCE: a score always exists, so the baseline always
# decides. That is not a defect of this mapping, it is the actual limitation of a
# score-only interface, and the abstention-quality row is where it shows up.
A_ESCALATE_AT = 60.0   # high + critical bands
A_MONITOR_AT = 20.0    # low + medium bands; below this is the info band


def system_a(conn) -> dict[str, dict]:
    """Threshold on the composite score — the 'no LLM at all' baseline."""
    rows = conn.execute(
        "SELECT id::text AS case_id, risk_score, severity FROM findings "
        "WHERE risk_score IS NOT NULL").fetchall()
    out = {}
    for r in rows:
        s = float(r["risk_score"])
        disp = ("ESCALATE" if s >= A_ESCALATE_AT
                else "MONITOR" if s >= A_MONITOR_AT
                else "DISMISS")
        out[r["case_id"]] = {"disposition": disp, "severity": r["severity"],
                             "n_claims": 0, "cited": False}
    return out


def system_b(conn) -> dict[str, dict]:
    """The deprecated one-shot /agent/triage. Latest decision per finding.

    Its verdicts live as a JSON blob in agent_runs.decisions — no per-step trace, no
    evidence, no citations. That shape IS the comparison: it is what the graph replaced.
    """
    rows = conn.execute(
        "SELECT decisions, created_at FROM agent_runs "
        "WHERE kind = 'triage' AND decisions IS NOT NULL ORDER BY created_at").fetchall()
    out = {}
    for run in rows:                      # later runs overwrite earlier ones
        for d in (run["decisions"] or []):
            if not isinstance(d, dict) or d.get("id") is None:
                continue
            out[str(d["id"])] = {
                "disposition": (d.get("decision") or "").upper(),
                "severity": (d.get("severity") or "").upper(),
                # A one-shot verdict cannot cite: there is no evidence store behind it.
                # Recorded explicitly so the grounding table shows 0/N rather than blank.
                "n_claims": 0,
                "cited": False,
                "has_reason": bool(d.get("reason")),
            }
    return out


def system_c(conn) -> dict[str, dict]:
    """The investigation graph. Latest verdict per subject."""
    rows = conn.execute("""
        SELECT DISTINCT ON (i.subject_id)
               i.subject_id::text AS case_id, i.model_name,
               r.recommended_disposition AS disposition,
               r.recommended_severity AS severity,
               COALESCE(jsonb_array_length(r.rationale_claims), 0) AS n_claims
          FROM investigations i JOIN triage_reports r USING (investigation_id)
         ORDER BY i.subject_id, i.created_at DESC
    """).fetchall()
    return {r["case_id"]: {"disposition": r["disposition"], "severity": r["severity"],
                           "n_claims": r["n_claims"], "cited": r["n_claims"] > 0,
                           "model": r["model_name"]} for r in rows}


def coverage_table(systems: dict[str, dict]) -> None:
    print("\n== Coverage (how many cases each system has an opinion on) ==")
    for name, s in systems.items():
        decided = sum(1 for v in s.values() if v["disposition"])
        abst = sum(1 for v in s.values() if v["disposition"] == "INSUFFICIENT_EVIDENCE")
        cited = sum(1 for v in s.values() if v["cited"])
        print(f"  {name:34s} {decided:4d} cases   abstained {abst:3d}   cited {cited:3d}")
    print("  A never abstains by construction: a score always exists, so a score-only")
    print("  interface always decides. That is the limitation, not a bug in the mapping.")


def disposition_mix(systems: dict[str, dict]) -> None:
    print("\n== Disposition mix (label-free: what each system tends to say) ==")
    print(f"  {'system':34s}" + "".join(f"{d[:9]:>11s}" for d in DISPOSITIONS))
    for name, s in systems.items():
        c = Counter(v["disposition"] for v in s.values())
        print(f"  {name:34s}" + "".join(f"{c.get(d, 0):11d}" for d in DISPOSITIONS))
    print("\n  This is comparable WITHOUT labels and is already informative: a system that")
    print("  only ever emits one class cannot be discriminating, however it scores later.")


def scored_comparison(labels: dict, systems: dict[str, dict]) -> bool:
    print("\n== Decision quality vs blind labels ==")
    if not labels:
        print("  NO LABELLED CASES — no accuracy is reported for any system.")
        print("  Comparing the three against each other instead would measure agreement,")
        print("  not correctness, and would let the worst system look good by consensus.")
        return False

    print(f"  {'system':34s} {'n':>4s} {'macro-F1':>9s} {'severity':>9s} {'cited':>6s}")
    for name, s in systems.items():
        overlap = [c for c in labels if c in s and s[c]["disposition"]]
        if not overlap:
            print(f"  {name:34s} {0:4d}   (no overlap with labelled cases)")
            continue
        disp = [(labels[c]["disposition"].strip().upper(), s[c]["disposition"]) for c in overlap]
        sev = [(labels[c].get("severity", "").strip().upper(), s[c]["severity"] or "")
               for c in overlap]
        cited = sum(1 for c in overlap if s[c]["cited"])
        print(f"  {name:34s} {len(overlap):4d} {macro_f1(disp, DISPOSITIONS):9.3f} "
              f"{weighted_severity_agreement(sev):9.3f} {cited:6d}")

    print("\n  The comparison that carries the contribution claim is C vs B. If C does not")
    print("  beat B, the graph has not been shown to help - only that an LLM helps - and")
    print("  that is the finding to report.")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", type=pathlib.Path)
    args = ap.parse_args()

    labels = load_labels(args.labels) if args.labels and args.labels.exists() else {}

    with psycopg.connect(dsn(), row_factory=dict_row) as conn:
        systems = {
            "A  composite score only": system_a(conn),
            "B  one-shot LLM": system_b(conn),
            "C  investigation graph": system_c(conn),
        }

        print("=" * 70)
        print("Three-system comparison — EVALUATION-PROTOCOL.md §1")
        print("=" * 70)
        print(f"labelled cases supplied: {len(labels)}")
        coverage_table(systems)
        disposition_mix(systems)
        scored = scored_comparison(labels, systems)

        models = {v.get("model") for v in systems["C  investigation graph"].values()}
        models.discard(None)
        if len(models) > 1:
            print(f"\n  !! system C spans multiple models {sorted(models)} — do not pool")
            print("     these into one number; a fake-llm run is not comparable to a real one.")

    if not scored:
        print("\n" + "=" * 70)
        print("No accuracy claim is supported. The label-free tables above are still")
        print("reportable, and the coverage row is already a real result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
