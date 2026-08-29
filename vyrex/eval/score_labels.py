"""Score VYREX's verdicts against blind human labels — the Phase 4 analysis harness.

Implements exactly the metrics [docs/EVALUATION-PROTOCOL.md](../docs/EVALUATION-PROTOCOL.md)
§3 pre-registered, and nothing else. Choosing metrics after seeing results is how honest
projects reach dishonest conclusions, so the set is fixed here and the code is the record.

    python eval/score_labels.py --labels eval/labels/labels-<stamp>.csv
    python eval/score_labels.py --labels ... --adjudicator eval/labels/advisor-<stamp>.csv

Two properties matter more than the arithmetic:

1. **It refuses to invent accuracy.** With no labelled rows it prints the grounding and
   operational sections — which need no labels and are measurable today — and says plainly
   that decision quality is unavailable. It never falls back to comparing the system
   against itself, which is the exact circularity METHODOLOGY.md §4.1 documents in the ML
   layer and EVALUATION-PROTOCOL.md §2 forbids repeating.

2. **No sklearn.** Macro-F1, the confusion matrix, Cohen's κ and weighted agreement are
   about forty lines of arithmetic. Adding a large dependency to an air-gapped project to
   avoid writing them would be a poor trade, and the formulas being visible here means a
   reader can check them rather than trust an import.
"""
from __future__ import annotations

import argparse
import csv
import os
import pathlib
import sys
from collections import Counter, defaultdict

import psycopg
from psycopg.rows import dict_row

DISPOSITIONS = ["ESCALATE", "MONITOR", "DISMISS", "INSUFFICIENT_EVIDENCE"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]   # ordinal, low -> high


# --------------------------------------------------------------- metrics

def confusion(pairs: list[tuple[str, str]], classes: list[str]) -> dict:
    """{true: {pred: n}}. Kept as a dict rather than a matrix so it prints readably."""
    m = {t: {p: 0 for p in classes} for t in classes}
    for truth, pred in pairs:
        if truth in m and pred in m[truth]:
            m[truth][pred] += 1
    return m


def per_class_f1(pairs: list[tuple[str, str]], classes: list[str]) -> dict[str, dict]:
    out = {}
    for c in classes:
        tp = sum(1 for t, p in pairs if t == c and p == c)
        fp = sum(1 for t, p in pairs if t != c and p == c)
        fn = sum(1 for t, p in pairs if t == c and p != c)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        out[c] = {"support": tp + fn, "precision": prec, "recall": rec, "f1": f1}
    return out


def macro_f1(pairs, classes) -> float:
    """Unweighted mean over classes PRESENT in the truth labels.

    Averaging over all four including classes nobody labelled would silently drag the
    score toward zero and make a small corpus look worse than it is.
    """
    per = per_class_f1(pairs, classes)
    present = [c for c in classes if per[c]["support"] > 0]
    return sum(per[c]["f1"] for c in present) / len(present) if present else 0.0


def cohens_kappa(pairs, classes) -> float:
    """Chance-corrected agreement. Reported for the advisor subsample only.

    κ, not raw agreement, because with four classes and an uneven distribution two raters
    who never spoke can agree most of the time by accident.
    """
    n = len(pairs)
    if not n:
        return 0.0
    po = sum(1 for a, b in pairs if a == b) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum((ca[c] / n) * (cb[c] / n) for c in classes)
    return (po - pe) / (1 - pe) if pe != 1 else 1.0


def weighted_severity_agreement(pairs) -> float:
    """Ordinal credit: HIGH-vs-CRITICAL is a smaller error than LOW-vs-CRITICAL.

    Linear penalty over the 4-point scale — 1.0 exact, 0.67 one step, 0.33 two, 0.0 three.
    """
    if not pairs:
        return 0.0
    idx = {s: i for i, s in enumerate(SEVERITIES)}
    span = len(SEVERITIES) - 1
    total = 0.0
    for truth, pred in pairs:
        if truth not in idx or pred not in idx:
            continue
        total += 1.0 - abs(idx[truth] - idx[pred]) / span
    return total / len(pairs)


# --------------------------------------------------------------- data

def dsn() -> str:
    return (
        f"host={os.getenv('POSTGRES_HOST', 'localhost')} "
        f"port={os.getenv('POSTGRES_PORT_INTERNAL', os.getenv('POSTGRES_PORT', '5432'))} "
        f"dbname={os.getenv('POSTGRES_DB', 'soc_central')} "
        f"user={os.getenv('POSTGRES_USER', 'soc')} "
        f"password={os.getenv('POSTGRES_PASSWORD', 'soc')}"
    )


def load_labels(path: pathlib.Path) -> dict[str, dict]:
    """Labelled rows only. A blank disposition is an unlabelled case, not a class."""
    out = {}
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if (row.get("disposition") or "").strip():
                out[row["case_id"].strip()] = row
    return out


def load_system_verdicts(conn) -> dict[str, dict]:
    """Latest verdict per finding, with the model that produced it.

    model_name is carried through because comparing a fake-llm run with a real one
    produced a wrong conclusion once already; the report prints the mix so it cannot
    happen silently again.
    """
    rows = conn.execute("""
        SELECT DISTINCT ON (i.subject_id)
               i.subject_id::text                     AS case_id,
               i.model_name, i.status,
               r.recommended_disposition              AS disposition,
               r.recommended_severity                 AS severity,
               r.confidence,
               COALESCE(jsonb_array_length(r.rationale_claims), 0) AS n_claims,
               r.rationale_claims,
               i.duration_ms,
               (SELECT count(*) FROM investigation_evidence e
                 WHERE e.investigation_id = i.investigation_id) AS n_evidence
          FROM investigations i
          JOIN triage_reports r USING (investigation_id)
         ORDER BY i.subject_id, i.created_at DESC
    """).fetchall()
    return {r["case_id"]: r for r in rows}


# --------------------------------------------------------------- report

def grounding_section(verdicts: dict[str, dict], conn) -> None:
    """Measurable with zero labels — and currently the only defensible numbers."""
    print("\n== 3.2 Grounding quality (no labels needed) ==")
    if not verdicts:
        print("  no verdicts recorded yet")
        return

    total = len(verdicts)
    uncited = [v for v in verdicts.values() if v["n_claims"] == 0]
    cited = total - len(uncited)

    # A citation is valid only if it resolves to evidence THIS investigation collected.
    resolvable = unresolvable = 0
    for cid, v in verdicts.items():
        for claim in (v["rationale_claims"] or []):
            for ref in claim.get("citation_ids", []):
                row = conn.execute(
                    "SELECT 1 FROM investigation_evidence e JOIN investigations i USING "
                    "(investigation_id) WHERE i.subject_id = %s AND e.citation_id = %s LIMIT 1",
                    (int(cid), ref)).fetchone()
                if row:
                    resolvable += 1
                else:
                    unresolvable += 1

    print(f"  verdicts                 {total}")
    print(f"  uncited-verdict rate     {len(uncited)}/{total}"
          f"  ({len(uncited) / total:.0%})")
    print(f"  verdicts with a citation {cited}/{total}")
    print(f"  citations resolvable     {resolvable}"
          + (f"  UNRESOLVABLE {unresolvable}" if unresolvable else "  (0 unresolvable)"))
    if not cited:
        print("  -> nothing the system says is attributable. This is the Phase 2 exit gate,")
        print("     and it is open. See docs/AGENT-ORCHESTRATION.md §7.")


def operational_section(verdicts: dict[str, dict]) -> None:
    print("\n== 3.3 Operational (no labels needed) ==")
    if not verdicts:
        print("  no runs recorded yet")
        return
    durs = sorted(v["duration_ms"] for v in verdicts.values() if v["duration_ms"])
    if durs:
        p50 = durs[len(durs) // 2] / 1000
        p95 = durs[min(len(durs) - 1, int(len(durs) * 0.95))] / 1000
        print(f"  latency p50 / p95        {p50:.1f}s / {p95:.1f}s")
    states = Counter(v["status"] for v in verdicts.values())
    print("  run outcomes             " + ", ".join(f"{k}={v}" for k, v in states.items()))
    models = Counter(v["model_name"] or "?" for v in verdicts.values())
    print("  models                   " + ", ".join(f"{k}={v}" for k, v in models.items()))
    if len(models) > 1:
        print("  !! more than one model in this set - do NOT pool these into one accuracy")
        print("     number. A fake-llm run and a real run are not comparable.")


def decision_section(labels: dict, verdicts: dict) -> bool:
    print("\n== 3.1 Decision quality (needs labels) ==")
    if not labels:
        print("  NO LABELLED CASES. Decision quality is unavailable and no substitute is")
        print("  computed: scoring the system against its own output, or against another")
        print("  model, is the circularity the protocol exists to prevent.")
        print("  Next step: label eval/labels/*.csv under docs/LABELLING-RUBRIC.md.")
        return False

    overlap = [c for c in labels if c in verdicts]
    if not overlap:
        print(f"  {len(labels)} labelled case(s), but none has a system verdict yet.")
        print("  Run investigations on the labelled cases first.")
        return False

    disp = [(labels[c]["disposition"].strip().upper(),
             (verdicts[c]["disposition"] or "").strip().upper()) for c in overlap]
    sev = [(labels[c].get("severity", "").strip().upper(),
            (verdicts[c]["severity"] or "").strip().upper()) for c in overlap]

    print(f"  scored cases             {len(overlap)} of {len(labels)} labelled")
    print(f"  macro-F1 (disposition)   {macro_f1(disp, DISPOSITIONS):.3f}")
    print(f"  weighted severity agree  {weighted_severity_agreement(sev):.3f}")

    print("\n  per class:")
    per = per_class_f1(disp, DISPOSITIONS)
    print(f"    {'class':24s} {'n':>4s} {'prec':>6s} {'rec':>6s} {'f1':>6s}")
    for c in DISPOSITIONS:
        d = per[c]
        print(f"    {c:24s} {d['support']:4d} {d['precision']:6.2f} {d['recall']:6.2f} {d['f1']:6.2f}")

    print("\n  confusion (rows = human label, cols = system):")
    m = confusion(disp, DISPOSITIONS)
    print("    " + " " * 24 + "".join(f"{c[:8]:>10s}" for c in DISPOSITIONS))
    for t in DISPOSITIONS:
        print(f"    {t:24s}" + "".join(f"{m[t][p]:10d}" for p in DISPOSITIONS))

    # Abstention quality: abstaining is a SUCCESS when the human also could not call it.
    sys_abstained = [(t, p) for t, p in disp if p == "INSUFFICIENT_EVIDENCE"]
    if sys_abstained:
        right = sum(1 for t, _ in sys_abstained if t == "INSUFFICIENT_EVIDENCE")
        print(f"\n  abstention quality       {right}/{len(sys_abstained)} of the system's")
        print( "                           abstentions were cases the human also could not call")
        if right == 0:
            print("                           -> it abstains where a human would decide;")
            print("                              that is caution without calibration.")
    return True


def adjudication_section(labels: dict, adj_path: pathlib.Path | None) -> None:
    print("\n== Inter-rater agreement (advisor subsample) ==")
    if not adj_path:
        print("  No adjudicator file supplied. Without a second rater there is NO")
        print("  inter-rater statistic, and the thesis must say so rather than imply")
        print("  the single-rater labels are reliable. (EVALUATION-PROTOCOL.md §2.3)")
        return
    adj = load_labels(adj_path)
    overlap = [c for c in adj if c in labels]
    if not overlap:
        print("  adjudicator file has no cases in common with the primary labels")
        return
    pairs = [(labels[c]["disposition"].strip().upper(),
              adj[c]["disposition"].strip().upper()) for c in overlap]
    k = cohens_kappa(pairs, DISPOSITIONS)
    raw = sum(1 for a, b in pairs if a == b) / len(pairs)
    print(f"  subsample                {len(overlap)} case(s)"
          f"  ({len(overlap) / max(1, len(labels)):.0%} of the corpus)")
    print(f"  raw agreement            {raw:.3f}")
    print(f"  Cohen's kappa            {k:.3f}")
    if k < 0.4:
        print("  -> below 0.4: the rubric is not reproducible enough to support accuracy")
        print("     claims. Report that rather than the accuracy. (rubric §11)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--labels", type=pathlib.Path, help="primary blind-label CSV")
    ap.add_argument("--adjudicator", type=pathlib.Path, help="advisor subsample CSV")
    args = ap.parse_args()

    labels = {}
    if args.labels:
        if not args.labels.exists():
            print(f"labels file not found: {args.labels}", file=sys.stderr)
            return 1
        labels = load_labels(args.labels)

    with psycopg.connect(dsn(), row_factory=dict_row) as conn:
        verdicts = load_system_verdicts(conn)

        print("=" * 68)
        print("VYREX evaluation — metrics pre-registered in EVALUATION-PROTOCOL.md §3")
        print("=" * 68)
        print(f"system verdicts on record: {len(verdicts)}")
        print(f"labelled cases supplied:   {len(labels)}")

        scored = decision_section(labels, verdicts)
        grounding_section(verdicts, conn)
        operational_section(verdicts)
        adjudication_section(labels, args.adjudicator)

    print("\n" + "=" * 68)
    if not scored:
        print("No accuracy claim is supported by this run. That is the correct output")
        print("for the current state, not a failure of the harness.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
