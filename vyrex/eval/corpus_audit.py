"""Audit the finding corpus against the stratification targets in the labelling rubric.

docs/LABELLING-RUBRIC.md §10 specifies what the evaluation corpus must cover. That section
is prose, which means "is the corpus ready?" is otherwise a matter of opinion and a lot of
ad-hoc SQL. This turns it into a number and a list of gaps.

Run it before labelling starts and after every batch of new fixtures:

    python eval/corpus_audit.py

Exit 0 when every target is met, 1 while gaps remain — so it can gate the point at which
labelling is allowed to begin.

Note on the last row: deliberate missing-evidence cases cannot be detected by a query,
because "the evidence a decision would have required is absent" is a judgement about the
case, not a column. They are counted by a marker in `rule_id`, which is also how
export_cases.py can flag them for the labeller.
"""
from __future__ import annotations

import os
import sys

import psycopg
from psycopg.rows import dict_row

# (label, SQL returning one integer, required minimum, why it matters)
CHECKS: list[tuple[str, str, int, str]] = [
    ("total findings",
     "SELECT count(*) FROM findings", 60,
     "rubric §10: 60-80 cases; an honest n=60 beats a dubious n=150"),

    ("severity CRITICAL",
     "SELECT count(*) FROM findings WHERE severity = 'CRITICAL'", 5,
     "each severity needs enough cases for a per-class F1 to mean anything"),
    ("severity HIGH",
     "SELECT count(*) FROM findings WHERE severity = 'HIGH'", 5, ""),
    ("severity MEDIUM",
     "SELECT count(*) FROM findings WHERE severity = 'MEDIUM'", 5, ""),
    ("severity LOW",
     "SELECT count(*) FROM findings WHERE severity = 'LOW'", 5, ""),

    ("distinct source tools",
     "SELECT count(DISTINCT source_tool) FROM findings", 3,
     "so the evaluation is not measuring one tool's output style"),
    ("distinct domains",
     "SELECT count(DISTINCT domain) FROM findings", 3,
     "vulnerability / network detection / host+compliance"),

    ("KEV findings",
     "SELECT count(*) FROM findings WHERE kev IS TRUE", 8,
     "KEV is the strongest escalation signal in the rubric's precedence"),
    ("non-KEV findings",
     "SELECT count(*) FROM findings WHERE kev IS NOT TRUE", 8,
     "without contrast, KEV cannot be shown to matter"),

    ("corroborated (n_tools >= 2)",
     "SELECT count(*) FROM findings WHERE (consensus->>'n_tools')::int >= 2", 6,
     "the fusion claim is a headline result; it needs cases"),
    ("singletons (n_tools < 2)",
     "SELECT count(*) FROM findings "
     "WHERE COALESCE((consensus->>'n_tools')::int, 1) < 2", 6,
     "the control for corroboration"),

    ("IOC matches",
     "SELECT count(*) FROM findings WHERE threat_intel IS NOT NULL "
     "AND threat_intel::text NOT IN ('null', '{}')", 5,
     "confirmed-malicious is the top of the rubric's precedence order"),
    ("ATT&CK technique present",
     "SELECT count(*) FROM findings WHERE attack IS NOT NULL AND attack <> ''", 10,
     "the ATT&CK specialist needs cases where it can contribute"),

    ("deliberate missing-evidence cases",
     "SELECT count(*) FROM findings WHERE rule_id LIKE 'eval-missing-%'", 6,
     "the ONLY way to measure abstention quality: without cases where abstaining is "
     "correct, a model that always abstains and one that abstains well score the same"),
]


def dsn() -> str:
    return (
        f"host={os.getenv('POSTGRES_HOST', 'localhost')} "
        f"port={os.getenv('POSTGRES_PORT_INTERNAL', os.getenv('POSTGRES_PORT', '5432'))} "
        f"dbname={os.getenv('POSTGRES_DB', 'soc_central')} "
        f"user={os.getenv('POSTGRES_USER', 'soc')} "
        f"password={os.getenv('POSTGRES_PASSWORD', 'soc')}"
    )


def main() -> int:
    gaps: list[tuple[str, int, int, str]] = []
    with psycopg.connect(dsn(), row_factory=dict_row) as conn:
        print(f"{'axis':34s} {'have':>5s} {'need':>5s}  status")
        print("-" * 62)
        for label, sql, need, why in CHECKS:
            row = conn.execute(sql).fetchone()
            have = int(list(row.values())[0] or 0)
            ok = have >= need
            print(f"{label:34s} {have:5d} {need:5d}  {'ok' if ok else 'GAP'}")
            if not ok:
                gaps.append((label, have, need, why))

    print()
    if not gaps:
        print("corpus meets every stratification target - labelling may begin.")
        return 0

    print(f"{len(gaps)} gap(s) remain before the corpus satisfies rubric §10:\n")
    for label, have, need, why in gaps:
        print(f"  {label}: need {need - have} more")
        if why:
            print(f"      {why}")
    print("\nCorpus expansion is calendar-bound work (EVALUATION-PROTOCOL.md §2.5) - no")
    print("amount of effort later compresses it, so close these before anything else.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
