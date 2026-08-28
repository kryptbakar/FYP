"""Seed the deliberate missing-evidence cases required by the labelling rubric.

docs/LABELLING-RUBRIC.md §10 requires **≥6 constructed cases where evidence a decision
would have needed is absent**, and §7 explains why they cannot be skipped:

    without cases where abstaining is CORRECT, a model that always abstains and a model
    that abstains appropriately score identically

That is not a hypothetical concern here. Both models measured abstain on 12/12 findings
(docs/AGENT-ORCHESTRATION.md §7). Without this subset the evaluation literally cannot tell
a well-calibrated system from one that never commits — which would make the headline
grounding result unfalsifiable, and therefore worthless.

These are **evaluation artefacts, not scanner output**, so they are seeded directly rather
than smuggled through a fixture. Each one names, in its own description, exactly which
evidence was withheld and why a competent analyst could not decide. Every row carries
`rule_id = 'eval-missing-NN'`, which is how corpus_audit.py counts them and how a labeller
can tell them apart from organic findings.

Idempotent: re-running updates rather than duplicating.

    python eval/seed_missing_evidence.py [--remove]
"""
from __future__ import annotations

import argparse
import os
import sys

import psycopg
from psycopg.rows import dict_row

# Each case removes exactly ONE class of evidence, so a labeller (and later an ablation)
# can attribute the abstention to a specific gap rather than to general vagueness.
CASES = [
    # asset_id is NULL rather than a made-up hostname: findings.asset_id carries a foreign
    # key to assets, so an unknown host cannot be fabricated - and NULL is the truer model
    # anyway. The finding genuinely has no resolvable asset context, which is precisely the
    # gap this case exists to represent.
    dict(
        rule_id="eval-missing-01",
        asset_id=None,
        domain="application",
        severity="HIGH",
        source_tool="trivy",
        title="openssl 3.0.2 vulnerable to CVE-2023-0286 on an unidentified host",
        description=(
            "WITHHELD: the asset. The scan result carries no resolvable host, so "
            "criticality, environment and internet exposure are all unknown. The rubric's "
            "precedence puts reachability and asset criticality at ranks 3 and 4; without "
            "either, ESCALATE and MONITOR cannot be separated."
        ),
        cve_id="CVE-2023-0286", cvss=7.4, kev=False,
    ),
    dict(
        rule_id="eval-missing-02",
        asset_id="host-lab-01",
        domain="network",
        severity="HIGH",
        source_tool="sigma",
        title="Detection rule susp_egress fired",
        description=(
            "WITHHELD: the observable. The rule fired but recorded no remote IP, no port "
            "and no process — only that it matched. Nothing can be corroborated, no IOC "
            "lookup is possible, and the analyst cannot tell a backup job from C2. This is "
            "the exact defect fixed in the Sigma producer on 2026-08-28; kept here "
            "deliberately as an evaluation case."
        ),
        cve_id=None, cvss=None, kev=False,
    ),
    dict(
        rule_id="eval-missing-03",
        asset_id="scan-target-01",
        domain="application",
        severity="CRITICAL",
        source_tool="nuclei",
        title="Possible remote code execution in an unidentified web service",
        description=(
            "WITHHELD: the identification. The scanner flagged anomalous behaviour but "
            "resolved no product, version or CVE. Severity CRITICAL is the scanner's "
            "assertion with nothing behind it — and the rubric explicitly forbids "
            "escalating on severity alone."
        ),
        cve_id=None, cvss=None, kev=False,
    ),
    dict(
        rule_id="eval-missing-04",
        asset_id="host-lab-01",
        domain="system",
        severity="MEDIUM",
        source_tool="agent",
        title="Configuration drift detected in /etc (contents not captured)",
        description=(
            "WITHHELD: the change itself. The agent recorded that files under /etc changed "
            "but not which files or how. Drift could be a routine package upgrade or "
            "persistence being installed; the two are indistinguishable from this record."
        ),
        cve_id=None, cvss=None, kev=False,
    ),
    dict(
        rule_id="eval-missing-05",
        asset_id="host-lab-01",
        domain="network",
        severity="HIGH",
        source_tool="misp",
        title="Outbound connection to an address with a stale intel record",
        description=(
            "WITHHELD: intel currency. The IOC match has no first/last-seen date and no "
            "source, so it cannot be told whether the indicator is current or years-dead "
            "and sinkholed. Rank 1 in the rubric's precedence is CONFIRMED malicious "
            "activity; an unverifiable indicator does not establish that."
        ),
        cve_id=None, cvss=None, kev=False,
    ),
    dict(
        rule_id="eval-missing-06",
        asset_id="scan-target-01",
        domain="application",
        severity="HIGH",
        source_tool="trivy",
        title="Vulnerable package present; reachability unknown",
        description=(
            "WITHHELD: whether the vulnerable code path is reachable. The package is "
            "installed, but nothing establishes that the affected function is ever called "
            "or the service exposed. The rubric makes 'not applicable' a DISMISS and "
            "'real but not urgent' a MONITOR — this record cannot distinguish them."
        ),
        cve_id="CVE-2022-1304", cvss=5.5, kev=False,
    ),
]

UPSERT = """
INSERT INTO findings (asset_id, domain, rule_id, title, description, severity,
                      source_tool, fingerprint, dedup_key, status, cve_id,
                      cvss_score, kev, risk_score, first_seen, last_seen)
VALUES (%(asset_id)s, %(domain)s, %(rule_id)s, %(title)s, %(description)s, %(severity)s,
        %(source_tool)s, %(fp)s, %(dk)s, 'open', %(cve_id)s,
        %(cvss)s, %(kev)s, NULL, now(), now())
ON CONFLICT (fingerprint) DO UPDATE
   SET title = EXCLUDED.title,
       description = EXCLUDED.description,
       severity = EXCLUDED.severity,
       last_seen = now()
RETURNING id
"""


def dsn() -> str:
    return (
        f"host={os.getenv('POSTGRES_HOST', 'localhost')} "
        f"port={os.getenv('POSTGRES_PORT_INTERNAL', os.getenv('POSTGRES_PORT', '5432'))} "
        f"dbname={os.getenv('POSTGRES_DB', 'soc_central')} "
        f"user={os.getenv('POSTGRES_USER', 'soc')} "
        f"password={os.getenv('POSTGRES_PASSWORD', 'soc')}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--remove", action="store_true", help="delete the seeded cases")
    args = ap.parse_args()

    with psycopg.connect(dsn(), row_factory=dict_row, autocommit=True) as conn:
        if args.remove:
            n = conn.execute(
                "DELETE FROM findings WHERE rule_id LIKE 'eval-missing-%'"
            ).rowcount
            print(f"removed {n} missing-evidence case(s)")
            return 0

        for c in CASES:
            params = dict(c)
            params["fp"] = f"{c['rule_id']}-fp"
            params["dk"] = f"{c['rule_id']}-dedup"
            row = conn.execute(UPSERT, params).fetchone()
            print(f"  {c['rule_id']}  finding {row['id']}  ({c['severity']}, "
                  f"{c['source_tool']})")

        total = conn.execute(
            "SELECT count(*) AS n FROM findings WHERE rule_id LIKE 'eval-missing-%'"
        ).fetchone()["n"]

    print(f"\n{total} missing-evidence case(s) in the corpus (rubric §10 requires 6).")
    print("risk_score is left NULL on purpose: these cases must not be scored as though")
    print("the missing evidence were merely absent-and-unimportant.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except psycopg.Error as e:
        print(f"database error: {e}", file=sys.stderr)
        raise SystemExit(1)
