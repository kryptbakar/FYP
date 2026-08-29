"""Freeze an evaluation corpus for blind labelling.

Writes two CSVs:

  cases/cases-<stamp>.csv    what the labeller is allowed to see
  labels/labels-<stamp>.csv  the same case_ids with empty label columns, to fill in

The point of exporting at all — rather than labelling from the console — is
[docs/LABELLING-RUBRIC.md](../docs/LABELLING-RUBRIC.md) §1: the labeller must not
be able to see any investigation output for a case. The console shows it one click
away. A frozen CSV cannot.

So this query deliberately does NOT join `investigations`, `triage_reports`,
`investigation_evidence` or `agent_runs`, and drops the triage_* columns on
findings. If you extend it, keep it that way: every column added here is a column
the labeller sees, and one leak of system output voids the temporal blinding for
that case (rubric §12) with no way to prove otherwise afterwards.

Usage (from vyrex/):
    docker compose --profile ml run --rm --entrypoint python risk-engine \\
        /app/../eval/export_cases.py
or locally, with POSTGRES_* set:
    python eval/export_cases.py [--limit N] [--out-dir eval]
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import pathlib
import sys

import psycopg
from psycopg.rows import dict_row

RUBRIC_VERSION = "rubric-v1"

# Ordered exactly as the labeller should read them: what it is, then how bad it
# claims to be, then the context that decides reachability and impact.
CASE_COLUMNS = [
    "case_id",
    "title",
    "description",
    "domain",
    "source_tool",
    "tool_severity",       # renamed from `severity` on purpose - see below
    "cve_id",
    "cvss_score",
    "epss",
    "kev",
    "exploit_available",
    "asset_id",
    "asset_hostname",
    "asset_os",
    # Business context. Without these the rubric's rank-3 signal (reachability) and rank-4
    # (asset criticality) cannot separate any two cases: every asset used to carry a flat
    # 0.5 and there was no exposure column at all.
    "asset_criticality",
    "asset_internet_exposed",
    "asset_environment",
    "asset_data_sensitivity",
    "asset_owner_team",
    "asset_business_service",
    "asset_criticality_rationale",
    "port",
    "proto",
    "risk_score",
    "n_tools",
    "corroborating_tools",
    "attack_techniques",
    "has_ioc_match",
]

LABEL_COLUMNS = [
    "case_id",
    "disposition",         # ESCALATE | MONITOR | DISMISS | INSUFFICIENT_EVIDENCE
    "severity",            # CRITICAL | HIGH | MEDIUM | LOW
    "rationale",
    "deciding_signals",
    "evidence_gaps",
    "confidence",          # certain | probable | uncertain
    "rubric_version",
    "labelled_at",
]

# `severity` is exported as `tool_severity` because rubric §8 asks the labeller for
# their OWN severity judgement. Presenting the tool's answer under the same name as
# the column they are filling in is an anchoring trap that would quietly turn the
# severity metric into "does the labeller agree with themselves".
QUERY = """
SELECT f.id::text                              AS case_id,
       f.title,
       f.description,
       f.domain,
       f.source_tool,
       f.severity                              AS tool_severity,
       f.cve_id,
       f.cvss_score,
       f.epss,
       f.kev,
       f.exploit_available,
       f.asset_id,
       a.hostname                              AS asset_hostname,
       a.os                                    AS asset_os,
       a.criticality                           AS asset_criticality,
       a.internet_exposed                      AS asset_internet_exposed,
       a.environment                           AS asset_environment,
       a.data_sensitivity                      AS asset_data_sensitivity,
       a.owner_team                            AS asset_owner_team,
       a.business_service                      AS asset_business_service,
       a.criticality_rationale                 AS asset_criticality_rationale,
       f.port,
       f.proto,
       f.risk_score,
       COALESCE(f.consensus->>'n_tools', '1')  AS n_tools,
       COALESCE(f.consensus->>'tools', '')     AS corroborating_tools,
       COALESCE(f.attack, '')                  AS attack_techniques,  -- plain text ("T1571"), not jsonb
       (f.threat_intel IS NOT NULL
        AND f.threat_intel::text <> 'null'
        AND f.threat_intel::text <> '{}')      AS has_ioc_match
  FROM findings f
  LEFT JOIN assets a ON a.host_id = f.asset_id   -- assets is keyed on host_id, not asset_id
 ORDER BY f.id
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
    ap.add_argument("--limit", type=int, default=0, help="cap the corpus (0 = all)")
    ap.add_argument("--out-dir", default=str(pathlib.Path(__file__).parent))
    args = ap.parse_args()

    out = pathlib.Path(args.out_dir)
    (out / "cases").mkdir(parents=True, exist_ok=True)
    (out / "labels").mkdir(parents=True, exist_ok=True)

    sql = QUERY + (f" LIMIT {args.limit}" if args.limit > 0 else "")
    with psycopg.connect(dsn(), row_factory=dict_row) as conn:
        rows = conn.execute(sql).fetchall()

    if not rows:
        print("no findings - nothing to export", file=sys.stderr)
        return 1

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    cases_path = out / "cases" / f"cases-{stamp}.csv"
    labels_path = out / "labels" / f"labels-{stamp}.csv"

    # Refuse to clobber. Labels are append-only (rubric §12) and a re-run that
    # silently overwrote a half-finished label file would destroy exactly the
    # evidence the blinding protocol rests on.
    for p in (cases_path, labels_path):
        if p.exists():
            print(f"refusing to overwrite {p}", file=sys.stderr)
            return 1

    with cases_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CASE_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

    with labels_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=LABEL_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({"case_id": r["case_id"], "rubric_version": RUBRIC_VERSION})

    leaked = set(CASE_COLUMNS) & {"disposition", "verdict", "confidence", "rationale"}
    assert not leaked, f"case export leaks system output: {leaked}"

    print(f"cases  -> {cases_path}  ({len(rows)} rows)")
    print(f"labels -> {labels_path}  (empty, {RUBRIC_VERSION})")
    print()
    print("Commit BOTH now, before labelling. The empty label file in git history is")
    print("what proves the rubric and the corpus predate the labels.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
