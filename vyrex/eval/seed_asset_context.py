"""Give the lab assets real business context, so the rubric's signals can discriminate.

[docs/LABELLING-RUBRIC.md](../docs/LABELLING-RUBRIC.md) §9 ranks **reachability third** and
**asset criticality fourth** among the six deciding signals. Before this, every asset in the
corpus carried `criticality = 0.5` and there was no exposure column at all — so a labeller
comparing the SOC's own sensor against a scratch VM had literally identical information
about both, and two of the six signals could not separate any pair of cases. Labelling
under those conditions would have produced numbers that looked fine and meant nothing.

This is **lab inventory**, not scanner output. A real deployment gets it from a CMDB or
asset-management system; here it is stated explicitly and committed so the values are
reviewable rather than invented ad hoc per case. Every `criticality_rationale` below is the
sentence a labeller (or an examiner) can argue with — which is the point of recording one.

    python eval/seed_asset_context.py [--show]
"""
from __future__ import annotations

import argparse
import os
import sys

import psycopg
from psycopg.rows import dict_row

# host_id -> business context. Chosen to give the rubric genuine spread (criticality
# 0.25..0.9, exposure true/false/unknown) rather than a flat field that decides nothing.
ASSETS = {
    "soc-sensor-01": dict(
        owner_team="Security Operations", environment="prod",
        business_service="VYREX detection pipeline", data_sensitivity="restricted",
        internet_exposed=False, criticality=0.90,
        criticality_rationale=(
            "The SOC's own sensor. Compromise does not just expose data - it blinds the "
            "detection capability that would otherwise catch the next step, so it is rated "
            "above the systems it protects."),
    ),
    "lab-vm-01": dict(
        owner_team="Platform Engineering", environment="prod",
        business_service="Customer-facing API", data_sensitivity="confidential",
        internet_exposed=True, criticality=0.80,
        criticality_rationale=(
            "Internet-facing production service holding customer data. Reachable from "
            "outside and valuable inside, which is the combination the rubric escalates on."),
    ),
    "wazuh-monitored-01": dict(
        owner_team="Infrastructure", environment="prod",
        business_service="Internal file and identity services", data_sensitivity="confidential",
        internet_exposed=False, criticality=0.70,
        criticality_rationale=(
            "Production, holds confidential data, but is not reachable from the internet - "
            "so intrinsic value is high while the attack path is longer."),
    ),
    "scan-target-01": dict(
        owner_team="Platform Engineering", environment="staging",
        business_service="Pre-production web application", data_sensitivity="internal",
        internet_exposed=True, criticality=0.55,
        criticality_rationale=(
            "Internet-reachable, which raises it, but staging with no production data, "
            "which caps it. A useful mid-scale case precisely because the two signals pull "
            "in opposite directions."),
    ),
    "host-lab-01": dict(
        owner_team="Security Operations", environment="lab",
        business_service="Analyst workstation (lab)", data_sensitivity="internal",
        internet_exposed=False, criticality=0.25,
        criticality_rationale=(
            "Disposable lab workstation, rebuilt from image. Low business impact, and the "
            "deliberate low end of the scale so 'critical CVE on an unimportant host' is a "
            "case the corpus actually contains."),
    ),
}

UPDATE = """
UPDATE assets SET
    owner_team = %(owner_team)s,
    environment = %(environment)s,
    business_service = %(business_service)s,
    data_sensitivity = %(data_sensitivity)s,
    internet_exposed = %(internet_exposed)s,
    criticality = %(criticality)s,
    criticality_rationale = %(criticality_rationale)s
WHERE host_id = %(host_id)s
RETURNING host_id
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
    ap.add_argument("--show", action="store_true", help="print the table and exit")
    args = ap.parse_args()

    with psycopg.connect(dsn(), row_factory=dict_row, autocommit=True) as conn:
        if not args.show:
            missing = []
            for host_id, ctx in ASSETS.items():
                row = conn.execute(UPDATE, {"host_id": host_id, **ctx}).fetchone()
                if row is None:
                    missing.append(host_id)
                else:
                    print(f"  {host_id:20s} crit={ctx['criticality']:.2f} "
                          f"exposed={str(ctx['internet_exposed']):5s} {ctx['environment']}")
            if missing:
                # Not fatal: a fresh lab may not have discovered every host yet. But say
                # so, because a silently-skipped asset keeps its flat 0.5 and quietly
                # weakens the very signal this script exists to restore.
                print(f"\n  NOT IN INVENTORY (skipped): {', '.join(missing)}", file=sys.stderr)

        rows = conn.execute(
            "SELECT host_id, criticality, internet_exposed, environment, data_sensitivity "
            "FROM assets ORDER BY criticality DESC NULLS LAST").fetchall()

    print(f"\n{'host':22s} {'crit':>5s} {'exposed':>8s} {'env':>9s} {'sensitivity':>13s}")
    for r in rows:
        print(f"{r['host_id']:22s} {str(r['criticality']):>5s} "
              f"{str(r['internet_exposed']):>8s} {str(r['environment']):>9s} "
              f"{str(r['data_sensitivity']):>13s}")

    spread = [float(r["criticality"]) for r in rows if r["criticality"] is not None]
    if spread and max(spread) - min(spread) < 0.2:
        print("\n  WARNING: criticality is nearly flat across the estate. The rubric's "
              "asset-criticality signal cannot discriminate; labelling would be distorted.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
