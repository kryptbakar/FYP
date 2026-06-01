"""enrichment — the assessment engine.

For each asset, read its latest host state from telemetry, run the three
assessment domains against the local feed mirror, and upsert findings. Runs once
(`--once`) or on an interval (default). Reads only local stores — no internet.
"""
from __future__ import annotations

import argparse
import logging
import os
import time
from datetime import datetime, timezone

import compliance
import db
import domains
import evidence
from matcher import Matcher

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("enrichment")


def env(k: str, d: str) -> str:
    return os.getenv(k) or d


def ts_dsn() -> str:
    return (f"host={env('TIMESCALE_HOST', 'timescaledb')} port={env('TIMESCALE_PORT_INTERNAL', '5432')} "
            f"dbname={env('TIMESCALE_DB', 'soc_telemetry')} user={env('TIMESCALE_USER', 'soc')} "
            f"password={env('TIMESCALE_PASSWORD', 'soc')}")


def pg_dsn() -> str:
    return (f"host={env('POSTGRES_HOST', 'postgres')} port={env('POSTGRES_PORT_INTERNAL', '5432')} "
            f"dbname={env('POSTGRES_DB', 'soc_central')} user={env('POSTGRES_USER', 'soc')} "
            f"password={env('POSTGRES_PASSWORD', 'soc')}")


def run_once() -> None:
    ts = db.connect(ts_dsn())
    pg = db.connect(pg_dsn())
    try:
        db.ensure_schema(pg)
        matcher = Matcher.load(pg)

        run_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
        assets = db.list_assets(ts)
        log.info("assessing %d asset(s) [run_id=%s]", len(assets), run_id)
        total = comp_total = 0
        for a in assets:
            host_id = a["host_id"]
            os_info = db.os_for(ts, host_id) or {}
            os_name = os_info.get("name")
            packages = db.packages_for(ts, host_id)
            installed = {p["name"] for p in packages}
            flows = db.flows_for(ts, host_id)

            db.upsert_asset(pg, host_id, a.get("hostname"), os_name, None, a.get("last_seen"))

            # --- vulnerability assessment (Phase 3) ---
            findings = []
            findings += domains.assess_application(host_id, packages, matcher)
            findings += domains.assess_system(host_id, installed, os_info)
            findings += domains.assess_network(host_id, flows)
            n = db.upsert_findings(pg, findings)
            total += n

            # --- compliance assessment (Phase 4): pass/fail/partial + hash-chained evidence ---
            kernel = db.osquery_latest(ts, host_id, "kernel_info")
            state = compliance.State(
                os=os_info,
                pkg_names={p.lower() for p in installed},
                kernel=(kernel[0] if kernel else None),
                listening=db.osquery_latest(ts, host_id, "listening_ports"),
                users=db.osquery_latest(ts, host_id, "logged_in_users"),
            )
            for result in compliance.evaluate_asset(state):
                record = {
                    "run_id": run_id, "asset_id": host_id, "rule_id": result["rule_id"],
                    "status": result["status"], "evidence": result["evidence"],
                    "evaluated_at": datetime.now(timezone.utc).isoformat(),
                }
                ev_hash = db.append_evidence(pg, run_id, host_id, result["rule_id"], record)
                db.upsert_compliance_result(pg, host_id, run_id, result, ev_hash)
                comp_total += 1

            log.info("asset=%s packages=%d flows=%d findings=%d compliance_rules=%d",
                     host_id, len(packages), len(flows), n, len(compliance.RULES))

        log.info("vuln findings upserted: %d", total)
        for domain, severity, count in db.summary(pg):
            log.info("  finding  %-12s %-8s %d", domain, severity, count)
        log.info("compliance results: %d (evidence records appended)", comp_total)
        for status, count in db.compliance_summary(pg):
            log.info("  compliance  %-16s %d", status, count)
        chain = evidence.verify_chain(db.evidence_rows(pg))
        log.info("evidence chain: ok=%s length=%s", chain["ok"], chain["length"])
    finally:
        ts.close()
        pg.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="run a single assessment and exit")
    ap.add_argument("--interval", type=int, default=int(env("ASSESS_INTERVAL", "120")))
    args = ap.parse_args()

    if args.once or args.interval <= 0:
        run_once()
        return

    log.info("enrichment loop every %ds", args.interval)
    while True:
        try:
            run_once()
        except Exception as e:  # keep the loop alive across transient DB hiccups
            log.error("assessment run failed: %s", e)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
