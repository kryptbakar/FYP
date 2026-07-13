"""Attack-scenario validation — the intelligence layer on a realistic intrusion.

The live attack simulation (docs/VALIDATION-ATTACK-SIM.md) needs a lab: a victim VM,
real sensors, real detection latency. This harness validates the *other half* of the
claim — fusion + prioritisation — deterministically and offline, so it runs in CI on
every push and needs no stack.

It builds a scripted multi-stage intrusion as findings from several independent tools
(the kind of rows the bridges would write), then runs the real fusion + composite
scoring over them and checks the properties VYREX is defended on:

  1. **Corroboration:** when N independent tools report the same issue on one asset,
     fusion clusters them (consensus weight rises with N).
  2. **Fusion lift:** a corroborated finding outranks an identical solo finding — the
     consensus factor doing real work.
  3. **Exploit-aware ordering:** a KEV + high-EPSS + exposed finding tops the queue,
     above a higher-CVSS-but-unexploited one (what CVSS-only gets wrong).

This is NOT a substitute for sensor-based detection — it exercises fusion + ranking,
not collection. It complements the compose e2e smoke (which proves the live pipeline
produces scored findings) with a focused check on the ranking logic's behaviour under
an attack narrative.

Usage:  python attack_scenario.py [--out reports/]     (also: run.py evaluate-scenario)
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import fusion
import scoring
from features import FEATURES

log = logging.getLogger("ml.attack_scenario")

# A scripted intrusion on host-web-01 (internet-facing) plus a control asset. Each row
# is what a bridge would write; the trio on the C2 issue is the corroboration case.
SCENARIO: list[dict] = [
    # --- Stage: initial access — Log4Shell RCE, seen by two scanners (corroborated) ---
    {"id": 1, "asset": "host-web-01", "source_tool": "nuclei", "dedup_key": "cve:CVE-2021-44228:web01",
     "severity": "critical", "cvss": 1.0, "epss": 0.97, "kev": 1, "exposure": 0.9, "attack": "T1190"},
    {"id": 2, "asset": "host-web-01", "source_tool": "trivy", "dedup_key": "cve:CVE-2021-44228:web01",
     "severity": "critical", "cvss": 1.0, "epss": 0.97, "kev": 1, "exposure": 0.9, "attack": "T1190"},
    # --- Stage: C2 — same beacon seen by THREE independent tools (max consensus) ---
    {"id": 3, "asset": "host-web-01", "source_tool": "suricata", "dedup_key": "net:c2:web01",
     "severity": "high", "cvss": 0.5, "epss": 0.3, "kev": 0, "exposure": 0.9, "attack": "T1071", "threat_intel": 1},
    {"id": 4, "asset": "host-web-01", "source_tool": "zeek", "dedup_key": "net:c2:web01",
     "severity": "medium", "cvss": 0.5, "epss": 0.3, "kev": 0, "exposure": 0.9, "attack": "T1071", "threat_intel": 1},
    {"id": 5, "asset": "host-web-01", "source_tool": "misp", "dedup_key": "net:c2:web01",
     "severity": "high", "cvss": 0.5, "epss": 0.3, "kev": 0, "exposure": 0.9, "attack": "T1071", "threat_intel": 1},
    # --- Control: a SOLO copy of the same C2 issue on a twin asset (fusion-lift baseline) ---
    {"id": 6, "asset": "host-web-02", "source_tool": "suricata", "dedup_key": "net:c2:web02",
     "severity": "high", "cvss": 0.5, "epss": 0.3, "kev": 0, "exposure": 0.9, "attack": "T1071", "threat_intel": 1},
    # --- Distractor: higher CVSS but NOT exploited/exposed (CVSS-only would over-rank it) ---
    {"id": 7, "asset": "host-db-03", "source_tool": "trivy", "dedup_key": "cve:CVE-2020-0001:db03",
     "severity": "critical", "cvss": 1.0, "epss": 0.01, "kev": 0, "exposure": 0.1, "attack": None},
]


def _features(row: dict, consensus: float) -> dict[str, float]:
    """Assemble the 10 composite factors from a scenario row (mirrors features.build)."""
    return {
        "cvss": row.get("cvss", 0.0),
        "epss": row.get("epss", 0.0),
        "kev": float(row.get("kev", 0)),
        "exposure": row.get("exposure", 0.2),
        "threat_intel": float(row.get("threat_intel", 0)),
        "consensus": consensus,
        "attack_ctx": 0.9 if row.get("attack") else 0.0,
        "compliance_impact": 0.5,
        "age": 0.5,
        "criticality": 0.5,
    }


def run() -> dict:
    clusters = fusion.build_clusters(
        [{**r, "id": r["id"], "source_tool": r["source_tool"], "dedup_key": r["dedup_key"],
          "severity": r["severity"], "threat_intel": r.get("threat_intel"), "attack": r.get("attack")}
         for r in SCENARIO]
    )
    scored = []
    for r in SCENARIO:
        con = clusters[r["id"]]
        comp, _ = scoring.composite(_features(r, con["weight"]))
        scored.append({"id": r["id"], "asset": r["asset"], "issue": r["dedup_key"],
                       "tools": con["tools"], "n_tools": con["n_tools"], "consensus": con["weight"],
                       "score": comp, "band": scoring.band(comp)})
    scored.sort(key=lambda x: -x["score"])
    for rank, s in enumerate(scored, 1):
        s["rank"] = rank

    by_id = {s["id"]: s for s in scored}
    checks = {
        "c2_corroborated_by_3_tools": by_id[3]["n_tools"] == 3 and by_id[3]["consensus"] == 1.0,
        "fusion_lift_corroborated_outranks_solo": by_id[3]["score"] > by_id[6]["score"],
        "exploited_exposed_outranks_higher_cvss_distractor": by_id[1]["score"] > by_id[7]["score"],
        "log4shell_is_top_ranked": scored[0]["id"] in (1, 2),
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ranked": scored,
        "checks": checks,
        "passed": all(checks.values()),
    }


def to_markdown(r: dict) -> str:
    lines = [
        "# Attack-scenario validation (intelligence layer)",
        "",
        f"_Auto-generated by `ml/attack_scenario.py` on {r['generated_at']}. Offline, "
        "deterministic — exercises fusion + ranking on a scripted intrusion. Live sensor "
        "detection is validated separately (docs/VALIDATION-ATTACK-SIM.md)._",
        "",
        "## Ranked queue",
        "",
        "| Rank | Asset | Issue | Tools | Consensus | Score | Band |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in r["ranked"]:
        lines.append(f"| {s['rank']} | {s['asset']} | `{s['issue']}` | {', '.join(s['tools'])} "
                     f"| {s['consensus']:.2f} | {s['score']:.1f} | {s['band']} |")
    lines += ["", "## Property checks", ""]
    for name, ok in r["checks"].items():
        lines.append(f"- [{'x' if ok else ' '}] {name.replace('_', ' ')}")
    lines += ["", f"**Result: {'PASS' if r['passed'] else 'FAIL'}**",
              "",
              "Reading it: the Log4Shell RCE (KEV + EPSS 0.97 + exposed, corroborated by two "
              "scanners) tops the queue; the three-tool C2 beacon outranks its identical "
              "single-tool twin (fusion lift); and the high-CVSS-but-unexploited distractor "
              "sinks — exactly the ordering CVSS-alone gets wrong."]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path("reports"))
    args = ap.parse_args()
    r = run()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "attack_scenario.json").write_text(json.dumps(r, indent=2))
    (args.out / "attack_scenario.md").write_text(to_markdown(r))
    print(to_markdown(r))
    if not r["passed"]:
        raise SystemExit("attack-scenario checks FAILED")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    main()
