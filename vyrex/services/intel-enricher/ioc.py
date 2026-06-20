"""MISP IOC matching — check telemetry indicators against the IOC store.

Pulls candidate indicators (remote IPs / domains) out of recent network/IDS/runtime
telemetry and matches them against MISP IOCs. Matches become high-confidence findings
(source_tool=misp) and carry the MISP event context in `threat_intel`.

Offline: a bundled IOC fixture (real-shaped MISP attributes). Live: PyMISP/REST against an
internal MISP instance feeds the same matcher (D-038).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import db

log = logging.getLogger("intel.ioc")
FIX = Path(__file__).parent / "fixtures" / "ioc.json"
_SEV = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def load_iocs() -> dict[str, dict]:
    return {i["value"]: i for i in json.loads(FIX.read_text())}


def candidates(row: dict) -> set[str]:
    p = row.get("payload") or {}
    k = row["kind"]
    out: set[str] = set()
    if k == "network_flow" and p.get("remote_ip"):
        out.add(p["remote_ip"])
    elif k == "ids_alert":
        out |= {p[f] for f in ("dest_ip", "src_ip") if p.get(f)}
    elif k == "traffic_metadata":
        if p.get("id.resp_h"):
            out.add(p["id.resp_h"])
        if p.get("query"):
            out.add(p["query"])
    elif k == "runtime_alert":
        fl = p.get("fields") or {}
        if fl.get("fd.sip"):
            out.add(fl["fd.sip"])
    return out


def run(pg, ts) -> int:
    iocs = load_iocs()
    rows = db.network_rows(ts)
    seen: set[tuple] = set()
    created = 0
    for row in rows:
        asset = row["host_id"]
        for ind in candidates(row):
            ioc = iocs.get(ind)
            if not ioc or (asset, ind) in seen:
                continue
            seen.add((asset, ind))
            db.ensure_asset(pg, asset)
            db.upsert_finding(pg, {
                "asset_id": asset, "domain": "network", "rule_id": f"ioc.{ind}",
                "title": f"IOC match: {ind} ({ioc.get('type')}) — {ioc.get('event_info')}",
                "description": f"Indicator {ind} from MISP event '{ioc.get('event_info')}' "
                               f"observed in {row['kind']} telemetry.",
                "severity": _SEV.get((ioc.get("threat_level") or "high").lower(), "HIGH"),
                "source_tool": "misp", "raw_ref": ind, "dedup_key": db.fp(asset, "ioc", ind),
                "fingerprint": db.fp("misp", asset, "network", f"ioc.{ind}"),
                "threat_intel": {"indicator": ind, "type": ioc.get("type"),
                                 "misp_event": ioc.get("event_info"), "tags": ioc.get("tags"),
                                 "observed_in": row["kind"]},
                "evidence": {"indicator": ind, "observed_in": row["kind"]},
            })
            created += 1
    log.info("misp: %d IOC-match finding(s) from %d telemetry rows", created, len(rows))
    return created
