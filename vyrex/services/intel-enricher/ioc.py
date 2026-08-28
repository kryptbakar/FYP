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


def _observable(row: dict, ind: str) -> tuple[str | None, int | None]:
    """The (remote_ip, remote_port) this indicator was seen on, when it IS the peer.

    Only meaningful when the matched indicator is the remote endpoint of a flow — a
    domain from a DNS query has no port, and we return (None, None) rather than invent
    one. A wrong observable is worse than no observable: it would cluster two unrelated
    findings and manufacture corroboration that does not exist.
    """
    p = row.get("payload") or {}
    if row.get("kind") == "network_flow" and p.get("remote_ip") == ind:
        port = p.get("remote_port")
        return ind, int(port) if port is not None else None
    if row.get("kind") == "ids_alert" and p.get("dest_ip") == ind:
        port = p.get("dest_port")
        return ind, int(port) if port is not None else None
    return None, None


def run(pg, ts) -> int:
    iocs = load_iocs()
    rows = db.network_rows(ts)
    seen: set[tuple] = set()
    created = 0
    for row in rows:
        asset = row["host_id"]
        for ind in candidates(row):
            ioc = iocs.get(ind)
            if not ioc:
                continue
            obs_ip, obs_port = _observable(row, ind)
            # Dedup at OBSERVABLE granularity, not just (asset, indicator): the same bad
            # IP contacted on two ports is two flows, and collapsing them would leave one
            # of them unable to cluster with the agent/Sigma findings about it.
            key = (asset, ind, obs_port)
            if key in seen:
                continue
            seen.add(key)
            db.ensure_asset(pg, asset)
            db.upsert_finding(pg, {
                "asset_id": asset, "domain": "network", "rule_id": f"ioc.{ind}",
                "title": f"IOC match: {ind} ({ioc.get('type')}) — {ioc.get('event_info')}",
                "description": f"Indicator {ind} from MISP event '{ioc.get('event_info')}' "
                               f"observed in {row['kind']} telemetry.",
                "severity": _SEV.get((ioc.get("threat_level") or "high").lower(), "HIGH"),
                "source_tool": "misp", "raw_ref": ind, "dedup_key": db.fp(asset, "ioc", ind),
                # What was OBSERVED, so this clusters with the agent rule and the Sigma
                # detection about the same connection instead of standing alone.
                "observable_key": db.observable_key(asset, obs_ip, obs_port),
                "port": obs_port,
                "fingerprint": db.fp("misp", asset, "network", f"ioc.{ind}", obs_port),
                "threat_intel": {"indicator": ind, "type": ioc.get("type"),
                                 "misp_event": ioc.get("event_info"), "tags": ioc.get("tags"),
                                 "observed_in": row["kind"]},
                "evidence": {"indicator": ind, "observed_in": row["kind"],
                             "remote_ip": obs_ip, "remote_port": obs_port},
            })
            created += 1
    log.info("misp: %d IOC-match finding(s) from %d telemetry rows", created, len(rows))
    return created
