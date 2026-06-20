"""wazuh-bridge — pull host-monitoring signal from the Wazuh Manager into the pipeline.

Wazuh's REST API is embedded in the Manager (port 55000, JWT auth) since 4.0 — the old
standalone wazuh-api repo is deprecated. This bridge authenticates, pulls **FIM (syscheck)**
and **SCA/CIS** results, normalizes them to the unified schema, and publishes onto the same
JetStream pipeline everything else uses:

  Wazuh syscheck (FIM)      -> kind=fim_event     (source_tool=wazuh)
  Wazuh SCA/CIS checks      -> kind=scan_finding  (source_tool=wazuh)

Reconciliation with our Go agent (D-035): both do FIM independently and BOTH feed the
pipeline tagged by source_tool — that's a multi-tool consensus signal, not duplication; the
Phase-F Fusion Engine dedups/merges by dedup_key and boosts confidence when they agree.

Modes:  --from-fixtures (offline, deterministic) | live (call the Manager API).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import nats

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("wazuh-bridge")


def env(k: str, d: str) -> str:
    return os.getenv(k) or d


NATS_URL = env("NATS_URL", "nats://nats:4222")
SUBJECT_PREFIX = env("INGEST_SUBJECT_PREFIX", "telemetry.v1")
WAZUH_URL = env("WAZUH_API_URL", "https://wazuh-manager:55000")
WAZUH_USER = env("WAZUH_API_USER", "wazuh-wui")
WAZUH_PASS = env("WAZUH_API_PASSWORD", "wazuh-wui")
AGENT_ID = env("WAZUH_AGENT_ID", "wazuh-001")
HOST_ID = env("WAZUH_HOST_ID", "wazuh-monitored-01")
FIXTURES = Path(__file__).parent / "fixtures"

# Wazuh syscheck event type -> our fim_event change enum.
_FIM_CHANGE = {"added": "created", "modified": "modified", "deleted": "deleted"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def envelope(kind: str, payload: dict, raw_ref: str | None) -> dict:
    return {
        "schema_version": "1.0", "event_id": str(uuid.uuid4()), "agent_id": AGENT_ID,
        "host": {"host_id": HOST_ID, "hostname": HOST_ID, "os": "linux"},
        "collected_at": now(), "ingested_at": now(),
        "kind": kind, "source_tool": "wazuh", "raw_ref": raw_ref,
        "labels": {"env": "lab", "layer": "host"}, "payload": payload,
    }


def fim_envelope(item: dict) -> dict:
    change = _FIM_CHANGE.get(item.get("event") or item.get("type"), "modified")
    payload = {"path": item.get("file") or item.get("path"), "change": change}
    if item.get("sha256"):
        payload["sha256"] = item["sha256"]
    if item.get("size") is not None:
        try:
            payload["size"] = int(item["size"])
        except (TypeError, ValueError):
            pass
    return envelope("fim_event", payload, raw_ref=item.get("file") or item.get("path"))


def sca_envelope(check: dict) -> dict:
    payload = {
        "scan_type": "cis_sca",
        "check_id": check.get("id"),
        "title": check.get("title"),
        "result": check.get("result"),               # passed | failed | not applicable
        "policy_id": check.get("policy_id"),
        "rationale": check.get("rationale"),
        "remediation": check.get("remediation"),
        "compliance": check.get("compliance"),        # e.g. [{"cis": ["1.1.1"]}]
    }
    return envelope("scan_finding", payload, raw_ref=str(check.get("id")))


# ---------------------------------------------------------------- sources ----
def from_fixtures() -> tuple[list, list]:
    syscheck = json.loads((FIXTURES / "syscheck.json").read_text())
    sca = json.loads((FIXTURES / "sca_checks.json").read_text())
    return syscheck, sca


def from_live() -> tuple[list, list]:
    with httpx.Client(verify=False, timeout=30) as c:  # Manager uses a self-signed cert
        tok = c.post(f"{WAZUH_URL}/security/user/authenticate", auth=(WAZUH_USER, WAZUH_PASS)).json()["data"]["token"]
        h = {"Authorization": f"Bearer {tok}"}
        agent = env("WAZUH_TARGET_AGENT", "000")
        syscheck = c.get(f"{WAZUH_URL}/syscheck/{agent}", headers=h, params={"limit": 500}).json()["data"]["affected_items"]
        checks: list = []
        policies = c.get(f"{WAZUH_URL}/sca/{agent}", headers=h).json()["data"]["affected_items"]
        for p in policies:
            pol = p.get("policy_id")
            checks += c.get(f"{WAZUH_URL}/sca/{agent}/checks/{pol}", headers=h,
                            params={"limit": 500}).json()["data"]["affected_items"]
    return syscheck, checks


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-fixtures", action="store_true", help="offline: use bundled Wazuh API fixtures")
    args = ap.parse_args()

    syscheck, sca = from_fixtures() if args.from_fixtures else from_live()
    log.info("wazuh: %d FIM item(s), %d SCA check(s) (%s)",
             len(syscheck), len(sca), "fixtures" if args.from_fixtures else "live")

    nc = await nats.connect(NATS_URL, name="wazuh-bridge", max_reconnect_attempts=-1)
    js = nc.jetstream()
    sent = 0
    try:
        for item in syscheck:
            e = fim_envelope(item)
            await js.publish(f"{SUBJECT_PREFIX}.fim_event", json.dumps(e).encode())
            sent += 1
        for check in sca:
            e = sca_envelope(check)
            await js.publish(f"{SUBJECT_PREFIX}.scan_finding", json.dumps(e).encode())
            sent += 1
    finally:
        log.info("published %d wazuh event(s)", sent)
        await nc.drain()


if __name__ == "__main__":
    asyncio.run(main())
