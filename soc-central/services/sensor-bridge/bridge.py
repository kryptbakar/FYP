"""sensor-bridge — turns file-based sensor output into telemetry on the broker.

Suricata and Zeek are server-side sensors that write FILES (eve.json / *.log), not
REST. This bridge tails those files and publishes normalized envelopes into the SAME
JetStream pipeline every other source uses, so the existing workers fan them out to
TimescaleDB + OpenSearch. The broker interface stays stable (no parallel ingestion).

  Suricata eve.json (event_type=alert) -> kind=ids_alert        (source_tool=suricata)
  Zeek  conn/dns/http/ssl/... logs     -> kind=traffic_metadata (source_tool=zeek)

Internal sensors publish straight to the broker (they run on the SOC host); only remote
*agents* go through ingest-edge's mTLS edge (see DECISIONS D-033). The bridge stamps
ingested_at because it IS the ingestion point for this data; workers still re-validate.

Modes:  --once (publish everything currently in the files, then exit)  |  default (tail -f).
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

import nats

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("sensor-bridge")


def env(k: str, d: str) -> str:
    return os.getenv(k) or d


NATS_URL = env("NATS_URL", "nats://nats:4222")
SUBJECT_PREFIX = env("INGEST_SUBJECT_PREFIX", "telemetry.v1")
AGENT_ID = env("SENSOR_AGENT_ID", "sensor-001")
HOST_ID = env("SENSOR_HOST_ID", "soc-sensor-01")
HOSTNAME = env("SENSOR_HOSTNAME", "soc-sensor-01")
EVE_PATH = Path(env("SURICATA_EVE", "/var/log/suricata/eve.json"))
ZEEK_DIR = Path(env("ZEEK_LOG_DIR", "/zeek-logs"))
FALCO_LOG = Path(env("FALCO_LOG", "/falco/events.json"))   # Falco file_output (JSON lines)
POLL = float(env("BRIDGE_POLL_SEC", "2"))


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def envelope(kind: str, source_tool: str, payload: dict, raw_ref: str | None) -> dict:
    return {
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "agent_id": AGENT_ID,
        "host": {"host_id": HOST_ID, "hostname": HOSTNAME, "os": "linux"},
        "collected_at": now(),
        "ingested_at": now(),          # bridge is the ingestion point for sensor data
        "kind": kind,
        "source_tool": source_tool,
        "raw_ref": raw_ref,
        "labels": {"env": "lab", "layer": "network"},
        "payload": payload,
    }


def suricata_alert(ev: dict) -> dict | None:
    if ev.get("event_type") != "alert":
        return None
    a = ev.get("alert", {})
    payload = {
        "signature": a.get("signature"),
        "signature_id": a.get("signature_id"),
        "category": a.get("category"),
        "severity": a.get("severity"),
        "action": a.get("action"),
        "proto": ev.get("proto"),
        "src_ip": ev.get("src_ip"), "src_port": ev.get("src_port"),
        "dest_ip": ev.get("dest_ip"), "dest_port": ev.get("dest_port"),
        "app_proto": ev.get("app_proto"),
    }
    return envelope("ids_alert", "suricata", payload, raw_ref=str(ev.get("flow_id")))


def zeek_record(logname: str, rec: dict) -> dict:
    payload = {"log": logname, **rec}
    raw = rec.get("uid") or rec.get("fuid") or rec.get("id")
    return envelope("traffic_metadata", "zeek", payload, raw_ref=str(raw) if raw else None)


def falco_event(rec: dict) -> dict:
    # Falco JSON: {rule, priority, output, time, output_fields:{...}}
    payload = {
        "rule": rec.get("rule"),
        "priority": rec.get("priority"),
        "output": rec.get("output"),
        "fields": rec.get("output_fields", {}),
    }
    return envelope("runtime_alert", "falco", payload, raw_ref=rec.get("rule"))


class Publisher:
    def __init__(self, js):
        self.js = js
        self.count = 0

    async def send(self, e: dict) -> None:
        await self.js.publish(f"{SUBJECT_PREFIX}.{e['kind']}", json.dumps(e).encode())
        self.count += 1


async def drain_suricata(pub: Publisher, fh) -> None:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            e = suricata_alert(json.loads(line))
            if e:
                await pub.send(e)
        except json.JSONDecodeError:
            continue


async def drain_zeek(pub: Publisher, path: Path, fh) -> None:
    logname = path.stem  # conn, dns, http, ssl, ...
    for line in fh:
        line = line.strip()
        if not line or line.startswith("#"):  # skip Zeek TSV headers if any
            continue
        try:
            await pub.send(zeek_record(logname, json.loads(line)))
        except json.JSONDecodeError:
            continue


async def drain_falco(pub: Publisher, fh) -> None:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            await pub.send(falco_event(json.loads(line)))
        except json.JSONDecodeError:
            continue


async def run_once(pub: Publisher) -> None:
    if EVE_PATH.exists():
        with EVE_PATH.open() as fh:
            await drain_suricata(pub, fh)
        log.info("suricata: published alerts from %s", EVE_PATH)
    for logp in sorted(ZEEK_DIR.glob("*.log")):
        with logp.open() as fh:
            await drain_zeek(pub, logp, fh)
        log.info("zeek: published records from %s", logp.name)
    if FALCO_LOG.exists():
        with FALCO_LOG.open() as fh:
            await drain_falco(pub, fh)
        log.info("falco: published alerts from %s", FALCO_LOG)


async def run_tail(pub: Publisher) -> None:
    offsets: dict[str, int] = {}
    log.info("tailing %s and %s/*.log", EVE_PATH, ZEEK_DIR)
    while True:
        if EVE_PATH.exists():
            with EVE_PATH.open() as fh:
                fh.seek(offsets.get(str(EVE_PATH), 0))
                await drain_suricata(pub, fh)
                offsets[str(EVE_PATH)] = fh.tell()
        for logp in sorted(ZEEK_DIR.glob("*.log")):
            with logp.open() as fh:
                fh.seek(offsets.get(str(logp), 0))
                await drain_zeek(pub, logp, fh)
                offsets[str(logp)] = fh.tell()
        if FALCO_LOG.exists():
            with FALCO_LOG.open() as fh:
                fh.seek(offsets.get(str(FALCO_LOG), 0))
                await drain_falco(pub, fh)
                offsets[str(FALCO_LOG)] = fh.tell()
        await asyncio.sleep(POLL)


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="publish current contents then exit")
    args = ap.parse_args()

    nc = await nats.connect(NATS_URL, name="sensor-bridge", max_reconnect_attempts=-1)
    js = nc.jetstream()
    pub = Publisher(js)
    try:
        if args.once:
            await run_once(pub)
        else:
            await run_tail(pub)
    finally:
        log.info("published %d sensor event(s)", pub.count)
        await nc.drain()


if __name__ == "__main__":
    asyncio.run(main())
