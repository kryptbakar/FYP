"""Telemetry worker — consume from JetStream, fan out to the data stores.

Flow:  JetStream (TELEMETRY / telemetry.v1.>)  ->  validate  ->  TimescaleDB + OpenSearch  ->  ack

Design notes:
- **Durable pull consumer.** Position is persisted server-side, so a worker
  restart resumes exactly where it left off (replay/no-loss). Scale out by
  running N replicas sharing the same durable name — JetStream load-balances.
- **Back-pressure** is a property of the broker: `max_ack_pending` bounds how
  many un-acked messages the server will hand out. If the data stores slow down,
  we stop acking, the server stops delivering, and messages safely accumulate in
  the stream instead of being dropped. `SLOW_MS` lets us demonstrate this.
- **Broker-agnostic seam:** all NATS specifics live in this file; the storage
  fan-out (storage.py) knows nothing about the broker, so Kafka could replace it.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
from pathlib import Path

import nats
import nats.errors
from jsonschema import Draft202012Validator
from nats.js.api import AckPolicy, ConsumerConfig, StorageType, StreamConfig

from storage import Storage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("workers")


def env(k: str, default: str) -> str:
    return os.getenv(k) or default


NATS_URL = env("NATS_URL", "nats://nats:4222")
STREAM = env("INGEST_STREAM", "TELEMETRY")
SUBJECT_PREFIX = env("INGEST_SUBJECT_PREFIX", "telemetry.v1")
DURABLE = env("WORKER_DURABLE", "telemetry-workers")
BATCH = int(env("WORKER_BATCH", "50"))
ACK_WAIT = int(env("WORKER_ACK_WAIT", "30"))
MAX_ACK_PENDING = int(env("WORKER_MAX_ACK_PENDING", "500"))
SLOW_MS = int(env("WORKER_SLOW_MS", "0"))  # artificial per-batch delay to demo back-pressure

PG_DSN = (
    f"host={env('TIMESCALE_HOST', 'timescaledb')} port={env('TIMESCALE_PORT_INTERNAL', '5432')} "
    f"dbname={env('TIMESCALE_DB', 'soc_telemetry')} user={env('TIMESCALE_USER', 'soc')} "
    f"password={env('TIMESCALE_PASSWORD', 'soc')}"
)
OS_URL = f"http://{env('OPENSEARCH_HOST', 'opensearch')}:{env('OPENSEARCH_PORT_INTERNAL', '9200')}"
OS_INDEX = env("OPENSEARCH_INDEX", "telemetry-v1")

# Defense-in-depth: re-validate against the same schema ingest-edge uses.
_SCHEMA_PATH = Path(env("SCHEMA_PATH", "/app/schema/envelope.schema.json"))
_validator: Draft202012Validator | None = None
if _SCHEMA_PATH.exists():
    _validator = Draft202012Validator(json.loads(_SCHEMA_PATH.read_text()))


async def ensure_stream(js) -> None:
    """Create the stream if it doesn't exist (workers may start before ingest-edge)."""
    try:
        await js.stream_info(STREAM)
    except Exception:
        await js.add_stream(
            StreamConfig(
                name=STREAM,
                subjects=[f"{SUBJECT_PREFIX}.>"],
                storage=StorageType.FILE,
                max_age=7 * 24 * 3600,
            )
        )
        log.info("created stream %s", STREAM)


async def run() -> None:
    storage = Storage(PG_DSN, OS_URL, OS_INDEX)
    await storage.init()

    nc = await nats.connect(NATS_URL, name="telemetry-worker", reconnect_time_wait=1, max_reconnect_attempts=-1)
    js = nc.jetstream()
    await ensure_stream(js)

    psub = await js.pull_subscribe(
        subject=f"{SUBJECT_PREFIX}.>",
        durable=DURABLE,
        stream=STREAM,
        config=ConsumerConfig(
            durable_name=DURABLE,
            ack_policy=AckPolicy.EXPLICIT,
            ack_wait=ACK_WAIT,
            max_ack_pending=MAX_ACK_PENDING,
        ),
    )
    log.info(
        "worker up: stream=%s durable=%s batch=%d max_ack_pending=%d slow_ms=%d",
        STREAM, DURABLE, BATCH, MAX_ACK_PENDING, SLOW_MS,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    total = 0
    while not stop.is_set():
        try:
            msgs = await psub.fetch(BATCH, timeout=2)
        except (asyncio.TimeoutError, nats.errors.TimeoutError):
            continue

        rows, docs, good = [], [], []
        for m in msgs:
            try:
                env_doc = json.loads(m.data)
                if _validator is not None:
                    _validator.validate(env_doc)
                seq = m.metadata.sequence.stream if m.metadata else None
                rows.append(Storage.to_row(env_doc, seq))
                docs.append(env_doc)
                good.append(m)
            except Exception as e:  # poison message: log + term so it isn't redelivered forever
                log.warning("dropping bad message: %s", e)
                await m.term()

        try:
            await storage.write_timescale(rows)
            await storage.write_opensearch(docs)
        except Exception as e:
            # Storage failed: NAK the batch so JetStream redelivers (no data loss).
            log.error("storage write failed, NAKing batch: %s", e)
            for m in good:
                await m.nak()
            await asyncio.sleep(1)
            continue

        for m in good:
            await m.ack()
        total += len(good)
        if good:
            log.info("processed batch=%d total=%d", len(good), total)
        if SLOW_MS:
            await asyncio.sleep(SLOW_MS / 1000.0)

    log.info("draining; processed total=%d", total)
    await nc.drain()
    await storage.close()


if __name__ == "__main__":
    asyncio.run(run())
