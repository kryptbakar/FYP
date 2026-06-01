# workers

**Built in:** Phase 1 (raw fan-out) · Phase 3 adds enrichment · **Language:** Python (asyncio)

Durable JetStream consumers that take raw telemetry and fan it out to the data
stores:

```
JetStream (TELEMETRY / telemetry.v1.>)  ->  validate  ->  TimescaleDB + OpenSearch  ->  ack
```

- **TimescaleDB** — `telemetry_raw` hypertable (queryable record for trends/dashboards).
- **OpenSearch** — `telemetry-v1` index, `_id = event_id` (idempotent, full-text search).

## Why it's built this way

- **Durable pull consumer** (`WORKER_DURABLE`): position persists server-side, so a
  restart **replays** from where it left off — no loss. Run N replicas with the same
  durable name to scale out; JetStream load-balances.
- **Back-pressure** is the broker's: `WORKER_MAX_ACK_PENDING` bounds in-flight
  un-acked messages. If the stores slow down we stop acking, JetStream stops
  delivering, and data safely accumulates in the stream. `WORKER_SLOW_MS` injects a
  per-batch delay to demonstrate this.
- **Poison messages** are `term()`-ed (logged, not redelivered forever); **storage
  failures** `nak()` the batch for redelivery.
- **Broker-agnostic seam:** all NATS code is in `worker.py`; `storage.py` knows
  nothing about the broker, so Kafka could replace it.

## Files
- `worker.py` — consume loop, ack/nak/term, back-pressure, signals.
- `storage.py` — TimescaleDB DDL + insert, OpenSearch index + `_bulk`.

## Config (env)
`NATS_URL`, `INGEST_STREAM`, `INGEST_SUBJECT_PREFIX`, `WORKER_DURABLE`,
`WORKER_BATCH`, `WORKER_ACK_WAIT`, `WORKER_MAX_ACK_PENDING`, `WORKER_SLOW_MS`,
`TIMESCALE_*`, `OPENSEARCH_HOST`, `OPENSEARCH_INDEX`.
