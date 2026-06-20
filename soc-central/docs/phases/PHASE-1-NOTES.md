# Phase 1 — Ingestion backbone

**Status:** complete and verified end-to-end. **Date:** 2026-06-01.

## What was built

The full ingestion path that every later phase feeds on:

```
fake-producer ──mTLS+token──> ingest-edge ──validate──> NATS JetStream ──> workers ──> TimescaleDB
   (agent stand-in)            (Go, stateless)        (TELEMETRY stream)   (Python)  └─> OpenSearch
```

| Component | Path | Role |
|-----------|------|------|
| Telemetry schema (v1) | [schema/telemetry/v1/](../schema/telemetry/v1/) | Versioned envelope contract; single source of truth, baked into both services. |
| `ingest-edge` (Go) | [services/ingest-edge/](../services/ingest-edge/) | mTLS + bearer token, CN↔`agent_id` binding, JSON-Schema validation, publish to `telemetry.v1.<kind>`. Stateless. |
| `workers` (Python) | [services/workers/](../services/workers/) | Durable JetStream pull consumer → TimescaleDB hypertable + OpenSearch index. Back-pressure + replay. |
| `fake-producer` (Python) | [tools/fake-producer/](../tools/fake-producer/) | Agent stand-in; generates all 5 telemetry kinds, posts over mTLS. Replaced by the Go agent in Phase 2. |
| Dev PKI | `scripts/gen-certs.sh` → `certs/` (gitignored) | CA + ingest-edge server cert + `agent-001` client cert. |

Design rationale is in [DECISIONS.md](../DECISIONS.md) D-011…D-014.

## How to run

```bash
make up                 # brings up the stack + generates certs (idempotent)
make produce N=500      # push 500 fake telemetry envelopes through the pipeline
# Windows:
pwsh scripts/dev.ps1 up
pwsh scripts/dev.ps1 produce -N 500
```

Then inspect: TimescaleDB `telemetry_raw`, OpenSearch index `telemetry-v1`,
JetStream stats at <http://localhost:8222/jsz?streams=true&consumers=true>.

## Verification (actual runs)

**1) End-to-end happy path** — 500 envelopes produced over mTLS:

```
producer:   sent=500 accepted=500 rejected=0  (574/s)
TimescaleDB telemetry_raw: 500 rows, hypertable (1 chunk)
  by kind: process_event 109 | system_info 103 | fim_event 102 | network_flow 97 | osquery_result 89
OpenSearch  telemetry-v1: count=500
```

**2) Auth + validation are enforced** (negative tests, `tools/fake-producer/negtest.py`):

| Case | Result |
|------|--------|
| No client cert | **BLOCKED at TLS handshake** (mTLS required) |
| Valid cert, wrong token | **401** `invalid or missing bearer token` |
| Valid cert+token, invalid schema (missing `payload.value`) | **400** rejected, schema error |
| Valid cert+token, `agent_id`=`agent-999` ≠ cert CN `agent-001` | **400** rejected, identity mismatch |
| Fully valid | **200** `accepted:1` |

**3) Back-pressure** — workers throttled to ~25 msg/s (`WORKER_SLOW_MS=2000`), then a
2000-envelope burst:

```
producer: sent=2000 accepted=2000 in 1.3s (1573/s)   <- producer far outruns workers
T0:     stream.messages=2501  num_pending=1999  num_ack_pending<=500   <- broker BUFFERS, doesn't drop
T+0s:   num_pending=1499  ack_floor=1003
T+10s:  num_pending=1249  ack_floor=1253     <- draining at the throttle rate, in order
T+20s:  num_pending=999   ack_floor=1503
```

`stream.messages` stayed **2501 throughout** — nothing dropped; the stream is the
durable buffer and `max_ack_pending` bounds in-flight work.

**4) Replay / durability / no-loss** — after restoring fast workers and draining:

```
num_pending=0  ack_floor=2502  delivered=2502
TimescaleDB telemetry_raw : 2501
OpenSearch  telemetry-v1  : 2501
distinct event_ids        : 2501     <- no loss, no duplication
```

The durable consumer was **force-recreated twice mid-stream** and resumed from its
persisted `ack_floor` (not from zero). Separately, a **full Docker Desktop restart**
mid-phase preserved all rows (durable volumes) and the stream/consumer state — proving
replay survives process and engine restarts.

## What's stubbed / deferred

- **Real agent** — the Go endpoint agent (eBPF/osquery/YARA/FIM) is Phase 2; the
  `fake-producer` stands in for now.
- **Enrichment** — workers currently write *raw* telemetry only; CVE mapping +
  CVSS/EPSS/KEV enrichment is Phase 3.
- **TimescaleDB dedup** — OpenSearch is idempotent (`_id=event_id`); Timescale upsert is
  deferred (see D-014). Acks keep pace, so no duplicates were observed.
- **Token storage** — single shared bearer token in `.env`; per-agent tokens/secrets
  move to Vault in the K3s phase.
- **Broker TLS** — agent↔ingest is mTLS; ingest↔NATS is in-cluster plaintext for the MVP.

## Acceptance

✅ Versioned telemetry schema · ✅ mTLS + agent auth + schema validation at the edge ·
✅ Durable enqueue to JetStream · ✅ Workers persist to TimescaleDB + OpenSearch ·
✅ Back-pressure and replay demonstrated · ✅ Fake producer for testing.
