# Performance benchmarks — methodology & results

Air-gapped buyers and FYP examiners both ask the same three questions: *how many
events per second can it ingest, how long until an event is queryable, and what
does it cost in hardware?* This document is the protocol for answering them with
numbers, plus the result tables. **Every number in §4 must come from a recorded
run** — rerun the harness and update the tables rather than estimating.

All harnesses are in-repo and containerised; nothing here needs internet access.

## 1. Test environment (record before every run)

| Item | Value (fill in per run) |
|---|---|
| Host CPU / cores | e.g. Ryzen 7 5800H, 8c/16t |
| RAM | e.g. 32 GB |
| Disk | e.g. NVMe SSD (model) |
| OS / kernel | e.g. Ubuntu 22.04, 6.8 |
| Docker / Compose version | |
| VYREX git commit | `git rev-parse --short HEAD` |
| Stack profile | core only / core+sensors / … |

Benchmarks are meaningless without this table — two runs are only comparable on
the same row values.

## 2. Harnesses

| # | Path measured | Command | Metric produced |
|---|---|---|---|
| B1 | Ingest throughput: `ingest-edge → JetStream → workers → TimescaleDB/OpenSearch` | `make bench-ingest N=50000` | envelopes/sec sustained (printed by the producer) |
| B2 | End-to-end ingest latency (same path, per event) | `make bench-e2e P=200` | p50 / p95 / p99 / max ms (printed by the probe) |
| B3 | API read path under analyst load | `make loadtest` (k6, thresholds: p95 < 400 ms, errors < 1%) | pass/fail gate + p95 per endpoint |
| B4 | Resource footprint at rest and under B1 | `docker stats --no-stream` before and during B1 | CPU% / RSS per container |
| B5 | Risk-engine scoring throughput | time `make risk-score` with the DB seeded (`make seed feeds-seed assess scan-ingest`) | findings scored/sec |

### Protocol notes

- Run each harness **3 times**, discard the first (cold caches), report the
  median of the remaining two.
- B1: ramp N through 5 000 → 50 000 → 200 000. The knee where accepted/sec
  flattens is the sustained capacity; note `WORKER_BATCH` / `WORKER_MAX_ACK_PENDING`
  values used (workers/README).
- B2: the probe polls the DB at ~10 ms resolution; subtract ~10 ms for the true
  pipeline figure. Run once on an idle stack and once concurrently with B1 —
  the delta is the queueing cost under load.
- B4: capture with `docker stats --no-stream | tee reports/stats-$(date +%s).txt`.
- Keep raw outputs in `reports/` (gitignored if large); paste medians here.

## 3. Capacity model (derive after B1/B2)

From B1's sustained rate, derive the sizing claims used in
docs/PRODUCTION-DEPLOYMENT.md:

- events/sec per worker replica → workers needed for a fleet of *X* endpoints at
  *Y* events/endpoint/min
- TimescaleDB growth: rows/day × avg row size (measure with
  `SELECT pg_size_pretty(hypertable_size('telemetry_raw'))` before/after B1)
  → disk/day per 1 000 endpoints, and the retention policy that fits the disk budget.

## 4. Results

### B1 — ingest throughput (sustained)

| N | Batch | Accepted/sec | Rejected | Worker lag observed |
|---|---|---|---|---|
| 5 000 | 200 | _run me_ | | |
| 50 000 | 200 | _run me_ | | |
| 200 000 | 200 | _run me_ | | |

### B2 — end-to-end latency (ms)

| Condition | p50 | p95 | p99 | max | lost |
|---|---|---|---|---|---|
| Idle stack | _run me_ | | | | |
| Concurrent with B1 @50k | _run me_ | | | | |

### B3 — API read path (k6, 20 VUs, 60 s)

| Endpoint group | p95 (ms) | Error rate | Gate |
|---|---|---|---|
| console hot paths (k6-api.js) | _run me_ | | p95<400ms, err<1% |

### B4 — resource footprint

| Container | Idle CPU% / RSS | Under B1 CPU% / RSS |
|---|---|---|
| ingest-edge | _run me_ | |
| nats | | |
| workers | | |
| timescaledb | | |
| opensearch | | |
| api | | |

### B5 — risk-engine scoring

| Findings in DB | Wall time | Findings/sec |
|---|---|---|
| _run me_ | | |

## 5. Reporting in the thesis

Quote B1 (sustained events/sec), B2 idle p95, and B3's gate result in the
evaluation chapter, with the §1 environment table as a footnote. The honest
framing: single-host Compose numbers are the floor; the K3s deployment scales
workers horizontally (deploy/helm), which is a claim about architecture, not a
measured number, until a multi-node run is recorded.
