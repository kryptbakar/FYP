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

Measured 2026-08-29, full stack idle (14 containers, `--profile agentic`), 16 GB host with
**5.788 GiB allocated to Docker**. `docker stats --no-stream`.

| Container | Idle CPU% | Idle RSS | Under B1 |
|---|---|---|---|
| opensearch | 1.22% | **1.208 GiB** | _run me_ |
| n8n | 0.31% | 484 MiB | |
| ollama (no model resident) | 0.00% | 111 MiB | |
| timescaledb | 0.01% | 89 MiB | |
| investigation-orchestrator | 0.00% | 77 MiB | |
| api | 0.20% | 69 MiB | |
| grafana | 0.05% | 60 MiB | |
| postgres | 0.00% | 58 MiB | |
| enrichment | 0.00% | 39 MiB | |
| workers | 0.09% | 32 MiB | |
| mailpit | 0.00% | 23 MiB | |
| ingest-edge | 3.26% | 7.9 MiB | |
| nats | 0.08% | 6.5 MiB | |
| console (nginx) | 0.00% | 6.7 MiB | |
| **total** | | **≈ 2.3 GiB** | |

Two things worth saying out loud. **OpenSearch alone is over half the idle footprint** —
more than the other thirteen services combined. And `ollama` reads as 111 MiB only because
no model is resident; loading `llama3.2:3b` adds ~2.2 GiB, which is why the heavy tools
profile and the LLM cannot coexist in 5.788 GiB. That is not a tuning problem — it is the
hardware constraint that shapes the entire agentic result below.

### B5 — risk-engine scoring

| Findings in DB | Wall time | Findings/sec |
|---|---|---|
| 63 | **3.7 s** (incl. container start) | ~17/s |

Container start dominates at this size, so this is a *floor*, not a throughput measurement:
scoring 63 findings is not the work — standing up Python and loading the XGBoost model is.
Re-run at 10k+ findings before quoting a rate.

### B6 — investigation orchestrator, per-node latency

The measurement the architecture rests on. Taken from persisted `investigation_steps` rows
— 13 real runs, `llama3.2:3b`, CPU-only.

| Node | Runs | p50 (ms) | p95 (ms) |
|---|---|---|---|
| **synthesize** (the only LLM call) | 13 | **121 367** | 237 634 |
| intel_context | 13 | 51 | 109 |
| historical_context | 13 | 47 | 107 |
| asset_context | 12 | 46 | 320 |
| load_subject | 13 | 41 | 252 |
| fusion_context | 13 | 40 | 194 |
| attack_context | 13 | 23 | 196 |
| validate | 13 | 12 | 78 |

**Synthesis is roughly 2 600× the median specialist and 10 000× the citation validator.**
Every deterministic node finishes in tens of milliseconds; the one node that consults a
model takes two minutes. This is the strongest quantitative form of the design position:
the evidence layer is essentially free, and the whole cost — and the whole risk — sits in a
single replaceable node.

It is also why the orchestrator runs serially (`ORCH_CONCURRENCY=1`), why
`POST /investigations` needs admission control despite answering in milliseconds, and why
the console polls instead of blocking.

`asset_context` p95 (320 ms) is an outlier against its own 46 ms median: that is the run
where a missing `compliance_results` grant made it fail. Kept in the table rather than
excluded — it is a real measurement of a real failure, and the fix is pinned by a test.

## 5. Reporting in the thesis

Quote B1 (sustained events/sec), B2 idle p95, and B3's gate result in the
evaluation chapter, with the §1 environment table as a footnote. The honest
framing: single-host Compose numbers are the floor; the K3s deployment scales
workers horizontally (deploy/helm), which is a claim about architecture, not a
measured number, until a multi-node run is recorded.
