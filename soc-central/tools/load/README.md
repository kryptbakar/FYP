# Load & performance testing

Two paths are exercised:

## 1. API read path (k6)

`k6-api.js` drives the endpoints the analyst console hits hardest, with SLA thresholds
(p95 < 400 ms, error rate < 1 %). A failing threshold fails the run, so it works as a
performance gate in CI.

```bash
# native k6
k6 run -e BASE=http://localhost:8000 -e VUS=20 -e DURATION=60s tools/load/k6-api.js

# or containerised (no install)
docker run --rm -i --network host -e BASE=http://localhost:8000 \
  -v "$PWD/tools/load:/s" grafana/k6 run /s/k6-api.js

# or via make
make loadtest
```

While it runs, watch live latency/throughput in Grafana → **SOC Central — API metrics**
(fed by the `/metrics` Prometheus endpoint).

## 2. Ingestion path (producer)

The broker/worker pipeline is load-tested with the bundled fake producer, which pushes
schema-valid telemetry envelopes through `ingest-edge → JetStream → workers → stores`:

```bash
make produce N=50000      # back-pressure + throughput under sustained ingest
```

Tune worker back-pressure with `WORKER_BATCH` / `WORKER_MAX_ACK_PENDING` (see workers/).
