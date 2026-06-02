# sensor-bridge

**Built in:** Phase B · **Language:** Python · **Role:** file-based sensors → broker

Suricata and Zeek are server-side sensors that write **files**, not REST. This bridge
**tails** their output and publishes normalized envelopes into the **same JetStream
pipeline** every other source uses, so the existing `workers` fan them out to
TimescaleDB + OpenSearch — no parallel ingestion path (keeps Ground-Rule #4).

```
Suricata eve.json (event_type=alert)  ──▶ kind=ids_alert        (source_tool=suricata)
Zeek conn/dns/http/ssl/... logs       ──▶ kind=traffic_metadata (source_tool=zeek)
        │                                                   │
        └────────── sensor-bridge ──▶ JetStream telemetry.v1.<kind> ──▶ workers ──▶ stores
```

- **Internal sensors publish straight to the broker** (they run on the SOC host); only
  remote *agents* go through ingest-edge's mTLS edge (D-033). The bridge stamps
  `ingested_at`; workers still re-validate against the schema.
- **Modes:** `--once` (publish current file contents then exit — used by `make sensors-test`)
  or default **tail -f** (continuous, as the compose service).

## Run

```bash
make sensors-test     # generate a test pcap -> run Suricata -> ship alerts -> stores
# or as a live service (with the sensors profile):
docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile sensors up -d
```

## Config (env)
`NATS_URL`, `INGEST_SUBJECT_PREFIX`, `SURICATA_EVE`, `ZEEK_LOG_DIR`, `SENSOR_AGENT_ID`,
`SENSOR_HOST_ID`, `BRIDGE_POLL_SEC`.

## Verify
```
curl -s localhost:9200/telemetry-v1/_search -H content-type:application/json \
  -d '{"size":0,"aggs":{"t":{"terms":{"field":"source_tool.keyword"}}}}'
```
