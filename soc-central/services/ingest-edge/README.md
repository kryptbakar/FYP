# ingest-edge

**Built in:** Phase 1 · **Language:** Go

The stateless edge of the ingestion backbone. It does **only** three things, on
purpose, so it stays horizontally scalable and holds no state:

1. **Authenticate the agent** — mutual TLS (client cert verified against the CA)
   **plus** a shared bearer token. The client-cert CN must match the envelope's
   `agent_id`.
2. **Validate** every telemetry envelope against the versioned JSON Schema
   (`schema/telemetry/v1/`, baked into the binary via `go:embed`, with `uuid` /
   `date-time` format assertions on).
3. **Enqueue** accepted envelopes onto NATS JetStream at `telemetry.v1.<kind>`
   (stamping `ingested_at`, deduping by `event_id`).

No database, no business logic — back-pressure is the broker's job.

## Endpoints

| Method | Path             | Port  | Notes |
|--------|------------------|-------|-------|
| POST   | `/v1/telemetry`  | 8443  | mTLS. Body: one envelope **or** a JSON array (batch). Returns `{accepted, rejected, errors}`. |
| GET    | `/health`        | 8081  | Liveness (plain HTTP — no client cert, so probes work). |
| GET    | `/ready`         | 8081  | Ready when connected to NATS. |

## Config (env)

`INGEST_ADDR` (`:8443`), `INGEST_HEALTH_ADDR` (`:8081`), `INGEST_TLS_ENABLED`,
`INGEST_TLS_CERT`, `INGEST_TLS_KEY`, `INGEST_CLIENT_CA` (set ⇒ mTLS required),
`INGEST_AGENT_TOKEN`, `NATS_URL`, `INGEST_STREAM` (`TELEMETRY`),
`INGEST_SUBJECT_PREFIX` (`telemetry.v1`).

## Build / run

Built and run via the root `docker-compose.yml` (build context is the repo root so
the shared schema can be embedded). Certs come from `make certs`.

## Example

```bash
curl --cacert certs/ca.crt \
     --cert certs/agent-001.crt --key certs/agent-001.key \
     -H "Authorization: Bearer $INGEST_AGENT_TOKEN" \
     -H "Content-Type: application/json" \
     --data @envelope.json \
     https://localhost:8443/v1/telemetry
```
