# Telemetry schema — v1

The **single source of truth** for the telemetry wire format. Both `ingest-edge`
(Go) and `workers` (Python) validate against `envelope.schema.json` — the schema
is baked into each image at build time from this directory, so there is exactly
one definition.

## Envelope

Every message is an *envelope* with a small fixed header plus a `kind`-specific
`payload`:

| Field            | Notes |
|------------------|-------|
| `schema_version` | `"1.0"` — pinned. A breaking change becomes **v2** with a new `telemetry.v2.>` subject namespace. |
| `event_id`       | UUID; reused as the OpenSearch `_id` (idempotent indexing). |
| `agent_id`       | Cross-checked against the mTLS client-cert CN at ingest. |
| `host`           | `{host_id, hostname, os?, ip?}`. |
| `collected_at`   | When the agent observed the event (RFC 3339). |
| `ingested_at`    | Stamped by `ingest-edge` on receipt (agents omit it). |
| `kind`           | One of `system_info, process_event, network_flow, fim_event, osquery_result`. |
| `labels`         | Optional `string→string` map. |
| `payload`        | Body; minimal required fields enforced per `kind`. |

## Subjects

`ingest-edge` publishes each envelope to `telemetry.v1.<kind>` on the JetStream
stream **`TELEMETRY`** (which captures `telemetry.v1.>`). Routing by subject lets
consumers subscribe to all telemetry or a single kind.

## Versioning rule

- **Additive, backward-compatible** changes (new optional payload field) stay in v1.
- **Breaking** changes (renamed/removed field, new required field, type change)
  require `v2/envelope.schema.json` and the `telemetry.v2.>` subject space, so old
  and new agents can coexist during rollout.
