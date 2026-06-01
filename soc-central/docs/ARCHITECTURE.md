# SOC Central — Architecture

> Status: living document. Phase 0 establishes the skeleton; each phase fills in
> a layer. This describes the **target** design and notes what is real vs. stubbed.

## 1. Goals & constraints

- **Air-gapped / on-prem first.** Every external feed is **mirrored locally** and
  consumed from the mirror. Exactly one component (`feed-sync`) may touch the
  internet; everything else is offline at runtime.
- **Integrate, don't reinvent.** Use best-in-class OSS for the commodity layers
  (data stores, broker, agent primitives). Spend our original effort on the
  **intelligence layer**: exploit-aware risk scoring + explainable ML + analyst-
  controlled response.
- **Understandable & defensible.** Clarity over cleverness; non-obvious choices
  are recorded in [DECISIONS.md](DECISIONS.md).
- **Linux-first.** Windows agent parity is out of scope for the MVP.

## 2. The four layers

```
                          ┌──────────────────────────────────────────────┐
                          │              PRESENTATION LAYER               │
                          │   Grafana (metrics/trends/heatmaps)           │
                          │   Next.js + Tailwind console (triage, cases,  │
                          │   XAI finding detail, analyst feedback)       │
                          └───────────────▲──────────────▲───────────────┘
                                          │ REST/SSE     │ dashboards
                          ┌───────────────┴──────────────┴───────────────┐
                          │                 DATA LAYER                    │
                          │  PostgreSQL    TimescaleDB     OpenSearch     │
                          │  (state)       (telemetry)     (log search)   │
                          └───▲───────────────▲────────────────▲─────────┘
                              │ fan-out (enrich workers)        │
   ┌──────────────────────────┴─────────────────────────────────────────┐
   │                 INGESTION & ASSESSMENT LAYER                         │
   │   ingest-edge (Go, stateless: authN + schema-validate + enqueue)     │
   │        │                                                             │
   │        ▼                                                             │
   │   NATS JetStream  ──►  Python workers (enrich, score, fan-out)       │
   │                                  ▲                                   │
   │                        feed-sync (the ONLY internet-facing job:      │
   │                        NVD / EPSS / KEV / abuse.ch → local mirror)   │
   └──────────────────────────▲──────────────────────────────────────────┘
                              │ mutual TLS, signed command channel
   ┌──────────────────────────┴──────────────────────────────────────────┐
   │                    ENDPOINT AGENT LAYER (Go)                          │
   │   eBPF (proc/net)   embedded osqueryd   YARA   FIM (fanotify/auditd)  │
   │   resource-capped · mTLS · signed active-response channel             │
   └───────────────────────────────────────────────────────────────────────┘
```

### Endpoint Agent Layer (Phase 2)
Lightweight Go agents on monitored Linux hosts: eBPF process/network observation,
embedded `osqueryd` for host-state SQL, YARA IOC scanning, file-integrity
monitoring (fanotify/auditd). Resource-capped (configurable CPU/mem), mutual TLS
to the server, and a **signed** command channel for analyst-approved active
response (containment only).

### Ingestion & Assessment Layer (Phases 1, 3)
- **`ingest-edge` (Go):** stateless and horizontally scalable. It does only three
  things — authenticate the agent (mTLS), validate the telemetry against the
  versioned schema, and enqueue to the broker. No business logic, no DB writes.
- **NATS JetStream:** durable broker giving us back-pressure and replay. The
  consumer interface is kept **broker-agnostic** so Kafka can be swapped in later.
- **Python workers:** consume from JetStream, enrich (CVE mapping + CVSS/EPSS/KEV
  from the local mirror), score, and fan out to the data stores.
- **`feed-sync`:** the single internet-facing job. Mirrors NVD/EPSS/KEV/abuse.ch
  into a local feed store on a schedule. All enrichment reads the mirror, never live.

### Data Layer (Phase 0 brings these up)
- **PostgreSQL** — transactional state: assets, findings, incidents, compliance
  results, audit log, analyst feedback.
- **TimescaleDB** — time-series telemetry: host/network metrics, eBPF flow rollups,
  trend data for dashboards.
- **OpenSearch** — full-text / log search over raw telemetry and events.

### Presentation Layer (Phase 7)
- **Grafana** — metrics, trends, exposure heatmaps, compliance status (provisioned
  datasources to Timescale/Postgres/OpenSearch).
- **Next.js + Tailwind console** — incident triage, case management, XAI-backed
  finding detail (SHAP contributions + counterfactuals), analyst feedback capture.

## 3. Primary data flow

1. Agent collects host state (osquery), file-integrity events, and process/network
   observations (eBPF); ships them over mTLS to `ingest-edge`.
2. `ingest-edge` authenticates + schema-validates + enqueues to JetStream.
3. Workers consume, write raw telemetry to TimescaleDB/OpenSearch, then **enrich**:
   map packages/OS/ports to CVEs and attach CVSS/EPSS/KEV from the local mirror.
4. The **scoring engine** computes a composite risk score (and, from Phase 5, an
   XGBoost prediction with SHAP explanation) per finding/asset.
5. The **compliance engine** evaluates CIS/org-policy rules against osquery state,
   storing pass/fail/partial with **hash-chained evidence records**.
6. Analysts triage in the console; **active response** (containment only) is issued
   over the signed command channel with audit logging and two-person approval for
   destructive actions.

## 4. The three assessment domains (Phase 3)
- **Application** — package CVEs from osquery inventory.
- **System** — CIS hardening gaps.
- **Network** — exposed ports / insecure services / eBPF flow anomalies.

## 5. Intelligence layer (Phase 5 — the differentiator)
Composite score = weighted blend of **CVSS + EPSS + KEV presence + asset exposure +
vuln age + compliance impact + service criticality**. An XGBoost model (trained on
the enriched dataset) ranks findings; **SHAP** surfaces per-finding contribution
analysis and counterfactuals. Analyst feedback feeds a monthly retraining loop.

## 6. Cross-cutting concerns
- **Security:** OIDC/SAML SSO, RBAC, mutual TLS, signed agent binaries, and a
  **hash-chained immutable audit log** (Phase 7). Vault-backed secrets in K3s (Phase 8).
- **Observability:** Prometheus + Grafana + Loki + OpenTelemetry.
- **Multi-tenancy:** modelled for, **not enforced** in the MVP (explicit non-goal).

## 7. Deployment evolution
- **MVP (now):** Docker Compose on a single host — data stores + broker + API,
  growing service-by-service. See [../docker-compose.yml](../docker-compose.yml).
- **Production (Phase 8):** K3s + Helm, CloudNativePG, OpenSearch operator, ArgoCD
  GitOps, Velero backup/DR, Vault secrets, signed agent binaries, air-gapped
  offline update channel for feed sync.

## 8. Phase 0 reality check (what's real today)
- ✅ Compose stack: PostgreSQL, TimescaleDB, OpenSearch, NATS JetStream, FastAPI, Grafana.
- ✅ API skeleton: `/`, `/health`, `/version`, `/health/ready` (readiness probes
  Postgres + OpenSearch + NATS to prove the stack is wired together).
- ✅ Grafana provisioned with Postgres/Timescale datasources (dashboards come in Phase 7).
- ⏳ Stubbed / not built yet: agent, ingest-edge, workers, feed-sync, ml, web —
  directories exist with phase markers.

## 9. Default ports (MVP)
| Service | Port | Notes |
|---------|------|-------|
| API | 8000 | FastAPI |
| PostgreSQL | 5432 | transactional |
| TimescaleDB | 5433→5432 | telemetry (host 5433 to avoid clashing with Postgres) |
| OpenSearch | 9200 | security plugin disabled in MVP |
| NATS | 4222 / 8222 | client / monitoring |
| Grafana | 3000 | admin/admin by default (change in `.env`) |
