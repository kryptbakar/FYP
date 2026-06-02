# SOC Central — Architecture

> Status: the build is complete (Phases 0–6, tool integration A–E, F fusion, G console,
> H air-gap, 8 K3s). This describes the design as built; §8 is the per-phase status.

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

### Tools Integration (Phases A–E, optional)
Ten battle-tested OSS security tools integrate behind opt-in Docker Compose
profiles (`--profile sensors`, `--profile scanners`, etc.), consuming output
without forking. Each tool's results are normalized to telemetry envelopes,
tagged with `source_tool`, and feed the pipeline as first-class findings. Heavy
platforms (OpenCTI, MISP, Wazuh) can be deployed independently per host capacity.
See [../docker-compose.tools.yml](../docker-compose.tools.yml) for details.

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

### Presentation Layer (Phase G)
- **Grafana** — metrics, trends, exposure heatmaps, compliance status (provisioned
  Postgres/Timescale datasources + the "SOC Central — Security Overview" dashboard).
- **Analyst console** — incident triage, case management, XAI-backed finding detail
  (the **SHAP waterfall** + multi-tool consensus + counterfactuals), and analyst
  feedback capture. Implemented as a **dependency-free SPA** served by nginx, which
  also reverse-proxies `/api` to the FastAPI (same-origin, no CORS) so the whole UI
  runs air-gapped with zero external assets (D-044/D-045). The Next.js/Tailwind
  toolchain named below is the production migration target once a mirrored npm
  registry exists (D-044).

## 3. Primary data flow

1. Agent collects host state (osquery), file-integrity events, and process/network
   observations (eBPF); ships them over mTLS to `ingest-edge`.
2. `ingest-edge` authenticates + schema-validates + enqueues to JetStream.
3. Workers consume from JetStream, write raw telemetry to TimescaleDB/OpenSearch,
   then **enrich**: map packages/OS/ports to CVEs and attach CVSS/EPSS/KEV from
   the local mirror. Workers also consume from internal sensors (Suricata/Zeek/Falco
   via `sensor-bridge`), active scanners (Trivy/Nuclei), and host/threat intel
   sources (Wazuh/MISP/OpenCTI), all normalized to telemetry envelopes and tagged
   with `source_tool` for multi-tool consensus and deduplication in Phase F.
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

## 4b. Tool Integration Layers (Phases A–E, optional)
All tools are optional and controlled by Docker Compose profiles:

- **Phase A (Sensors)** — Suricata (network IDS) + Zeek (traffic analysis).
  `sensor-bridge` tails EVE JSON / Zeek logs → normalizes to `ids_alert` /
  `traffic_metadata` → JetStream (D-034).

- **Phase B (Scanners)** — Trivy (container/image CVEs) + Nuclei (template scans).
  Results consumed by `enrichment --scan`, enriched with CVSS/EPSS/KEV from
  the local mirror, written as `scan_finding` (D-037).

- **Phase C (Host Monitoring)** — Wazuh Manager (FIM/SCA/CIS via embedded REST API
  on port 55000, JWT).
  `wazuh-bridge` polls the Manager API, normalizes FIM/SCA to `fim_event` /
  `scan_finding` (D-036).

- **Phase D (Runtime, optional)** — Falco (syscall detection).
  `sensor-bridge` tails file_output (JSON) → `runtime_alert`. Marked optional
  (D-031) as it overlaps the agent's eBPF and requires kernel access.

- **Phase E (Threat Intelligence)** — MISP (IOC store) + OpenCTI (ATT&CK mapping).
  `intel-enricher` matches agent findings against MISP IOCs and maps ATT&CK
  techniques via OpenCTI, producing `ioc_match` findings.

## 5. Intelligence layer (Phases 5 + F — the differentiator)
**Composite score (Phase 5/F)** = weighted blend of ten factors: **CVSS + EPSS + KEV +
asset exposure + vuln age + compliance impact + service criticality**, plus the three
**fusion factors** added in Phase F — **live threat-intel (MISP IOC) + multi-tool
consensus + ATT&CK context**. An XGBoost model (trained on the enriched dataset + analyst
feedback at 5× weight) ranks findings; native TreeSHAP surfaces a per-finding **waterfall**
(base → each factor → final) plus counterfactuals. Analyst feedback feeds a monthly
retraining loop.

**AI Fusion Engine (Phase F).** Before scoring, `ml/fusion.py` groups findings from every
tool by their `dedup_key` into clusters, records *which* tools agree, and derives a
saturating **consensus weight** (1 tool→0, 2→0.5, 3+→1.0) that boosts confidence when
independent tools corroborate. The cluster's tool list + threat-intel + ATT&CK context are
written to `findings.consensus` and surfaced in the console — this multi-tool dedup +
consensus front end is SOC Central's core original contribution. See [../ml/FUSION.md](../ml/FUSION.md).

## 6. Cross-cutting concerns
- **Security:** OIDC/SSO + RBAC via **Keycloak + oauth2-proxy** (Phase 8 / `deploy/identity`),
  mutual TLS (dev PKI now, Vault PKI in K3s), **Ed25519-signed** active-response channel
  with two-person approval + a **hash-chained immutable audit log** (Phase 6), and a
  **cosign-signed agent supply chain** with fail-closed endpoint verification (Phase 8).
  Vault-backed secrets in K3s (Phase 8).
- **Air-gap:** enforced + verified — a Docker `internal` network in the lab
  (`docker-compose.airgap.yml` + `make airgap-verify`) and a **K3s NetworkPolicy**
  (egress-deny / ingress-allow) in production. Only `feed-sync` egresses. See
  [AIRGAP.md](AIRGAP.md).
- **Observability:** Grafana dashboards; Prometheus/Loki/OpenTelemetry are roadmap.
- **Multi-tenancy:** modelled for, **not enforced** in the MVP (explicit non-goal).

## 7. Deployment evolution
- **MVP (now):** Docker Compose on a single host — data stores + broker + API,
  growing service-by-service. See [../docker-compose.yml](../docker-compose.yml).
  Tool integrations are optional behind Docker Compose profiles; `make up`
  launches only the core stack. Add tools with `docker compose -f docker-compose.yml
  -f docker-compose.tools.yml --profile <name> up` (see
  [../docker-compose.tools.yml](../docker-compose.tools.yml)).
- **Production (Phase 8):** K3s + Helm, CloudNativePG, OpenSearch operator, ArgoCD
  GitOps, Velero backup/DR, Vault secrets, signed agent binaries, air-gapped
  offline update channel for feed sync. Tool services deployed per capacity and
  security posture.

## 8. Build status (complete)
All planned phases are built, verified end-to-end, and on `main`:
- ✅ **Core (0–6):** Compose stack (Postgres/Timescale/OpenSearch/NATS/FastAPI/Grafana);
  Go ingest-edge (mTLS + schema-validate + JetStream); Python workers; Go endpoint agent
  (sysinfo/network/osquery/FIM + signed responder); feed-sync mirror + enrichment
  (CVE/CVSS/EPSS/KEV) across application/system/network domains; compliance engine with
  hash-chained evidence; risk engine (composite + XGBoost/SHAP); incidents + signed
  active response.
- ✅ **Tool integration (A–E):** Suricata/Zeek/Wazuh/Trivy/Nuclei/MISP/OpenCTI/Sigma/Falco
  behind opt-in profiles, normalized via bridges + enrichers, tagged `source_tool`.
- ✅ **F — AI Fusion Engine:** cross-tool dedup + consensus weighting + threat-intel/ATT&CK
  features + SHAP waterfall.
- ✅ **G — Presentation:** analyst console (5 views) + provisioned Grafana dashboard.
- ✅ **H — Air-gap hardening:** enforced + verified egress control + tool-feed mirroring.
- ✅ **8 — Production:** air-gapped K3s Helm chart, HA data plane, Vault, Keycloak OIDC/RBAC,
  Velero DR, ArgoCD GitOps, signed-agent release (lint/render-validated; no live cluster).

Live demo: `make up` → console `:3001`, Grafana `:3000`, API docs `:8000/docs`.

## 9. Default ports (MVP)
| Service | Port | Notes |
|---------|------|-------|
| Console | 3001 | analyst SPA (nginx; proxies `/api`) |
| API | 8000 | FastAPI |
| PostgreSQL | 5432 | transactional |
| TimescaleDB | 5433→5432 | telemetry (host 5433 to avoid clashing with Postgres) |
| OpenSearch | 9200 | security plugin disabled in MVP |
| NATS | 4222 / 8222 | client / monitoring |
| Grafana | 3000 | admin/admin by default (change in `.env`) |
