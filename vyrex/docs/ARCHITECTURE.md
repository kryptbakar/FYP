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

## 2. The five layers

```
                          ┌──────────────────────────────────────────────┐
                          │              PRESENTATION LAYER               │
                          │   Grafana (metrics/trends/heatmaps)           │
                          │   Next.js + Tailwind console (triage, cases,  │
                          │   XAI finding detail, analyst feedback,       │
                          │   Investigations: graph + cited verdict)      │
                          └───────────────▲──────────────▲───────────────┘
                                          │ REST/SSE     │ dashboards
                          ┌───────────────┴──────────────┴───────────────┐
                          │            INVESTIGATION LAYER (§5b)          │
                          │  outbox ─► LangGraph worker (own DB role,     │
                          │  no grant on response tables)                 │
                          │  5 deterministic specialists ‖ 1 LLM node     │
                          │  ─► citation validator ─► steps + evidence    │
                          └───────────────────────▲──────────────────────┘
                                                  │ reads findings/assets (SELECT only)
                          ┌───────────────────────┴──────────────────────┐
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

## 5b. Investigation layer (the agent-orchestration track)

Scoring answers *"which finding matters most?"*. This layer answers *"what is actually
going on with it, and can I check your working?"* It replaces the previous single-pass
`/agent/*` call, which fired one prompt, parsed the reply in a bare `try/except`, and
persisted the whole run as one JSON blob with no per-step trace and no resumability.

`services/investigation-orchestrator` is a **LangGraph** worker driven by a transactional
outbox. The shape:

```
finding ──▶ load_subject ──▶ router ──┬─▶ asset_context      ┐
                                      ├─▶ attack_context     │  all deterministic SQL,
                                      ├─▶ intel_context      │  run in PARALLEL
                                      ├─▶ fusion_context     │
                                      └─▶ historical_context ┘
                                                │
                                        synthesize (the ONLY LLM node)
                                                │
                                      citation validator (deterministic)
                                                │
                             steps + evidence + report ──▶ API ──▶ console
```

Four properties, each enforced rather than intended:

1. **Every claim cites stored evidence.** Citation ids are checked against an allow-list of
   records the graph actually created, so an invented reference is dropped as unresolved
   rather than believed. A verdict other than `INSUFFICIENT_EVIDENCE` with **no** cited
   claim fails contract validation outright.
2. **The model does not set its own confidence.** The output schema has no confidence
   field and rejects extras; confidence is derived from how many evidence branches
   actually succeeded.
3. **Skipped ≠ failed.** Each node persists its own status and reason, so "found nothing"
   and "crashed" stay distinguishable — they are identical in a single-blob agent, and an
   analyst has to be able to tell them apart. One branch raising degrades the run; it
   never takes the investigation down.
4. **It cannot act.** The orchestrator connects as a dedicated `vyrex_orchestrator` role
   with **no grant** on `response_actions`, `users`, `sessions` or audit tables. The
   containment boundary is a database privilege, not a code path nobody happened to write.

Durability comes from the outbox plus a Postgres checkpointer: a worker killed mid-graph
resumes from its last checkpoint instead of re-running completed nodes — including a
completed LLM call. **Deliberately no NATS here:** once the outbox existed, the table
already provided durability, ordering, retry counting and a dead-letter state, and
`FOR UPDATE SKIP LOCKED` gave the same competing-consumer semantics with one fewer
delivery guarantee to reason about. `repository.claim_next_job` is the only seam that
changes if a broker is ever wanted.

**Honest framing for the viva:** this is *one deterministic router + five specialist
retrieval nodes + one citation-bound LLM synthesis step*, not "five AI agents". Everything
feeding the model is code you can read and test, which is what makes *"the model decided"*
never the explanation for a verdict. Full design, measured behaviour and the model
benchmark: [AGENT-ORCHESTRATION.md](AGENT-ORCHESTRATION.md). The LLM trust boundary and a
demonstrated prompt injection: [THREAT-MODEL.md §3.1](THREAT-MODEL.md).

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

### Agent-orchestration track (§5b) — status

- ✅ **Durable orchestration:** outbox → LangGraph worker, resume-after-crash verified by
  SIGKILL mid-synthesis, duplicate requests collapse to one active run.
- ✅ **Evidence layer:** five parallel deterministic specialists; branch isolation proven by
  a real failure that degraded the run instead of ending it.
- ✅ **Console workspace:** execution graph in the shape it ran, clickable citations that
  scroll to the cited record, and an explicit callout when a verdict cites nothing.
- ✅ **Security & hardening:** least-privilege DB role (no grant on response/identity/audit
  tables, pinned by a test that reads the queries and the grants and compares them);
  untrusted-evidence containment in the synthesis prompt; a demonstrated prompt injection
  with a control; admission control on `POST /investigations` (the endpoint answers in
  milliseconds but commits ~2 minutes of serial inference); an Ollama circuit breaker so a
  dead model costs one timeout per cooldown rather than one per investigation.
- ✅ **Deployment & air-gap:** Helm chart with `replicas: 1` pinned and the reason in the
  manifest; the K3s NetworkPolicy fixed to actually select pods; compose sealing split into
  three paired overlays; both halves enforced by `tools/airgap/check-coverage.py` in CI; the
  offline bundle carries model digest, quantisation and licence, and the installer verifies
  the digest rather than mere presence.
- ✅ **Observability:** Grafana dashboard driven from the orchestration tables (queue depth,
  oldest wait, node latency on a log scale, branch health, cited-verdict count).
- 🔶 **Evaluation:** corpus frozen at 63 findings meeting all 14 stratification targets,
  rubric pre-registered, and the scoring harness built and unit-pinned — but **zero cases
  labelled** and advisor adjudication not secured. No accuracy claim is made until both
  exist, and `eval/score_labels.py` refuses to compute one.
- ⚠️ **Known ceiling, measured not assumed:** no locally-runnable model satisfies the
  citation contract on this hardware. `llama3.2:3b` and `qwen2.5:3b` each abstained 12/12
  and cited 0/12 on the same findings; `qwen3:4b` never finished in 900 s. The pipeline is
  correct and the constraint is inference capacity — see
  [AGENT-ORCHESTRATION.md §7](AGENT-ORCHESTRATION.md).

Live demo: `make up` → console `:3001`, Grafana `:3000`, API docs `:8000/docs`.
Investigations: `--profile agentic` (see AGENT-ORCHESTRATION.md).

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
