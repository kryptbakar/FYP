# VYREX

A centralized **Security Operations Center** and vulnerability-intelligence platform.
Bachelor's senior design project (GIKI, BS Cyber Security), built as a proof-of-concept
for an **air-gapped / on-premises** government deployment (PITB).

> **Design philosophy:** integrate best-in-class open-source components rather than
> reinvent them, and contribute original value in the **intelligence layer** —
> exploit-aware risk scoring, explainable ML, multi-tool fusion, and analyst-controlled
> response. Every external feed is mirrored locally; only one job ever touches the internet.

## What it does

- **Collects** endpoint telemetry (a Go agent: sysinfo, process/network, osquery, FIM) and
  ingests detections from **ten integrated OSS tools** — Suricata, Zeek, Wazuh, Trivy,
  Nuclei, MISP, OpenCTI, Sigma, Falco — all normalized to one telemetry envelope.
- **Enriches** every CVE with CVSS + EPSS exploit probability + CISA KEV from a **local
  mirror** (no live calls), and evaluates **CIS compliance** with a hash-chained,
  tamper-evident evidence log.
- **Prioritizes** with the **AI Fusion Engine**: cross-tool dedup + consensus weighting
  (independent tools agreeing raises confidence) feeding a composite score **and** an
  XGBoost model, with a per-finding **SHAP waterfall** so every score is explainable.
- **Responds** via an Ed25519-**signed** command channel with two-person approval and a
  hash-chained audit trail (containment only).
- **Presents** it all in a real-time analyst **console** + Grafana dashboards.

## Architecture (four layers)

1. **Endpoint Agent** — lightweight Go agents (process/network, embedded osquery, FIM)
   over mutual TLS with a *signed* command channel for active response.
2. **Ingestion & Assessment** — stateless Go edge-ingest → NATS JetStream → async Python
   enrichment/fusion workers → data stores. Tool output arrives via bridges/enrichers.
3. **Data** — PostgreSQL (transactional), TimescaleDB (telemetry), OpenSearch (search).
4. **Presentation** — analyst console (dependency-free SPA; Next.js/Tailwind is the
   production target) + Grafana (metrics/trends/heatmaps).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detail and
[docs/DECISIONS.md](docs/DECISIONS.md) for the rationale behind 49 logged decisions.

## Repository layout

```
soc-central/
  docker-compose.yml          # core stack: data stores + broker + API + console + Grafana
  docker-compose.tools.yml    # 10 OSS tools behind opt-in profiles
  docker-compose.airgap.yml   # egress-sealed overlay (air-gap verification harness)
  Makefile / scripts/dev.ps1  # task runner (Linux/macOS / Windows)
  services/
    api/            # FastAPI backend (findings, risk, incidents, compliance, response)
    ingest-edge/    # Go: mTLS + schema-validate + enqueue
    workers/        # Python: JetStream consumers → stores
    feed-sync/      # the ONLY internet-facing job (NVD/EPSS/KEV mirror)
    enrichment/     # CVE matching + CVSS/EPSS/KEV + compliance + scanner ingest
    sensor-bridge/  # Suricata/Zeek/Falco → JetStream
    wazuh-bridge/   # Wazuh Manager API → findings
    intel-enricher/ # MISP IOC + OpenCTI ATT&CK + Sigma
  agent/            # Go endpoint agent
  ml/               # composite score + XGBoost/SHAP + the AI Fusion Engine (FUSION.md)
  web/console/      # analyst console (SPA on nginx, proxies /api)
  grafana/          # provisioned datasources + dashboard
  deploy/           # air-gapped K3s: Helm chart, CNPG/OpenSearch, Vault, Keycloak, Velero, ArgoCD
  reference/        # cloned repos for STUDY ONLY (gitignored)
  docs/             # ARCHITECTURE, DECISIONS, per-phase notes, AIRGAP
```

## Quick start

**Prerequisites:** Docker + Docker Compose. (Python/Go/Node run only inside containers.)

```bash
make up            # build + start the core stack (data stores, API, console, Grafana)
make feeds-seed    # load the offline NVD/EPSS/KEV mirror (bundled fixtures)
make assess        # enrich host state → findings + compliance
make risk-train    # train the XGBoost risk model
make risk-score    # composite + ML risk + SHAP for every finding
```
Windows: `pwsh scripts/dev.ps1 <target>` (same targets).

Then open the **analyst console → http://localhost:3001**.

| Surface | URL |
|---------|-----|
| **Analyst console** | http://localhost:3001/ |
| Grafana dashboards | http://localhost:3000/ |
| API docs (Swagger) | http://localhost:8000/docs |
| Health / readiness | http://localhost:8000/health · `/health/ready` |

### Going further
```bash
make scan-ingest   # ingest Trivy + Nuclei scanner findings (offline fixtures)
make intel-enrich  # MISP IOC + OpenCTI ATT&CK + Sigma over the stores
make airgap-verify # prove the air gap: runtime sealed, only feed-sync egresses
```
Tool profiles: `docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile <sensors|scanners|hostmon|intel> up`.

## Air-gap & security
Every external feed is mirrored locally; only `feed-sync` egresses, enforced and **verified**
(`make airgap-verify`; K3s NetworkPolicy in production). mTLS ingestion, Ed25519-signed
response commands, hash-chained audit + compliance evidence, OIDC/RBAC via Keycloak (K3s),
and a cosign-signed agent supply chain. Secrets move to HashiCorp Vault in K3s — see
[docs/AIRGAP.md](docs/AIRGAP.md). Reference repos and their **verified** licenses (GPL/AGPL
flagged, never vendored) are in [ATTRIBUTIONS.md](ATTRIBUTIONS.md).

## Status

**Build complete.** Phases 0–6 (core), A–E (tool integration), F (AI Fusion Engine),
G (console + dashboards), H (air-gap hardening), and 8 (air-gapped K3s deployment). See the
per-phase notes in [docs/](docs/) and the status summary in
[docs/ARCHITECTURE.md §8](docs/ARCHITECTURE.md).
