# SOC Central

A centralized **Security Operations Center** and vulnerability-intelligence
platform. Bachelor's senior design project (GIKI, BS Cyber Security), built as a
proof-of-concept for an **air-gapped / on-premises** government deployment (PITB).

> **Design philosophy:** integrate best-in-class open-source components rather
> than reinvent them, and contribute original value in the **intelligence layer**
> — exploit-aware risk scoring, explainable ML, and analyst-controlled response.

## Architecture (four layers)

1. **Endpoint Agent** — lightweight Go agents (eBPF, embedded Osquery, YARA, FIM)
   over mutual TLS with a *signed* command channel for active response.
2. **Ingestion & Assessment** — stateless Go edge-ingest → NATS JetStream broker →
   async Python enrichment workers → data stores.
3. **Data** — PostgreSQL (transactional), TimescaleDB (telemetry), OpenSearch (search).
4. **Presentation** — Grafana (metrics/trends/heatmaps) + Next.js/Tailwind analyst console.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detail and
[docs/DECISIONS.md](docs/DECISIONS.md) for the rationale behind key choices.

## Repository layout

```
soc-central/
  docker-compose.yml     # MVP stack: data stores + broker + API
  Makefile               # task runner (Linux/macOS)
  scripts/dev.ps1        # task runner (Windows)
  services/
    api/                 # FastAPI backend (the core, grown across phases)
    ingest-edge/         # Go: auth + schema-validate + enqueue   (Phase 1)
    workers/             # Python: broker consumers + enrichment   (Phase 1/3)
    feed-sync/           # the ONLY internet-facing job            (Phase 3)
  agent/                 # Go endpoint agent                        (Phase 2)
  ml/                    # XGBoost + SHAP scoring engine            (Phase 5)
  web/                   # Next.js + Tailwind console               (Phase 7)
  grafana/               # provisioned datasources + dashboards
  deploy/helm/           # K3s Helm charts                          (Phase 8)
  reference/             # cloned repos for STUDY ONLY (gitignored)
  docs/
```

## Quick start (MVP — Phase 0)

**Prerequisites:** Docker + Docker Compose. (Python/Go/Node are only needed
inside containers or in later phases — not on the host.)

```bash
# Linux / macOS
make up        # build + start the stack
make health    # check API liveness, version, readiness
make down      # stop (keeps data)

# Windows (PowerShell)
pwsh scripts/dev.ps1 up
pwsh scripts/dev.ps1 health
pwsh scripts/dev.ps1 down
```

Then browse:

| Service          | URL                              |
|------------------|----------------------------------|
| API root         | http://localhost:8000/           |
| API docs (Swagger) | http://localhost:8000/docs     |
| Liveness         | http://localhost:8000/health     |
| Readiness        | http://localhost:8000/health/ready |
| Version          | http://localhost:8000/version    |
| Grafana          | http://localhost:3000/           |
| OpenSearch       | http://localhost:9200/           |
| NATS monitoring  | http://localhost:8222/           |

## Reference repositories

All study repos are cloned into `reference/` (gitignored). Clone/refresh them with:

```bash
make clone-refs    # or: bash scripts/clone-references.sh
```

Every reference repo and its **verified** license is recorded in
[ATTRIBUTIONS.md](ATTRIBUTIONS.md). Copyleft (GPL/AGPL) repos are flagged there
and are used as **design reference only** — never vendored into the product tree.

## Configuration & secrets

Copy `.env.example` to `.env` (gitignored) and edit. Real secrets never enter
git; they move to HashiCorp Vault in the K3s phase.

## Status

**Phase 0 — Scaffolding: complete.** See [docs/PHASE-0-NOTES.md](docs/PHASE-0-NOTES.md).
Next: Phase 1 — ingestion backbone.
