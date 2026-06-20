# Phase 0 — Scaffolding — Notes

**Goal:** stand up the monorepo, the MVP Docker Compose stack (PostgreSQL +
TimescaleDB + OpenSearch + NATS JetStream + a FastAPI skeleton + Grafana), clone
and license-verify all reference repos, and prove the stack starts and the API
responds. Stop for review before Phase 1.

## What was built

### Monorepo & scaffolding
- Full directory layout under `vyrex/` (`services/`, `agent/`, `web/`, `ml/`,
  `deploy/`, `grafana/`, `docs/`, gitignored `reference/`).
- `.gitignore` (ignores `reference/`, `.env`, data volumes, build artifacts).
- `.env.example` — every config/secret the stack reads; copy to `.env` for local dev.
- `Makefile` (Linux/macOS) **and** `scripts/dev.ps1` (Windows) with identical
  targets: `up`, `down`, `clean`, `restart`, `ps`, `logs`, `health`, `clone-refs`,
  plus phase-stubbed `seed`, `test`, `agent-run`.
- `docker-compose.yml` — the six-service MVP stack (below).
- Docs: `ARCHITECTURE.md`, `DECISIONS.md` (9 decisions logged), this file.
- `ATTRIBUTIONS.md` — all 21 reference repos with **verified** licenses.

### FastAPI skeleton (`services/api/`)
- `GET /` — service banner.
- `GET /health` — liveness (cheap, no external deps).
- `GET /version` — service/version/environment.
- `GET /health/ready` — readiness; actively probes **Postgres**, **OpenSearch**,
  and **NATS** so Phase 0 proves the stack is wired together, not just that the
  API process runs. Returns `503` until all three are reachable.
- `GET /docs` — Swagger UI (FastAPI built-in).
- Containerised (`python:3.12-slim`, non-root user, built-in `HEALTHCHECK`).

### Data + broker + presentation (compose services)
| Service | Image | Purpose |
|---------|-------|---------|
| postgres | `postgres:16` | transactional state |
| timescaledb | `timescale/timescaledb:latest-pg16` | time-series telemetry (host port 5433) |
| opensearch | `opensearchproject/opensearch:2.18.0` | full-text/log search (security plugin off in MVP) |
| nats | `nats:2.10` | JetStream broker (`-js`), monitoring on 8222 |
| api | built from `services/api` | FastAPI skeleton |
| grafana | `grafana/grafana:11.4.0` | dashboards; Postgres/Timescale datasources provisioned |

### Reference repos — all 21 cloned & license-verified
Shallow-cloned into `reference/` (gitignored, relocated to `D:` via a junction —
see decision D-009). Licenses were read from each repo's actual `LICENSE`/`COPYING`
file. Highlights / surprises:
- **osquery** is dual **Apache-2.0 OR GPL-2.0** — we elect Apache-2.0.
- **SOC-IN-A-BOX** is **proprietary / non-commercial**, not OSS despite the name.
- **5 repos declare no license** (CVEraptor, Faraday_CVE_Parser, cve-enriched-dataset,
  cvss_score_prediction_model, Open-Source-SIEM_SOC-Stack) → all-rights-reserved,
  study concepts only.
- Copyleft flagged: GPL (faraday, wazuh), AGPL (TheHive, Cortex, velociraptor) —
  reference-only, reimplement.
See `ATTRIBUTIONS.md` for the full register and distribution implications.

## How to run

```bash
# Linux / macOS
make up        # builds the api image + starts all six services
make health    # prints /health, /version, /health/ready

# Windows (PowerShell)
pwsh scripts/dev.ps1 up
pwsh scripts/dev.ps1 health
```

Endpoints once up: API `http://localhost:8000` (`/docs` for Swagger), Grafana
`http://localhost:3000`, OpenSearch `http://localhost:9200`, NATS monitoring
`http://localhost:8222`.

Refresh reference repos any time with `make clone-refs` (idempotent; skips repos
already present).

## Verification

Actual run on the dev host (2026-06-01), all six services healthy:

```
$ docker compose ps
SERVICE       STATE     STATUS
api           running   Up (healthy)
grafana       running   Up
nats          running   Up
opensearch    running   Up (healthy)
postgres      running   Up (healthy)
timescaledb   running   Up (healthy)
```

API endpoints:

```
GET /health        -> {"status":"ok","uptime_seconds":36.6}
GET /version       -> {"service":"vyrex-api","version":"0.0.0-phase0","environment":"development"}
GET /health/ready  -> {"status":"ready","checks":{
                         "postgres":{"ok":true,"detail":"reachable"},
                         "opensearch":{"ok":true,"detail":"http 200"},
                         "nats":{"ok":true,"detail":"tcp open"}}}
```

Backing stores (proves the stack is wired end-to-end, not just that the API runs):

```
OpenSearch  GET /_cluster/health  -> status: green, 1 node, shards 100% active
Grafana     GET /api/health       -> {"database":"ok","version":"11.4.0"}
NATS        GET :8222/healthz      -> {"status":"ok"}
```

→ **Phase 0 acceptance met:** `make up` brings the whole stack up and the API
reports ready against PostgreSQL, OpenSearch, and NATS JetStream.

## What is stubbed (built in later phases)
- `agent/` (Phase 2), `services/ingest-edge/` (Phase 1), `services/workers/`
  (Phase 1/3), `services/feed-sync/` (Phase 3), `ml/` (Phase 5), `web/` (Phase 7),
  `deploy/helm/` (Phase 8) — each has a README phase marker.
- OpenSearch security, SSO/RBAC, mTLS, audit log — Phase 7.
- The ~30 domain REST endpoints — grown across Phases 1–7.

## Environment notes (this dev machine)
- No host-level `python`/`go`/`make` — not required for Phase 0 (the API runs in a
  container; `scripts/dev.ps1` replaces `make` on Windows).
- `C:` was space-constrained; `reference/` (~1.1 GB) was relocated to `D:` via an
  NTFS junction so the path is unchanged (decision D-009).
- During the first `make up`, Docker's data disk filled `C:` and the pull aborted
  with an `input/output error`. Fixed by relocating Docker's WSL data folder
  (`...\Docker\wsl`, ~9.8 GB) to `D:` via a junction and restarting the engine
  (decision D-010). The stack then came up cleanly.
- `.env.example` originally set `TIMESCALE_PORT=5432`, colliding with PostgreSQL on
  the host; corrected to `5433` (TimescaleDB internal port stays 5432).

## Next: Phase 1 — Ingestion backbone
Define the versioned unified telemetry schema; build `ingest-edge` (Go: mTLS + auth
+ schema-validate + enqueue) and the Python workers (consume → write raw telemetry
to TimescaleDB/OpenSearch); demonstrate back-pressure and replay; add a fake
telemetry producer.

**→ Paused for review. Phase 1 starts on your go-ahead.**
