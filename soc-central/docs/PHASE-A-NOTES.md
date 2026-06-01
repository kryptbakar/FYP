# Phase A — Tool-integration inventory + scaffolding

**Status:** scaffolding complete; tools defined + config-validated; light tools started
(heavy platforms deferred on this host — see below). **Date:** 2026-06-02.

This is Phase A of the **tool-integration expansion** (extends the existing 6-phase MVP).
Goal: get all ten tools *present and defined*, references cloned, licenses registered, and
the unified schema extended — **without** disturbing the running core stack.

## What was added

- **`docker-compose.tools.yml`** — all ten tools as their own containers, behind **opt-in
  profiles** so `make up` is unchanged:
  - `sensors` → Suricata (EVE JSON), Zeek (logs)
  - `scanners` → Trivy (server), Nuclei (on-demand)
  - `runtime` → Falco (optional, D-031)
  - `hostmon` → Wazuh Manager (REST API :55000)
  - `intel` → MISP (+ mariadb + redis), OpenCTI (+ Elastic + Redis + MinIO + RabbitMQ)
  - Run a group: `docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile <group> up -d`
- **Schema extension** (additive, stays v1): envelope gains optional `source_tool` /
  `raw_ref` and five tool-sourced `kind`s (`ids_alert`, `traffic_metadata`, `scan_finding`,
  `ioc_match`, `runtime_alert`); `findings` gains `source_tool` / `raw_ref` / `dedup_key` /
  `consensus` (D-032). These are the provenance + fusion fields Phase F needs.
- **References** — 15/16 new repos shallow-cloned into `reference/` (gitignored). `nvdlib`
  failed on the network this run (optional; `feed-sync` already mirrors NVD).
- **`ATTRIBUTIONS.md`** — every tool registered with its **license verified from the cloned
  LICENSE file**. Copyleft flagged: **Suricata GPL-2.0**, **Wazuh GPL-2.0**, plus pySigma
  (LGPL-2.1) / pySigma-backend-opensearch (LGPL-3.0); Sigma rules = DRL 1.1.

## Scope changes flagged for the panel (D-029, D-031)

- **Suricata/Zeek + network detection are now IN scope** — the original scope document
  listed them as an explicit **MVP non-goal** (Phase 2 roadmap). This expansion is
  supervisor-sanctioned; recorded in `docs/DECISIONS.md` D-029.
- **Falco** wasn't in the original architecture — included as an **optional** runtime layer
  (D-031), off by default.

## How to verify

```bash
make up                                  # core stack — unaffected by the tools file
docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile tools config --services   # all 23 services parse
docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile scanners --profile sensors --profile runtime up -d
```

## What actually runs here vs. deferred (D-030)

This lab host has **~7 GB free** on the Docker disk; the full tool set needs ~15–20 GB of
images + several GB RAM, so per the honesty rule we start what fits and defer the rest:

- **Config validation:** all **23 services** (9 core + 14 tool) parse via `compose config`.
- **Actually started (verified):**
  - **Trivy** — `running` (REST server on :4954). ✓
  - **Nuclei** — `exited (0)` — one-shot `-version` as designed (real scans are on-demand). ✓
  - **Suricata** — pulled + starts, but **crash-loops** here (no live capture interface in the
    lab) → **stopped**; a real interface/PCAP + mirrored ET rules come in Phase B.
  - **Falco** — pulled + starts, but **crash-loops** on Docker Desktop/WSL (no privileged
    kernel access) → **stopped**; optional layer (D-031).
- **Deferred (network/disk on this host):**
  - **Zeek** — image pull dropped on the flaky link (its ~82 MB layer); defined, retry on a
    better link. (Zeek + Suricata are the Phase-B focus.)
  - **Wazuh Manager, MISP (+db/redis), OpenCTI (+Elastic/Redis/MinIO/RabbitMQ)** — **defined +
    config-validated**, not pulled: the light tools already took D: from 7.2 → 4.2 GB, and the
    heavy set needs ~10+ GB. Started on a capable host (D-030). Core stack stayed **healthy**
    throughout (api/postgres/opensearch/nats/enrichment all up).

> Nothing is wired into our pipeline yet — Phase A is presence + scaffolding only. Consuming
> each tool's output (EVE tail, Zeek shipper, Nuclei/Trivy parsers, Wazuh API puller, Sigma
> evaluator, MISP/OpenCTI enrichers) is Phases B–E; the Fusion Engine is Phase F.

## Air-gap (preview; full design in Phase H)

Every tool would fetch rules/DBs/feeds from the internet by default. The compose entries are
pinned toward offline operation (Trivy `--offline-scan`/`skip-db-update`, Nuclei local
templates, Suricata local rules path). The controlled mirror + `docs/AIRGAP.md` and an
egress-blocked verification land in **Phase H**.

## Acceptance (Phase A)

✅ Ten tools defined as containers behind opt-in profiles · ✅ references cloned (15/16) ·
✅ `ATTRIBUTIONS.md` updated with verified licenses (GPL flagged) · ✅ unified schema extended
(`source_tool`/`raw_ref`/`dedup_key`) · ✅ core stack still starts with one command ·
✅ scope change documented. **Stop for review before Phase B (Suricata + Zeek wiring).**
