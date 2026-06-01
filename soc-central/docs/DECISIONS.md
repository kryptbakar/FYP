# Decision Log

Non-obvious engineering choices, with rationale, so they can be defended in a viva
and revisited later. Newest at the top. Each entry: **context → decision → why →
alternatives considered**.

---

## D-010 — Docker's WSL data disk relocated to `D:` via a junction
**Context:** the first `make up` filled `C:` (Docker's `docker_data.vhdx` grew until
the drive hit 0.02 GB free) and the image pull died with
`failed to copy: ... input/output error` — the classic disk-full symptom. **Decision:**
stopped Docker, `wsl --shutdown`, moved `…\AppData\Local\Docker\wsl` (~9.8 GB) to
`D:\Docker\wsl`, and left an NTFS **junction** at the original path; restarted Docker
Desktop. **Why:** frees `C:` and gives Docker the headroom of `D:` without touching
Docker's settings schema — the engine opens the same path, the bytes live on `D:`.
Verified the data root resolves to `D:\Docker\wsl` and the engine came up clean.
**Alternative:** Docker Desktop's "Disk image location" GUI setting — equally valid,
but the junction is scriptable and version-independent.

## D-009 — Reference repos relocated to `D:` via a junction
**Context:** The dev machine's `C:` had ~1.7 GB free after the shallow clones; the
Docker images for the stack need ~3 GB. **Decision:** moved `reference/` (study-only,
gitignored, ~1.1 GB) onto the `D:` drive and replaced `C:\...\reference` with an NTFS
**junction** pointing at it. **Why:** frees `C:` for Docker without changing any path
the repo or scripts use — `reference/` still resolves normally. **Alternatives:**
relocating Docker's WSL2 data-root to `D:` (more invasive, risk of breaking Docker),
or deleting the heavy study repos (loses material the later phases need).

## D-008 — Reference repos cloned shallow (`--depth 1 --single-branch --no-tags`)
**Decision:** all 21 study repos are shallow-cloned. **Why:** we only need to *read*
current source and verify licenses, not their history; this cut disk/bandwidth by an
order of magnitude (e.g., osquery 29 MB vs. hundreds of MB full). **Trade-off:** no
`git log` archaeology on references — acceptable, they are study material.

## D-007 — Licenses verified from each repo's actual LICENSE file
**Decision:** ATTRIBUTIONS.md records the license read from each repo's `LICENSE`/
`COPYING` file, not from memory or GitHub's sidebar. **Why:** Ground Rule #2 demands
it, and several assumptions would have been wrong — e.g., **osquery is dual Apache-2.0
OR GPL-2.0**, **SOC-IN-A-BOX is proprietary non-commercial** (not OSS despite the name),
and five repos declare **no license at all** (= all rights reserved). Copyleft
(GPL/AGPL) and no-license repos are flagged as **reference-only**.

## D-006 — Grafana runs as an unmodified standalone service (AGPL handled cleanly)
**Context:** Grafana is AGPL-3.0. **Decision:** use the **official image unmodified**
and only *configure* it via provisioned datasources/dashboards. **Why:** AGPL
obligations attach to modified/derivative works; running the stock service and
configuring it does not make our code a derivative. We never fork or link Grafana.

## D-005 — OpenSearch security plugin DISABLED in the MVP
**Decision:** `DISABLE_SECURITY_PLUGIN=true` for the lab. **Why:** removes TLS/auth
friction for a single-host demo and avoids the mandatory strong-password bootstrap;
lets readiness checks hit `http://opensearch:9200` directly. **Risk & mitigation:**
this is **insecure by default** — acceptable only because the MVP is an isolated lab.
SSO/RBAC/TLS for OpenSearch is re-enabled in **Phase 7**, and the platform is
air-gapped regardless. Flagged here so it is never shipped to production as-is.

## D-004 — TimescaleDB exposed on host port 5433
**Decision:** map TimescaleDB to host `5433` (container stays 5432). **Why:** Postgres
and TimescaleDB are both Postgres servers; both can't own host 5432. Internal
service-to-service traffic still uses 5432 over the compose network.

## D-003 — Readiness probe actively checks Postgres, OpenSearch, and NATS
**Decision:** `/health/ready` connects to all three backing stores (and `/health`
stays a cheap dependency-free liveness check). **Why:** Phase 0's job is to *prove*
the whole stack is wired together, not just that the API process starts. Liveness vs.
readiness are kept separate so orchestrators (Compose now, K3s later) restart vs.
gate traffic correctly.

## D-002 — NATS JetStream as the MVP broker (broker-agnostic consumer interface)
**Decision:** NATS JetStream now; keep the worker/consumer interface abstract so
Kafka can replace it later. **Why:** JetStream is dramatically simpler to run in a
single-host lab than Kafka (no ZooKeeper/KRaft, one small binary) while still giving
durable streams, back-pressure, and replay — exactly what Phase 1 must demonstrate.

## D-001 — Provide both a Makefile and a PowerShell task runner
**Context:** the dev host is Windows (no `make`); the target deployment is Linux.
**Decision:** ship `Makefile` (Linux/macOS) **and** `scripts/dev.ps1` (Windows) with
identical targets (`up`, `down`, `health`, …). **Why:** "one command per phase"
(Ground Rule #9) must work for whoever is driving, regardless of OS, without
installing `make` on Windows.

## D-000 — Monorepo under `soc-central/`, product code split from reference
**Decision:** single repo with `services/`, `agent/`, `web/`, `ml/`, `deploy/` for
product code and a **gitignored** `reference/` for study clones. **Why:** Ground Rule
#3 — third-party source must never enter the product tree; a clean separation makes
licensing, review, and the viva defensible.
