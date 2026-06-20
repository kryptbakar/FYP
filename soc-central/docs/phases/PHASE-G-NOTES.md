# Phase G — Dashboards + analyst console (the presentation layer)

**Goal (original prompt Phase 7, folded into the expansion as Phase G):** provision
Grafana dashboards and build the Next.js/Tailwind analyst console (triage, case
management, XAI finding detail, feedback capture), with the platform's hash-chained audit
surfaced. This is the flagship, demo-facing deliverable.

## What shipped
- **Analyst console** (`web/console/`) — a **dependency-free SPA** (no npm/CDN/build) on
  nginx that also reverse-proxies `/api` → the FastAPI (same-origin, no CORS). Five views:
  - **Command Center** — six KPIs, a risk-band donut, severity breakdown, **detection-fusion
    by tool + corroboration count**, ATT&CK coverage, top exploited CVEs, and the live
    risk-prioritized queue.
  - **Triage** — the full risk-ranked table with source-tool + consensus badges and
    KEV/ATT&CK/IOC signal chips.
  - **Finding detail (XAI drawer)** — composite + ML scores, the **multi-tool consensus**
    panel (which tools agree + a weight ring), the **SHAP waterfall** (base → each factor →
    final), composite breakdown, counterfactuals, and the **analyst feedback form** (POSTs
    to `/findings/{id}/feedback`, feeding the monthly retrain).
  - **Incidents** — SLA-tracked case list.
  - **Compliance** — CIS posture donut + the **tamper-evident evidence-chain** integrity
    badge + per-asset scores.
- **Grafana** — provisioned datasources with stable UIDs (`soc-postgres`, `soc-timescale`)
  and a **"SOC Central — Security Overview"** dashboard (KPI stats, severity + fusion
  pies, per-asset bargauge, the top-15 risk table with a gauge column, and a TimescaleDB
  telemetry-volume timeseries).
- **API** — added a configurable `CORSMiddleware` (belt-and-suspenders; the normal path is
  the same-origin proxy). New compose service `console` (port 3001) + `make console` /
  `pwsh dev.ps1 console`.
- **DECISIONS D-044** (dependency-free SPA, air-gap-pure; Next.js deferred to a mirrored
  registry) and **D-045** (nginx same-origin `/api` proxy).

## Verified end-to-end (live, 2026-06-02)
- Console shell + assets served (`app.css` 17 KB, `app.js` 28 KB); `app.js` passes
  `node --check`.
- `/api` proxy returns live data: `/api/version`, `/api/risk/ranking`, and
  `/api/findings/11/explain` (the latter carries the SHAP `waterfall` + `consensus` the
  drawer renders — e.g. the agent+trivy CVE-2023-4911 cluster, ML score 94.31).
- CORS header present when an `Origin` is sent.
- Grafana dashboard `soc-overview` provisioned and listed via the Grafana API.

## Deferred / honest notes
- **OIDC/SSO + RBAC** (named in Phase 7) are **not** wired yet — they belong with the
  identity provider (Keycloak) that lands in the K3s phase; the console is currently
  open on the trusted LAN. Tracked for Phase 8.
- **OpenSearch log dashboards** need the `grafana-opensearch-datasource` plugin, whose
  install pulls from the internet — incompatible with the air gap until mirrored. The
  Phase-G dashboards therefore run on the Postgres datasource (where the findings / risk /
  compliance data lives); raw-log dashboards follow once the plugin is mirrored.
- **Next.js migration**: per D-044 the console is a static SPA now; it migrates to the
  named Next.js/Tailwind toolchain once a mirrored npm registry (Verdaccio) exists in K3s.
- The air-gap overlay seals the console too, so (per D-042's documented limitation) the UI
  is reached on the normal `make up` stack, not the sealed verification harness.
