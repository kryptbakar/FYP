# web/console — SOC Central analyst console

**Built in:** Phase G · **Role:** the analyst workbench — the human face of the platform.

A dependency-free single-page console (no npm, no CDN, no build step) served by nginx,
which also reverse-proxies `/api/*` to the FastAPI. The browser therefore makes
**same-origin** calls — no CORS, no API host baked into the client, and **zero external
assets**, so the whole UI runs air-gapped (see `docs/DECISIONS.md` D-044/D-045).

## Run
```bash
make console          # build + start (http://localhost:3001)
# or it comes up with the full stack:
make up
```
Grafana (metrics/trends) is at `http://localhost:3000`.

## Views
| View | What it shows |
|------|----------------|
| **Command Center** | KPIs (assets, findings, critical/high, KEV, incidents, compliance), risk-band donut, severity breakdown, **detection-fusion** by tool + corroboration count, ATT&CK coverage, top exploited CVEs, and the risk-prioritized queue. |
| **Triage** | The full risk-ranked findings table — composite + ML score, source-tool + consensus badges, KEV/ATT&CK/IOC signals. Click any row for the XAI drawer. |
| **Finding detail (XAI)** | Composite + ML scores, the **multi-tool consensus** panel (which tools agree + weight ring), the **SHAP waterfall** (base → each factor → final), composite breakdown, counterfactuals, and the **analyst feedback form** that feeds the monthly retrain. |
| **Incidents** | Case list with SLA tracking and lifecycle status. |
| **Compliance** | CIS control posture donut, the tamper-evident **evidence-chain integrity** badge, and per-asset scores. |

## Architecture
```
browser ──(same origin)──▶ nginx ──/ ───▶ static SPA (index.html + assets)
                                 └──/api ─▶ FastAPI (risk, findings, incidents, compliance)
```
- `index.html` — app shell (sidebar + topbar + drawer + toast mounts).
- `assets/app.css` — the design system (dark command-center theme, severity scale).
- `assets/app.js` — router, API client, pure-SVG charts (donut/bars/**waterfall**/ring), and all views.
- `nginx.conf` — serve + `/api` reverse proxy. `Dockerfile` — `nginx:alpine`, copy, done.

## Why not Next.js (yet)
The architecture names Next.js/Tailwind. For this air-gapped PoC a dependency-free SPA is
the more honest fit — it ships zero external assets and needs no registry at build time
(D-044). The production migration to the Next.js/Tailwind toolchain happens once a mirrored
npm registry (Verdaccio) exists in the K3s phase; the API contract and design system carry
over unchanged.
