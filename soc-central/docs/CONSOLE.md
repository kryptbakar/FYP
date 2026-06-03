# The Analyst Console

**Location:** [`web/console/`](../web/console/) · **Served at:** `http://localhost:3001`
(nginx; reverse-proxies `/api` → FastAPI `:8000`, same-origin, no CORS — D-044/D-045).

An **intelligence workspace**, not a dashboard: decision-centric, explainable,
human-in-the-loop. **CrowdStrike-Falcon-inspired** design language — graphite near-black
canvas + signature crimson accent (D-049); **color = meaning only**, severity is encoded by
**shape + label** (never hue alone) for WCAG AA. Dependency-free — vanilla HTML/CSS/JS, all
charts hand-built in inline SVG/CSS, **zero external/network assets**, so it runs fully
air-gapped. Deep-link a finding with `#f/<id>`.

## Run & verify
```bash
make up                      # console comes up with the core stack
# open http://localhost:3001  (API docs: http://localhost:8000/docs)
```
- **LIVE vs DEMO:** the top-right indicator shows `LIVE /api` when the backend answers and
  `DEMO DATA` when it doesn't. The console renders fully from embedded fixtures
  (`assets/fixtures.js`) when `/api` is unreachable, then switches to live data automatically.
- **Air-gap:** no CDN/fonts/scripts/images are fetched at runtime (verify in devtools:
  zero non-same-origin requests). Fonts use the system stack.

## File structure
```
web/console/
  index.html          app shell (rail + topbar + drawer + toast mounts)
  nginx.conf          serve static + reverse-proxy /api -> api:8000
  Dockerfile          nginx:alpine, copy assets (no build step)
  assets/
    app.css           design system (§3 tokens: bg/surface/elevated/accent/severity)
    fixtures.js       embedded demo data (offline fallback; mirrors real API shapes)
    api.js            same-origin client + fixture fallback + LIVE/DEMO state
    ui.js             primitives: severity (shape+label), SHAP waterfall, consensus pips,
                      counterfactuals, provenance, two-person approval gate, ATT&CK names
    views.js          the five views + the finding-detail (hero) drawer
    app.js            router, keyboard nav, boot
```

## The five views
| View | Purpose | Key `/api` contracts |
|------|---------|----------------------|
| **Triage** (home) | Decision queue ranked by composite risk; each card = a conclusion + one action. Filters: domain, severity, source_tool, KEV-only. | `GET /risk/ranking`, `GET /assets` |
| **Finding detail** (hero) | The XAI view: big composite + ML score, **SHAP waterfall** (base → 10 factors → final), multi-tool **consensus**, ATT&CK + threat-intel, counterfactuals, evidence/provenance, the **containment gate**, and analyst feedback. | `GET /findings/{id}/explain`, `GET /findings/{id}`, `POST /findings/{id}/feedback`, `POST /actions/{id}/approve|reject` |
| **Compliance** | CIS posture as a conclusion + control list + the **hash-chained evidence** integrity badge. | `GET /compliance/{summary,results,evidence/verify}` |
| **Cases** | Incidents with SLA + a hash-chained **audit timeline** of actions. | `GET /incidents`, `GET /actions`, `GET /response/audit/verify` |
| **Sensors & Fusion** | The honest analog of an "agent roster": the real **pipeline** (feed-sync → ingest-edge → JetStream → workers → scoring → fusion) + the integrated-tool grid with live status + envelope types. | derived from `GET /risk/ranking` (`source_tool` counts, consensus), `GET /stats/summary`, `GET /version` |

## Key components
- **SHAP waterfall** — renders the model's TreeSHAP explanation on a fixed **0–100 x-domain**
  (ticks 0/25/50/75/100). Base marker → one step bar per factor (risk-raising extends right
  in amber/red, risk-lowering left in green, signed `+/−` labels) → final marker. Asserts
  `base + Σ contributions ≈ final` and prints the reconciliation line. The ten factors: CVSS,
  EPSS, KEV, asset exposure, vuln age, compliance impact, service criticality, threat-intel
  (MISP IOC), multi-tool consensus, ATT&CK context.
- **Consensus** — saturating weight (1 tool → 0.0, 2 → 0.5, 3+ → 1.0) shown as a 3-segment
  pip + a plain-language statement + the `dedup_key` + `source_tool` chips.
- **Two-person approval gate** — destructive/containment actions follow
  `proposed → approved_by_you → awaiting_second_approver → authorized → executing → contained`;
  **two distinct approvals** are required before authorize (the server enforces this too,
  D-027/D-028 — Ed25519-signed channel, hash-chained audit). In DEMO mode a clearly-labelled
  `(simulate second approver)` control stands in for the second human. Nothing destructive
  auto-executes.
- **Provenance chip** — every claim is traceable to a `source_tool`; click an evidence row to
  reveal the raw signal/record.
- **Severity indicator** — `critical` filled square · `high` filled triangle · `medium` hollow
  circle · `low/info` dash — shape **and** text label carry the meaning; color reinforces.

## Keyboard map
`/` focus search · `1`–`4` switch views (Triage/Compliance/Cases/Sensors&Fusion) ·
`j`/`k` move selection · `Enter` open selected · `Esc` close drawer / blur search.
(The hero **Finding detail** opens from a Triage row via click/`Enter` — it's a contextual
drawer over the queue, so the queue's filters/scroll are preserved underneath.)

## Honest notes (no fabrication)
- There are **no autonomous "AI agents"** in this product; "Sensors & Fusion" shows the real
  pipeline + integrated tools, not invented investigators.
- A few Sensors-&-Fusion stats (e.g. exact JetStream depth) aren't exposed by the API yet, so
  they're **derived** from available data or shown as status rather than precise gauges — no
  backend endpoints were added for the console (read-only, same-origin only).
- ATT&CK **technique names** are a small static reference map (`ui.js` `ATTACK`) — air-gap
  clean; the backend stores the technique **ID** on each finding.

## Self-hosting fonts (optional)
The console defaults to the system font stack (air-gap safe). To use Inter / IBM Plex,
drop the `.woff2` files into `assets/fonts/`, add `@font-face` rules to `app.css`, and set
`--sans`/`--mono` — nothing is ever fetched at runtime.
