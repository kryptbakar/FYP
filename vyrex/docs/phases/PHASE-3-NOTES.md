# Phase 3 — Vulnerability assessment + enrichment

**Status:** complete and verified end-to-end. **Date:** 2026-06-01.

The first slice of the **intelligence layer**: mirror the public vuln feeds locally, map
the agent's host state to CVEs, and produce explainable findings across three domains.

## What was built

```
feed-sync ──(only outbound job)──▶ Postgres mirror (nvd_cve/nvd_affected, epss, kev, pkg_product_alias)
                                          │
TimescaleDB (agent host state) ───────────┤
                                          ▼
                                    enrichment ──▶ findings + assets (Postgres) ──▶ API /findings, /assets, /stats/summary
```

- **[services/feed-sync/](../services/feed-sync/)** — the *only* internet-facing job
  (D-018). Mirrors **CISA KEV**, **FIRST EPSS** (daily CSV), and **NVD CVE 2.0**
  (incremental window) into Postgres; caches normalized rows for air-gapped replay
  (`--from-cache`); ships a deterministic offline `--seed` fixture set.
- **[services/enrichment/](../services/enrichment/)** — the assessment engine. Reads only
  local stores. Package→CVE matcher (`pkg_product_alias` + version-range, D-019) enriches
  each match with CVSS + EPSS + KEV. Three domains:
  - **application** — package CVEs
  - **system** — rule-based hardening gaps (auditd, firewall, auto-updates, insecure services)
  - **network** — exposed sensitive ports + suspicious egress, from flow telemetry
- **API** — `GET /assets`, `GET /findings` (filter by domain/severity/cve/kev/asset),
  `GET /findings/{id}`, `GET /stats/summary`.

## How to run

```bash
make up           # stack (incl. enrichment service, which loops every ASSESS_INTERVAL)
make feeds-seed   # populate the mirror from fixtures (offline)   | make feeds-sync = live
make assess       # one-shot assessment now
curl localhost:8000/stats/summary
```

## Verification (actual run)

Mirror seeded (offline fixtures): `nvd=4 epss=4 kev=4 aliases=17`.
Assessment over 3 discovered assets → **14 findings**:

**Application — real CVE matches on the agent's actual packages, fully enriched:**
```
asset         cve_id         package   version            cvss  sev   epss     kev
6b369…(agent) CVE-2022-3715  bash      5.2.15-2+b13       7.8   HIGH  0.00052  f
6b369…(agent) CVE-2023-4911  libc6     2.36-9+deb12u14    7.8   HIGH  0.00091  t   <- KEV (due 2024-01-22)
6b369…(agent) CVE-2023-4911  libc-bin  2.36-9+deb12u14    7.8   HIGH  0.00091  t
host-lab-01   CVE-2023-0286  openssl   3.0.2-0ubuntu1.15  7.4   HIGH  0.0021   f
```
- `CVE-2023-4911` (Looney Tunables) matched glibc range `[2.34, 2.39)` → libc6 2.36 ✓ and
  lit up the **KEV** join end-to-end.
- `CVE-2022-37434` (zlib < 1.2.12) **correctly did NOT match** zlib 1.2.13 — version
  filtering is precise (no false positive).

**System** — `auditd_missing`, `no_firewall` (MEDIUM), `no_auto_updates` (LOW) per asset.
**Network** — `net.suspicious_egress.4444` (HIGH) on the asset with C2-like flows.

**API:**
```
GET /stats/summary -> {"assets":3,"kev_findings":2,
  "by_domain_severity":[application/HIGH 4, network/HIGH 1, system/LOW 3, system/MEDIUM 6],
  "top_cves":[CVE-2022-3715 7.8, CVE-2023-4911 7.8 kev, CVE-2023-0286 7.4]}
GET /findings?kev=true -> CVE-2023-4911 findings with kev_due_date 2024-01-22
```

## What's stubbed / deferred

- **MISP + abuse.ch** (URLhaus/MalwareBazaar/ThreatFox) — approved sources, stubbed; slot
  in as feed-sync fetchers writing IOC tables.
- **Full CPE applicability + dpkg version semantics** — current matcher is the curated
  alias map + approximate version compare (D-019).
- **Full CIS engine + hash-chained evidence** — Phase 4 (system domain here is a starter
  rule set).
- **Composite risk score + ML/XAI** — Phase 5 (`findings.risk_score` reserved); severity
  today is the preliminary CVSS/rule severity.
- **Live feed sync** — implemented (`make feeds-sync`); verification used the offline
  `--seed` path for determinism (NVD rate limits + air-gap philosophy).

## Acceptance

✅ feed-sync mirrors NVD/EPSS/KEV locally (air-gapped, only outbound job) · ✅ enrichment
maps osquery package/OS/network findings to CVEs and enriches with CVSS/EPSS/KEV from the
mirror · ✅ three assessment domains (application/system/network) producing findings ·
✅ findings queryable via the API.
