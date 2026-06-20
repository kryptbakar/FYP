# Phase D — Active scanning (Nuclei + Trivy)

**Status:** complete and verified (fixtures; live offline runs documented). **Date:** 2026-06-02.

Active scanners now produce **first-class, enriched, ranked findings** by reusing the
existing mirror enrichment + risk engine.

## What was built

```
Trivy image/fs scan (JSON) ─┐
Nuclei -jsonl (templates)  ─┴─▶ enrichment --scan ──▶ EPSS+KEV from local mirror ──▶ findings (source_tool=trivy|nuclei) ──▶ risk-engine ranks
```

- **`services/enrichment/scanners.py`** — `parse_trivy()` (Results→Vulnerabilities) and
  `parse_nuclei()` (template-id, severity, `classification.cve-id`). Each CVE is enriched with
  **EPSS + KEV from the local feed mirror** (CVSS from the scanner or `nvd_cve`); non-CVE
  Nuclei hits (exposed panels) become **network** findings.
- **`enrichment --scan`** subcommand — reads Trivy JSON + Nuclei JSONL (bundled fixtures by
  default, or mounted live output), upserts `findings` tagged `source_tool`, per-tool
  fingerprint + shared `dedup_key` for Phase-F fusion (D-037).
- **API** — `/findings` and `/risk/ranking` now return `source_tool` (provenance for the console).
- **Runner** — `make scan-ingest` / `pwsh scripts/dev.ps1 scan-ingest`.

## How to run

```bash
make feeds-seed && make scan-ingest      # mirror + ingest Trivy/Nuclei fixtures
make risk-train && make risk-score       # rank them
curl 'localhost:8000/findings?asset_id=scan-target-01'
curl 'localhost:8000/risk/ranking'
```

## Verification (actual run)

`enrichment --scan` → **6 findings** (3 Trivy + 3 Nuclei). `findings.source_tool`: agent 26,
trivy 3, nuclei 3. Enrichment from the mirror:

```
source_tool  cve_id          sev       cvss  epss     kev   title
trivy        CVE-2023-4911   HIGH      7.8   0.00091  t     glibc Looney Tunables in libc6
trivy        CVE-2023-0286   HIGH      7.4   0.0021   f     openssl X.400 in libssl3
trivy        CVE-2022-1304   MEDIUM    5.5   -        f     e2fsprogs OOB
nuclei       CVE-2021-44228  CRITICAL  -     -        t     Apache Log4Shell  <- KEV from mirror
nuclei       (none)          MEDIUM    -     -        f     Exposed .git/config        (network)
nuclei       (none)          LOW       -     -        f     Exposed Swagger UI         (network)
```

After `risk-score`, `/risk/ranking` ranks them: **CVE-2023-4911 (trivy)** and **Log4Shell
(nuclei, KEV)** sit at the top — a Nuclei scanner finding enriched with KEV from our mirror,
prioritized by the XGBoost/SHAP engine.

## What's stubbed / deferred

- **Live scanner runs need their data:** Trivy needs its vuln DB (~600 MB), Nuclei its
  templates — both fetched over the network and **mirrored** for air-gap (§6). On this
  flaky/disk-constrained host we verify with **real-shaped fixtures**; live runs
  (`trivy image --server … --format json`, `nuclei -jsonl -disable-update-check`) feed the
  exact same parser. Trivy is running in server mode (`:4954`); Nuclei runs on-demand.
- **Consensus/dedup across tools** (e.g. agent + trivy both flag CVE-2023-4911 → merge +
  confidence boost) is wired via `dedup_key` but executed by the **Phase-F Fusion Engine**.

## Acceptance

✅ Nuclei + Trivy output parsed · ✅ CVE findings routed through the existing **NVD/EPSS/KEV**
mirror enrichment · ✅ written as ranked, explainable `findings` tagged by `source_tool` ·
✅ offline (mirrored DB/templates per §6). **Stop for review before Phase E (MISP + OpenCTI + Sigma).**
