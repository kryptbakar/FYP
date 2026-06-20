# enrichment

**Built in:** Phase 3 · **Language:** Python · **Role:** the assessment engine

Turns raw host telemetry into **explainable findings**, reading only local stores
(no internet). For each asset it pulls the latest host state from TimescaleDB and
runs three assessment domains against the local feed mirror in Postgres, writing
findings (and an asset inventory) back to Postgres.

```
TimescaleDB (host state) ─┐
                          ├─▶ matcher + 3 domains ─▶ findings (Postgres)
Postgres mirror (NVD/EPSS/KEV) ─┘
```

## Domains

| Domain | What it checks | Output |
|--------|----------------|--------|
| **application** | each osquery package `(name, version)` → matched CVEs via `pkg_product_alias` + version-range; enriched with CVSS + EPSS + KEV | one finding per asset×CVE×package |
| **system** | rule-based hardening gaps (auditd, host firewall, auto-updates, insecure services) — CIS-flavoured | one finding per failed rule |
| **network** | exposed sensitive ports + suspicious egress (e.g. :4444) from flow telemetry | one finding per asset×port |

Every finding carries `evidence` (matched range, CVSS vector, sample IPs…) so it's
**explainable**. The *composite* risk score + SHAP explanations come in Phase 5; the
`risk_score` column is reserved for it.

## Compliance engine (Phase 4)

The same engine also runs a **compliance pass**: `compliance.py` grades CIS-Benchmark +
org-policy rules against the host's osquery state → **pass / fail / partial /
not_applicable**, and `evidence.py` writes each evaluation to a **hash-chained,
append-only evidence log** (`compliance_evidence`) for tamper-evident audit. Results are
in `compliance_results`. Verify the chain any time:

```
GET /compliance/summary           # per-asset score
GET /compliance/results?status=fail
GET /compliance/evidence/verify    # recomputes the hash chain; flags tampering
```

## Matching (the hard part)

`matcher.py` loads the mirror into memory and answers "which CVEs affect this
`(package, version)`?". Distro package names are mapped to upstream CPE products via
`pkg_product_alias`; versions are compared with a best-effort upstream-version
normalizer (`version.py`) — approximate for the MVP (D-019), enough to place
glibc `2.36` inside `[2.34, 2.39)` while keeping zlib `1.2.13` out of `(-inf, 1.2.12)`.

## Run

```bash
make feeds-seed   # populate the mirror first
make assess       # one-shot assessment now   (pwsh scripts/dev.ps1 assess)
```
As a service it re-assesses every `ASSESS_INTERVAL` seconds (default 120). Findings
upsert by fingerprint, so re-runs refresh rather than duplicate, and analyst-owned
`status` is never overwritten.

View results: `GET /findings`, `/assets`, `/stats/summary` on the API.
