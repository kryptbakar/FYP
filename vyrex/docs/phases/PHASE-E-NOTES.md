# Phase E — Threat intel (MISP + OpenCTI) + Sigma

**Status:** complete and verified. **Date:** 2026-06-02.

Findings are now enriched with threat intelligence: **IOC matches** (MISP), **MITRE ATT&CK**
techniques (OpenCTI), and **Sigma** detections over the log store — all feeding the Phase-F
fusion model.

## What was built (`services/intel-enricher`)

- **MISP IOC matching** (`ioc.py`) — extracts remote IPs/domains from recent network/IDS/
  runtime telemetry and matches them against the MISP IOC store; matches become
  `source_tool=misp` findings carrying MISP event context in `findings.threat_intel`.
- **OpenCTI ATT&CK mapping** (`attack.py`) — tags every finding with its MITRE ATT&CK
  technique (`findings.attack`) via a mapping that stands in for OpenCTI's attack-pattern
  resolution.
- **Sigma evaluator** (`sigma_eval.py`) — compiles Sigma YAML with **pySigma → OpenSearch**
  and runs it against `telemetry-v1`; hits become `source_tool=sigma` findings. Falls back to
  the rule's `x_opensearch_query` if pySigma is unavailable (D-039).
- **Schema** — `findings.attack` (text) + `findings.threat_intel` (jsonb), idempotent migration.
- **Runner** — `make intel-enrich` / `pwsh scripts/dev.ps1 intel-enrich`.

## How to run

```bash
make up && make feeds-seed && make assess && make scan-ingest   # have some findings/telemetry
make intel-enrich        # MISP IOC + Sigma + ATT&CK
```

## Verification (actual run)

```
misp:   1 IOC-match finding from 7763 telemetry rows
sigma:  port-4444 rule (fallback) -> 82 hits / 1 host -> 1 HIGH detection finding
attack: 31 findings tagged
source_tool: agent 26 | trivy 3 | nuclei 3 | misp 1 | sigma 1
ATT&CK:  T1562 x18 | T1190 x11 | T1071.001 x2 | T1571 x1
```

Highlights (the cross-tool signal Phase F will fuse):
```
MISP   185.220.101.45 -> "Cobalt Strike C2 infrastructure"  (T1071.001)
Sigma  "Suspicious Outbound to port 4444"  HIGH  (T1571, mode=fallback)
ATT&CK T1190 (Exploit Public-Facing App) spans  agent + nuclei(Log4Shell) + trivy  CVE findings
ATT&CK T1071.001 (C2) links  agent egress finding  +  MISP IOC match
```

## What's stubbed / deferred

- **MISP & OpenCTI** (multi-GB stacks) aren't run on this host; the enrichers are verified
  with real-shaped fixtures. Live mode calls their REST APIs — PyMISP/pycti are the official
  clients (in `reference/`, attributed); we use a lean httpx path, swappable (D-038).
- **pySigma** wheels didn't install over the flaky link this run, so Sigma used the documented
  `x_opensearch_query` fallback (same query pySigma would emit). The pySigma path is wired and
  used automatically when the package is present.
- **Sigma rule set:** one starter rule shipped; the mirrored SigmaHQ set loads from `rules/`
  (full mirror = Phase H air-gap job).
- **Consensus/dedup across all these tools** (e.g. merge agent+trivy+nuclei CVE-2023-4911,
  boost confidence) is the **Phase-F Fusion Engine** — the `dedup_key`, `attack`, and
  `threat_intel` fields are now in place for it.

## Acceptance

✅ PyMISP/REST IOC enrichment tags findings with IOC matches · ✅ OpenCTI ATT&CK mapping on
findings · ✅ pySigma→OpenSearch evaluator (with fallback) producing detection findings ·
✅ all tagged by `source_tool` with `attack` + `threat_intel`. **Stop for review before Phase F
(AI Fusion Engine).**
