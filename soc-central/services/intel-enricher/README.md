# intel-enricher

**Built in:** Phase E · **Language:** Python · **Role:** threat-intel layer

Enriches findings/telemetry with threat intelligence and detection logic:

| Capability | Tool | Output |
|------------|------|--------|
| IOC matching | **MISP** (`ioc.py`) | matches telemetry IPs/domains vs IOCs → `source_tool=misp` findings + `findings.threat_intel` |
| ATT&CK mapping | **OpenCTI** (`attack.py`) | tags findings with the MITRE technique → `findings.attack` |
| Detection rules | **Sigma** (`sigma_eval.py`) | pySigma→OpenSearch query over `telemetry-v1` → `source_tool=sigma` findings |

These three signals (`source_tool`, `attack`, `threat_intel`, plus the `dedup_key` from
earlier phases) are exactly what the **Phase-F Fusion Engine** consumes to dedup, consensus-
weight, and explain.

## Run
```bash
make intel-enrich        # MISP IOC + Sigma + ATT&CK over the current stores
```

## Notes
- MISP/OpenCTI are heavy; verified offline with fixtures (`fixtures/ioc.json`, `attack.py`
  map). Live mode hits their REST APIs (PyMISP/pycti are the official clients — D-038).
- Sigma uses **pySigma** when installed, else the per-rule `x_opensearch_query` fallback
  (D-039). Rules live in `rules/` (mirrored SigmaHQ set).
- No internet at runtime — reads the internal MISP/OpenCTI + the log store.
