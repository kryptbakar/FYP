# Phase C — Host + runtime (Wazuh + Falco)

**Status:** complete and verified (fixtures; live paths documented). **Date:** 2026-06-02.

Host monitoring (Wazuh) and runtime detection (Falco) now feed the unified pipeline,
**complementing** the Go agent rather than duplicating it.

## What was built

- **`services/wazuh-bridge`** (Python) — authenticates to the **Wazuh Manager REST API**
  (JWT :55000) and pulls **FIM (syscheck)** → `fim_event` and **SCA/CIS** → `scan_finding`
  (CIS control mappings preserved), publishing onto the existing JetStream pipeline.
  `--from-fixtures` for offline/deterministic runs (D-036).
- **Falco tailer in `sensor-bridge`** — reads Falco's JSON `file_output` → `runtime_alert`
  (`source_tool=falco`). Falco runs as a container (`runtime` profile, optional, D-031); on a
  capable host its `file_output` lands in the `falco_logs` volume the bridge tails.
- **Reconciliation (D-035)** — Go agent + Wazuh both do FIM; both feed the pipeline tagged by
  `source_tool`. Independent agreement is a consensus signal the Phase-F Fusion Engine uses
  (dedup by `dedup_key`, confidence boost), not duplication to suppress.
- **Compose / runner** — `wazuh-bridge` (hostmon profile); `falco_logs` volume;
  `make wazuh-pull [FIXTURES=1]`, `pwsh scripts/dev.ps1 wazuh-pull`.

## How to run

```bash
make up
make wazuh-pull FIXTURES=1     # Wazuh FIM + SCA -> pipeline (offline)
# Falco: inject events into the falco_logs volume, then `sensor-bridge --once` (see PHASE-C run log)
curl -s localhost:9200/telemetry-v1/_search -H content-type:application/json \
  -d '{"size":0,"aggs":{"t":{"terms":{"field":"source_tool.keyword"}}}}'
```

## Verification (actual run)

`wazuh-bridge --from-fixtures` → **8 events** (4 FIM + 4 SCA); Falco fixture → **3
runtime_alerts**. OpenSearch `source_tool` breakdown: `wazuh=8, falco=3` (alongside Phase-B
suricata/zeek). Normalized content in TimescaleDB:

```
Wazuh FIM (fim_event):   /root/.ssh/authorized_keys=created | /usr/bin/sudo=modified | /etc/cron.d/.hidden=created
Wazuh SCA (scan_finding): "Ensure auditd is installed"=failed (CIS 4.1.1) | "/etc/passwd 644"=passed (6.1.2)
Falco (runtime_alert):    Critical "Outbound connection to C2" | Notice "Terminal shell in container" | Warning "Write below etc"
```

## What's stubbed / deferred

- **Wazuh Manager** (~1.5 GB image, multi-GB RAM) isn't run on this host; the bridge is
  verified with `--from-fixtures` (real-shaped syscheck + SCA JSON). Live mode = same code,
  real Manager (defined under the `hostmon` profile).
- **Falco** needs privileged kernel access (eBPF/kmod) it lacks on Docker Desktop/WSL; the
  tailer/normalization is verified with a fixture. On a real host Falco's `file_output` flows
  through the same tailer.
- **Falco gRPC** (`client-go`) is an alternative to file_output; we chose the file tailer to
  reuse the sensor-bridge (no new transport). gRPC subscription can be added later.
- **Wazuh SCA ↔ our compliance engine** reconciliation (merging into `compliance_results`)
  and FIM dedup with the Go agent are part of the **Phase-F Fusion Engine**; here they're
  ingested + tagged, not yet fused.

## Acceptance

✅ Wazuh Manager API (JWT :55000) integration pulling FIM + SCA/CIS · ✅ normalized to the
unified schema (`fim_event` / `scan_finding`, source_tool=wazuh) · ✅ reconciled-by-design with
the Go agent (consensus, not duplication) · ✅ Falco runtime alerts via JSON tailer
(`runtime_alert`) · ✅ all land in OpenSearch + Timescale through the existing pipeline.
**Stop for review before Phase D (Nuclei + Trivy).**
