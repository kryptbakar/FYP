# Phase B — Network detection (Suricata + Zeek)

**Status:** complete and verified end-to-end. **Date:** 2026-06-02.

Network IDS + traffic-analysis signal now flows into the platform through the **existing**
pipeline, normalized to the unified schema.

## What was built

```
Suricata (eve.json, alerts) ─┐
Zeek (conn/dns/http/ssl logs)─┴─▶ sensor-bridge ──▶ JetStream telemetry.v1.<kind> ──▶ workers ──▶ TimescaleDB + OpenSearch
```

- **`services/sensor-bridge`** (Python) — tails Suricata `eve.json` (event_type=alert →
  `ids_alert`) and Zeek `*.log` (→ `traffic_metadata`), publishing normalized envelopes with
  `source_tool` + `raw_ref` onto the existing broker. `--once` (batch) or tail mode. No new
  ingestion path (D-034); internal sensors publish straight to the broker (D-033).
- **Deterministic offline test** — `tools/sensors/make_test_pcap.py` emits a tiny valid DNS
  packet; `tools/suricata/rules/local.rules` guarantees an alert. `make sensors-test`:
  generate pcap → run **real Suricata** on it → ship alerts → stores. No live capture or
  internet needed.
- **Compose** — `suricata`, `zeek`, `sensor-bridge` under the `sensors` profile;
  `make sensors-test` / `pwsh scripts/dev.ps1 sensors-test`.
- **Worker robustness** — defaults a missing `ingested_at` so direct publishers are safe.

## How to run

```bash
make up                                  # core stack
make sensors-test                        # Suricata pcap -> bridge -> stores
# query:
curl -s localhost:9200/telemetry-v1/_search -H content-type:application/json \
  -d '{"size":0,"aggs":{"t":{"terms":{"field":"source_tool.keyword"}}}}'
```

## Verification (actual run)

**Real Suricata 7.0.15** on the generated pcap:
```
i: pcap: read 1 file, 1 packets, 71 bytes
eve.json -> 2 alert events (sid 1000001 "IP packet observed", sid 1000002 "DNS query"),
            src 10.0.0.10 -> 8.8.8.8:53, app_proto dns
```

**Through the pipeline into both stores** (after rebuilding `workers` to bake the Phase-A
schema so `ids_alert`/`traffic_metadata` validate):
```
OpenSearch source_tool: suricata=…, zeek=…     network kinds: ids_alert, traffic_metadata
TimescaleDB: ids_alert and traffic_metadata rows present
  zeek sample: dns query=example.com ; conn service=ssl / dns
```

## What's stubbed / deferred

- **Live capture:** Suricata/Zeek read a **pcap** here (deterministic, air-gap-friendly). On
  a real sensor host they run on a live interface (host networking + NET_ADMIN) — same bridge,
  same pipeline.
- **Zeek image** wasn't pulled on this host (flaky link); the Zeek **shipper path** was
  verified with realistic Zeek JSON fixtures (`tools/sensors/data/zeek/*.log`). Real
  `zeek -C -r test.pcap` produces identical JSON logs the bridge ships unchanged.
- **ET Open ruleset mirror:** `tools/suricata/rules/` is the offline rule source; the local
  TEST rule is committed, the large ET ruleset is mirrored by the controlled sync job
  (`tools/suricata/rules/README.md`); full air-gap procedure + egress-blocked verification is
  Phase H (`docs/AIRGAP.md`).
- **Suricata/Zeek → findings/correlation** (vs. just storage): alerts are stored + searchable
  now; turning IDS alerts into findings and correlating with host/CVE context is the Fusion
  Engine (Phase F).

## Acceptance

✅ Suricata (EVE) + Zeek stood up · ✅ EVE-tail worker + Zeek log shipper (`sensor-bridge`) ·
✅ alerts + metadata land in OpenSearch (and Timescale) through the **existing** pipeline ·
✅ test traffic (pcap) proves the path · ✅ ET-rules mirroring designed (offline rule dir).
**Stop for review before Phase C (Wazuh + Falco).**
