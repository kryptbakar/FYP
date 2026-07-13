# Connector model — the pluggable integration surface

> **Positioning (read this first).** VYREX's sellable unit is the **intelligence
> layer** — fusion, exploit-aware scoring, explainability — not the ten tools it can
> ingest. "Ten tools integrated" is *deployment burden* for a customer; the thing they
> pay for is one ranked, explained queue over **whatever detectors they already run**.
> This document defines the connector contract so VYREX drops on top of an existing
> estate instead of demanding all ten tools. Each connector is independently
> enable/disable-able; the fusion + scoring engine works the same whether one connector
> feeds it or ten.

This is not a rewrite of the bridges — it names and specifies the contract they
**already** implement, so a customer (or a future you) can write a new connector for a
tool VYREX has never seen, in one file, without touching the core.

---

## 1. Two connector shapes

Every integration is one of two shapes, distinguished by what it emits:

| Shape | Emits | Path into VYREX | Examples (today) |
|---|---|---|---|
| **Telemetry connector** | Envelope v1 events (`kind`, `payload`) | `ingest-edge` → NATS `telemetry.v1.<kind>` → workers → stores | Go agent, `sensor-bridge` (Suricata/Zeek/Falco) |
| **Finding connector** | Rows in the `findings` table | direct DB write from an enricher/bridge | `enrichment` (Trivy/Nuclei), `wazuh-bridge`, `intel-enricher` (MISP/OpenCTI/Sigma) |

Telemetry connectors describe *observations*; finding connectors describe *judgements*
(a CVE match, an IOC hit, a detection). Both converge on `findings`, which is where
fusion + scoring operate — so **the intelligence layer is agnostic to which connectors
exist.**

---

## 2. The telemetry-connector contract (Envelope v1)

Emit JSON conforming to `schema/telemetry/v1/envelope.schema.json` and POST it to
`ingest-edge` over mTLS + bearer token (see `tools/fake-producer/produce.py` for a
100-line reference implementation). Required fields:

```jsonc
{
  "schema_version": "1.0",
  "event_id": "<uuid>",                  // OpenSearch _id → idempotent
  "agent_id": "<logical shipper id>",    // cross-checked vs the mTLS cert CN
  "host": { "host_id": "...", "hostname": "..." },
  "collected_at": "<RFC3339>",
  "kind": "process_event | network_flow | ids_alert | scan_finding | ioc_match | ...",
  "payload": { /* kind-specific, validated per phase */ }
}
```

Rules that make a telemetry connector well-behaved:

- **Version by `schema_version`.** Breaking payload changes require a v2 schema and the
  `telemetry.v2.>` subject — never mutate v1 in place.
- **`event_id` is the idempotency key.** Re-shipping the same id is a no-op downstream.
- **Leave `ingested_at` absent** — `ingest-edge` stamps it on receipt.
- The connector never talks to the DB; it only speaks the envelope. That keeps it
  stateless and lets ingest back-pressure protect the stores.

## 3. The finding-connector contract

Write rows to `findings` with — at minimum — `asset_id`, `domain`, `severity`, a
tool-unique `fingerprint` (for exact idempotency), `source_tool`, and a **`dedup_key`**
(§4). Optional-but-valuable: `cve_id`, `cvss_score`, `epss`, `kev`, `attack` (an ATT&CK
technique id), `threat_intel` (an IOC-hit marker). The more of these a connector
populates, the more the scoring factors light up — but none are mandatory.

The three existing finding connectors (`enrichment`, `wazuh-bridge`, `intel-enricher`)
are the templates; a new one mirrors their finding-insert helper (`upsert_findings`
in `services/enrichment/db.py`, `upsert_finding` in `services/intel-enricher/db.py`).

## 4. The `dedup_key` — the one field that makes fusion work

Fusion clusters findings that **share a `dedup_key`**, so independent tools that
discover the same issue collide and corroborate (raising the `consensus` score). The
key is deliberately **tool-independent**. Recipes every connector must follow (also in
`ml/FUSION.md`):

| Finding domain | `dedup_key` recipe |
|---|---|
| Vuln (agent/Trivy/Nuclei) | `sha1(asset, domain, cve_id, port)` |
| Network (egress/exposed)  | `sha1(asset, domain, rule_id, port)` |
| MISP IOC match            | `sha1(asset, "ioc", indicator)` |
| Sigma detection           | `sha1(asset, "sigma", rule_id)` |
| Wazuh FIM                 | `sha1(asset, path)` |
| Wazuh SCA / compliance    | `sha1(asset, cis_control)` |

A finding with **no** `dedup_key` becomes its own singleton cluster — never lost, just
not corroborated. Fusion **annotates, never deletes**: each tool's raw row survives with
its own `fingerprint`; the shared `consensus` record is written onto every cluster
member. Get the key right and a new connector automatically participates in consensus
scoring with zero core changes — **that is the whole point of the contract.**

## 5. Enable/disable — connectors are opt-in today

Compose profiles already make integrations independently selectable:

```bash
# run VYREX consuming ONLY the customer's existing Wazuh, nothing else:
docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile hostmon up -d
make risk-score            # fusion + scoring + SHAP run the same over just those findings
```

Profiles: `sensors` (Suricata/Zeek), `scanners` (Trivy/Nuclei), `hostmon`
(Wazuh/Falco), `intel` (MISP/OpenCTI/Sigma). A customer turns on only what maps to
tools they already operate; the intelligence layer needs no reconfiguration.

## 6. Writing a new connector (checklist)

1. Decide the shape: telemetry (observation) or finding (judgement) — §1.
2. Telemetry: emit Envelope v1 to `ingest-edge` (copy `fake-producer`). Finding: write
   to `findings` via the service's insert helper (copy `intel-enricher`/`wazuh-bridge`).
3. Stamp the correct **`dedup_key`** (§4) so it fuses with corroborating tools.
4. Populate whatever scoring inputs you have (`cve_id`/`epss`/`kev`/`attack`/…).
5. Add it as a Compose service under a profile (or a K3s Deployment) so it's opt-in.
6. Add a fixture + a line in the e2e smoke (`deploy/smoke/compose-smoke.sh`) so CI
   proves it produces findings.

## 7. Roadmap (productizing this further — ROADMAP B4)

Today the contract is real but expressed as "write to these tables / emit this
envelope." The product increments:

- A thin `connector-sdk` (a base class wrapping the finding insert + `dedup_key`
  helpers) so a connector is truly one small file.
- A connector registry + health surface in the console (which connectors are live,
  last-seen, findings/hour).
- A "bring-your-own-SIEM" finding connector that reads an existing Splunk/Elastic
  alert stream and lands it as VYREX findings — the clearest expression of "sell the
  intelligence layer, not the glue."
