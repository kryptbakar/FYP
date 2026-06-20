# wazuh-bridge

**Built in:** Phase C · **Language:** Python · **Role:** Wazuh Manager API → broker

Pulls host-monitoring signal from the **Wazuh Manager REST API** (port 55000, JWT — the
API is embedded in the Manager since 4.0; the standalone `wazuh-api` repo is deprecated)
and publishes it onto the existing JetStream pipeline:

```
Wazuh syscheck (FIM)   -> kind=fim_event     (source_tool=wazuh)
Wazuh SCA / CIS checks -> kind=scan_finding  (source_tool=wazuh, with CIS mappings)
```

## Reconciliation with the Go agent (D-035)

Our Go agent **and** Wazuh both do FIM/host checks. We keep **both**, tagged by
`source_tool` — independent corroboration is a *signal*, not duplication. The Phase-F
Fusion Engine dedups by `dedup_key` (asset+path for FIM, asset+CIS-control for compliance)
and boosts confidence when tools agree.

## Run

```bash
make wazuh-pull FIXTURES=1     # offline: bundled real-shaped API responses
make wazuh-pull                # live: calls the Wazuh Manager (needs it running)
```

## Config (env)
`WAZUH_API_URL` (`https://wazuh-manager:55000`), `WAZUH_API_USER`, `WAZUH_API_PASSWORD`,
`WAZUH_TARGET_AGENT`, `NATS_URL`.

## Note
The Wazuh Manager image (~1.5 GB) isn't run on the lab host; the integration is verified
with `--from-fixtures` (real-shaped syscheck + SCA JSON in `fixtures/`). Live mode is the
same code path against a real Manager.
