# Phase H — Air-gap hardening

**Goal (expansion prompt §6 + §7-H):** finalize the offline-mirror design, mirror every
tool feed locally, and **verify by running with egress blocked** that only the sync job
reaches the internet. Fold new secrets into the Vault plan for K3s.

## What shipped
- **`docker-compose.airgap.yml`** — enforcement overlay. Two networks: `socnet`
  (`internal: true`, no route off-host) carries every runtime service; `egress` (bridge)
  is attached **only** to `feed-sync`/`mirror-sync`. Assigning a service `networks:[socnet]`
  replaces its default membership, so it physically cannot egress.
- **`tools/airgap/mirror-sync.sh`** — the sibling internet-facing job. Mirrors Nuclei
  templates, Trivy DB, SigmaHQ rules, and ET Open Suricata rules into named volumes using
  each tool's own offline-prepare; `--seed` lays down a deterministic minimal mirror from
  the repo's bundled rules for this host (D-043).
- **`tools/airgap/verify-egress.sh`** — probes the sealed network and a normal-bridge
  positive control; asserts `NO-ROUTE` vs `REACHED` and prints `AIR-GAP ENFORCED`.
- **`docs/AIRGAP.md`** — the egress matrix (who may egress + why each tool is offline),
  mirror layout, controlled (sneakernet) refresh procedure, the lab-vs-prod note, and the
  Vault secrets plan for Phase 8.
- **Task runner**: `make mirror-sync [SEED=1]`, `make airgap-up`, `make airgap-verify`
  (and the `pwsh scripts/dev.ps1` equivalents).
- **DECISIONS D-042** (enforce + verify the gap; K3s NetworkPolicy in prod) and **D-043**
  (mirror via each tool's own offline-prepare + `--seed`).

## Verified end-to-end (live, 2026-06-02)
1. `docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d` — core stack
   recreated onto the sealed network (data volumes persisted).
2. `make airgap-verify` →
   ```
   sealed runtime  (socnet, internal:true) -> NO-ROUTE   PASS: air-gapped
   control bridge  (egress-capable)        -> REACHED     PASS: probe works
   == verdict: AIR-GAP ENFORCED ==
   ```
3. Direct check: `api` container `socket.create_connection(("api.first.org",443))` →
   **name resolution failure** (sealed); same probe on a normal bridge reached it.
4. `make mirror-sync SEED=1` → all four mirror volumes populated: `nuclei_templates`
   (seed template), `trivy_cache` (`db/.mirrored-at`), `sigma_rules`
   (`sigma/susp_egress.yml`), `suricata_rules` (`local.rules`, `README.md`).
5. Restored the normal stack (`make up`); API health OK — the console/UI path is unaffected.

## Notes / honest limitations
- **`internal: true` blocks both directions**, so in sealed mode a service also loses host
  port-publishing (the UI isn't reachable from the host). The overlay is therefore a
  **verification harness** that proves egress-deny; the day-to-day stack and the Phase-G
  console run on `make up`. Production uses a **K3s NetworkPolicy** (egress-deny except the
  sync job, ingress-allow for the console) — Phase 8. This is called out in AIRGAP.md +
  D-042.
- `mirror-sync` online mode and the heavy tools (MISP/OpenCTI live feeds) aren't exercised
  on this host (~GB-scale pulls, flaky link); the live commands are documented and the
  offline path is fully verified via `--seed`, matching the pattern used since Phase A.
- Cross-platform seed-copy uses `tar`-over-stdin rather than a host bind-mount, because
  Docker Desktop/Windows doesn't resolve git-bash `/c/...` source paths (D-043).
