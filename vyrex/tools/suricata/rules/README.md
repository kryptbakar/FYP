# Suricata rules (local + mirrored)

This directory is mounted into the Suricata container at
`/var/lib/suricata/rules` and is the **only** rule source it loads (air-gapped).

- **`local.rules`** — SOC Central local rules (committed). Includes a deterministic
  TEST rule used by `make sensors-test`.
- **`*.rules` (ET Open)** — the **mirrored Emerging Threats Open ruleset** lands here,
  fetched by the controlled sync job (NOT by Suricata). Suricata runs with
  `-disable-update-check`-equivalent behaviour: it never reaches the internet; it loads
  whatever rule files are present in this directory.

## Air-gap mirroring (Phase B / §6; finalized in Phase H)

The ET Open ruleset is **not** committed (it's large and changes daily, and is
gitignored under `*.rules` except `local.rules`). On a connected staging host the sync
job downloads `emerging.rules.tar.gz`, extracts the `.rules` files into this directory,
and the bundle is carried to the air-gapped site (sneakernet / scheduled channel). At
runtime Suricata egresses nowhere — it only reads these files. Full procedure +
egress-blocked verification: `docs/AIRGAP.md` (Phase H).
