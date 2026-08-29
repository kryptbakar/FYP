# Air-gap design — offline operation & egress control

**Built in:** Phase H (the air-gap ground rule has shaped every phase) ·
**Verify:** `make airgap-verify`

SOC Central is built for an **air-gapped / on-prem** site (PITB). The ground rule:
**only one job may touch the internet; nothing else egresses at runtime.** Every
external feed is mirrored locally and consumed from the mirror. This document is the
single source of truth for *what* would egress, *how* it's mirrored, and *how we prove*
the gap holds.

---

## 1. The egress matrix — who may reach the internet

| Component | Runtime egress? | Why / how it's offline |
|-----------|-----------------|------------------------|
| **feed-sync** | **YES (the only one)** | Mirrors NVD/EPSS/KEV into Postgres. Dual-homed on the `egress` network. |
| **mirror-sync** | **YES (sync job)** | Mirrors tool feeds (Nuclei/Trivy/Sigma/Suricata) into local volumes. Run from a connected *staging* host or via sneakernet. |
| ingest-edge, workers, api, enrichment, risk-engine | no | Read the broker / DB / mirror only. |
| Suricata, Zeek | no | Rules loaded from the local mirror; capture is local traffic. |
| Trivy | no | `TRIVY_OFFLINE_SCAN=true`, `TRIVY_SKIP_DB_UPDATE=true`; DB from the mirror. |
| Nuclei | no | `-disable-update-check`; templates from the local mirror. |
| Sigma (intel-enricher) | no | Rules compiled from the mirrored SigmaHQ copy. |
| MISP / OpenCTI | no | Internal instances; external community feeds arrive via the controlled sync job, not the tools. |
| postgres, timescaledb, opensearch, nats, grafana | no | Internal data plane. |

---

## 2. The local mirror layout

`feed-sync` owns the CVE-intel mirror (in Postgres). `mirror-sync`
(`tools/airgap/mirror-sync.sh`) owns the **tool-feed** mirror in named Docker volumes
that the tool containers mount **read-only**:

| Volume | Mounted by | Contents | Refreshed by |
|--------|-----------|----------|--------------|
| `nuclei_templates` | nuclei | ProjectDiscovery templates | `nuclei -update-templates` |
| `trivy_cache` | trivy | Trivy vuln DB (`trivy-db`/`fanal`) | `trivy image --download-db-only` |
| `sigma_rules` | intel-enricher | SigmaHQ rule set | `git clone SigmaHQ/sigma` |
| `suricata_rules` | suricata | ET Open ruleset | ET Open `emerging.rules.tar.gz` |

Each download uses the **tool's own** offline-prepare mechanism — we don't re-implement
fetching/parsing. See `mirror-sync.sh`.

In Postgres (`feed-sync`): `nvd_cve`, `epss`, `kev`, `pkg_product_alias`, with a
`feed_sync_log` recording each refresh (feed, row count, mode, timestamp).

---

## 3. Refreshing the mirror in a controlled way

Air-gapped sites cannot pull live, so the mirror is refreshed out-of-band:

1. **Staging host (connected):** run `make feeds-sync` and `make mirror-sync` against
   the internet. `feed-sync` also writes a normalized on-disk cache (`/feeds-cache`).
2. **Transfer (sneakernet / one-way data diode):** carry the Postgres feed cache and the
   four named volumes to the air-gapped site on approved media.
3. **Air-gapped site (sealed):** load them — `make feeds-sync` uses `--from-cache`
   (replay the cache, no internet) and the tool volumes are imported
   (`docker volume`/`docker run … tar`). For dev/CI determinism there is also
   `make feeds-seed` (bundled NVD/EPSS/KEV fixtures) and `make mirror-sync SEED=1`
   (a minimal deterministic tool mirror from the repo's bundled rules).

Cadence: weekly for NVD/EPSS/KEV and Nuclei/ET rules; KEV on CISA's schedule. Every
import is logged (`feed_sync_log`) so an auditor can see the mirror's age.

---

## 4. Enforcing & verifying the gap

`docker-compose.airgap.yml` makes the rule **enforced**, not just intended, via two
Docker networks:

- **`socnet` (`internal: true`)** — Docker installs no default route, so containers on
  it have **no path off-host**. Every runtime service lives here.
- **`egress`** — an ordinary bridge with NAT. Attached **only** to `feed-sync`
  (and `mirror-sync`), which are dual-homed so they can reach both Postgres and the net.

Sealing is split across three paired overlays, because a compose overlay cannot name a
service that no included file defines (see §4.1):

```bash
# core only
docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d

# core + LLM/automation (this is the one to demo)
docker compose -f docker-compose.yml -f docker-compose.n8n.yml \
               -f docker-compose.airgap.yml -f docker-compose.airgap.n8n.yml \
               --profile agentic up -d

# ...and add -f docker-compose.tools.yml -f docker-compose.airgap.tools.yml for the tools
make airgap-verify
```

`tools/airgap/verify-egress.sh` runs a probe on the sealed network and on a normal
bridge (a positive control), and asserts:

```
sealed runtime  (socnet, internal:true) -> NO-ROUTE     PASS: air-gapped
control bridge  (egress-capable)        -> REACHED       PASS: probe works
== verdict: AIR-GAP ENFORCED ==
```

The control proves the block is real (the probe *can* egress on a normal bridge), not a
broken test or an offline host.

### 4.1 The check used to pass while the stack leaked (fixed 2026-08-28)

The probe above answers *"does socnet have a route?"* It never answered *"is anything
actually on socnet?"* — and those are different questions. A service missing from the
overlay keeps its default bridge, has full internet, and the probe still prints
**AIR-GAP ENFORCED**.

That was not hypothetical. On 2026-08-28 an audit found **21 of 35 services unsealed**,
including the investigation orchestrator, `ollama`, `n8n`, `mailpit` and the entire tool
stack. The orchestrator is the worst of them: it is the one component that feeds untrusted
finding text to a language model, so it is exactly the path a prompt-injection payload
would exfiltrate through — and it had unrestricted egress in the configuration this
document calls air-gapped. **This check passed the whole time.**

The lesson is worth stating plainly because it generalises beyond this project: *a
verification that cannot fail when the property is violated is not a verification.* The
script now audits **membership** as well as reachability — it enumerates running
containers, resolves each one's actual network attachments, and fails if any non-exempt
service is on a network that is not `internal: true`.

Two compose behaviours defeat sealing silently, and neither is guessable:

- **An overlay may not name a service that no included file defines** — the project fails
  to load entirely. Hence three paired files: `docker-compose.airgap.yml` (core),
  `docker-compose.airgap.n8n.yml`, `docker-compose.airgap.tools.yml`. Include the pair
  whenever you include the stack.
- **Declaring `networks: [default]` explicitly does not restate the default.** Compose
  *unions* it with an override's `[socnet]` instead of replacing it, so the service lands
  on both — sealed and egress-capable at once, which is the same as unsealed. `ollama`,
  `n8n` and `mailpit` were doing exactly this.

Relatedly, `dns:` **cannot be undone by a later override** (`dns: []` is ignored and the
entries survive), so a resolver committed to a base file follows the service into a sealed
deployment. The model-pull workaround therefore lives in an opt-in
`docker-compose.pull.yml`, never in `docker-compose.n8n.yml`.

### 4.2 Verified end-to-end, including the negative control

**2026-08-28, core + LLM/automation stack, 14 running services:**

```
  service membership audit (project: vyrex)
    ok    api            ok    investigation-orchestrator
    ok    console        ok    mailpit
    ok    enrichment     ok    n8n
    ok    grafana        ok    nats
    ok    ingest-edge    ok    ollama          (+ opensearch, postgres, timescaledb, workers)
  PASS: all 14 running services are sealed.
== verdict: AIR-GAP ENFORCED ==
```

Then the part that makes the PASS mean something — `ollama` was deliberately attached to an
ordinary bridge and the check re-run:

```
    LEAK  ollama — attached to egress-capable network(s): airgap-leak-test
  FAIL: 1 of 14 running services can reach off-host networks.
== verdict: LEAK DETECTED ==            (exit 1)
```

It names the service, names the network, and exits non-zero. A passing check is only
evidence if you have shown it can fail; this is that demonstration, and it is worth
re-running before the viva so the claim is same-day.

**Known limit, stated rather than papered over:** the audit can only inspect containers
that are **running**. A stopped service is not evidence of anything, so a partially-started
stack must not be read as a clean bill of health — the script prints this caveat itself.

### 4.3 The same bug existed in Kubernetes, and was worse

Compose was not the only place the air-gap was asserted rather than enforced. The K3s
NetworkPolicy (D-042, "the production air-gap primitive") default-denies egress for pods
matching:

```yaml
podSelector:
  matchLabels:
    app.kubernetes.io/part-of: vyrex
```

But `part-of` lived only in the chart's `soc.labels` helper, which is stamped on the
**Deployment object**. A NetworkPolicy selects **pods**, and object labels are not pod
labels. Rendering the chart and counting settles it:

```
pod templates: 9   carrying part-of: 0
```

**The default-deny-egress policy matched nothing.** Every workload had unrestricted egress
in the production deployment target, while the chart, this document and the decision log
all described it as air-gapped. The lab overlay was at least half-right; the production
primitive was inert.

The fix is a separate `soc.podLabels` helper (selector + `part-of`) used only in pod
template metadata. It is deliberately *not* added to `soc.selector`, because that feeds
`spec.selector.matchLabels`, which Kubernetes treats as **immutable** — changing it would
force every existing Deployment to be deleted and recreated. After the fix:

```
pod templates: 9   carrying part-of: 9
selector blocks: 5   containing part-of: 0   (matchLabels unchanged, upgrades in place)
```

Both halves are now enforced by `tools/airgap/check-coverage.py` in CI, which fails if a
compose service is missing from a sealing overlay **or** if a Helm pod template uses
`soc.selector` where it needs `soc.podLabels`. Verified in both directions — reverting one
template to the buggy form produces `workers.yaml:12 uses soc.selector for pod labels`.

> **The pattern is worth naming for the write-up.** Three times in one day the air-gap was
> enforced in a place that looked right but selected the wrong thing: services absent from
> the overlay, `networks: [default]` unioning instead of replacing, and object labels
> standing in for pod labels. In each case the system worked, the docs were confident, and
> nothing failed. The lesson is not "be careful" — it is that a security property nobody
> has *watched fail* is not yet known to hold.

> **Lab limitation (honest note).** `internal: true` blocks traffic in *both*
> directions, so a service attached only to `socnet` also loses host **port
> publishing** — the API/Grafana UI isn't reachable from the host while in sealed mode.
> So the overlay is a **verification harness** (it proves the egress-deny property); the
> day-to-day stack and the Phase-G console run on `make up`. In production the right
> primitive is a **Kubernetes NetworkPolicy** (Phase 8): `egress: deny` to everything
> except the sync job's destinations, while `ingress: allow` keeps the console reachable
> on the trusted LAN. Compose can only approximate that with the blunt `internal` flag.

---

## 5. Secrets (Vault plan for the K3s phase)

The air-gap doesn't remove secrets, it just keeps them on-prem. New secrets introduced
by the tool integration + sync jobs, to be sealed in **HashiCorp Vault** (Phase 8):

| Secret | Used by | Notes |
|--------|---------|-------|
| `NVD_API_KEY` | feed-sync | Optional (higher NVD rate limit); only on the connected staging host. |
| Wazuh Manager API creds | wazuh-bridge | JWT to `:55000`. |
| MISP auth key, OpenCTI token | intel-enricher | Internal instances. |
| mTLS PKI (CA, ingest-edge, agent certs) | ingest-edge, agent | Today via `gen-certs.sh`; Vault PKI engine issues + rotates in K3s. |
| `command_signing.key` (Ed25519) | api (active response) | Signs response commands; agents hold only the public key. **Highest-value secret.** |
| DB / Grafana / OpenSearch passwords | data plane | Currently `.env`; move to Vault + CSI provider. |

Plan: Vault runs on-prem (no cloud auto-unseal — manual/HSM unseal suits an air-gapped
site); services authenticate with the Kubernetes auth method and read secrets via the
Vault Agent / Secrets Store CSI driver; PKI and the signing key use Vault's PKI/transit
engines so private keys never sit in env vars or images.
