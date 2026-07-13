# Production deployment — running VYREX in a real organisation

This is the operator's guide: what hardware and OS you need, how the network is
laid out, how to get software into an air-gapped site, how to roll out agents and
sensors across a real estate, and how to run it day to day. The single-laptop
`make up` in the README is the demo; this is the real thing.

> Two supported footprints: **(A) single-node Docker Compose** for a pilot or a
> small site (up to a few hundred endpoints), and **(B) air-gapped K3s** with the
> Helm chart (`deploy/helm/vyrex`) for a production, HA deployment. Start with A
> for a pilot, graduate to B.

---

## 1. Do I need Linux? What hardware?

**The VYREX server stack is Linux-only** (it is Docker/Kubernetes and Linux
containers). Use **Ubuntu 22.04 LTS** or **RHEL/Rocky 9** — both are what
government sites standardise on. macOS/Windows work only for the *demo* via Docker
Desktop; do not run production on them.

**Endpoint agents are cross-platform** — the Go agent cross-compiles to Linux,
Windows, and macOS (`GOOS=linux|windows|darwin go build`), so you monitor a mixed
estate even though the server is Linux.

### Server sizing (starting points — confirm with docs/BENCHMARKS.md on your hardware)

| Footprint | Endpoints | CPU | RAM | Disk | Notes |
|---|---|---|---|---|---|
| Pilot (Compose) | ≤ 100 | 4 cores | 16 GB | 200 GB SSD | OpenSearch is the RAM hog; give it ≥ 4 GB heap |
| Small site (Compose) | ≤ 500 | 8 cores | 32 GB | 1 TB SSD | Add sensor/scanner profiles as needed |
| Production (K3s) | 500–5 000 | 3+ nodes × 8 cores | 3+ × 32 GB | NVMe + backup volume | Workers/OpenSearch scale horizontally |

Disk is driven by telemetry retention: derive GB/day from BENCHMARKS §3 (rows/day
× row size) and set the TimescaleDB retention policy to fit your budget. SSD/NVMe
is required — OpenSearch and Timescale are I/O-bound.

**Network sensor caveat:** Suricata/Zeek need to *see* traffic. In production
that means a **SPAN/mirror port** or a network TAP feeding the sensor host NIC in
promiscuous mode. Plan this with the network team before deployment — it is the
one requirement you cannot satisfy in software.

---

## 2. Network architecture

```
                         ┌─────────────────── Air-gapped site ───────────────────┐
   Endpoints ──agent/mTLS──▶  ingest-edge ─▶ NATS ─▶ workers ─▶ [PG|Timescale|OpenSearch]
   (Win/Lin/mac)                                                        │
   SPAN/TAP ──────────────▶  Suricata/Zeek ─▶ sensor-bridge ─▶ NATS ────┤
   Scanners (Trivy/Nuclei) ─────────────────▶ enrichment ──────────────┤
                                                                        ▼
   Analysts ──OIDC/TLS──▶  console + API + Grafana   ◀── Keycloak (SSO), Vault (secrets)
                                                                        │
   ┌── DMZ / staging host (the ONLY box that ever touches the internet) │
   │   feed-sync + mirror-sync ── pull NVD/EPSS/KEV + tool feeds ── then carry inside
   └────────────────────────────────────────────────────────────────────┘
```

Rules:

- **One egress point.** Only `feed-sync` (and the staging-host `mirror-sync`) ever
  reach the internet, and only to fetch the vulnerability/tool feeds. Everything
  else is sealed. In K3s this is enforced by NetworkPolicy; prove it with
  `make airgap-verify` (NFR1). See docs/AIRGAP.md.
- **Segment the analyst plane** from the data plane; analysts reach only the
  console/API/Grafana, never the stores directly.
- **Agents dial in** to ingest-edge over mTLS on 8443 — endpoints never expose a
  listening port to VYREX, so the blast radius of the SOC is minimal.

---

## 3. Getting software into an air-gapped site

You cannot `docker pull` inside the gap. The transfer workflow:

1. **On a connected staging host** (same CPU arch as the target):
   ```bash
   # a) mirror the vulnerability + tool feeds into named volumes
   bash tools/airgap/mirror-sync.sh              # NVD/EPSS/KEV handled by feed-sync
   # b) build/pull every image and save to a tarball
   cd vyrex && docker compose -f docker-compose.yml -f docker-compose.tools.yml build
   docker save $(docker compose config --images) -o vyrex-images.tar
   # c) export the feed/tool mirror volumes too (docker run --rm -v vol:/v busybox tar ...)
   ```
2. **Carry** `vyrex-images.tar` + the mirror volume tarballs + the git checkout
   across the gap on approved removable media (follow the site's media policy).
3. **On the air-gapped server:**
   ```bash
   docker load -i vyrex-images.tar
   # restore mirror volumes, then:
   make up                      # core stack, no internet needed
   make feeds-seed              # load the carried NVD/EPSS/KEV mirror
   ```
4. **Updates** repeat the loop: re-run `mirror-sync` on the staging host, carry the
   delta in, `docker load`. This is your patch cadence for feeds and images.

> **Shortcut — the bundler does all of the above.** On the staging host run
> `make bundle` (`tools/airgap/bundle.sh`): it saves every image, exports the feed/
> tool mirror volumes, copies the run config, and writes a `SHA256SUMS` manifest into
> one directory. Carry that inside and run `make install-offline` (`install.sh`): it
> **verifies the checksums fail-closed**, `docker load`s the images, restores the
> volumes, and brings the stack up — no internet. The manual steps above are what the
> bundler automates, kept here for transparency. (Cosign-**signing** the manifest is
> the remaining hardening step — ROADMAP B6.)

---

## 4. Bring-up checklist (Compose footprint)

```bash
# 0. Prereqs: Docker Engine + Compose plugin on Ubuntu 22.04
# 1. Secrets & PKI — DO NOT ship the dev defaults
cp .env.example .env            # then edit: strong DB/Grafana passwords
make certs                      # generate the mTLS PKI (per-agent certs)
# 2. Core stack
make up
make feeds-seed                 # offline NVD/EPSS/KEV mirror
make assess                     # host state -> findings + compliance
make risk-train && make risk-score   # train + score (composite + ML + SHAP)
# 3. Turn on the tools you need (each is an opt-in profile)
docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile sensors  up -d
docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile scanners up -d
docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile hostmon  up -d
docker compose -f docker-compose.yml -f docker-compose.tools.yml --profile intel    up -d
# 4. Verify the gap and health
make airgap-verify
curl -s localhost:8000/health/ready
```

Tool profiles: `sensors` (Suricata/Zeek), `scanners` (Trivy/Nuclei), `hostmon`
(Wazuh/Falco), `intel` (MISP/OpenCTI/Sigma). Enable only what the site will
actually feed with data — an enabled sensor with no traffic is just overhead.

### Harden before go-live (do not skip)

- [ ] Change every default password/secret in `.env`; move secrets to Vault (K3s).
- [ ] **API authentication is enforced.** It is automatic when `SOC_ENV=production`
      (or set `API_AUTH_REQUIRED=true`); the `auth_guard` middleware then requires a
      principal (Keycloak/oauth2-proxy header or a local session token) + RBAC on every
      non-public route. Verify: an unauthenticated `GET /findings` returns 401.
- [ ] TLS on the console/API ingress (not plain :3001/:8000).
- [ ] Set TimescaleDB/OpenSearch retention to fit disk (BENCHMARKS §3).
- [ ] Configure Velero/`deploy/backup` for the stores; test a restore.
- [ ] Run `make airgap-verify` and the security-review skill; fix findings.
- [ ] Run one attack-simulation (VALIDATION-ATTACK-SIM.md) as an acceptance test.

---

## 5. Production footprint (K3s)

For HA and horizontal scale, deploy the Helm chart:

```bash
# air-gapped K3s cluster, images loaded into the local registry (see deploy/)
helm install vyrex deploy/helm/vyrex -f deploy/helm/vyrex/values.yaml
```

What K3s adds over Compose (see deploy/ and PHASE-8-NOTES):

- **Keycloak** for OIDC SSO + RBAC across the console/API.
- **HashiCorp Vault** for secrets + PKI (issues/rotates the mTLS certs).
- **CNPG / OpenSearch operators** for replicated, backed-up stores.
- **Velero** for scheduled backup/restore.
- **NetworkPolicy** to enforce the single-egress air gap in the platform itself.
- **ArgoCD** for GitOps deploys inside the gap.
- Horizontal scale-out of stateless workers — the throughput lever for large estates.

Validate the chart before a real cluster with `make k3d-smoke` (throwaway k3d).

---

## 6. Agent rollout across the estate

1. Build per-OS agents from `agent/` (cross-compile). Sign the release —
   reproducible build + cosign-signed `SHA256SUMS` (D-048); endpoints verify
   fail-closed before install.
2. Issue each endpoint a **client certificate** from the PKI (Vault PKI in K3s).
   The agent authenticates to ingest-edge with mTLS + a bearer token.
3. Distribute via your existing management plane (GPO/Intune for Windows, Ansible/
   config-mgmt for Linux); the systemd unit template is in `deploy/agent-release`.
4. Confirm telemetry lands (console Telemetry view / `/api/telemetry/recent`)
   before declaring an endpoint onboarded.

---

## 7. Day-2 operations

| Task | How |
|---|---|
| Health / readiness | `curl /health` · `/health/ready`; Grafana "API metrics" dashboard |
| Feed updates | re-run `mirror-sync` on staging, carry in, `docker load`, `feeds-sync` |
| Model retraining | fold analyst feedback → `make risk-train` (monthly cadence, D-notes) |
| Backups | Velero schedule (K3s) / `deploy/backup` (Compose); **test restores** |
| Capacity watch | BENCHMARKS harnesses periodically; watch worker lag + disk growth |
| Incident response | analyst-driven, signed containment with two-person approval (D-028) |
| Audit integrity | verify the hash-chained audit + compliance evidence chain |

---

## 8. Sizing worksheet (fill per site)

- Endpoints: ____  × events/endpoint/min: ____ = ingest rate ____ /sec
- Compare against measured B1 sustained rate → worker replicas needed: ____
- Retention days: ____ × GB/day (BENCHMARKS §3): ____ = telemetry disk: ____ GB
- Sensors in scope (SPAN available?): ____  Scanners: ____  Hostmon: ____
- Footprint decision: Compose (pilot) / K3s (production): ____

Take these numbers from a real BENCHMARKS run on representative hardware — do not
guess them in a proposal.
