# Phase 8 — Hardening + K3s (the production deployment layer)

**Goal (original prompt Phase 8):** Helm charts; HA via CloudNativePG + OpenSearch
operator; Velero backup/DR; air-gapped update channel for offline feed sync; Vault-backed
secrets; signed agent binaries with tamper detection; ArgoCD GitOps. Plus the OIDC/SSO +
RBAC and the K3s NetworkPolicy air-gap primitive deferred from Phases G and H.

This is the deployment story for a real air-gapped, on-prem K3s site. As with the heavy
OSS tools, a live cluster isn't stood up on the dev host — everything here is delivered as
**production-grade, lint-clean manifests** and verified by rendering, with the live path
documented.

## What shipped (`deploy/`)
- **Helm chart** `deploy/helm/vyrex/` — templates the product workloads (api ×2,
  console ×2, ingest-edge ×2 mTLS, workers ×3) and jobs (feed-sync, enrichment, monthly
  retrain + daily score), all with non-root/read-only/seccomp pod security, Vault-sourced
  secrets via `envFrom`, probes, and resource limits. Plus the security primitives:
  **NetworkPolicies**, OIDC-protected **Ingress**, ServiceAccount, ConfigMap.
- **HA data plane** — `databases/postgres-cnpg.yaml` (CloudNativePG: 3 instances, PITR/WAL
  archiving + daily base backups to MinIO) and `databases/opensearch-cluster.yaml`
  (OpenSearch operator: 3-node TLS cluster); clustered NATS JetStream noted.
- **Vault** — `vault/vault-values.yaml` (Raft HA, manual Shamir unseal, pki+transit) and
  `vault/external-secrets.yaml` (ESO `ClusterSecretStore` + `ExternalSecret`s for db,
  opensearch, ingest token, and the Ed25519 command-signing key) — the secret list from
  `docs/AIRGAP.md §5` made concrete.
- **Identity** — `identity/realm-vyrex.json` (Keycloak realm: roles soc-admin /
  soc-analyst / soc-viewer, clients for console+API and Grafana, roles→`groups` claim) and
  `identity/oauth2-proxy.yaml` (forward-auth in front of the ingress). **Closes the
  OIDC/SSO + RBAC item deferred from Phase G.**
- **Backup/DR** — `backup/velero-schedule.yaml` (BSL on on-prem MinIO + daily 30-day and
  weekly 90-day schedules).
- **GitOps** — `argocd/application.yaml` (reconciles from the on-prem git mirror; a deploy
  is a git push, never an internet pull).
- **Signed agent** — `agent-release/sign-release.sh` (reproducible cross-builds + SHA-256
  manifest + cosign signature) and `verify.sh` (fail-closed endpoint verification).
- **DECISIONS D-046** (NetworkPolicy air-gap primitive), **D-047** (Vault on-prem + ESO),
  **D-048** (signed agent supply chain).

## Verified (2026-06-02)
- `helm lint deploy/helm/vyrex` → **0 charts failed** (only the cosmetic "icon
  recommended" info).
- `helm template soc deploy/helm/vyrex` renders cleanly: 4 NetworkPolicies,
  ConfigMap + ServiceAccount, 3 Services, 4 Deployments, 4 CronJobs, Ingress — no errors.
- The other manifests (CNPG/OpenSearch/Vault/ESO/Keycloak/Velero/ArgoCD) are standard CRs
  for their operators; they apply on a cluster with those operators installed (per
  `deploy/README.md`).

## Honest scope notes
- No live K3s on this host (resources); validation is `helm lint`/`template` + manifest
  review. Standing the chart up on a real K3s (k3d/kind for CI) is the natural next step.
- Image references use `registry.soc.local/...` (the on-prem mirror) — repoint `global.imageRegistry`
  for a given site. Images must be loaded into that registry first (air-gap, no pulls).
- Operator/add-on **install** (CNPG, OpenSearch, Vault, ESO, Keycloak, Velero, ArgoCD) is
  documented, not automated here — at an air-gapped site these come from mirrored Helm
  charts, which is a site-provisioning concern outside this repo.

## Status
This completes the full build: **Phases 0–6**, the tool-integration **expansion A–H**
(including the AI Fusion Engine), the **Phase-G** presentation layer, and now **Phase 8**.
