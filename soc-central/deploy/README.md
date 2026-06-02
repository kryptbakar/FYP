# deploy/ — air-gapped K3s deployment (Phase 8)

**Built in:** Phase 8 (Hardening + K3s). Production deployment of SOC Central onto an
**air-gapped, on-prem K3s** cluster — HA data plane, GitOps, Vault secrets, OIDC/RBAC,
backup/DR, a NetworkPolicy-enforced air gap, and a signed agent supply chain.

> Like the heavy OSS tools in the earlier phases, a real K3s cluster isn't stood up on
> the dev host. These are **production-grade, lint-clean manifests** (the Helm chart
> passes `helm lint` and renders) plus the operator CRs and platform configs; the live
> path is documented here.

## Layout
```
deploy/
  helm/soc-central/      Helm chart for the PRODUCT workloads + security primitives
    templates/           api · console · workers · ingest-edge · cronjobs · networkpolicy · ingress
  databases/             HA data plane: CloudNativePG Cluster, OpenSearchCluster, NATS notes
  vault/                 Vault (Raft HA, manual unseal) + External Secrets wiring
  identity/              Keycloak realm (OIDC/SSO + RBAC roles) + oauth2-proxy
  backup/                Velero BackupStorageLocation + schedules (MinIO, on-prem)
  argocd/                ArgoCD Application (GitOps from the on-prem git mirror)
  agent-release/         sign-release.sh + verify.sh (signed binaries, tamper detection)
```

## Order of operations (air-gapped site)
1. **Load images** into the on-prem registry (`registry.soc.local`) and `ctr images import`
   on each node — nothing pulls from the internet.
2. **Operators** (from mirrored Helm charts): CloudNativePG, OpenSearch operator, Vault,
   External Secrets, Keycloak, Velero, ArgoCD.
3. **Secrets**: unseal Vault, enable `kv-v2` + `pki` + `transit`, populate `soc/*` paths,
   then apply `vault/external-secrets.yaml` (projects them into k8s Secrets).
4. **Data plane**: `kubectl apply -f databases/` (CloudNativePG + OpenSearch + NATS).
5. **Identity**: import `identity/realm-soc-central.json`, apply `identity/oauth2-proxy.yaml`.
6. **App**: `helm install soc deploy/helm/soc-central -n soc-central` (or hand it to ArgoCD
   via `argocd/application.yaml` — the GitOps path).
7. **Backup/DR**: `kubectl apply -f backup/`.

## How each Phase-8 requirement is met
| Requirement | Where |
|-------------|-------|
| Helm charts | `helm/soc-central/` (lint-clean; renders 4 Deployments, 4 CronJobs, 4 NetworkPolicies, Ingress, …) |
| HA: CloudNativePG | `databases/postgres-cnpg.yaml` — 3 instances + PITR to MinIO |
| HA: OpenSearch operator | `databases/opensearch-cluster.yaml` — 3-node cluster, TLS |
| Velero backup/DR | `backup/velero-schedule.yaml` — daily + weekly to on-prem MinIO |
| Air-gapped update channel | `feed-sync` CronJob (the only egress-allowed workload) + the egress NetworkPolicy |
| Vault-backed secrets | `vault/` — Raft HA, manual unseal, PKI + transit; secrets list from `docs/AIRGAP.md §5` |
| Signed agent + tamper detection | `agent-release/sign-release.sh` + `verify.sh` (cosign + SHA-256, fail-closed) |
| ArgoCD GitOps | `argocd/application.yaml` — reconciles from the on-prem git mirror |
| **NetworkPolicy air gap** (D-042) | `helm/.../networkpolicy.yaml` — egress-DENY + DNS/in-cluster allow + feed-sync-only egress + ingress-allow |
| **OIDC/SSO + RBAC** (deferred from G) | `identity/` — Keycloak realm (soc-admin/analyst/viewer) + oauth2-proxy forward-auth |

## Verify the chart locally (no cluster needed)
```bash
docker run --rm -v "$PWD/deploy/helm:/charts" alpine/helm:3.16.3 lint /charts/soc-central
docker run --rm -v "$PWD/deploy/helm:/charts" alpine/helm:3.16.3 template soc /charts/soc-central
```
