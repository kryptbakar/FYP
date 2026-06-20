#!/usr/bin/env bash
# Stand up a throwaway k3d (K3s-in-Docker) cluster and validate the Helm chart end to end.
# This is the "prove the manifests actually apply to a live cluster" gate that lint/template
# alone can't give. Runs locally and in CI (see .github/workflows/ci.yml :: k3s-smoke).
#
# Requires: docker, k3d, kubectl, helm.
set -euo pipefail

CLUSTER="${CLUSTER:-soc-smoke}"
NS="${NS:-vyrex}"
CHART="deploy/helm/vyrex"

cleanup() { k3d cluster delete "${CLUSTER}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> creating k3d cluster ${CLUSTER}"
k3d cluster create "${CLUSTER}" --agents 1 --wait --timeout 180s

echo "==> kube context"
kubectl cluster-info
kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f -

echo "==> helm lint"
helm lint "${CHART}"

echo "==> helm template (render sanity)"
helm template soc "${CHART}" -n "${NS}" >/tmp/soc-rendered.yaml
test -s /tmp/soc-rendered.yaml

echo "==> server-side dry-run apply against the live API server"
# Validates every manifest against the real cluster schema (CRDs for operators are
# skipped here; --include-crds + operator install is the full-site path in deploy/README).
helm install soc "${CHART}" -n "${NS}" \
  --set image.registry=ghcr.io/example \
  --dry-run=server >/dev/null

echo "==> NetworkPolicy + workload object counts"
helm template soc "${CHART}" -n "${NS}" | grep -cE '^kind: (Deployment|CronJob|NetworkPolicy|Ingress)' \
  | xargs -I{} echo "    rendered {} core workload/policy objects"

echo "PASS: chart lints, renders, and server-side dry-run applies to a live K3s cluster."
