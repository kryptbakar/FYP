#!/usr/bin/env bash
# Rotate the API/ingest TLS cert from Vault PKI and roll the workloads.
#
# Closes the "TLS/PKI cert-rotation automation" gap: Vault's PKI engine issues a fresh
# short-lived cert, we project it into the in-cluster Secret, then trigger a rolling
# restart so pods pick it up with zero downtime. Designed to run as a CronJob
# (cert-rotation-cronjob.yaml) inside the cluster, or by hand for break-glass.
#
# Requires: vault CLI (authed via the Kubernetes auth method), kubectl.
set -euo pipefail

NAMESPACE="${NAMESPACE:-vyrex}"
PKI_ROLE="${PKI_ROLE:-soc-server}"
COMMON_NAME="${COMMON_NAME:-api.vyrex.svc}"
TTL="${TTL:-72h}"
SECRET_NAME="${SECRET_NAME:-soc-tls}"

echo "[rotate-certs] issuing cert for ${COMMON_NAME} (ttl=${TTL}) from pki/${PKI_ROLE}"
ISSUE_JSON="$(vault write -format=json "pki/issue/${PKI_ROLE}" \
  common_name="${COMMON_NAME}" ttl="${TTL}")"

CERT="$(echo "${ISSUE_JSON}" | jq -r '.data.certificate')"
KEY="$(echo "${ISSUE_JSON}"  | jq -r '.data.private_key')"
CA="$(echo "${ISSUE_JSON}"   | jq -r '.data.issuing_ca')"

echo "[rotate-certs] updating Secret ${SECRET_NAME} in ${NAMESPACE}"
kubectl create secret generic "${SECRET_NAME}" -n "${NAMESPACE}" \
  --from-literal=tls.crt="${CERT}${CA}" \
  --from-literal=tls.key="${KEY}" \
  --from-literal=ca.crt="${CA}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "[rotate-certs] rolling workloads to pick up the new cert"
kubectl rollout restart deployment/soc-api deployment/soc-ingest-edge -n "${NAMESPACE}"

echo "[rotate-certs] done."
