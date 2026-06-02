#!/usr/bin/env bash
# =====================================================================
# Endpoint-side verification gate (Phase 8). Run BEFORE installing the agent.
# Fails closed: no valid signature + matching checksum => no install. This is the
# tamper-detection control for the agent supply chain.
#
# Usage: COSIGN_PUB=/etc/soc/agent-signing.pub bash verify.sh <release-dir> <binary>
# =====================================================================
set -euo pipefail
DIR="${1:?release dir}"; BIN="${2:?binary name}"
PUB="${COSIGN_PUB:-/etc/soc/agent-signing.pub}"

echo "==> verifying signature on the checksum manifest"
cosign verify-blob --key "$PUB" --signature "$DIR/SHA256SUMS.sig" "$DIR/SHA256SUMS" \
  || { echo "FAIL: signature INVALID — manifest is not from SOC Central. Aborting." >&2; exit 1; }

echo "==> verifying $BIN checksum against the signed manifest"
( cd "$DIR" && grep " $BIN\$" SHA256SUMS | sha256sum -c - ) \
  || { echo "FAIL: checksum mismatch — $BIN was modified. Aborting." >&2; exit 1; }

echo "PASS: $BIN is authentic and untampered — safe to install."
