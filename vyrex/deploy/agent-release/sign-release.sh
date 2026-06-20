#!/usr/bin/env bash
# =====================================================================
# Build + SIGN the SOC Central endpoint agent for release (Phase 8).
#
# Endpoints run the agent in a hostile place, so a tampered or trojanized binary is a
# real threat. We (1) build reproducibly, (2) emit SHA-256 checksums, and (3) sign with
# cosign keyless-or-key. At a true air-gapped site the signing key lives in Vault's
# transit engine and never touches disk. Endpoints verify the signature before install
# (see verify.sh) — that's the tamper-detection gate.
#
# Usage: VERSION=1.0.0 bash deploy/agent-release/sign-release.sh
# =====================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="${VERSION:-0.0.0-dev}"
OUT="$ROOT/dist/agent/$VERSION"
COSIGN_KEY="${COSIGN_KEY:-vault://transit/soc-agent-signing}"  # or cosign.key

mkdir -p "$OUT"
echo "==> building agent $VERSION (static, reproducible) for linux/{amd64,arm64}, windows/amd64"
build() {  # $1=os $2=arch $3=ext
  docker run --rm -v "$ROOT/agent":/src -w /src \
    -e CGO_ENABLED=0 -e GOOS="$1" -e GOARCH="$2" \
    -e GOFLAGS="-trimpath" registry.soc.local/golang:1.23-alpine \
    go build -ldflags "-s -w -X main.version=$VERSION -buildid=" \
      -o "/src/soc-agent-$1-$2$3" .
  mv "$ROOT/agent/soc-agent-$1-$2$3" "$OUT/"
}
build linux amd64 ""
build linux arm64 ""
build windows amd64 ".exe"

echo "==> checksums"
( cd "$OUT" && sha256sum soc-agent-* > SHA256SUMS && cat SHA256SUMS )

echo "==> signing the checksum manifest with cosign ($COSIGN_KEY)"
# Signing the SHA256SUMS file covers every artifact with one signature.
if command -v cosign >/dev/null 2>&1; then
  cosign sign-blob --yes --key "$COSIGN_KEY" \
    --output-signature "$OUT/SHA256SUMS.sig" "$OUT/SHA256SUMS"
  echo "    -> $OUT/SHA256SUMS.sig"
else
  echo "    cosign not on PATH — run in the release container (registry.soc.local/cosign)." >&2
fi
echo "==> release staged at $OUT"
echo "    Ship $OUT/ to endpoints; they run verify.sh before installing."
