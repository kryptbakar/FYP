#!/usr/bin/env bash
# =====================================================================
# VYREX offline installer bundle — BUILD side (run on a CONNECTED staging host).
#
# Productises the air-gap transfer (docs/PRODUCTION-DEPLOYMENT.md §3) into a single,
# checksummed directory you carry across the gap and hand to install.sh. Bundles:
#   - every service image (docker save)                → images.tar
#   - the feed/tool mirror volumes (NVD/EPSS/KEV etc.) → volumes/*.tar
#   - the Ollama model volume (the LLM weights)        → volumes/vyrex_ollamadata.tar.gz
#   - the compose files + Makefile + .env.example      → repo config to run it
#   - SHA256SUMS over all of the above                 → integrity, verified on install
#
# The n8n overlay is included deliberately: it carries n8n, mailpit AND ollama. Without
# it the bundle installs a SOC with no automation engine and no LLM, and the first
# `agent triage` on the far side would try to `ollama pull` across a gap that has no
# route — the model has to travel as a volume, it cannot be fetched on arrival.
#
# Usage (from repo root, on the staging host, after `make feeds-seed`/`mirror-sync`):
#   bash tools/airgap/bundle.sh [OUT_DIR]      # default OUT_DIR=dist/vyrex-bundle
#
# Then: tar czf vyrex-bundle.tgz -C dist vyrex-bundle  and carry it inside.
# =====================================================================
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."          # repo root = vyrex/
OUT="${1:-dist/vyrex-bundle}"
COMPOSE_FILES=(docker-compose.yml docker-compose.tools.yml docker-compose.n8n.yml docker-compose.airgap.yml)
# Mirror volumes created by feeds-seed + mirror-sync (names match the compose mounts),
# plus ollamadata — the pulled LLM weights, which cannot be re-fetched inside the gap.
VOLUMES=(vyrex_nuclei_templates vyrex_trivy_cache vyrex_sigma_rules vyrex_suricata_rules vyrex_ollamadata)

echo "==> preparing $OUT"
rm -rf "$OUT"; mkdir -p "$OUT/volumes"

echo "==> resolving image list from compose"
mapfile -t IMAGES < <(docker compose $(printf -- '-f %s ' "${COMPOSE_FILES[@]}") config --images 2>/dev/null | sort -u)
[ "${#IMAGES[@]}" -gt 0 ] || { echo "no images resolved — run 'make up' / build first" >&2; exit 1; }
printf '%s\n' "${IMAGES[@]}" > "$OUT/images.list"
echo "    ${#IMAGES[@]} images"

echo "==> saving images (this is the big one)…"
docker save "${IMAGES[@]}" -o "$OUT/images.tar"

echo "==> exporting mirror volumes"
for v in "${VOLUMES[@]}"; do
  if docker volume inspect "$v" >/dev/null 2>&1; then
    docker run --rm -v "$v":/v -v "$PWD/$OUT/volumes":/out alpine:3 \
      tar czf "/out/$v.tar.gz" -C /v . && echo "    $v"
  else
    echo "    (skip $v — not present; run feeds-seed / mirror-sync to include it)"
  fi
done

# The model weights are not optional. Skipping them here produces a bundle that looks
# fine and only fails on the far side of the gap, where it cannot be repaired — so fail
# on this side instead, where a pull is still possible.
if [ ! -f "$OUT/volumes/vyrex_ollamadata.tar.gz" ]; then
  echo "!! vyrex_ollamadata is missing — this bundle would ship WITHOUT the LLM." >&2
  echo "   Pull the model on this (connected) host first, then re-run:" >&2
  echo "     docker compose -f docker-compose.yml -f docker-compose.n8n.yml up -d ollama" >&2
  echo "     docker exec vyrex-ollama ollama pull \${OLLAMA_MODEL:-llama3.2:3b}" >&2
  exit 1
fi

echo "==> copying run config"
mkdir -p "$OUT/config"
cp "${COMPOSE_FILES[@]}" Makefile .env.example "$OUT/config/" 2>/dev/null || true
cp tools/airgap/install.sh "$OUT/install.sh"

echo "==> writing manifest + checksums"
{
  echo "VYREX offline bundle"
  echo "built_at=$(date -u +%FT%TZ)"
  echo "git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "images=${#IMAGES[@]}"
  # Record which LLM travelled with this bundle — the far side has no way to look it up.
  echo "ollama_model=${OLLAMA_MODEL:-llama3.2:3b}"
  echo "ollama_volume_bytes=$(stat -c %s "$OUT/volumes/vyrex_ollamadata.tar.gz" 2>/dev/null || echo 0)"
} > "$OUT/MANIFEST.txt"
( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )

echo "==> DONE. Bundle at: $OUT"
echo "    carry it inside, then run:  bash install.sh   (from the bundle dir)"
du -sh "$OUT" 2>/dev/null || true
