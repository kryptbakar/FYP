#!/usr/bin/env bash
# =====================================================================
# VYREX offline installer bundle — BUILD side (run on a CONNECTED staging host).
#
# Productises the air-gap transfer (docs/PRODUCTION-DEPLOYMENT.md §3) into a single,
# checksummed directory you carry across the gap and hand to install.sh. Bundles:
#   - every service image (docker save)                → images.tar
#   - the feed/tool mirror volumes (NVD/EPSS/KEV etc.) → volumes/*.tar
#   - the compose files + Makefile + .env.example      → repo config to run it
#   - SHA256SUMS over all of the above                 → integrity, verified on install
#
# Usage (from repo root, on the staging host, after `make feeds-seed`/`mirror-sync`):
#   bash tools/airgap/bundle.sh [OUT_DIR]      # default OUT_DIR=dist/vyrex-bundle
#
# Then: tar czf vyrex-bundle.tgz -C dist vyrex-bundle  and carry it inside.
# =====================================================================
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."          # repo root = vyrex/
OUT="${1:-dist/vyrex-bundle}"
COMPOSE_FILES=(docker-compose.yml docker-compose.tools.yml docker-compose.airgap.yml)
# Mirror volumes created by feeds-seed + mirror-sync (names match the compose mounts).
VOLUMES=(vyrex_nuclei_templates vyrex_trivy_cache vyrex_sigma_rules vyrex_suricata_rules)

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
} > "$OUT/MANIFEST.txt"
( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )

echo "==> DONE. Bundle at: $OUT"
echo "    carry it inside, then run:  bash install.sh   (from the bundle dir)"
du -sh "$OUT" 2>/dev/null || true
