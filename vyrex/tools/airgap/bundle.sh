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
# DISK REQUIREMENT — read before running, it is larger than it looks.
# Budget roughly TWICE the payload in free space, not once. `docker save` and the volume
# tar containers write through Docker's own data disk, so on any host where that disk
# shares a volume with OUT_DIR you pay for the archive AND for the VHDX growing beneath
# it. Measured 2026-08-29: a 16-image + 6 GB-model bundle consumed ~5.7 GB of archive and
# grew the VHDX by 6.2 GB (56.2 -> 62.4 GB), exhausting a 16.6 GB volume and taking the
# Docker daemon down with it. Build on a host with headroom, or point OUT_DIR at a
# different physical volume from Docker's data.
#
# Usage (from repo root, on the staging host, after `make feeds-seed`/`mirror-sync`):
#   bash tools/airgap/bundle.sh [OUT_DIR]      # default OUT_DIR=dist/vyrex-bundle
#   PROFILES="feeds ml agentic" bash tools/airgap/bundle.sh   # core-only bundle
#
# Then: tar czf vyrex-bundle.tgz -C dist vyrex-bundle  and carry it inside.
# =====================================================================
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."          # repo root = vyrex/
OUT="${1:-dist/vyrex-bundle}"
COMPOSE_FILES=(docker-compose.yml docker-compose.tools.yml docker-compose.n8n.yml docker-compose.airgap.yml)
# EVERY profile, because `docker compose config --images` silently omits services whose
# profile is not active — it does not warn, it just returns a shorter list. Without these
# the bundle resolved 13 core images and left out the investigation orchestrator, the ML
# risk engine, feed-sync, intel-enricher and every sensor/scanner: an "offline installer"
# that installs a SOC with no scoring and no agent. Adding a profile to a compose file
# means adding it here too.
# Overridable, because "everything" is not the only valid deployment. A site running the
# core SOC without the heavy intel stack should not be forced to build MISP and OpenCTI
# images just to produce a bundle — and on a constrained staging host, being unable to
# bundle at all is worse than bundling a smaller, honestly-described stack.
#   PROFILES="feeds ml agentic" bash tools/airgap/bundle.sh
# The profiles that are IN the bundle are recorded in MANIFEST.txt, so the far side can
# see what it did and did not receive rather than discovering it by absence.
read -r -a PROFILES <<< "${PROFILES:-tools sensors scanners hostmon runtime intel agent feeds ml agentic}"
# Mirror volumes created by feeds-seed + mirror-sync (names match the compose mounts),
# plus ollamadata — the pulled LLM weights, which cannot be re-fetched inside the gap.
VOLUMES=(vyrex_nuclei_templates vyrex_trivy_cache vyrex_sigma_rules vyrex_suricata_rules vyrex_ollamadata)
# Images the bundle is worthless without. Substring-matched against the resolved list, so
# a renamed service or a dropped profile fails the build here rather than across the gap.
REQUIRED_IMAGES=(investigation-orchestrator risk-engine api console workers)

echo "==> preparing $OUT"
rm -rf "$OUT"; mkdir -p "$OUT/volumes"

echo "==> resolving image list from compose (all profiles)"
mapfile -t IMAGES < <(docker compose \
  $(printf -- '-f %s ' "${COMPOSE_FILES[@]}") \
  $(printf -- '--profile %s ' "${PROFILES[@]}") \
  config --images 2>/dev/null | sort -u)
[ "${#IMAGES[@]}" -gt 0 ] || { echo "no images resolved — run 'make up' / build first" >&2; exit 1; }
printf '%s\n' "${IMAGES[@]}" > "$OUT/images.list"
echo "    ${#IMAGES[@]} images"

# Same discipline as the ollamadata check below: a bundle missing a core service looks
# fine until it is unpacked somewhere with no route to a registry, so fail while a
# `docker compose build` can still repair it.
missing=()
for want in "${REQUIRED_IMAGES[@]}"; do
  printf '%s\n' "${IMAGES[@]}" | grep -q -- "$want" || missing+=("$want")
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "!! these core images did not resolve: ${missing[*]}" >&2
  echo "   A profile is probably missing from PROFILES, or a service was renamed." >&2
  exit 1
fi

# docker save fails with a bare "reference does not exist" that does not say which image,
# and after a profile change the answer is nearly always "it was never built".
notbuilt=()
for img in "${IMAGES[@]}"; do
  docker image inspect "$img" >/dev/null 2>&1 || notbuilt+=("$img")
done
if [ "${#notbuilt[@]}" -gt 0 ]; then
  echo "!! not present locally, so they cannot be saved:" >&2
  printf '     %s\n' "${notbuilt[@]}" >&2
  echo "   Build/pull them first, e.g.:" >&2
  echo "     docker compose $(printf -- '-f %s ' "${COMPOSE_FILES[@]}")$(printf -- '--profile %s ' "${PROFILES[@]}")build" >&2
  exit 1
fi

echo "==> saving images (this is the big one)…"
# Compressed, because this archive is physically carried across the gap and `docker save`
# writes layer tarballs raw — 34 images measured at 9.1 GB uncompressed. `gzip -1` is
# deliberate: the marginal ratio from higher levels is small on already-compressed layers
# while the time cost is not, and a bundle nobody is willing to wait for gets skipped.
# `set -euo pipefail` (line 23) makes a docker-save failure fail the pipeline rather than
# leaving a truncated archive that only breaks on the far side.
docker save "${IMAGES[@]}" | gzip -1 > "$OUT/images.tar.gz"

echo "==> exporting mirror volumes"
for v in "${VOLUMES[@]}"; do
  if docker volume inspect "$v" >/dev/null 2>&1; then
    # tar over STDOUT rather than a host bind-mount for the output directory.
    # Bind-mounting `$PWD/$OUT/volumes` works on Linux and fails on Docker Desktop for
    # Windows: Git Bash rewrites the POSIX path on its way to docker.exe, and the mount
    # silently lands somewhere else — observed writing to
    # `G:/Final Year Project/tools/PortableGit/out/`, so every volume tar failed with
    # "can't open". Worse, it failed QUIETLY enough that the run continued to the
    # ollamadata check and reported a missing model, which is a true statement about a
    # completely wrong cause. tools/airgap/mirror-sync.sh already avoids this the same
    # way; this is the same quirk, so it gets the same fix.
    # The container path lives INSIDE the `sh -c` string on purpose. Git Bash rewrites
    # any absolute path passed as a standalone argv element on its way to docker.exe:
    # `-C /v` arrived as `V:/` (single letters become drive specs) and `-C /vol` arrived
    # as `G:/…/PortableGit/vol` (the MSYS root gets prepended). Quoted inside sh -c the
    # path is just string data and reaches the container intact — which is portable,
    # unlike an MSYS_NO_PATHCONV escape that would only help on Windows.
    if docker run --rm -v "$v":/vol alpine:3 \
         sh -c 'cd /vol && tar czf - .' > "$OUT/volumes/$v.tar.gz"; then
      echo "    $v ($(du -h "$OUT/volumes/$v.tar.gz" | cut -f1))"
    else
      rm -f "$OUT/volumes/$v.tar.gz"   # never leave a truncated archive behind
      echo "!! failed to export volume $v" >&2
      exit 1
    fi
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

echo "==> capturing model provenance"
# The weights cross the gap as an opaque tarball. Without this, the far side can verify
# the ARCHIVE (SHA256SUMS) but knows nothing about the MODEL inside it — not which build,
# not what quantisation, not under what licence it may be run. For a security product the
# answer to "which exact weights produced this verdict?" has to survive the sneakernet.
MODEL="${OLLAMA_MODEL:-llama3.2:3b}"
if docker ps --format '{{.Names}}' | grep -qx 'vyrex-ollama'; then
  {
    echo "model=$MODEL"
    # `ollama list` prints the content digest; it is the only stable identity for the
    # weights, since the tag can be re-pointed upstream at any time.
    echo "digest=$(docker exec vyrex-ollama ollama list 2>/dev/null \
                   | awk -v m="$MODEL" '$1==m {print $2; exit}')"
    docker exec vyrex-ollama ollama show "$MODEL" 2>/dev/null \
      | sed -n 's/^ *\(architecture\|parameters\|quantization\|context length\) */\1=/p' \
      | tr -s ' '
  } > "$OUT/MODEL-MANIFEST.txt"
  # Licence text travels with the weights. Llama 3.2 and Qwen ship community licences with
  # attribution and use conditions; shipping the model without them is a compliance gap,
  # and on the far side there is no internet to go and look them up.
  docker exec vyrex-ollama ollama show "$MODEL" --license > "$OUT/MODEL-LICENSE.txt" 2>/dev/null || true
  [ -s "$OUT/MODEL-LICENSE.txt" ] || echo "(no licence text reported by ollama for $MODEL)" > "$OUT/MODEL-LICENSE.txt"
  echo "    $(sed -n 's/^digest=//p' "$OUT/MODEL-MANIFEST.txt") $MODEL"
else
  echo "!! vyrex-ollama is not running, so the model digest and licence cannot be" >&2
  echo "   captured. The bundle would ship weights with no provenance." >&2
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
  echo "ollama_model=$MODEL"
  echo "ollama_digest=$(sed -n 's/^digest=//p' "$OUT/MODEL-MANIFEST.txt")"
  # Which profiles this bundle actually contains. Without it the far side cannot tell a
  # deliberate core-only bundle from one that silently lost half its services.
  echo "profiles=${PROFILES[*]}"
  echo "ollama_volume_bytes=$(stat -c %s "$OUT/volumes/vyrex_ollamadata.tar.gz" 2>/dev/null || echo 0)"
  echo "ollama_volume_sha256=$(sha256sum "$OUT/volumes/vyrex_ollamadata.tar.gz" | cut -d' ' -f1)"
} > "$OUT/MANIFEST.txt"
( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )

echo "==> DONE. Bundle at: $OUT"
echo "    carry it inside, then run:  bash install.sh   (from the bundle dir)"
du -sh "$OUT" 2>/dev/null || true
