#!/usr/bin/env bash
# =====================================================================
# VYREX offline installer — INSTALL side (run INSIDE the air-gapped site).
#
# Consumes a bundle produced by bundle.sh. Verifies integrity, loads images, restores
# the feed/tool mirror volumes, and brings the core stack up — with NO internet access.
#
# Usage (from the unpacked bundle directory):
#   bash install.sh [TARGET_DIR]     # default TARGET_DIR=./vyrex-run
#
# Fails closed on any checksum mismatch — a tampered bundle is never installed.
# =====================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-./vyrex-run}"
cd "$HERE"

echo "==> 1. verify bundle integrity (SHA256SUMS)"
[ -f SHA256SUMS ] || { echo "SHA256SUMS missing — refusing to install" >&2; exit 1; }
if ! sha256sum -c SHA256SUMS --quiet; then
  echo "INTEGRITY CHECK FAILED — bundle is corrupt or tampered. Aborting." >&2
  exit 1
fi
echo "    integrity OK"
[ -f MANIFEST.txt ] && cat MANIFEST.txt

echo "==> 2. load images (offline)"
docker load -i images.tar

echo "==> 3. restore mirror volumes"
if [ -d volumes ]; then
  for f in volumes/*.tar.gz; do
    [ -e "$f" ] || continue
    v="$(basename "$f" .tar.gz)"
    docker volume create "$v" >/dev/null
    docker run --rm -v "$v":/v -v "$PWD/volumes":/in alpine:3 \
      sh -c "cd /v && tar xzf /in/$(basename "$f")" && echo "    restored $v"
  done
fi

echo "==> 4. stage run config"
mkdir -p "$TARGET"
cp -r config/* "$TARGET"/ 2>/dev/null || true
cd "$TARGET"
[ -f .env ] || { cp .env.example .env; echo "    created .env from example — EDIT SECRETS before production"; }

echo "==> 5. bring up the core stack + automation/LLM overlay (no internet needed)"
# The n8n overlay carries n8n, mailpit and ollama. Restoring vyrex_ollamadata in step 3
# is only half the job — without this overlay the weights sit in a volume nothing mounts.
COMPOSE_ARGS=(-f docker-compose.yml)
[ -f docker-compose.n8n.yml ] && COMPOSE_ARGS+=(-f docker-compose.n8n.yml)
docker compose "${COMPOSE_ARGS[@]}" up -d

echo "==> 6. wait for readiness"
API="http://localhost:${API_PORT:-8000}"
for _ in $(seq 1 60); do
  curl -fsS "$API/health/ready" >/dev/null 2>&1 && break || sleep 3
done
curl -fsS "$API/health/ready" && echo || { echo "readiness not reached — check 'docker compose logs'"; exit 1; }

echo "==> 7. verify the LLM arrived with the bundle (a pull here would have no route)"
if docker ps --format '{{.Names}}' | grep -qx 'vyrex-ollama'; then
  WANT="$(sed -n 's/^ollama_model=//p' "$HERE/MANIFEST.txt" 2>/dev/null || true)"
  WANT="${WANT:-llama3.2:3b}"
  if docker exec vyrex-ollama ollama list 2>/dev/null | grep -q "${WANT%%:*}"; then
    echo "    LLM present offline: $WANT"
  else
    echo "    WARNING: '$WANT' is not in the local Ollama store. The AI analyst will fail," >&2
    echo "    and it CANNOT be fetched from inside the gap. Re-bundle with the model volume." >&2
  fi
else
  echo "    (ollama not running — AI analyst unavailable in this install)"
fi

echo "==> DONE. VYREX is up. Load the offline feed mirror if not already: make feeds-seed"
echo "    Console: http://localhost:${CONSOLE_PORT:-3001}   API docs: $API/docs"
echo "    REMINDER: set SOC_ENV=production (or API_AUTH_REQUIRED=true) + strong secrets before go-live."
