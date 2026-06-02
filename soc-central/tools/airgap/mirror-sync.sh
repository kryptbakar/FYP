#!/usr/bin/env bash
# =====================================================================
# SOC Central — tool mirror-sync (Phase H). The sibling internet-facing job.
#
# feed-sync mirrors NVD/EPSS/KEV into Postgres. This mirrors the *tool* feeds that
# Nuclei/Trivy/Sigma/Suricata would otherwise fetch live, into named Docker volumes
# the tools mount read-only at runtime. After this runs, every scanner/sensor reads
# its rules/DB from the mirror and can run with updates disabled — see docs/AIRGAP.md.
#
# Each download uses the TOOL'S OWN offline-prepare mechanism (no bespoke parsing):
#   nuclei  -update-templates           -> nuclei_templates volume
#   trivy   image --download-db-only    -> trivy_cache volume
#   git     clone SigmaHQ/sigma         -> sigma_rules volume
#   curl    ET Open emerging.rules.tar  -> suricata_rules volume
#
# Modes:
#   (default)  ONLINE — pull fresh from upstream (run from a connected staging host)
#   --seed     OFFLINE — lay down a minimal deterministic mirror from bundled fixtures
#              so the offline runtime path works on a host with no/poor connectivity.
#
# Usage:  bash tools/airgap/mirror-sync.sh [--seed] [nuclei|trivy|sigma|suricata ...]
# =====================================================================
set -euo pipefail

# Resolve the repo root from the script's own location so seed-copy sources work
# regardless of the caller's working directory.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

SEED=0
TARGETS=()
for a in "$@"; do
  case "$a" in
    --seed) SEED=1 ;;
    nuclei|trivy|sigma|suricata) TARGETS+=("$a") ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done
[ ${#TARGETS[@]} -eq 0 ] && TARGETS=(nuclei trivy sigma suricata)

# Volume names match the docker-compose.tools.yml mounts.
V_NUCLEI=soc-central_nuclei_templates
V_TRIVY=soc-central_trivy_cache
V_SIGMA=soc-central_sigma_rules
V_SURICATA=soc-central_suricata_rules
NET=soc-central_egress     # the dual-homed egress network from the airgap overlay

# Online downloads run on the egress network; seed (offline) needs no network at all.
run_egress() {
  if [ "$SEED" = 1 ]; then docker run --rm "$@"; else docker run --rm --network "$NET" "$@"; fi
}

mk() { docker volume create "$1" >/dev/null; }

mirror_nuclei() {
  mk "$V_NUCLEI"
  if [ "$SEED" = 1 ]; then
    echo "[seed] nuclei: writing a minimal local template tree"
    run_egress -v "$V_NUCLEI":/t alpine:3 sh -c \
      'mkdir -p /t/http/misconfiguration && printf "id: local-seed-tls\ninfo:\n  name: seed template (offline mirror marker)\n  severity: info\n" > /t/http/misconfiguration/local-seed-tls.yaml'
  else
    echo "[online] nuclei: updating templates into the mirror"
    run_egress -v "$V_NUCLEI":/root/nuclei-templates projectdiscovery/nuclei:latest \
      -update-templates -update-template-dir /root/nuclei-templates
  fi
}

mirror_trivy() {
  mk "$V_TRIVY"
  if [ "$SEED" = 1 ]; then
    echo "[seed] trivy: marking cache dir (real DB ships via sneakernet — see AIRGAP.md)"
    run_egress -v "$V_TRIVY":/c alpine:3 sh -c 'mkdir -p /c/db && date -u +%FT%TZ > /c/db/.mirrored-at'
  else
    echo "[online] trivy: downloading the vuln DB into the cache"
    run_egress -v "$V_TRIVY":/root/.cache/trivy aquasec/trivy:0.58.0 \
      image --download-db-only --cache-dir /root/.cache/trivy
  fi
}

# Copy a host dir into a named volume WITHOUT a host bind-mount (which is fragile on
# Docker Desktop/Windows): tar the files on the host and pipe them into the container.
seed_copy() {  # $1=host src dir  $2=volume  $3=dest path in volume
  tar -C "$1" -cf - . | docker run --rm -i -v "$2":/dst alpine:3 \
    sh -c "mkdir -p /dst$3 && tar -C /dst$3 -xf - && ls -R /dst$3 | head -20"
}

mirror_sigma() {
  mk "$V_SIGMA"
  if [ "$SEED" = 1 ]; then
    echo "[seed] sigma: copying the repo's mirrored rules into the volume"
    seed_copy "$ROOT/services/intel-enricher/rules" "$V_SIGMA" "/sigma"
  else
    echo "[online] sigma: cloning SigmaHQ/sigma into the mirror"
    run_egress -v "$V_SIGMA":/s alpine/git:latest \
      clone --depth 1 https://github.com/SigmaHQ/sigma.git /s/sigma
  fi
}

mirror_suricata() {
  mk "$V_SURICATA"
  if [ "$SEED" = 1 ]; then
    echo "[seed] suricata: copying the repo's local rules into the volume"
    seed_copy "$ROOT/tools/suricata/rules" "$V_SURICATA" ""
  else
    echo "[online] suricata: fetching ET Open ruleset into the mirror"
    run_egress -v "$V_SURICATA":/r curlimages/curl:latest \
      -fsSL -o /r/emerging.rules.tar.gz https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz
  fi
}

echo "mirror-sync: mode=$([ "$SEED" = 1 ] && echo seed || echo online) targets=${TARGETS[*]}"
for t in "${TARGETS[@]}"; do "mirror_$t"; done
echo "mirror-sync: done. Tools now read rules/DB from the local volumes (updates disabled)."
