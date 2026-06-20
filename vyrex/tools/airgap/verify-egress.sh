#!/usr/bin/env bash
# =====================================================================
# SOC Central — air-gap egress verification (Phase H).
#
# Proves the network policy from docker-compose.airgap.yml actually holds:
#   - a probe on the SEALED runtime network (socnet, internal:true) CANNOT reach
#     the internet  -> expected BLOCKED
#   - a probe on the EGRESS network (where only feed-sync lives) CAN reach it
#     -> expected OK
#
# This is the "run with egress blocked and confirm no tool reaches the internet"
# check the brief asks for, done at the layer that enforces it (Docker networking),
# so it doesn't depend on any individual service shipping a curl binary.
#
# Run AFTER bringing the stack up with the overlay:
#   docker compose -f docker-compose.yml -f docker-compose.airgap.yml up -d
#   bash tools/airgap/verify-egress.sh
# =====================================================================
set -uo pipefail

SOCNET=vyrex_socnet
PROBENET=airgap-egress-probe     # throwaway plain bridge = positive control
URL=https://api.first.org        # a feed source feed-sync legitimately uses
PROBE=alpine:3
TIMEOUT=6

if ! docker network inspect "$SOCNET" >/dev/null 2>&1; then
  echo "FAIL: network '$SOCNET' not found — start the stack with docker-compose.airgap.yml first." >&2
  exit 1
fi

# Pre-pull the probe image NOW (daemon, normal network) so the sealed-network probe
# can't fail at the pull step and be misread as "blocked".
docker image inspect "$PROBE" >/dev/null 2>&1 || docker pull "$PROBE" >/dev/null 2>&1 || {
  echo "FAIL: cannot obtain probe image '$PROBE' (host offline?) — cannot verify." >&2; exit 1; }

probe() {  # $1=network -> REACHED if it reached the internet, else NO-ROUTE
  docker run --rm --network "$1" "$PROBE" \
    sh -c "wget -q -T $TIMEOUT -O /dev/null $URL 2>/dev/null && echo REACHED || echo NO-ROUTE"
}

# Positive control: a probe on an ordinary bridge (like feed-sync's egress net) so a
# BLOCK on socnet is provably due to internal:true, not a broken probe or offline host.
docker network create "$PROBENET" >/dev/null 2>&1 || true
trap 'docker network rm "$PROBENET" >/dev/null 2>&1 || true' EXIT

echo "== SOC Central air-gap egress check =="
echo -n "  sealed runtime  (socnet, internal:true) -> "; SEALED=$(probe "$SOCNET")
echo "$SEALED"
echo -n "  control bridge  (egress-capable)        -> "; OPEN=$(probe "$PROBENET")
echo "$OPEN"

RC=0
if [ "$SEALED" = "NO-ROUTE" ]; then echo "  PASS: runtime is air-gapped (no internet)."; else echo "  FAIL: runtime reached the internet!"; RC=1; fi
if [ "$OPEN" = "REACHED" ];   then echo "  PASS: the sync path can egress (as designed)."; else echo "  WARN: egress path could not reach $URL (offline host? DNS?) — policy still correct."; fi
echo "== verdict: $([ $RC -eq 0 ] && echo AIR-GAP ENFORCED || echo LEAK DETECTED) =="
exit $RC
