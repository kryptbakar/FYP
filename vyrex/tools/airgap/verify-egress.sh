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

# ---------------------------------------------------------------------
# Check 2: MEMBERSHIP. The probe above only proves socnet has no route. It says
# nothing about which services are actually ON socnet — so a service missing from
# docker-compose.airgap.yml keeps its default bridge, has full internet, and the
# probe still prints AIR-GAP ENFORCED.
#
# That was not hypothetical: until 2026-08-28 the investigation orchestrator, ollama,
# n8n, mailpit and the entire tool stack were absent from the overlay — 21 of 35
# services unsealed — and this script passed the whole time. A verification that
# cannot fail when the property is violated is not a verification.
#
# So: enumerate what is RUNNING and audit each container's actual attachments.
# ---------------------------------------------------------------------
PROJECT="${COMPOSE_PROJECT_NAME:-vyrex}"
# feed-sync is dual-homed by design (docker-compose.airgap.yml); mirror-sync is the
# same job under a different entrypoint. Everything else must be sealed.
ALLOWED_EGRESS_RE='^(feed-sync|mirror-sync)$'

echo
echo "  service membership audit (project: $PROJECT)"

mapfile -t CONTAINERS < <(docker ps \
  --filter "label=com.docker.compose.project=$PROJECT" \
  --format '{{.Label "com.docker.compose.service"}}\t{{.Names}}' | sort)

if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  echo "    WARN: no running containers for project '$PROJECT' — nothing to audit." >&2
  echo "    Set COMPOSE_PROJECT_NAME if your project is named differently." >&2
else
  # Cache each network's internal flag; a container is sealed only if EVERY network
  # it is attached to is internal:true.
  is_internal() {
    case "$(docker network inspect -f '{{.Internal}}' "$1" 2>/dev/null)" in
      true) return 0 ;; *) return 1 ;;
    esac
  }

  UNSEALED=0
  for row in "${CONTAINERS[@]}"; do
    svc="${row%%$'\t'*}"; name="${row##*$'\t'}"
    mapfile -t NETS < <(docker inspect -f \
      '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$name" 2>/dev/null)

    # No networks at all means network_mode: host — the host's routes, so not sealed.
    if [ "${#NETS[@]}" -eq 0 ] || [ -z "${NETS[0]:-}" ]; then
      echo "    LEAK  $svc — host networking (no container network)"; UNSEALED=$((UNSEALED+1)); continue
    fi

    open_nets=()
    for n in "${NETS[@]}"; do
      [ -n "$n" ] || continue
      is_internal "$n" || open_nets+=("$n")
    done

    if [ "${#open_nets[@]}" -eq 0 ]; then
      echo "    ok    $svc"
    elif printf '%s' "$svc" | grep -Eq "$ALLOWED_EGRESS_RE"; then
      echo "    ok    $svc — egress permitted by design (${open_nets[*]})"
    else
      echo "    LEAK  $svc — attached to egress-capable network(s): ${open_nets[*]}"
      UNSEALED=$((UNSEALED+1))
    fi
  done

  if [ "$UNSEALED" -eq 0 ]; then
    echo "  PASS: all ${#CONTAINERS[@]} running services are sealed."
  else
    echo "  FAIL: $UNSEALED of ${#CONTAINERS[@]} running services can reach off-host networks." >&2
    echo "        Add them to docker-compose.airgap.yml, or justify the exception." >&2
    RC=1
  fi
  # Only what is RUNNING can be audited. A stopped service is not proof of anything,
  # so say so rather than letting a partial stack read as a clean bill of health.
  echo "  NOTE: audited running containers only — services that are down were not checked."
fi

echo "== verdict: $([ $RC -eq 0 ] && echo AIR-GAP ENFORCED || echo LEAK DETECTED) =="
exit $RC
