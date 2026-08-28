#!/usr/bin/env python3
"""Fail if any compose service is missing from an air-gap sealing overlay.

Static check — parses the compose files, runs no containers, needs no Docker daemon —
so it can run in CI on every push.

Why this exists: on 2026-08-28 an audit found 21 of 35 services had no `socnet`
assignment, including the investigation orchestrator and `ollama`. The runtime check
(tools/airgap/verify-egress.sh) now catches that too, but only for services that happen to
be RUNNING when someone remembers to run it. This catches it at the moment the service is
added, which is the only time it is cheap to fix.

The failure mode being prevented is specific and quiet: adding a service to
docker-compose.yml and forgetting the one-line entry in the sealing overlay. Nothing warns
you. The stack keeps working. The air-gap claim just silently stops being true.

Usage:
    python tools/airgap/check-coverage.py          # from vyrex/
Exit codes: 0 = every service sealed or explicitly exempt, 1 = coverage gap.
"""
from __future__ import annotations

import pathlib
import re
import sys

# Each stack file and the overlay that is required to seal it.
PAIRS = [
    ("docker-compose.yml", "docker-compose.airgap.yml"),
    ("docker-compose.n8n.yml", "docker-compose.airgap.n8n.yml"),
    ("docker-compose.tools.yml", "docker-compose.airgap.tools.yml"),
]

# Services allowed to reach the internet, with the reason. Anything here is a deliberate,
# reviewable exception rather than an oversight - which is the whole point of naming them.
EXEMPT = {
    "feed-sync": "the single egress path: mirrors NVD/EPSS/KEV, dual-homed on purpose",
    "mirror-sync": "same job under a different entrypoint",
}

# Matches a service key at exactly two-space indent, whether the body is a nested block
# (`  api:`) or inline flow style (`  api: { networks: [socnet] }`). The overlays use the
# inline form throughout, so anchoring at end-of-line would silently match nothing there
# and report every service as unsealed.
SERVICE_RE = re.compile(r"^  ([a-zA-Z0-9][\w.-]*):(?:\s|$)")


def services_in(path: pathlib.Path) -> list[str]:
    """Top-level service names.

    Deliberately a line-based scan rather than a YAML parse: it keeps the check
    dependency-free (no PyYAML in CI) and the two-space-indent convention is uniform
    across these files. It stops at `volumes:`/`networks:` so their children are not
    mistaken for services.
    """
    names: list[str] = []
    in_services = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.match(r"^services:\s*$", line):
            in_services = True
            continue
        if re.match(r"^[a-zA-Z]", line):        # any other top-level key ends the block
            in_services = False
            continue
        if in_services:
            m = SERVICE_RE.match(line)
            if m:
                names.append(m.group(1))
    return names


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]   # vyrex/
    failures: list[str] = []
    checked = sealed = 0

    for stack_name, overlay_name in PAIRS:
        stack, overlay = root / stack_name, root / overlay_name
        if not stack.exists():
            print(f"  skip   {stack_name} (not present)")
            continue
        if not overlay.exists():
            failures.append(f"{stack_name}: sealing overlay {overlay_name} is missing "
                            f"entirely - every service in it is unsealed")
            continue

        defined = services_in(stack)
        covered = set(services_in(overlay))
        checked += len(defined)

        missing = [s for s in defined if s not in covered and s not in EXEMPT]
        if missing:
            failures.append(
                f"{stack_name}: {len(missing)} service(s) absent from {overlay_name}: "
                + ", ".join(sorted(missing))
            )
        sealed += len(defined) - len(missing)

        exempt_here = [s for s in defined if s in EXEMPT]
        print(f"  {stack_name:28s} {len(defined):2d} services, "
              f"{len(defined) - len(missing):2d} sealed"
              + (f", {len(exempt_here)} exempt" if exempt_here else ""))

    # A stale exemption is its own quiet failure: a service that no longer exists leaves a
    # permanent hole in the check for whoever reuses the name later.
    all_defined = {s for name, _ in PAIRS
                   if (root / name).exists()
                   for s in services_in(root / name)}
    for name in EXEMPT:
        if name not in all_defined:
            print(f"  note   exemption '{name}' matches no service (defined for a job "
                  f"invoked via `run`, or stale)")

    print()
    if failures:
        print("AIR-GAP COVERAGE GAP", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print("\nAdd the service to the overlay as `  <name>: { networks: [socnet] }`, or "
              "add it to EXEMPT here with a reason if it genuinely needs egress.",
              file=sys.stderr)
        return 1

    print(f"OK: {sealed}/{checked} services sealed, "
          f"{len(EXEMPT)} documented exemption(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
