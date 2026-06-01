"""Liveness, readiness, and version endpoints.

- /health        liveness   — the process is up (no external deps touched).
- /health/ready  readiness  — can we reach Postgres, OpenSearch, and NATS?
- /version       build/version metadata.

Readiness deliberately probes each backing store so that during Phase 0 we can
*prove* the whole compose stack is wired together, not just that the API runs.
"""
from __future__ import annotations

import asyncio
import socket
import time

import httpx
import psycopg
from fastapi import APIRouter, Response, status

from ..config import settings

router = APIRouter(tags=["system"])

# Process start time, for a simple uptime readout.
_STARTED_AT = time.time()


@router.get("/health", summary="Liveness probe")
async def health() -> dict:
    """Liveness: the API process is running. Cheap and dependency-free."""
    return {"status": "ok", "uptime_seconds": round(time.time() - _STARTED_AT, 1)}


@router.get("/version", summary="Build / version metadata")
async def version() -> dict:
    return {
        "service": "soc-central-api",
        "version": settings.soc_version,
        "environment": settings.soc_env,
    }


async def _check_postgres() -> tuple[bool, str]:
    try:
        # psycopg connect is blocking; run it off the event loop.
        def _connect() -> None:
            with psycopg.connect(settings.postgres_dsn, connect_timeout=3) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    cur.fetchone()

        await asyncio.to_thread(_connect)
        return True, "reachable"
    except Exception as exc:  # noqa: BLE001 - report any failure as not-ready
        return False, str(exc).splitlines()[0] if str(exc) else "unreachable"


async def _check_opensearch() -> tuple[bool, str]:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(settings.opensearch_url, auth=None)
        # 200 (no security) or 401 (security on but reachable) both mean "up".
        if resp.status_code in (200, 401):
            return True, f"http {resp.status_code}"
        return False, f"http {resp.status_code}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc).splitlines()[0] if str(exc) else "unreachable"


async def _check_nats() -> tuple[bool, str]:
    try:
        def _connect() -> None:
            with socket.create_connection(
                (settings.nats_host, settings.nats_port), timeout=3
            ):
                pass

        await asyncio.to_thread(_connect)
        return True, "tcp open"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc).splitlines()[0] if str(exc) else "unreachable"


@router.get("/health/ready", summary="Readiness probe (checks backing stores)")
async def ready(response: Response) -> dict:
    pg, os_, nats = await asyncio.gather(
        _check_postgres(), _check_opensearch(), _check_nats()
    )
    checks = {
        "postgres": {"ok": pg[0], "detail": pg[1]},
        "opensearch": {"ok": os_[0], "detail": os_[1]},
        "nats": {"ok": nats[0], "detail": nats[1]},
    }
    all_ok = all(c["ok"] for c in checks.values())
    if not all_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if all_ok else "not_ready", "checks": checks}
