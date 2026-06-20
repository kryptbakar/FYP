"""Access audit — records *who viewed or changed what*.

Distinct from the response-action hash-chain (which covers destructive actions): this is
the access log a regulated buyer asks for. To avoid flooding, only state-changing requests
(POST/PATCH/PUT/DELETE) and explicit identity checks (/whoami) are recorded. The DB write
runs in a worker thread so it never blocks the event loop, and failures are swallowed so the
audit can never take the API down.
"""
from __future__ import annotations

import asyncio
import logging

import psycopg

from .config import settings

log = logging.getLogger("api.access")

_AUDITED_METHODS = {"POST", "PATCH", "PUT", "DELETE"}


def _role(groups: str) -> str | None:
    if "admin" in groups:
        return "admin"
    if "analyst" in groups:
        return "analyst"
    return "viewer" if groups else None


def _write(actor, role, tenant, method, path, status) -> None:
    try:
        with psycopg.connect(settings.postgres_dsn, autocommit=True, connect_timeout=2) as conn:
            conn.execute(
                "INSERT INTO access_audit (actor, role, tenant, method, path, status) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (actor, role, tenant, method, path, status),
            )
    except Exception as e:  # never let auditing break a request
        log.debug("access audit skipped: %s", e)


async def access_audit_middleware(request, call_next):
    response = await call_next(request)
    path = request.url.path
    if request.method in _AUDITED_METHODS or path.endswith("/whoami"):
        groups = request.headers.get("x-auth-request-groups", "")
        actor = request.headers.get("x-auth-request-user") or request.headers.get("x-forwarded-user") or "anonymous"
        tenant = request.headers.get("x-tenant", "default")
        try:
            await asyncio.to_thread(_write, actor, _role(groups), tenant, request.method, path, response.status_code)
        except Exception as e:
            log.debug("access audit dispatch skipped: %s", e)
    return response
