"""Current-user identity, surfaced from the oauth2-proxy / Keycloak forward-auth.

In the production topology (Phase 8) oauth2-proxy authenticates every request and injects
the user and their realm roles as X-Auth-Request-* headers. This endpoint reflects them so
the console can show *who is signed in and with what role* — i.e. make SSO/RBAC visible in
the product, not just in the K3s manifests. With no proxy in front (dev/demo) it returns an
unauthenticated marker and the console shows a demo identity.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Header, Query

from .. import db

router = APIRouter(tags=["identity"])


@router.get("/whoami", summary="Current authenticated user & roles (from SSO forward-auth)")
async def whoami(
    x_auth_request_user: Annotated[str | None, Header()] = None,
    x_auth_request_email: Annotated[str | None, Header()] = None,
    x_auth_request_groups: Annotated[str | None, Header()] = None,
    x_forwarded_user: Annotated[str | None, Header()] = None,
) -> dict:
    user = x_auth_request_user or x_forwarded_user
    groups = [g.strip() for g in (x_auth_request_groups or "").split(",") if g.strip()]
    # Map Keycloak realm roles to a single primary role for the UI.
    role = "viewer"
    if any("admin" in g for g in groups):
        role = "admin"
    elif any("analyst" in g for g in groups):
        role = "analyst"
    return {
        "authenticated": bool(user),
        "user": user,
        "email": x_auth_request_email,
        "roles": groups,
        "role": role if user else None,
        "sso": "keycloak / oauth2-proxy" if user else "none (forward-auth not in front of API)",
    }


@router.get("/tenants", summary="List organizations (multi-tenancy foundation)")
async def tenants() -> list[dict]:
    rows = await db.fetch("SELECT id, name, created_at FROM tenants ORDER BY created_at")
    return rows or [{"id": "default", "name": "Default organization"}]


@router.get("/access/audit", summary="Access audit log — who viewed/changed what")
async def access_audit_log(limit: Annotated[int, Query(ge=1, le=200)] = 50) -> list[dict]:
    return await db.fetch(
        "SELECT seq, actor, role, tenant, method, path, status, created_at "
        "FROM access_audit ORDER BY seq DESC LIMIT %(l)s",
        {"l": limit},
    )
