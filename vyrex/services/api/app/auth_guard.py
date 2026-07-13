"""Authentication + RBAC enforcement — the gate the threat model (TB2) requires.

VYREX already has identities (local login in routers/auth.py, or oauth2-proxy/Keycloak
headers in K3s) but, until now, nothing *enforced* them: any caller could reach any
route. This middleware closes that gap.

Design goals:
  - **Fail safe, not surprising.** Off by default (`settings.auth_required` is False in
    dev) so the local demo is unchanged; ALWAYS on in production (soc_env=production).
  - **Two identity sources, one principal.** Accept either the oauth2-proxy headers
    (x-auth-request-user / -groups) used in K3s, or a local session bearer token
    (sessions table). Whichever is present wins.
  - **Least privilege by role.** viewer = read-only; analyst = read + write;
    admin = everything including response/defense and the AI-analyst trigger.
  - **Agent routes use the agent token,** not a human session (the endpoint agent
    posts command results over mTLS + bearer). They are gated separately.

The decision logic (`authorize`, path classifiers) is pure and unit-tested without a
DB; the middleware only adds principal resolution (header or session lookup).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi.responses import JSONResponse

from . import db
from .config import settings

log = logging.getLogger("api.authz")

WRITE_METHODS = {"POST", "PATCH", "PUT", "DELETE"}

# Always reachable without a principal: probes, service banner, metrics, the API docs,
# and the login/logout/me endpoints themselves (you must be able to log in).
PUBLIC_EXACT = {"/", "/health", "/health/ready", "/version", "/metrics",
                "/openapi.json", "/auth/login", "/auth/me", "/auth/logout"}
PUBLIC_PREFIXES = ("/docs", "/redoc")

# Endpoint-agent routes — authenticated by the shared agent token, not a human session.
AGENT_PREFIXES = ("/v1/",)

# Routes that require the admin role: active response (approve/reject/execute),
# autonomous defense, and triggering the AI analyst. Requesting a containment action
# (POST /incidents/{id}/actions) is analyst-level; approving it is admin.
ADMIN_PREFIXES = ("/actions", "/defense", "/agent/triage")


@dataclass
class Principal:
    user: str
    role: str          # admin | analyst | viewer
    source: str        # header | session


def role_from_groups(groups: str) -> str | None:
    """Map oauth2-proxy group membership to a role (most-privileged wins)."""
    g = (groups or "").lower()
    if "admin" in g:
        return "admin"
    if "analyst" in g:
        return "analyst"
    return "viewer" if g else None


def is_public(path: str) -> bool:
    return path in PUBLIC_EXACT or path.startswith(PUBLIC_PREFIXES)


def is_agent_path(path: str) -> bool:
    return path.startswith(AGENT_PREFIXES)


def requires_admin(path: str) -> bool:
    return path.startswith(ADMIN_PREFIXES)


def authorize(principal: Principal | None, method: str, path: str) -> tuple[bool, int, str]:
    """Pure authorization decision. Returns (allowed, http_status, reason).

    Assumes public and agent paths are handled by the caller (they never reach here)."""
    if principal is None:
        return False, 401, "authentication required"
    if requires_admin(path) and principal.role != "admin":
        return False, 403, "admin role required for response/defense actions"
    if method in WRITE_METHODS and principal.role not in ("admin", "analyst"):
        return False, 403, "viewer role is read-only"
    return True, 200, "ok"


def _bearer(request) -> str:
    return (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()


def _valid_agent_token(request) -> bool:
    token = settings.ingest_agent_token
    return bool(token) and _bearer(request) == token


async def resolve_principal(request) -> Principal | None:
    """Header identity (oauth2-proxy / Keycloak) first, then a local session token."""
    user = request.headers.get("x-auth-request-user") or request.headers.get("x-forwarded-user")
    role = role_from_groups(request.headers.get("x-auth-request-groups", ""))
    if user and role:
        return Principal(user=user, role=role, source="header")
    token = _bearer(request)
    if token:
        s = await db.fetch_one("SELECT username, role FROM sessions WHERE token=%(t)s", {"t": token})
        if s:
            return Principal(user=s["username"], role=s["role"], source="session")
    return None


def _deny(status: int, reason: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"detail": reason})


async def auth_guard_middleware(request, call_next):
    if not settings.auth_required:
        return await call_next(request)  # dev/demo: unchanged behaviour

    path = request.url.path
    if is_public(path):
        return await call_next(request)
    if is_agent_path(path):
        if _valid_agent_token(request):
            return await call_next(request)
        return _deny(401, "valid agent token required")

    principal = await resolve_principal(request)
    allowed, status, reason = authorize(principal, request.method, path)
    if not allowed:
        return _deny(status, reason)
    return await call_next(request)
