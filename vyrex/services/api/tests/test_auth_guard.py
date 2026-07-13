"""Tests for the auth-guard decision logic (THREAT-MODEL TB2 enforcement).

The pure functions — path classification and the RBAC decision — are tested without
a DB or a running app, so they run in CI on every push.
"""
from app.auth_guard import (
    Principal,
    authorize,
    is_agent_path,
    is_public,
    requires_admin,
    role_from_groups,
)
from app.config import Settings

ADMIN = Principal("root", "admin", "session")
ANALYST = Principal("ana", "analyst", "session")
VIEWER = Principal("vue", "viewer", "header")


# ---------------------------------------------------------------- path classifiers

def test_public_paths():
    for p in ("/", "/health", "/health/ready", "/version", "/metrics",
              "/openapi.json", "/docs", "/docs/oauth2-redirect", "/auth/login"):
        assert is_public(p), p
    assert not is_public("/findings")
    assert not is_public("/defense/policy")


def test_agent_paths():
    assert is_agent_path("/v1/commands/42/result")
    assert not is_agent_path("/findings")


def test_admin_paths():
    for p in ("/actions/7/approve", "/defense/policy", "/defense/heal", "/agent/triage"):
        assert requires_admin(p), p
    assert not requires_admin("/findings")
    assert not requires_admin("/incidents/1/actions")  # requesting is analyst-level


def test_role_from_groups():
    assert role_from_groups("vyrex-admin") == "admin"
    assert role_from_groups("soc analyst team") == "analyst"
    assert role_from_groups("readers") == "viewer"
    assert role_from_groups("") is None
    assert role_from_groups("ADMIN") == "admin"  # case-insensitive


# ---------------------------------------------------------------- authorize()

def test_unauthenticated_is_401():
    allowed, status, _ = authorize(None, "GET", "/findings")
    assert not allowed and status == 401


def test_viewer_can_read_not_write():
    assert authorize(VIEWER, "GET", "/findings")[0]
    allowed, status, _ = authorize(VIEWER, "POST", "/incidents/1/actions")
    assert not allowed and status == 403


def test_analyst_can_write_but_not_admin_routes():
    assert authorize(ANALYST, "POST", "/incidents/1/actions")[0]
    allowed, status, _ = authorize(ANALYST, "POST", "/actions/9/approve")
    assert not allowed and status == 403
    allowed, status, _ = authorize(ANALYST, "PUT", "/defense/policy")
    assert not allowed and status == 403


def test_admin_can_do_everything():
    for method, path in [("GET", "/findings"), ("POST", "/incidents/1/actions"),
                         ("POST", "/actions/9/approve"), ("PUT", "/defense/policy"),
                         ("POST", "/agent/triage")]:
        assert authorize(ADMIN, method, path)[0], (method, path)


# ---------------------------------------------------------------- enforcement flag

def test_production_forces_auth_required():
    assert Settings(soc_env="production", api_auth_required=False).auth_required is True
    assert Settings(soc_env="development", api_auth_required=False).auth_required is False
    assert Settings(soc_env="development", api_auth_required=True).auth_required is True
