"""Tests for /whoami role mapping — makes SSO/RBAC behaviour explicit & defensible.

The endpoint is an async coroutine; called directly (outside FastAPI) the header
parameters fall back to their `= None` defaults, which is exactly the unauthenticated
path we want to assert.
"""
import asyncio

from app.routers.identity import whoami


def _call(**kw):
    return asyncio.run(whoami(**kw))


def test_unauthenticated_when_no_user():
    r = _call()
    assert r["authenticated"] is False
    assert r["role"] is None


def test_admin_role_from_groups():
    r = _call(x_auth_request_user="alice", x_auth_request_groups="soc-admin,platform")
    assert r["authenticated"] is True
    assert r["role"] == "admin"
    assert "soc-admin" in r["roles"]


def test_analyst_role_from_groups():
    r = _call(x_auth_request_user="bob", x_auth_request_groups="soc-analyst")
    assert r["role"] == "analyst"


def test_viewer_is_default_role():
    r = _call(x_auth_request_user="carol", x_auth_request_groups="")
    assert r["role"] == "viewer"


def test_forwarded_user_header_is_honoured():
    r = _call(x_forwarded_user="dave")
    assert r["authenticated"] is True
    assert r["user"] == "dave"
