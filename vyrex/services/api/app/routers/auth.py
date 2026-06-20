"""Local authentication for the console — a login gate with real password hashing + RBAC.

Complements the production SSO path (Keycloak/oauth2-proxy in K3s): a self-contained login
so the running console actually requires credentials and carries a role. Passwords are
pbkdf2-hashed; sessions are opaque bearer tokens. Seeded with admin/analyst/viewer.
"""
from __future__ import annotations

import hashlib
import logging
import os
import uuid
from typing import Annotated

import psycopg
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import db
from ..config import settings

log = logging.getLogger("api.auth")
router = APIRouter(tags=["auth"])

# Demo seed users (same password 'vyrex', different roles) — change in production.
SEED_USERS = [("admin", "vyrex", "admin"), ("analyst", "vyrex", "analyst"), ("viewer", "vyrex", "viewer")]


def _hash(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 120_000).hex()


def seed_users() -> None:
    """Insert the seed users if absent. Called once at API startup (idempotent)."""
    try:
        with psycopg.connect(settings.postgres_dsn, autocommit=True) as conn:
            for username, pw, role in SEED_USERS:
                salt = os.urandom(16).hex()
                conn.execute(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (%s,%s,%s,%s) "
                    "ON CONFLICT (username) DO NOTHING",
                    (username, _hash(pw, salt), salt, role))
        log.info("seed users ready")
    except Exception as e:
        log.info("seed users deferred: %s", e)


def _token(authorization: str | None) -> str:
    return (authorization or "").removeprefix("Bearer ").strip()


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/auth/login", summary="Log in (returns a session token + role)")
async def login(c: LoginIn) -> dict:
    u = await db.fetch_one(
        "SELECT username, password_hash, salt, role FROM users WHERE username=%(u)s", {"u": c.username})
    if not u or _hash(c.password, u["salt"]) != u["password_hash"]:
        raise HTTPException(401, "invalid username or password")
    token = uuid.uuid4().hex
    await db.execute("INSERT INTO sessions (token, username, role) VALUES (%(t)s,%(u)s,%(r)s)",
                     {"t": token, "u": u["username"], "r": u["role"]})
    return {"token": token, "user": u["username"], "role": u["role"]}


@router.get("/auth/me", summary="Current session (from bearer token)")
async def me(authorization: Annotated[str | None, Header()] = None) -> dict:
    token = _token(authorization)
    if not token:
        return {"authenticated": False}
    s = await db.fetch_one("SELECT username, role FROM sessions WHERE token=%(t)s", {"t": token})
    if not s:
        return {"authenticated": False}
    return {"authenticated": True, "user": s["username"], "role": s["role"]}


@router.post("/auth/logout", summary="Invalidate the current session")
async def logout(authorization: Annotated[str | None, Header()] = None) -> dict:
    token = _token(authorization)
    if token:
        await db.execute("DELETE FROM sessions WHERE token=%(t)s", {"t": token})
    return {"ok": True}
