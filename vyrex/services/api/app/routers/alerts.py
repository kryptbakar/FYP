"""Alerting — notification channels, routing rules, and delivery.

In-app notifications are not enough for a real product: alerts must be *delivered* to where
the team watches (a webhook / ticketing intake / chat). Webhook delivery is real (an internal
HTTP POST, which stays air-gap-friendly); email/slack are recorded as 'queued' until a
transport is wired at the deployment site, so the workflow is honest end to end.
"""
from __future__ import annotations

import json
from typing import Annotated

import httpx
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import db

router = APIRouter(tags=["alerting"])

CHANNEL_TYPES = {"webhook", "email", "slack"}


# ------------------------------------------------------------------ channels ---
class ChannelIn(BaseModel):
    name: str
    type: str = "webhook"
    target: str


@router.get("/alert-channels", summary="List alert channels")
async def list_channels() -> list[dict]:
    return await db.fetch("SELECT id, name, type, target, enabled, created_at FROM alert_channels ORDER BY id")


@router.post("/alert-channels", summary="Add an alert channel")
async def add_channel(c: ChannelIn) -> dict:
    if c.type not in CHANNEL_TYPES:
        raise HTTPException(400, f"unknown type; allowed: {sorted(CHANNEL_TYPES)}")
    return await db.execute(
        "INSERT INTO alert_channels (name, type, target) VALUES (%(n)s,%(t)s,%(tg)s) "
        "RETURNING id, name, type, target, enabled",
        {"n": c.name, "t": c.type, "tg": c.target}) or {}


class ChannelPatch(BaseModel):
    enabled: bool


@router.patch("/alert-channels/{channel_id}", summary="Enable/disable a channel")
async def patch_channel(channel_id: int, p: ChannelPatch) -> dict:
    return await db.execute(
        "UPDATE alert_channels SET enabled=%(e)s WHERE id=%(id)s RETURNING id, name, enabled",
        {"e": p.enabled, "id": channel_id}) or {}


async def _deliver(channel: dict, subject: str, payload: dict) -> dict:
    """Deliver to one channel and record the outcome."""
    status, detail = "queued", ""
    if channel["type"] == "webhook":
        try:
            async with httpx.AsyncClient(timeout=4) as client:
                resp = await client.post(channel["target"], json={"subject": subject, **payload})
            status = "delivered" if resp.status_code < 400 else "failed"
            detail = f"HTTP {resp.status_code}"
        except Exception as e:  # unreachable webhook -> failed, not fatal
            status, detail = "failed", str(e)[:140]
    else:
        detail = f"{channel['type']} transport not configured at this site (air-gapped); recorded as queued"
    await db.execute(
        "INSERT INTO alert_deliveries (channel_id, channel_name, subject, status, detail) "
        "VALUES (%(c)s,%(cn)s,%(s)s,%(st)s,%(d)s)",
        {"c": channel["id"], "cn": channel["name"], "s": subject, "st": status, "d": detail})
    return {"channel": channel["name"], "status": status, "detail": detail}


@router.post("/alert-channels/{channel_id}/test", summary="Send a test alert to a channel")
async def test_channel(channel_id: int) -> dict:
    ch = await db.fetch_one("SELECT id, name, type, target FROM alert_channels WHERE id=%(id)s", {"id": channel_id})
    if not ch:
        raise HTTPException(404, "channel not found")
    return await _deliver(ch, "VYREX test alert", {"severity": "info", "body": "This is a test from VYREX alerting."})


# --------------------------------------------------------------------- rules ---
class RuleIn(BaseModel):
    name: str
    min_severity: str = "high"
    kind: str | None = None
    channel_id: int


@router.get("/alert-rules", summary="List routing rules")
async def list_rules() -> list[dict]:
    return await db.fetch(
        """SELECT r.id, r.name, r.min_severity, r.kind, r.channel_id, r.enabled, c.name AS channel_name
           FROM alert_rules r LEFT JOIN alert_channels c ON c.id = r.channel_id ORDER BY r.id""")


@router.post("/alert-rules", summary="Add a routing rule")
async def add_rule(r: RuleIn) -> dict:
    return await db.execute(
        "INSERT INTO alert_rules (name, min_severity, kind, channel_id) VALUES (%(n)s,%(s)s,%(k)s,%(c)s) "
        "RETURNING id, name, min_severity, kind, channel_id, enabled",
        {"n": r.name, "s": r.min_severity, "k": r.kind, "c": r.channel_id}) or {}


# ----------------------------------------------------------------- dispatch ---
_SEV = {"critical": 3, "high": 2, "medium": 1, "info": 0}


@router.post("/alerts/dispatch", summary="Route unacknowledged notifications to channels per rules")
async def dispatch() -> dict:
    notifs = await db.fetch(
        "SELECT id, kind, severity, title, body FROM notifications WHERE NOT acknowledged ORDER BY created_at DESC LIMIT 50")
    rules = await db.fetch(
        """SELECT r.min_severity, r.kind, c.id, c.name, c.type, c.target
           FROM alert_rules r JOIN alert_channels c ON c.id=r.channel_id
           WHERE r.enabled AND c.enabled""")
    results = []
    for n in notifs:
        nsev = _SEV.get((n["severity"] or "").lower(), 0)
        for r in rules:
            if nsev < _SEV.get(r["min_severity"], 2):
                continue
            if r["kind"] and r["kind"] != "any" and r["kind"] != n["kind"]:
                continue
            ch = {"id": r["id"], "name": r["name"], "type": r["type"], "target": r["target"]}
            results.append(await _deliver(ch, n["title"], {"severity": n["severity"], "body": n["body"]}))
    return {"notifications": len(notifs), "deliveries": len(results), "results": results[:20]}


@router.get("/alert-deliveries", summary="Delivery log")
async def deliveries(limit: int = 50) -> list[dict]:
    return await db.fetch(
        "SELECT id, channel_name, subject, status, detail, created_at FROM alert_deliveries "
        "ORDER BY id DESC LIMIT %(l)s", {"l": limit})
