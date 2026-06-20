"""Automation status — a window onto the n8n automation engine for the console.

Air-gap clean: it always works off VYREX's own data (the n8n alert-channel deliveries and the
playbook hand-offs it recorded), and pings n8n's /healthz for reachability. If an n8n API key is
configured (N8N_API_KEY), it additionally pulls live execution status from n8n's own API.
"""
from __future__ import annotations

import httpx
from fastapi import APIRouter

from .. import db
from ..config import settings

router = APIRouter(tags=["automation"])

# Static catalogue of the bundled workflows (matches deploy/n8n/workflows/).
WORKFLOWS = [
    {"id": "vyrexAutoTriage1", "name": "Auto-triage loop", "trigger": "every 15 min", "kind": "schedule",
     "does": "pull ranking → correlate → dispatch alerts"},
    {"id": "vyrexCriticalRsp", "name": "Critical finding responder", "trigger": "webhook /webhook/vyrex", "kind": "webhook",
     "does": "branch on severity → correlate → dispatch → respond"},
    {"id": "vyrexAlertIntake", "name": "Alert intake", "trigger": "webhook /webhook/vyrex-alert", "kind": "webhook",
     "does": "receive dispatched alerts; escalate criticals; fan out"},
    {"id": "vyrexSlaEscal01", "name": "SLA-breach escalation", "trigger": "hourly", "kind": "schedule",
     "does": "count SLA breaches → escalate + executive report"},
    {"id": "vyrexIocRespond1", "name": "Live-IOC responder", "trigger": "every 20 min", "kind": "schedule",
     "does": "high-risk findings with a live MISP IOC → correlate + dispatch"},
    {"id": "vyrexDailyReport", "name": "Daily posture report", "trigger": "daily 08:00", "kind": "schedule",
     "does": "generate report → notify"},
]


@router.get("/automation/status", summary="n8n automation engine status + recent activity")
async def status() -> dict:
    # 1) reachability (always)
    reachable = False
    try:
        async with httpx.AsyncClient(timeout=3) as c:
            reachable = (await c.get(f"{settings.n8n_base_url}/healthz")).status_code == 200
    except Exception:
        reachable = False

    # 2) live executions from n8n's own API (only if a key is configured)
    executions: list[dict] = []
    if settings.n8n_api_key:
        try:
            async with httpx.AsyncClient(timeout=4) as c:
                r = await c.get(f"{settings.n8n_base_url}/api/v1/executions?limit=12",
                                headers={"X-N8N-API-KEY": settings.n8n_api_key})
                if r.status_code == 200:
                    for e in r.json().get("data", []):
                        executions.append({
                            "id": e.get("id"),
                            "workflow": (e.get("workflowData") or {}).get("name") or e.get("workflowId"),
                            "status": e.get("status") or ("success" if e.get("finished") else "running"),
                            "started": e.get("startedAt"), "mode": e.get("mode"),
                        })
        except Exception:
            executions = []

    # 3) VYREX-side activity (always available — this is what we actually sent to n8n)
    deliveries = await db.fetch(
        "SELECT channel_name, subject, status, detail, created_at FROM alert_deliveries "
        "WHERE channel_name = 'n8n automation' ORDER BY created_at DESC LIMIT 12")
    handoffs = await db.fetch(
        "SELECT id, playbook_id, trigger_ref, status, created_at FROM playbook_runs "
        "WHERE playbook_id = 'pb-n8n-automation' ORDER BY id DESC LIMIT 12")
    channel = await db.fetch_one(
        "SELECT id, name, target, enabled FROM alert_channels WHERE target LIKE %(p)s LIMIT 1",
        {"p": "%n8n%"})

    return {
        "engine": "n8n", "reachable": reachable,
        "base_url": settings.n8n_base_url, "webhook_url": settings.n8n_webhook_url,
        "api_key_configured": bool(settings.n8n_api_key),
        "channel": channel, "workflows": WORKFLOWS,
        "executions": executions, "deliveries": deliveries, "handoffs": handoffs,
    }
