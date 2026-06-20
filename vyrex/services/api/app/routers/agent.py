"""Agentic AI analyst — an air-gapped, self-hosted LLM (Ollama) reasons over VYREX's already-
explained findings and produces governed triage decisions.

What makes this defensible (and rare): the agent runs entirely on-prem (nothing egresses), it
reasons over findings that are *already scored and explained* (SHAP/consensus), it records its
reasoning, and it can ESCALATE / MONITOR / DISMISS or PROPOSE containment — but it can NEVER execute
a destructive action. Containment stays behind VYREX's two-person, Ed25519-signed approval gate.
Agentic power, air-gapped trust.
"""
from __future__ import annotations

import json

import httpx
from fastapi import APIRouter
from pydantic import BaseModel

from .. import db
from ..config import settings

router = APIRouter(tags=["agent"])

SYSTEM = (
    "You are VYREX, a senior SOC analyst performing tier-1 triage in an air-gapped environment. "
    "You receive open security findings that are already scored and explained: severity, composite "
    "risk score, KEV flag (known-exploited), EPSS exploit probability, how many independent tools "
    "agree (consensus), ATT&CK technique, and the affected asset. For EACH finding choose exactly "
    "one decision: ESCALATE (a real threat — open an incident), MONITOR (watch, not urgent), or "
    "DISMISS (noise / low risk). Prioritise by exploitability (KEV and high EPSS), multi-tool "
    "consensus, and asset exposure. You may PROPOSE containment in your reason, but you must never "
    "claim to have executed any action. Reply with ONLY compact JSON, no prose: "
    '{"summary":"<2-3 sentence shift summary>","decisions":[{"id":<finding id int>,'
    '"decision":"ESCALATE|MONITOR|DISMISS","reason":"<<=160 chars, cite the deciding factor>"}]}'
)


class TriageReq(BaseModel):
    limit: int = 8


def _finding_line(f: dict) -> str:
    con = f.get("consensus") or {}
    ntools = con.get("n_tools", 1) if isinstance(con, dict) else 1
    return (
        f"#{f['id']} [{(f.get('severity') or '').upper()}] {(f.get('title') or '')[:90]} | "
        f"score {f.get('risk_score')} | {'KEV ' if f.get('kev') else ''}"
        f"CVSS {f.get('cvss_score') or '-'} | EPSS {f.get('epss') or '-'} | "
        f"{ntools} tool(s) agree | asset {f.get('asset_id')} | ATT&CK {f.get('attack') or '-'}"
    )


async def _ollama_chat(prompt: str) -> str:
    payload = {
        "model": settings.ollama_model, "stream": False, "format": "json",
        "options": {"temperature": 0.1},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
    }
    async with httpx.AsyncClient(timeout=180) as c:
        r = await c.post(f"{settings.ollama_url}/api/chat", json=payload)
        r.raise_for_status()
        return ((r.json().get("message") or {}).get("content")) or ""


@router.get("/agent/status", summary="Self-hosted LLM reachability + model readiness")
async def agent_status() -> dict:
    reachable, models = False, []
    try:
        async with httpx.AsyncClient(timeout=4) as c:
            r = await c.get(f"{settings.ollama_url}/api/tags")
            if r.status_code == 200:
                reachable = True
                models = [m.get("name") for m in r.json().get("models", [])]
    except Exception:
        reachable = False
    return {
        "engine": "ollama", "reachable": reachable, "url": settings.ollama_url,
        "model": settings.ollama_model, "models_available": models,
        "model_ready": any((settings.ollama_model.split(":")[0] in (m or "")) for m in models),
    }


@router.post("/agent/triage", summary="Agentic AI analyst — LLM triages open findings (governed)")
async def agent_triage(req: TriageReq) -> dict:
    rows = await db.fetch(
        "SELECT id, asset_id, title, severity, cve_id, risk_score, kev, cvss_score, epss, "
        "consensus, attack, COALESCE(triage_status,'open') AS triage_status "
        "FROM findings WHERE risk_score IS NOT NULL AND COALESCE(triage_status,'open')='open' "
        "ORDER BY risk_score DESC LIMIT %(l)s",
        {"l": max(1, min(req.limit, 20))},
    )
    if not rows:
        return {"error": "no open findings to triage", "decisions": [], "model": settings.ollama_model}

    prompt = "Open findings to triage:\n" + "\n".join(_finding_line(f) for f in rows)
    try:
        content = await _ollama_chat(prompt)
    except Exception as e:
        return {"error": f"self-hosted LLM unreachable — pull the model first "
                         f"(docker exec vyrex-ollama ollama pull {settings.ollama_model}). {str(e)[:120]}",
                "model": settings.ollama_model, "decisions": []}

    try:
        parsed = json.loads(content)
    except Exception:
        parsed = {"summary": content[:400], "decisions": []}

    by_id = {f["id"]: f for f in rows}
    out, escalated = [], 0
    for d in (parsed.get("decisions") or []):
        fid = d.get("id")
        f = by_id.get(fid) or {}
        dec = (d.get("decision") or "").upper()
        out.append({"id": fid, "title": f.get("title"), "asset_id": f.get("asset_id"),
                    "severity": f.get("severity"), "decision": dec, "reason": d.get("reason")})
        if dec == "ESCALATE" and fid:  # governed: record an escalation notification, never contain
            escalated += 1
            await db.execute(
                "INSERT INTO notifications (dedup_key, kind, severity, title, body, ref_type, ref_id) "
                "VALUES (%(k)s,'agent',%(sev)s,%(t)s,%(b)s,'finding',%(rid)s) "
                "ON CONFLICT (dedup_key) DO NOTHING",
                {"k": f"agent:escalate:{fid}", "sev": (f.get("severity") or "high"),
                 "t": f"AI analyst escalated — {(f.get('title') or '')[:64]}",
                 "b": d.get("reason"), "rid": str(fid)},
            )

    run = await db.execute(
        "INSERT INTO agent_runs (model, summary, considered, escalated, decisions) "
        "VALUES (%(m)s,%(s)s,%(c)s,%(e)s,%(d)s) RETURNING id, created_at",
        {"m": settings.ollama_model, "s": parsed.get("summary"), "c": len(rows),
         "e": escalated, "d": json.dumps(out)},
    )
    return {"model": settings.ollama_model, "considered": len(rows), "escalated": escalated,
            "summary": parsed.get("summary"), "decisions": out, "run_id": (run or {}).get("id")}


@router.get("/agent/runs", summary="Recent AI-analyst runs")
async def agent_runs(limit: int = 10) -> list[dict]:
    return await db.fetch(
        "SELECT id, kind, model, summary, considered, escalated, ref_id, decisions, created_at "
        "FROM agent_runs WHERE kind = 'triage' ORDER BY id DESC LIMIT %(l)s",
        {"l": limit},
    )


# ───────────────────────────── investigation agent ───────────────────────────
SYSTEM_INVESTIGATE = (
    "You are VYREX, a senior incident responder. You receive an incident and ALL its correlated "
    "findings (each with asset, CVE, ATT&CK technique, IOC indicator, detecting tool, severity). "
    "Pivot across them and produce a focused investigation. Reply with ONLY compact JSON, no prose: "
    '{"narrative":"<2-4 sentences: what most likely happened and why it matters>",'
    '"timeline":[{"step":"<short label>","detail":"<what/where, cite the finding or asset>"}],'
    '"killchain":[{"tactic":"<ATT&CK tactic>","technique":"<Txxxx>","evidence":"<which finding/IOC>"}],'
    '"recommendations":["<concrete next investigative or containment step; containment is proposal-only>"]}'
    " Order the timeline and kill-chain by attack progression (initial access → execution → ... → impact)."
)


class InvestigateReq(BaseModel):
    incident_id: int


@router.post("/agent/investigate", summary="Investigation agent — LLM pivots an incident into a narrative + kill-chain")
async def agent_investigate(req: InvestigateReq) -> dict:
    inc = await db.fetch_one(
        "SELECT id, title, severity, status, created_at FROM incidents WHERE id = %(id)s",
        {"id": req.incident_id},
    )
    if not inc:
        return {"error": f"incident #{req.incident_id} not found"}
    findings = await db.fetch(
        "SELECT fd.id, fd.title, fd.severity, fd.risk_score, fd.cve_id, fd.kev, fd.asset_id, "
        "fd.attack, fd.threat_intel, fd.source_tool, fd.cvss_score, fd.epss "
        "FROM incident_findings link JOIN findings fd ON fd.id = link.finding_id "
        "WHERE link.incident_id = %(id)s ORDER BY fd.risk_score DESC NULLS LAST",
        {"id": req.incident_id},
    )
    if not findings:
        return {"error": f"incident #{req.incident_id} has no linked findings to investigate"}

    # deterministic pivot: collect the entities the agent reasons over
    assets = sorted({f["asset_id"] for f in findings if f.get("asset_id")})
    techniques = sorted({f["attack"] for f in findings if f.get("attack")})
    tools = sorted({f["source_tool"] for f in findings if f.get("source_tool")})
    iocs = []
    for f in findings:
        ti = f.get("threat_intel")
        if isinstance(ti, dict) and ti.get("indicator"):
            iocs.append(f"{ti.get('indicator')} ({ti.get('type', 'ioc')})")

    lines = [f"INCIDENT #{inc['id']}: {inc['title']} [{(inc.get('severity') or '').upper()}]"]
    lines.append(f"Assets: {', '.join(assets) or '-'} | Tools: {', '.join(tools) or '-'} | "
                 f"IOCs: {', '.join(sorted(set(iocs))) or 'none'}")
    lines.append("Findings:")
    for f in findings:
        lines.append(
            f"  #{f['id']} [{(f.get('severity') or '').upper()}] {(f.get('title') or '')[:90]} | "
            f"{'KEV ' if f.get('kev') else ''}CVSS {f.get('cvss_score') or '-'} | "
            f"asset {f.get('asset_id')} | ATT&CK {f.get('attack') or '-'} | tool {f.get('source_tool')}"
        )

    payload = {
        "model": settings.ollama_model, "stream": False, "format": "json",
        "options": {"temperature": 0.2},
        "messages": [{"role": "system", "content": SYSTEM_INVESTIGATE},
                     {"role": "user", "content": "\n".join(lines)}],
    }
    try:
        async with httpx.AsyncClient(timeout=240) as c:
            r = await c.post(f"{settings.ollama_url}/api/chat", json=payload)
            r.raise_for_status()
            content = ((r.json().get("message") or {}).get("content")) or ""
    except Exception as e:
        return {"error": f"self-hosted LLM unreachable — pull the model first. {str(e)[:120]}",
                "model": settings.ollama_model}

    try:
        result = json.loads(content)
    except Exception:
        result = {"narrative": content[:600], "timeline": [], "killchain": [], "recommendations": []}

    result.setdefault("entities", {})
    result["entities"] = {"assets": assets, "techniques": techniques, "tools": tools,
                          "iocs": sorted(set(iocs)), "findings": len(findings)}

    run = await db.execute(
        "INSERT INTO agent_runs (kind, model, summary, considered, ref_id, decisions) "
        "VALUES ('investigation',%(m)s,%(s)s,%(c)s,%(rid)s,%(d)s) RETURNING id, created_at",
        {"m": settings.ollama_model, "s": (result.get("narrative") or "")[:400],
         "c": len(findings), "rid": str(req.incident_id), "d": json.dumps(result)},
    )
    return {"model": settings.ollama_model, "incident": dict(inc), "considered": len(findings),
            "result": result, "run_id": (run or {}).get("id")}


@router.get("/agent/investigations", summary="Recent investigation runs")
async def agent_investigations(limit: int = 10) -> list[dict]:
    return await db.fetch(
        "SELECT id, model, summary, considered, ref_id, decisions, created_at "
        "FROM agent_runs WHERE kind = 'investigation' ORDER BY id DESC LIMIT %(l)s",
        {"l": limit},
    )
