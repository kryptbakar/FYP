"""Security analytics — MITRE ATT&CK coverage and risk-posture trends.

Two things buyers and managers expect: a Navigator-style picture of *which adversary
techniques we actually see and which tools cover them*, and a *trend* line that answers
"is our posture getting better?" — not just a single point in time.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Query

from .. import db

router = APIRouter(tags=["analytics"])

# Technique -> (tactic, friendly name). Local reference data (air-gap clean) covering the
# techniques our detections emit; unknown techniques fall into "other".
TECHNIQUES = {
    "T1190": ("initial-access", "Exploit Public-Facing Application"),
    "T1133": ("initial-access", "External Remote Services"),
    "T1566": ("initial-access", "Phishing"),
    "T1078": ("initial-access", "Valid Accounts"),
    "T1059": ("execution", "Command & Scripting Interpreter"),
    "T1203": ("execution", "Exploitation for Client Execution"),
    "T1204": ("execution", "User Execution"),
    "T1547": ("persistence", "Boot/Logon Autostart"),
    "T1543": ("persistence", "Create/Modify System Process"),
    "T1068": ("privilege-escalation", "Exploitation for Privilege Escalation"),
    "T1548": ("privilege-escalation", "Abuse Elevation Control"),
    "T1562": ("defense-evasion", "Impair Defenses"),
    "T1070": ("defense-evasion", "Indicator Removal"),
    "T1071": ("command-and-control", "Application Layer Protocol"),
    "T1071.001": ("command-and-control", "Web Protocols (C2)"),
    "T1090": ("command-and-control", "Proxy"),
    "T1571": ("command-and-control", "Non-Standard Port"),
    "T1041": ("exfiltration", "Exfiltration Over C2"),
    "T1048": ("exfiltration", "Exfiltration Over Alternative Protocol"),
    "T1486": ("impact", "Data Encrypted for Impact"),
}
TACTIC_ORDER = ["initial-access", "execution", "persistence", "privilege-escalation",
                "defense-evasion", "credential-access", "discovery", "lateral-movement",
                "collection", "command-and-control", "exfiltration", "impact", "other"]


@router.get("/attack/coverage", summary="MITRE ATT&CK coverage matrix (techniques x tactics x tools)")
async def attack_coverage() -> dict:
    rows = await db.fetch(
        "SELECT attack, COALESCE(source_tool,'agent') AS tool, count(*) AS n, max(risk_score) AS top "
        "FROM findings WHERE attack IS NOT NULL GROUP BY attack, COALESCE(source_tool,'agent')")
    by_tech: dict[str, dict] = {}
    for r in rows:
        t = r["attack"]
        meta = TECHNIQUES.get(t) or TECHNIQUES.get(str(t).split(".")[0]) or ("other", "technique")
        e = by_tech.setdefault(t, {"technique": t, "tactic": meta[0], "name": meta[1],
                                   "findings": 0, "tools": set(), "top_risk": 0})
        e["findings"] += r["n"]
        e["tools"].add(r["tool"])
        e["top_risk"] = max(e["top_risk"], float(r["top"] or 0))
    techniques = []
    for e in by_tech.values():
        e["tools"] = sorted(e["tools"])
        e["tool_count"] = len(e["tools"])
        techniques.append(e)
    techniques.sort(key=lambda x: (TACTIC_ORDER.index(x["tactic"]) if x["tactic"] in TACTIC_ORDER else 99,
                                   -x["top_risk"]))
    tactics = [t for t in TACTIC_ORDER if any(x["tactic"] == t for x in techniques)]
    return {"tactics": tactics, "techniques": techniques,
            "covered": len(techniques), "total_known": len(TECHNIQUES)}


# ---------------------------------------------------------------- posture trend ---
async def _take_snapshot() -> dict:
    agg = await db.fetch_one(
        """SELECT count(*) FILTER (WHERE risk_score IS NOT NULL) AS open_findings,
                  count(*) FILTER (WHERE kev) AS kev,
                  count(*) FILTER (WHERE risk_score>=80) AS critical,
                  count(*) FILTER (WHERE risk_score>=60 AND risk_score<80) AS high,
                  count(*) FILTER (WHERE COALESCE(exploit_available,false)) AS exploit_available,
                  round(avg(risk_score),1) AS avg_risk
           FROM findings""")
    comp = await db.fetch("SELECT status, count(*) AS n FROM compliance_results GROUP BY status")
    bs = {r["status"]: r["n"] for r in comp}
    graded = (bs.get("pass", 0) + bs.get("fail", 0) + bs.get("partial", 0)) or 1
    cpct = round(bs.get("pass", 0) / graded * 100, 1)
    a = agg or {}
    await db.execute(
        """INSERT INTO posture_snapshots (snap_date, open_findings, kev, critical, high,
               exploit_available, avg_risk, compliance_pct)
           VALUES (current_date, %(of)s,%(kev)s,%(crit)s,%(high)s,%(expl)s,%(avg)s,%(cpct)s)
           ON CONFLICT (snap_date) DO UPDATE SET open_findings=EXCLUDED.open_findings, kev=EXCLUDED.kev,
               critical=EXCLUDED.critical, high=EXCLUDED.high, exploit_available=EXCLUDED.exploit_available,
               avg_risk=EXCLUDED.avg_risk, compliance_pct=EXCLUDED.compliance_pct""",
        {"of": a.get("open_findings", 0), "kev": a.get("kev", 0), "crit": a.get("critical", 0),
         "high": a.get("high", 0), "expl": a.get("exploit_available", 0),
         "avg": float(a.get("avg_risk") or 0), "cpct": cpct},
    )
    return {"snapshotted": True}


@router.post("/posture/snapshot", summary="Capture today's posture snapshot (idempotent per day)")
async def snapshot() -> dict:
    return await _take_snapshot()


@router.get("/posture/trends", summary="Posture trend over time (daily snapshots)")
async def trends(days: Annotated[int, Query(ge=1, le=365)] = 90) -> list[dict]:
    rows = await db.fetch(
        "SELECT snap_date, open_findings, kev, critical, high, exploit_available, avg_risk, compliance_pct "
        "FROM posture_snapshots WHERE snap_date >= current_date - %(d)s ORDER BY snap_date",
        {"d": days})
    if not rows:
        # No history yet: take today's snapshot so the chart has at least one real point.
        await _take_snapshot()
        rows = await db.fetch(
            "SELECT snap_date, open_findings, kev, critical, high, exploit_available, avg_risk, compliance_pct "
            "FROM posture_snapshots ORDER BY snap_date")
    return rows
