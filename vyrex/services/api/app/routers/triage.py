"""Finding lifecycle & risk acceptance (DefectDojo pattern) + alert correlation
(agentic-soc-platform pattern).

Two capabilities the references have that a raw findings list lacks:

1. **Lifecycle / risk acceptance** — a finding isn't just open/closed; an analyst triages it
   to false-positive / risk-accepted (with an expiry) / mitigated / resolved, and those leave
   the active queue. This is the core value of a vuln-management platform over a scanner dump.

2. **Correlation -> auto-incident** — independent high-risk findings on the same asset in the
   same time window are correlated by a deterministic key and rolled up into a single incident
   automatically, instead of an analyst hand-creating cases.
"""
from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel

from .. import db

router = APIRouter(tags=["triage"])

# Active (in-queue) vs closed (triaged-away) lifecycle states.
CLOSED_STATES = {"false_positive", "risk_accepted", "mitigated", "resolved"}
VALID_STATES = {"open", "triaged", "investigating"} | CLOSED_STATES


class TriageIn(BaseModel):
    status: str
    note: str | None = None
    risk_accepted_until: date | None = None


@router.post("/findings/{finding_id}/triage", summary="Set finding lifecycle state / accept risk")
async def triage(finding_id: int, t: TriageIn,
                 x_analyst: Annotated[str | None, Header()] = None) -> dict:
    if t.status not in VALID_STATES:
        raise HTTPException(400, f"invalid status; allowed: {sorted(VALID_STATES)}")
    if t.status == "risk_accepted" and not t.risk_accepted_until:
        raise HTTPException(400, "risk_accepted requires risk_accepted_until (an expiry date)")
    row = await db.execute(
        """UPDATE findings
           SET triage_status=%(s)s, triage_note=%(n)s, triaged_by=%(by)s, triaged_at=now(),
               risk_accepted_until=%(rau)s
           WHERE id=%(id)s
           RETURNING id, triage_status, risk_accepted_until, triaged_by, triaged_at""",
        {"s": t.status, "n": t.note, "by": x_analyst or "analyst",
         "rau": t.risk_accepted_until, "id": finding_id},
    )
    if not row:
        raise HTTPException(404, "finding not found")
    return row


# ----------------------------------------------------------------- correlation ---
def _time_bucket(dt: datetime, hours: int = 24) -> str:
    """Bucket a timestamp to a window (agentic-soc-platform pattern)."""
    if hours >= 24:
        return dt.strftime("%Y%m%d")
    b = (dt.hour // hours) * hours
    return dt.replace(hour=b, minute=0, second=0, microsecond=0).strftime("%Y%m%d%H")


def _correlation_uid(asset: str, technique: str | None, bucket: str) -> str:
    raw = "|".join(["corr", asset, technique or "-", bucket])
    return "corr-" + hashlib.sha256(raw.encode()).hexdigest()[:16]


class CorrelateIn(BaseModel):
    min_score: float = 60.0
    window_hours: int = 24


@router.post("/incidents/correlate", summary="Correlate high-risk findings into auto-incidents")
async def correlate(c: CorrelateIn,
                    x_analyst: Annotated[str | None, Header()] = None) -> dict:
    """Group open high-risk findings by (asset + ATT&CK technique + time bucket) and roll each
    group into one incident (idempotent via a unique correlation_uid). Returns what it created
    or matched — the SIEM-style 'alerts became a case' step, automated."""
    findings = await db.fetch(
        """SELECT id, asset_id, attack, severity, title, risk_score,
                  COALESCE(last_seen, first_seen, now()) AS observed_at
           FROM findings
           WHERE risk_score >= %(m)s
             AND COALESCE(triage_status,'open') NOT IN ('false_positive','risk_accepted','mitigated','resolved')
           ORDER BY risk_score DESC""",
        {"m": c.min_score},
    )
    groups: dict[str, list[dict]] = {}
    for f in findings:
        ts = f["observed_at"]
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                ts = datetime.now(timezone.utc)
        bucket = _time_bucket(ts, c.window_hours)
        uid = _correlation_uid(f["asset_id"], f.get("attack"), bucket)
        groups.setdefault(uid, []).append(f)

    created, matched = [], []
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    for uid, members in groups.items():
        if len(members) < 2:
            continue  # a single finding isn't a correlation
        top = max(members, key=lambda m: sev_rank.get((m.get("severity") or "").upper(), 0))
        asset = members[0]["asset_id"]
        title = f"Correlated activity on {asset} — {len(members)} findings"
        inc = await db.execute(
            """INSERT INTO incidents (title, description, severity, status, created_by,
                                      correlation_uid, auto_created, sla_due)
               VALUES (%(t)s,%(d)s,%(sev)s,'open',%(by)s,%(uid)s,true, now() + interval '24 hours')
               ON CONFLICT (correlation_uid) WHERE correlation_uid IS NOT NULL DO NOTHING
               RETURNING id""",
            {"t": title, "d": f"Auto-correlated by {x_analyst or 'soc-auto'}: "
                              + ", ".join(m["title"][:60] for m in members[:5]),
             "sev": (top.get("severity") or "high").lower(), "by": x_analyst or "soc-auto", "uid": uid},
        )
        if not inc:
            matched.append(uid)
            continue
        incident_id = inc["id"]
        for m in members:
            await db.execute(
                "INSERT INTO incident_findings (incident_id, finding_id) VALUES (%(i)s,%(f)s) "
                "ON CONFLICT DO NOTHING",
                {"i": incident_id, "f": m["id"]},
            )
        created.append({"incident_id": incident_id, "correlation_uid": uid, "findings": len(members)})
    return {"correlated_groups": len(created), "already_present": len(matched), "created": created}
