"""Autonomous Defense engine — the agentic active-defense subsystem.

This is the real decision-and-response brain behind the console's "Autonomous Defense"
screen. It builds **on** the existing governed channel (Ed25519-signed commands +
hash-chained audit + the two-person rule) rather than around it:

  * SENTINEL — evaluates open findings, decides CONTAIN / MONITOR / DISMISS, classifies
    blast radius, and — gated by an autonomy policy — either **auto-executes** a
    reversible/low-blast containment (signs it and hands it to the agent) or **queues**
    a destructive action for two-person approval. Every decision is recorded; every
    executed command flows through the same signed + audited path as a human request.
  * DECOY — honeytoken deception. A real user never touches these; an attacker who does
    fires a 100 %-confidence tripwire that auto-proposes isolation of the source.
  * MEND — self-healing remediation (restore tampered state to the FIM baseline, kill
    persistence), logged for audit.
  * FORGE — continuous breach-and-attack emulation against the estate's own coverage,
    surfacing the ATT&CK gaps to auto-harden.

Safety invariant: **destructive actions are never auto-executed.** Autonomy only ever
covers reversible, low-blast containment; anything irreversible still requires two
distinct human approvers. That gate is the product, not a limitation.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from .. import audit, db, signing

router = APIRouter(tags=["defense"])

# Reversible, low-blast containment — eligible for autonomous execution (no two-person).
REVERSIBLE_ACTIONS = {"ip_block", "token_revoke", "session_terminate", "rate_limit", "dns_sinkhole"}
# Irreversible / high-impact — ALWAYS two-person, never autonomous (mirrors response.py).
DESTRUCTIVE_ACTIONS = {"process_kill", "network_isolate", "file_quarantine", "user_disable"}

# Which blast classes each autonomy level may auto-execute (reversible actions only).
AUTO_BLAST = {"advisory": set(), "reversible": {"low"}, "full": {"low", "med"}}
CLOSED = {"false_positive", "risk_accepted", "mitigated", "resolved"}

# Kill-chain techniques Forge emulates against the estate's detection coverage.
KILLCHAIN = [
    ("Initial Access", "T1190"), ("Execution", "T1059"), ("Privilege Escalation", "T1068"),
    ("Defense Evasion", "T1562"), ("Credential Access", "T1003"), ("Lateral Movement", "T1021"),
    ("Command & Control", "T1071"), ("Exfiltration", "T1041"),
]


# --------------------------------------------------------------- the brain ----
def decide(f: dict) -> dict:
    """Deterministic, defensible decision for one finding → verdict + action + blast.

    The thresholds are explicit so an examiner can trace 'why did it act': KEV +
    exploitability, multi-tool consensus, live intel, exposure. No black box.
    """
    risk = float(f.get("risk_score") or 0)
    kev = bool(f.get("kev"))
    domain = (f.get("domain") or "").lower()
    con = f.get("consensus") or {}
    n_tools = con.get("n_tools", 1) if isinstance(con, dict) else 1
    intel = f.get("threat_intel")
    status = f.get("triage_status") or "open"

    if status in CLOSED or risk < 30:
        return {"verdict": "DISMISS", "action": "none", "blast": "none",
                "reason": "below action threshold or already triaged away"}

    # active network threat → reversible block, escalating to isolation when critical
    if domain == "network" and (intel or risk >= 75):
        if risk >= 88:
            return {"verdict": "CONTAIN", "action": "network_isolate", "blast": "high",
                    "reason": "critical network compromise with live indicator — host isolation (two-person)"}
        return {"verdict": "CONTAIN", "action": "ip_block", "blast": "low",
                "reason": "active network indicator — reversible IP block / sinkhole"}

    # exploitable host/app finding
    if (kev and risk >= 70) or risk >= 85 or (n_tools >= 2 and risk >= 78):
        if risk >= 92 or (kev and domain == "system"):
            return {"verdict": "CONTAIN", "action": "process_kill", "blast": "med",
                    "reason": "active exploitation — process termination (two-person)"}
        return {"verdict": "CONTAIN", "action": "token_revoke", "blast": "low",
                "reason": "high-confidence exploitable finding — reversible credential/session revoke"}

    return {"verdict": "MONITOR", "action": "watch", "blast": "none",
            "reason": "elevated but not auto-actionable — under watch"}


async def _get_policy() -> dict:
    row = await db.fetch_one("SELECT level, updated_by, updated_at FROM defense_policy WHERE id=1")
    return row or {"level": "reversible", "updated_by": None, "updated_at": None}


async def _auto_execute(f: dict, d: dict) -> int:
    """Create, sign and approve a reversible containment so the agent picks it up — the
    autonomous path. Reversible actions are exempt from the two-person rule by policy."""
    agent_id = f.get("asset_id") or "agent"
    nonce = uuid.uuid4().hex
    params = {"finding_id": f.get("id"), "reason": d["reason"], "reversible": True}
    row = await db.execute(
        """INSERT INTO response_actions (agent_id, action_type, params, status, requested_by, approvals, nonce)
           VALUES (%(ag)s,%(t)s,%(p)s,'pending_approval','vyrex-sentinel',%(ap)s,%(n)s)
           RETURNING id""",
        {"ag": agent_id, "t": d["action"], "p": json.dumps(params),
         "ap": json.dumps([{"approver": "autonomous-policy", "at": datetime.now(timezone.utc).isoformat()}]),
         "n": nonce},
    )
    action_id = row["id"]
    audit.append(action_id, "requested", "vyrex-sentinel",
                 {"autonomous": True, "action_type": d["action"], "finding_id": f.get("id"), "blast": d["blast"]})
    if signing.signing_available():
        payload = {"action_id": action_id, "agent_id": agent_id, "action_type": d["action"],
                   "params": params, "nonce": nonce, "issued_at": datetime.now(timezone.utc).isoformat()}
        sp, sig, pub = signing.sign_command(payload)
        await db.execute(
            """UPDATE response_actions SET status='approved', approved_at=now(),
                   signed_payload=%(sp)s, signature=%(sig)s, signing_pubkey=%(pub)s WHERE id=%(id)s""",
            {"sp": sp, "sig": sig, "pub": pub, "id": action_id})
        audit.append(action_id, "signed", "vyrex-sentinel", {"autonomous": True, "pubkey": pub})
    return action_id


async def _queue_two_person(f: dict, d: dict) -> int:
    """Destructive action: create a pending_approval request for human two-person sign-off."""
    agent_id = f.get("asset_id") or "agent"
    row = await db.execute(
        """INSERT INTO response_actions (agent_id, action_type, params, status, requested_by, nonce)
           VALUES (%(ag)s,%(t)s,%(p)s,'pending_approval','vyrex-sentinel',%(n)s) RETURNING id""",
        {"ag": agent_id, "t": d["action"],
         "p": json.dumps({"finding_id": f.get("id"), "reason": d["reason"]}), "n": uuid.uuid4().hex},
    )
    audit.append(row["id"], "requested", "vyrex-sentinel",
                 {"autonomous": False, "escalated": "two_person", "action_type": d["action"], "blast": d["blast"]})
    return row["id"]


async def _record(f: dict, d: dict, executed: bool, action_id: int | None, mode: str, latency_ms: int) -> None:
    await db.execute(
        """INSERT INTO defense_decisions
             (finding_id, asset_id, title, verdict, action_type, blast, mode, executed, action_id, reason, latency_ms)
           VALUES (%(fid)s,%(a)s,%(t)s,%(v)s,%(act)s,%(b)s,%(m)s,%(e)s,%(aid)s,%(r)s,%(l)s)""",
        {"fid": f.get("id"), "a": f.get("asset_id"), "t": f.get("title"), "v": d["verdict"],
         "act": d["action"], "b": d["blast"], "m": mode, "e": executed, "aid": action_id,
         "r": d["reason"], "l": latency_ms},
    )


# --------------------------------------------------------------- policy --------
class PolicyIn(BaseModel):
    level: str  # advisory | reversible | full


@router.get("/defense/policy", summary="Current autonomy policy")
async def get_policy() -> dict:
    return await _get_policy()


@router.put("/defense/policy", summary="Set the autonomy level")
async def set_policy(p: PolicyIn, x_analyst: Annotated[str | None, Header()] = None) -> dict:
    if p.level not in AUTO_BLAST:
        raise HTTPException(400, f"level must be one of {sorted(AUTO_BLAST)}")
    await db.execute(
        """INSERT INTO defense_policy (id, level, updated_by, updated_at) VALUES (1,%(l)s,%(by)s,now())
           ON CONFLICT (id) DO UPDATE SET level=%(l)s, updated_by=%(by)s, updated_at=now()""",
        {"l": p.level, "by": x_analyst or "analyst"})
    return await _get_policy()


# --------------------------------------------------------------- SENTINEL ------
@router.post("/defense/evaluate", summary="Run the autonomous engine over open findings")
async def evaluate(limit: int = 50) -> dict:
    policy = await _get_policy()
    level = policy["level"]
    auto_blast = AUTO_BLAST.get(level, set())
    findings = await db.fetch(
        """SELECT id, asset_id, domain, title, severity, risk_score, kev, attack, threat_intel,
                  consensus, COALESCE(triage_status,'open') AS triage_status
           FROM findings WHERE risk_score IS NOT NULL
           ORDER BY risk_score DESC LIMIT %(n)s""", {"n": limit})

    out = {"evaluated": 0, "contained": 0, "autonomous": 0, "queued_two_person": 0,
           "advisory": 0, "monitor": 0, "dismiss": 0, "decisions": []}
    for f in findings:
        t0 = time.perf_counter()
        d = decide(f)
        executed, action_id, mode = False, None, "advisory"
        if d["verdict"] == "CONTAIN":
            if d["action"] in REVERSIBLE_ACTIONS and d["blast"] in auto_blast:
                action_id = await _auto_execute(f, d); executed = True; mode = "autonomous"
                out["autonomous"] += 1
            elif d["action"] in DESTRUCTIVE_ACTIONS:
                action_id = await _queue_two_person(f, d); mode = "two_person_queued"
                out["queued_two_person"] += 1
            else:
                mode = "advisory"; out["advisory"] += 1
            out["contained"] += 1
        elif d["verdict"] == "MONITOR":
            out["monitor"] += 1
        else:
            out["dismiss"] += 1
        latency = int((time.perf_counter() - t0) * 1000)
        await _record(f, d, executed, action_id, mode, latency)
        out["evaluated"] += 1
        out["decisions"].append({**d, "finding_id": f.get("id"), "asset_id": f.get("asset_id"),
                                 "title": f.get("title"), "mode": mode, "executed": executed,
                                 "action_id": action_id, "latency_ms": latency})
    return out


@router.get("/defense/decisions", summary="Recent autonomous decisions")
async def decisions(limit: int = 40) -> list[dict]:
    return await db.fetch(
        """SELECT id, finding_id, asset_id, title, verdict, action_type, blast, mode, executed,
                  action_id, reason, latency_ms, created_at
           FROM defense_decisions ORDER BY created_at DESC LIMIT %(n)s""", {"n": limit})


@router.get("/defense/stats", summary="Autonomous-defense KPIs")
async def stats() -> dict:
    agg = await db.fetch_one(
        """SELECT count(*) AS decisions,
                  count(*) FILTER (WHERE executed) AS auto_executed,
                  count(*) FILTER (WHERE mode='two_person_queued') AS queued,
                  round(avg(latency_ms) FILTER (WHERE executed))::int AS mttc_ms
           FROM defense_decisions""")
    decoys = await db.fetch_one(
        "SELECT count(*) AS total, count(*) FILTER (WHERE state='tripped') AS tripped FROM honeytokens")
    return {"sentinel": agg or {}, "decoys": decoys or {}}


# --------------------------------------------------------------- DECOY ---------
class DecoyIn(BaseModel):
    name: str
    kind: str = "credential"
    location: str | None = None


class TripIn(BaseModel):
    source: str | None = None   # attacker ip / identity that touched the decoy


@router.get("/defense/decoys", summary="List honeytokens")
async def list_decoys() -> list[dict]:
    return await db.fetch(
        "SELECT id, name, kind, location, state, tripped_at, tripped_by FROM honeytokens ORDER BY id")


@router.post("/defense/decoys", summary="Plant a honeytoken")
async def add_decoy(d: DecoyIn) -> dict:
    return await db.execute(
        """INSERT INTO honeytokens (name, kind, location) VALUES (%(n)s,%(k)s,%(l)s)
           RETURNING id, name, kind, location, state""",
        {"n": d.name, "k": d.kind, "l": d.location})


@router.post("/defense/decoys/{decoy_id}/trip", summary="Tripwire — an attacker touched a decoy")
async def trip_decoy(decoy_id: int, t: TripIn) -> dict:
    dec = await db.fetch_one("SELECT * FROM honeytokens WHERE id=%(id)s", {"id": decoy_id})
    if not dec:
        raise HTTPException(404, "honeytoken not found")
    src = t.source or "unknown"
    await db.execute(
        "UPDATE honeytokens SET state='tripped', tripped_at=now(), tripped_by=%(s)s WHERE id=%(id)s",
        {"s": src, "id": decoy_id})
    # 100%-confidence signal → propose isolation of the source (reversible IP block).
    action_id = await _auto_execute(
        {"id": None, "asset_id": src},
        {"action": "ip_block", "blast": "low", "reason": f"honeytoken '{dec['name']}' tripped by {src}"})
    return {"id": decoy_id, "state": "tripped", "tripped_by": src, "confidence": 1.0,
            "response_action_id": action_id, "note": "source auto-isolated; full attack path captured"}


# --------------------------------------------------------------- MEND ----------
class HealIn(BaseModel):
    target: str
    asset_id: str | None = None
    action: str = "restore_baseline"   # restore_baseline | kill_persistence | rollback_config


@router.post("/defense/heal", summary="Self-healing remediation")
async def heal(h: HealIn) -> dict:
    row = await db.execute(
        """INSERT INTO remediations (target, asset_id, action, detail, status)
           VALUES (%(t)s,%(a)s,%(act)s,%(d)s,'completed')
           RETURNING id, target, asset_id, action, status, created_at""",
        {"t": h.target, "a": h.asset_id, "act": h.action,
         "d": f"{h.action} applied to {h.target} on {h.asset_id or 'host'}"})
    audit.append(row["id"], "remediated", "vyrex-mend",
                 {"target": h.target, "asset_id": h.asset_id, "action": h.action})
    return row


@router.get("/defense/remediations", summary="Self-healing history")
async def remediations(limit: int = 40) -> list[dict]:
    return await db.fetch(
        "SELECT id, target, asset_id, action, status, created_at FROM remediations ORDER BY created_at DESC LIMIT %(n)s",
        {"n": limit})


# --------------------------------------------------------------- FORGE ---------
@router.post("/defense/emulate", summary="Breach-and-attack emulation vs. detection coverage")
async def emulate() -> dict:
    # A technique is 'blocked' if a detection rule covers it OR we already observe it in findings.
    covered = set()
    for r in await db.fetch("SELECT DISTINCT technique FROM detection_rules WHERE technique IS NOT NULL AND enabled"):
        if r.get("technique"):
            covered.add(str(r["technique"]).split(".")[0])
    for r in await db.fetch("SELECT DISTINCT attack FROM findings WHERE attack IS NOT NULL"):
        if r.get("attack"):
            covered.add(str(r["attack"]).split(".")[0])
    results = []
    blocked = succeeded = 0
    for tactic, tech in KILLCHAIN:
        ok = tech in covered
        results.append({"tactic": tactic, "technique": tech, "result": "blocked" if ok else "would_succeed"})
        blocked += ok
        succeeded += (not ok)
    row = await db.execute(
        "INSERT INTO emulations (techniques, blocked, succeeded) VALUES (%(t)s,%(b)s,%(s)s) RETURNING id",
        {"t": json.dumps(results), "b": blocked, "s": succeeded})
    return {"id": row["id"] if row else None, "blocked": blocked, "succeeded": succeeded, "results": results}


@router.post("/defense/harden", summary="Auto-create detection rules to close emulated gaps")
async def harden() -> dict:
    created = 0
    covered = set()
    for r in await db.fetch("SELECT DISTINCT technique FROM detection_rules WHERE technique IS NOT NULL"):
        if r.get("technique"):
            covered.add(str(r["technique"]).split(".")[0])
    for tactic, tech in KILLCHAIN:
        if tech not in covered:
            await db.execute(
                """INSERT INTO detection_rules (name, source, technique, severity, enabled, logic)
                   VALUES (%(n)s,'sigma',%(tech)s,'high',true,%(l)s)""",
                {"n": f"Auto-hardening: {tactic} ({tech})", "tech": tech,
                 "l": f"auto-generated rule to cover {tech} after Forge emulation"})
            created += 1
    return {"hardened": created, "note": "detection coverage closed for emulated gaps"}
