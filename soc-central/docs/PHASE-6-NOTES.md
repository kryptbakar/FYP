# Phase 6 — Incident management + active response

**Status:** complete and verified end-to-end, incl. tamper/forgery refusal. **Date:** 2026-06-01.

Incident lifecycle over the findings, plus a **signed, two-person-approved** containment
command channel with a **hash-chained audit** — the analyst-controlled response half of the
intelligence layer.

## What was built

**Incident management** (API, `routers/incidents.py`, schema in `app/schema.py`):
- `incidents` (open/in_progress/resolved/closed, assignee, **SLA** due from severity),
  `incident_findings` (linked evidence).
- `POST /incidents` (open, optionally from findings), `GET /incidents` (with SLA-breach
  flag + finding count), `GET /incidents/{id}` (detail + findings + actions),
  `PATCH /incidents/{id}` (status/assignee/severity), `POST /incidents/{id}/findings`.

**Active response** (`routers/response.py`, `signing.py`, `audit.py`; agent `responder.go`):
- `response_actions` lifecycle: `pending_approval → approved → dispatched → completed |
  failed | verify_failed | rejected`.
- **Two-person approval** (D-027), **Ed25519-signed commands** (D-028), **hash-chained
  `action_audit`** (D-026).
- Endpoints: `POST /incidents/{id}/actions`, `POST /actions/{id}/approve|reject`,
  `GET /actions`, agent channel `GET /v1/agents/{id}/commands` + `POST /v1/commands/{id}/result`,
  `GET /response/audit/verify`.
- **Agent responder** polls, verifies each command's signature against the **provisioned**
  server public key, and executes containment: `file_quarantine`, `process_kill`,
  `network_isolate` (nftables), `user_disable` (usermod) — containment only, no patching.

## How to run

```bash
make up && make agent-run                          # stack + agent (signing key from `make certs`)
# via API (see docs/PHASE-6-NOTES for the full demo):
POST /incidents {title, severity, finding_ids}
POST /incidents/{id}/actions {agent_id, action_type:"file_quarantine", params:{path}}
POST /actions/{id}/approve {approver: alice}       # then a DIFFERENT approver: bob
# agent polls, verifies signature, executes; check /actions and /response/audit/verify
```

## Verification (actual run)

**Incident + two-person rule:**
```
POST /incidents (high, linked finding) -> id=1, sla_due = +24h
POST /incidents/1/actions file_quarantine /watch/malware.sh -> pending_approval
approve by requester (hamza) -> 403 "separation of duties: requester cannot approve own action"
approve alice -> 1/2 ; approve bob -> 2/2 -> status=approved, signed=true
```

**Agent executed the signed command:**
```
/watch  -> empty (malware.sh gone)
/quarantine/malware.sh.quarantined  (mode 000, neutralized)
GET /actions -> id=1 status=completed, result="quarantined /watch/malware.sh -> /quarantine/... (mode 000)"
```

**Hash-chained audit — tamper-evident:**
```
/response/audit/verify -> ok, length 6 (requested, approved×2, signed, dispatched, completed)
UPDATE action_audit seq=3 -> verify ok:false, broken_at:3, "record tampered"
restore -> ok, identical head hash
```

**Forged command refused (signed channel works):**
```
(agent stopped) approve action 2 -> signed ; tamper signed_payload in transit ; (agent started)
agent log: "REFUSED command: signature verification failed" action=2
action 2 status=verify_failed ; /etc/hostname NOT touched  <- destructive action did not run
```

## What's stubbed / deferred

- **Transport:** agent↔API command poll uses the shared bearer token; the *command* is the
  real security boundary (signed + verified). Full mTLS-everywhere is Phase 8 (D-028).
- **Executors in a container:** `file_quarantine`/`process_kill` work on container-local
  targets; `network_isolate` (nftables) / `user_disable` (usermod) attempt the real action
  and report graceful failure where the lab container lacks privileges — honest, not
  silently "successful". On a real host with caps they execute.
- **SLA escalation/notifications** and richer incident workflow (comments, timelines) are
  console features (Phase 7).
- External anchoring of the audit head hash → Phase 8.

## Acceptance

✅ Incident lifecycle (open/in-progress/resolved) + assignment + SLA + linked evidence ·
✅ active-response (kill/isolate/quarantine/disable) over a **signed** command channel ·
✅ per-action **hash-chained audit** + verify · ✅ **two-person approval** for destructive
actions · ✅ forged/tampered command refused.
