# VYREX — Autonomous Defense

The agentic active-defense subsystem: VYREX doesn't just *see* attacks, it **acts** on them —
deciding, containing, deceiving, healing and hardening — at machine speed, while staying
**governed, signed, and auditable**. This is *active defense inside your own walls*, never
hack-back.

> **Backend:** `services/api/app/routers/defense.py` (engine) + tables in `schema.py`.
> **Console:** Automate → **Autonomous Defense** (`web/console/assets/autonomous.js`).

---

## The safety invariant (state this first in a viva)

**Destructive, irreversible actions are *never* auto-executed.** Autonomy only ever covers
**reversible, low-blast** containment (IP block, token/session revoke, rate-limit, DNS
sinkhole). Anything irreversible (process kill, host isolation, file quarantine, account
disable) still requires **two distinct human approvers** and an Ed25519-signed command — the
exact path in `response.py`. The autonomy dial *widens* what the machine may do reversibly; it
never removes the human gate on destructive actions. **That gate is the product.**

---

## The four pillars

### 1. SENTINEL — graded-autonomy response
`POST /defense/evaluate` runs the decision engine over open findings. For each finding,
`decide()` produces a **traceable** verdict (no black box):

| Signal | Decision |
|---|---|
| risk < 30 or already triaged | **DISMISS** |
| network + live indicator, risk ≥ 88 | **CONTAIN** → `network_isolate` (destructive → two-person) |
| network + indicator/risk ≥ 75 | **CONTAIN** → `ip_block` (reversible → autonomous) |
| KEV+risk≥70, or risk≥85, or 2-tool consensus + risk≥78 | **CONTAIN** → `token_revoke` (reversible), escalating to `process_kill` (two-person) at risk≥92 |
| otherwise elevated | **MONITOR** |

The **autonomy policy** (`GET/PUT /defense/policy`, levels `advisory | reversible | full`)
decides what may auto-execute: `advisory` proposes only; `reversible` auto-runs low-blast
reversible actions; `full` extends to medium-blast reversible. Auto-executed actions are
**signed and handed to the agent through the same channel a human request uses**, and every
decision is persisted to `defense_decisions` with its latency (the sub-second MTTC).

### 2. DECOY — deception
Honeytokens (`GET/POST /defense/decoys`) — fake credentials, canary files, decoy services and
hosts — that a real user never touches. `POST /defense/decoys/{id}/trip` is the tripwire: a
single touch is a **100 %-confidence** signal that auto-proposes isolation of the source
(reversible `ip_block`) and captures the path. Legal "fight back": you weaponise *your own*
environment, you don't attack theirs.

### 3. MEND — self-healing
`POST /defense/heal` restores tampered state to the FIM baseline, kills persistence, or rolls
back hijacked config — logged to `remediations` and the hash-chained audit. The estate repairs
itself.

### 4. FORGE — continuous adversary emulation
`POST /defense/emulate` runs a breach-and-attack simulation across the kill chain against the
estate's *own* detection coverage (`detection_rules` + observed ATT&CK), reporting which
techniques **would succeed**. `POST /defense/harden` auto-creates the missing detection rules —
you're patched before the real adversary arrives.

---

## How it threads through what already exists

- **Signed channel** (`signing.py`) — autonomous reversible actions are signed exactly like
  human-approved ones; the agent verifies before executing.
- **Hash-chained audit** (`audit.py`) — every autonomous request/sign/dispatch is appended, so
  "the machine did X at 02:14, signed, here's the chain" is provable and tamper-evident.
- **Two-person rule** (`response.py`) — destructive escalations land in the same
  `pending_approval` queue humans already use.
- **Console** — the Autonomous Defense screen drives the demo and, when live, fires the real
  endpoints (so a demo creates real signed actions visible in **Cases** and the **Trust Center**
  audit timeline).

## Endpoints

```
GET  /defense/policy            PUT  /defense/policy           {level}
POST /defense/evaluate          GET  /defense/decisions        GET /defense/stats
GET  /defense/decoys            POST /defense/decoys           POST /defense/decoys/{id}/trip
POST /defense/heal              GET  /defense/remediations
POST /defense/emulate           POST /defense/harden
```

## Honest scope (for the viva)

The **decision engine, signed-action creation, audit integration, two-person gating, deception
tripwire, remediation log and emulation are real and persisted.** The one thing held back is
*live destructive execution on a production endpoint* — gated behind the autonomy dial and the
two-person rule on purpose, because a wrong auto-isolate takes down production. That is a design
decision, not a missing feature.
