# Phase 4 — Compliance engine

**Status:** complete and verified, incl. tamper-evident audit chain. **Date:** 2026-06-01.

Rule-based CIS-Benchmark + org-policy evaluation of each asset's osquery state →
**pass / fail / partial / not_applicable**, with every evaluation written to a
**hash-chained, append-only evidence log** for audit traceability.

## What was built (in the enrichment service)

- **[compliance.py](../services/enrichment/compliance.py)** — 11 starter rules (CIS
  Debian 12 §1–5 flavour + org-policy): auditd, host firewall, MAC/AppArmor, time-sync,
  logging, legacy/cleartext services, cleartext listening ports, auto-updates, approved
  OS, no remote root, SSH PermitRootLogin. Each returns a status + rationale + evidence.
- **[evidence.py](../services/enrichment/evidence.py)** — the hash chain:
  `hash = SHA-256(prev_hash + canonical(record))`, genesis `0×64`, and `verify_chain`.
- **db.py / main.py** — `compliance_results` (current per-rule state, upserted) +
  `compliance_evidence` (immutable, hash-chained history). The assessment loop now runs
  both the vuln pass (Phase 3) and the compliance pass.
- **Compliance API** — `GET /compliance/results` (filter asset/status/benchmark),
  `/compliance/summary` (per-asset score), `/compliance/evidence` (audit tail),
  `/compliance/evidence/verify` (recomputes the chain, flags tampering).

## How to run

```bash
make feeds-seed   # (mirror, from Phase 3)
make assess       # runs vuln + compliance, appends evidence
curl localhost:8000/compliance/summary
curl localhost:8000/compliance/evidence/verify
```

## Verification (actual run)

**Compliance results** — 11 rules × 3 assets = 33 results: `pass 11 · fail 19 ·
not_applicable 3` (partial supported but not triggered on these minimal hosts).

Per-asset score (`/compliance/summary`):
```
asset         pass fail partial na  score%
6b369…(agent)   5    5    0      1   50.0
host-lab-01     3    7    0      1   30.0
h1              3    7    0      1   30.0
```

Sample (agent):
```
CIS-3.5.1  Ensure a host firewall is installed          fail   no host firewall package installed
CIS-4.1.1  Ensure auditd is installed                   fail   auditd not installed
CIS-2.3.1  Ensure time synchronization is in use        fail   no time-sync service installed
ORG-POL-001 Host runs an approved/supported OS          pass   Debian GNU/Linux 12 is approved
CIS-5.2.7  Ensure SSH PermitRootLogin is disabled       not_applicable  sshd_config not collected (honest)
```

**Hash-chained evidence — tamper-evident (the headline):**
```
GET /compliance/evidence/verify        -> {ok:true,  length:66, head_hash:4358c9ce…}
UPDATE compliance_evidence … seq=1     (inject a key)
GET /compliance/evidence/verify        -> {ok:false, broken_at:1, reason:"record tampered (hash mismatch)"}
UPDATE compliance_evidence … (restore) (remove the key)
GET /compliance/evidence/verify        -> {ok:true,  length:66, head_hash:4358c9ce…}   <- identical head hash
```
Editing any past record breaks the chain from that point; restoring the exact content
re-verifies to the *same* head hash. The log is append-only and grew across two runs
(service loop + one-shot) → length 66.

## What's stubbed / deferred

- **Rule coverage** — 11 representative rules, not the full CIS Debian 12 set; more rules
  are pure data (D-022). Controls needing uncollected state (sshd_config, file perms,
  sysctl, mounts) are honestly `not_applicable` until the agent's osquery pack grows.
- **External anchoring** — the chain is self-verifying; Phase 8 can anchor the head hash
  off-box (e.g. signed/notarized) for stronger guarantees.
- **`partial`** is implemented (e.g. journald-only logging) but didn't trigger on the
  minimal lab hosts.

## Acceptance

✅ Rule-based CIS + org-policy evaluation vs osquery state → pass/fail/partial ·
✅ results stored with **hash-chained evidence records** · ✅ chain integrity verifiable
and tamper-detection demonstrated · ✅ exposed via the API.
