# Threat model — VYREX itself

A security product is a high-value target: it holds the crown-jewel telemetry of
everything it monitors and can issue response commands to endpoints. This
document models threats **against the platform**, using STRIDE per trust
boundary, and maps each to an existing or planned control. It doubles as an FYP
appendix (evidence of security-by-design) and a buyer-facing assurance artifact.

Scope: the VYREX deployment (agents, ingest, brokers, stores, API, console,
risk-engine, response channel, feed-sync). Out of scope: the monitored assets'
own vulnerabilities (that is VYREX's *job*, not its threat model).

## 1. Assets to protect

| Asset | Why it matters |
|---|---|
| Endpoint telemetry (Timescale/OpenSearch) | Reveals the entire estate's posture; a map for an attacker |
| The response command channel | Can execute containment actions on endpoints — RCE-equivalent if hijacked |
| Audit + compliance evidence log | Its integrity is the product's trust anchor |
| CVE/EPSS/KEV mirror & enrichment | Poisoning it degrades every downstream score |
| Analyst credentials / sessions | Grant access to all of the above |
| The agent binary & its signing key | A trojaned agent is estate-wide compromise |
| The ML model & training data | Poisoning mis-prioritises real threats |

## 2. Trust boundaries

```
[Endpoints/agents] ──(TB1: mTLS)──▶ [ingest-edge] ──▶ [NATS] ──▶ [workers] ──▶ [stores]
                                                                                  │
[Analyst browser] ──(TB2: OIDC/TLS)──▶ [console/API] ──(TB3)──▶ [stores]         │
[feed-sync] ──(TB4: the ONLY egress)──▶ internet mirror ──▶ [enrichment] ────────┘
[API] ──(TB5: signed command)──▶ [agent responder] (active response)
```

- **TB1** agent ↔ ingest-edge: mutual TLS + bearer token.
- **TB2** analyst ↔ console/API: OIDC (Keycloak, K3s) + TLS.
- **TB3** API ↔ data stores: internal network, least-privilege DB roles.
- **TB4** feed-sync ↔ internet: the sole egress point, NetworkPolicy-enforced.
- **TB5** API ↔ agent responder: Ed25519-signed commands, two-person approval.

## 3. STRIDE by component

### TB1 — Agent → ingest-edge

| Threat | Vector | Control | Status |
|---|---|---|---|
| **S**poofing | Rogue agent posts fake telemetry | mTLS client cert + bearer token; unknown cert rejected | In place |
| **T**ampering | Envelope modified in transit | TLS integrity; ingest-edge schema-validates every envelope | In place |
| **R**epudiation | Agent denies sending | `event_id` + `agent_id` recorded with ingest time | In place |
| **I**nfo disclosure | Telemetry sniffed | TLS 1.2+ only | In place |
| **D**oS | Flood of envelopes | JetStream back-pressure; per-agent token-bucket rate limit in ingest-edge (429 over quota) | In place (unit-tested) |
| **E**oP | Compromised agent gains server foothold | ingest-edge is stateless, no shell, minimal image | In place |

### TB2 — Analyst → console/API

| Threat | Vector | Control | Status |
|---|---|---|---|
| **S** | Session hijack / no auth | OIDC via Keycloak (K3s) **or** local session tokens, enforced by `auth_guard` middleware; forced on in production | **Closed** — enforcement implemented (settings.auth_required); on by default when soc_env=production |
| **T** | Parameter tampering | Pydantic request models validate all input | In place |
| **R** | Analyst denies an action | Every response/approval written to hash-chained audit | In place |
| **I** | IDOR across tenants | Single-tenant today; add row-level tenant scoping | **Gap** — multi-tenancy (roadmap B5) |
| **D** | API flooding | k6-gated perf; add rate-limit middleware | Partial |
| **E** | Analyst → admin | RBAC in `auth_guard.authorize`: viewer read-only, analyst read+write, admin for response/defense | In place (unit-tested) — extend per-route as needed |

### TB4 — feed-sync (the only egress)

| Threat | Vector | Control | Status |
|---|---|---|---|
| **T** | Mirror poisoning (bad CVE/EPSS/KEV) | Feed cache is SHA-256-stamped on build and verified fail-closed on import (`integrity.py`); upstream signature-pinning is the further step | In place for the carried cache (unit-tested) |
| **I** | Egress used to exfiltrate | NetworkPolicy allows *only* feed-sync egress; `airgap-verify` proves it | In place (NFR1) |
| **E** | feed-sync compromised → pivot | Runs isolated, write-only to the mirror volume | In place |

### TB5 — Active response channel

| Threat | Vector | Control | Status |
|---|---|---|---|
| **S** | Forged command to an endpoint | Ed25519 signature; agent verifies before executing (fail-closed) | In place (D-028) |
| **T** | Replay of an old command | Nonce/expiry in signed command; agent rejects stale | Verify nonce present (roadmap check) |
| **R** | Who approved this containment? | Two-person approval + hash-chained audit | In place |
| **E** | Response used for arbitrary exec | Commands are a fixed containment allow-list, not shell | In place |

### Supply chain (agent binary + images)

| Threat | Vector | Control | Status |
|---|---|---|---|
| **T** | Trojaned agent binary | Reproducible build + cosign-signed SHA256 manifest; endpoint verifies fail-closed | In place (D-048) |
| **T** | Malicious base image / dep | Trivy scan in CI now **gates** on a fixable CRITICAL (HIGH reported); trivy-action SHA-pinned | In place — gating on; digest-pinning of base images is the remaining step |

### ML pipeline

| Threat | Vector | Control | Status |
|---|---|---|---|
| **T** | Training-data poisoning via fake analyst feedback | Authenticated + audited; `ml/feedback.py` sanity bounds drop NaN/inf/out-of-range labels and cap feedback to ≤25% of training mass | In place (unit-tested) |
| **I** | Model inversion leaks estate detail | Model outputs a priority score only, no raw features exposed | In place |

## 4. Residual risks & priorities

Ranked, and mapped to the roadmap:

1. ~~API auth optional in non-K3s deploys~~ → **Closed**: `auth_guard` middleware
   enforces authentication + RBAC on every non-public route, forced on in production
   (ROADMAP B2). This was the highest priority — it gated every other TB2 control.
2. **Single-tenant IDOR surface** → row-level tenant scoping (ROADMAP B5). *(Open — needs a schema change.)*
3. ~~Mirror-poisoning of the feed~~ → **Closed** for the carried cache: `integrity.py`
   SHA-256 stamp + fail-closed verify. Upstream signature-pinning is a further step.
4. ~~Per-agent ingest quota~~ → **Closed**: token-bucket rate limit in ingest-edge.
5. **Image base-digests not all pinned** → Trivy now gates on fixable CRITICAL;
   pinning base-image digests still requires a connected build to capture them.

(ML training-data poisoning is closed — see the ML pipeline row: `ml/feedback.py`
bounds + influence cap. Of the original six residual risks, four are now closed;
the two open items — multi-tenancy and base-digest pinning — each need a schema
change or a connected build and are scoped above.)

## 5. How this was derived

STRIDE applied per trust boundary (Microsoft SDL method), assets and boundaries
taken from docs/ARCHITECTURE.md, controls cross-referenced to the decision log
(D-028 command signing, D-048 supply chain). Re-run this analysis whenever a new
trust boundary is added (e.g. a new external connector), and validate the "in
place" controls with the security-review skill and a lab pentest before any real
deployment.
