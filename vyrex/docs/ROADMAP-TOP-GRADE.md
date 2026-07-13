# VYREX roadmap — from "built a lot" to top-graded FYP **and** a real product

The build is complete (README §Status). What separates a *demo-grade* project
from a **top-graded FYP and an investable startup** is not more features — it is
**evidence it works** (measured, not asserted) and **hardening for real use**.
This is the master checklist for that, organised so every item has a concrete
deliverable and an acceptance criterion. Check items off as you go.

Legend: ✅ done in this repo · 🔨 harness/skeleton in place, needs a real run ·
⬜ not started.

---

## Part A — Academic: make it defensible (the FYP gap)

> Examiner's first question: *"How do you know it works, and how well?"* These
> items answer it. **Do A1–A3 before the defense; they are the highest-value work.**

### A1 — Risk/fusion engine evaluation ✅ (harness) 🔨 (write-up)
- ✅ `ml/evaluate.py` — ranking experiment: CVSS-only vs composite vs ML on a
  held-out population; Spearman, NDCG@k, precision@k, KEV-capture; JSON + markdown
  report. Run: `make risk-eval` (or `python ml/evaluate.py`).
- ✅ `ml/eval_fusion.py` — dedup false-merge / missed-merge rates on a labeled
  sample (`ml/tests/fixtures/fusion_labeled.json`). Run: `make fusion-eval`.
- ✅ Unit tests pin every metric (`ml/tests/test_evaluate.py`) and the
  model-beats-baseline claim as a regression gate.
- 🔨 **Deliverable:** paste `reports/evaluation.md` + `reports/fusion_evaluation.md`
  into the report's evaluation chapter; discuss the KEV-capture and Spearman gaps.
- **Acceptance:** report shows composite ≫ CVSS-only on Spearman and ML ≥ composite;
  false-merge < missed-merge (precision-first). Both already hold on synthetic data.

### A2 — Live attack-simulation validation 🔨 (live) ✅ (offline half)
- ✅ `docs/VALIDATION-ATTACK-SIM.md` — full Atomic Red Team runbook + results tables.
- ✅ **Automated offline half:** `ml/attack_scenario.py` (+ `make attack-scenario`, CI
  gate, `ml/tests/test_attack_scenario.py`) runs the fusion + ranking logic over a
  scripted multi-tool intrusion and asserts consensus, fusion lift, and exploit-aware
  ordering — no VM needed. This validates the *intelligence layer* on an attack
  narrative; it does not replace sensor-based detection.
- ⬜ **Live half (needs a lab):** one victim VM + the stack, run the 7-technique
  kill-chain, fill the §5 table (latency, tools fired, SHAP fidelity, coverage).
- **Acceptance:** offline property checks green (met); live results table is the
  lab-dependent remainder.

### A3 — Performance benchmarks 🔨
- ✅ `docs/BENCHMARKS.md` protocol + `tools/fake-producer/e2e_latency.py` probe +
  `make bench-ingest` / `make bench-e2e` targets.
- ⬜ **Run them** on representative hardware; fill the §4 result tables + §1 env.
- **Acceptance:** real events/sec, p50/p95/p99 latency, and footprint numbers in
  the report; capacity model (§3) derived from them.

### A4 — Methodology framing ✅
- ✅ `docs/METHODOLOGY.md` — Design-Science (DSRM) framing, FR/NFR requirements
  table tied to evaluations, DECISIONS.md as the audit trail, SIEM comparison
  (Wazuh/Elastic/Splunk/VYREX).
- 🔨 **Deliverable:** adopt this as the report's methodology + evaluation chapters;
  verify the comparison-table cells against current product docs before submission.

### A5 — Threat model of the platform ✅
- ✅ `docs/THREAT-MODEL.md` — STRIDE per trust boundary, controls mapped to
  decisions, residual risks ranked.
- 🔨 **Deliverable:** include as a report appendix; run the security-review skill
  + a lab pentest to validate the "in place" controls (feeds Part B).

---

## Part B — Product: make it real (the startup gap)

> Due-diligence's first question: *"Is this a demo or a product?"* These harden it.

### B1 — Tests & CI ✅ (expanded) 🔨 (broaden)
- ✅ ML test suite expanded 1 → 5 files (fusion, features, dataset, evaluate);
  API suite gained `test_auth_guard.py` — 55 tests green.
- ✅ CI runs the evaluation harnesses as a gate (`.github/workflows/ci.yml`).
- ✅ **Compose end-to-end smoke** (`deploy/smoke/compose-smoke.sh` + `compose-smoke`
  CI job): builds the stack → seeds the feed mirror → ingests scanner findings →
  pushes telemetry → assesses → trains + scores → **asserts findings exist and
  carry a risk_score**. This is the "demo or product?" gate.
- ✅ Enrichment component tests: `services/enrichment/tests/` covers version→CVE
  range matching (security-critical) and the compliance engine — 22 tests. Total
  suite now **77 tests** across ml / api / enrichment.
- ⬜ Broaden further: worker/bridge unit tests.
- **Acceptance:** CI builds every image and runs an e2e smoke on each PR — met.

### B2 — Mandatory authentication (security-critical) ✅
- ✅ `services/api/app/auth_guard.py` — middleware enforcing authentication + RBAC on
  every non-public route. Two identity sources (oauth2-proxy/Keycloak headers OR local
  session token); roles: viewer read-only, analyst read+write, admin for
  response/defense. Agent routes gated by the agent token.
- ✅ Off by default in dev (`settings.auth_required`), **forced on when
  soc_env=production** — production can never run unauthenticated.
- ✅ Unit-tested (`services/api/tests/test_auth_guard.py`): 401 unauth, viewer→403 on
  write, analyst→403 on response routes, admin allowed, production-forces-auth.
- ✅ `.env.example` documents `API_AUTH_REQUIRED`; deployment checklist updated.
- 🔨 **Optional next:** per-route dependency annotations for finer-grained scopes
  beyond the middleware's method/prefix policy.

### B3 — The ML data problem (pilots → real labels) 🔨 (loop hardened, needs pilot data)
- ✅ The analyst-feedback loop is wired AND hardened: `run.py do_train` folds
  `analyst_feedback` in, now via `ml/feedback.py` sanity bounds (drop NaN/inf/
  out-of-range) with a 25%-of-training-mass influence cap so a hostile batch can't
  swamp the prior. Unit-tested.
- ⬜ **Needs real data (pilot):** capture triage decisions in a deployment →
  re-run `risk-eval` on **real** labels. Seed it from the attack-sim (VALIDATION §6).
- **Acceptance:** `evaluation.md` regenerated with ≥1 real-label fold; the "trained
  only on synthetic" threat-to-validity retired. (Loop is ready; only real telemetry
  is outstanding — inherently pilot-dependent.)

### B4 — Sell the intelligence layer, not the glue ✅ (spec) 🔨 (SDK)
- ✅ `docs/CONNECTORS.md` — formalises the contract the bridges already implement:
  two connector shapes (telemetry / finding), the Envelope v1 + `findings`/`dedup_key`
  requirements, and the opt-in enable/disable model. A new connector for an unseen
  tool is one file, no core changes.
- ✅ Documented that a customer can run VYREX over **only** their existing tool (e.g.
  `--profile hostmon` for Wazuh alone) and still get fusion + scoring + SHAP.
- 🔨 **Next (product):** a thin `connector-sdk` base class, a connector health surface
  in the console, and a bring-your-own-SIEM (Splunk/Elastic) finding connector.
- **Acceptance:** connectors doc ✅; single-tool operation ✅; SDK is the follow-on.

### B5 — Multi-tenancy & upgrade path ⬜
- Row-level tenant scoping (THREAT-MODEL TB2 IDOR) for MSSP use; a versioned
  schema-migration + rolling-upgrade story.
- **Acceptance:** two tenants' data provably isolated; a documented N→N+1 upgrade.

### B6 — Offline installer bundle ✅
- ✅ `tools/airgap/bundle.sh` (build side) packages every image (`docker save`), the
  feed/tool mirror volumes, the compose/Make config, and a `SHA256SUMS` manifest into
  one directory. `tools/airgap/install.sh` (air-gap side) **verifies the checksums
  fail-closed**, loads images, restores volumes, and brings the stack up — no internet.
- ✅ `make bundle` / `make install-offline`; PRODUCTION-DEPLOYMENT §3 references them.
- 🔨 **Next:** cosign-sign the manifest (reuse the D-048 agent-signing key) so the
  bundle is not just checksummed but signed.
- **Acceptance:** one bundle dir + `bash install.sh` stands up a site — met (signing
  is the hardening follow-on).

### B7 — Platform security sign-off 🔨 (in progress)
- ✅ (1) mandatory auth [B2] — done.
- ✅ ML training-data poisoning — `ml/feedback.py` bounds + influence cap [B7 this pass].
- ⬜ (2) tenant scoping [B5]; (3) feed-signature verification (touches feed-sync);
  (4) per-agent ingest quota (touches ingest-edge, Go); (5) pin all image digests +
  Trivy-gate (flip the existing Trivy job `exit-code` to 1).
- ⬜ Short pentest write-up (run the security-review skill + a lab pass).
- **Acceptance:** each residual risk closed or explicitly accepted; two of the six are
  now closed, the rest are scoped in THREAT-MODEL §4.

---

## Part C — Positioning (the pitch)

The defensible wedge — say it plainly in both the viva and any pitch:

> VYREX is not trying to out-feature Splunk. It is the **air-gapped, on-prem SOC
> intelligence layer** for government and defence-adjacent orgs (motivating
> stakeholder: PITB) that cannot use foreign SaaS SIEMs. Its original contribution
> is **fusion + exploit-aware, explainable prioritisation** over best-in-class OSS
> — turning ten disjoint consoles into one ranked, explained queue, with zero live
> internet calls. That constraint (air-gap) is the moat.

- **FYP framing:** original contribution = the intelligence layer, evaluated three
  ways (experiment A1, adversary emulation A2, systems benchmark A3).
- **Startup framing:** niche where incumbents structurally can't play (data can't
  leave the premises), OSS-cost base, feedback loop that improves with each pilot.

---

## Suggested order of work

1. **A1 write-up** (harness already runs — just generate + discuss the report). ½ day.
2. **A2 execute** the attack simulation — the single highest-value viva artifact. 1–2 days.
3. **A3 run** the benchmarks on your hardware, fill the tables. ½ day.
4. ~~B2 mandatory auth~~ — ✅ done (enforcement middleware + RBAC + tests).
5. ~~B1 e2e smoke in CI~~ — ✅ done (`compose-smoke` builds the stack and asserts
   findings are produced + scored). Remaining: more component unit tests.
6. Everything else (B3–B7) as time allows before/after the defense; each is a
   standalone increment.

Items 1–3 alone move the project from "we built a lot" to "we built it and
measured it against baselines" — which is the top-grade differentiator.
