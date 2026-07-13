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

### A2 — Live attack-simulation validation 🔨
- ✅ `docs/VALIDATION-ATTACK-SIM.md` — full Atomic Red Team runbook + results tables.
- ⬜ **Execute it**: one victim VM + the stack, run the 7-technique kill-chain,
  fill the §5 table (latency, tools fired, fusion lift, SHAP fidelity, coverage).
- **Acceptance:** a completed results table + narrative; honest coverage number;
  ≥1 technique shown corroborated by multiple tools and ranked at the top.

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
- ✅ ML test suite expanded 1 → 5 files (fusion, features, dataset, evaluate) —
  37 tests green.
- ✅ CI runs the evaluation harnesses as a gate (`.github/workflows/ci.yml`).
- ⬜ Broaden: worker/enrichment/bridge unit tests; a compose-based end-to-end
  smoke test in CI (build all images → ingest → assess → score → assert findings).
- **Acceptance:** CI builds every image and runs an e2e smoke on each PR.

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

### B3 — The ML data problem (pilots → real labels) ⬜
- The model trains on synthetic data (`ml/dataset.py`). Productise the
  analyst-feedback loop: capture triage decisions → `analyst_feedback` → retrain
  at 5× weight (already wired in `run.py do_train`) → re-run `risk-eval` on **real**
  labels. Seed it from the attack-sim (VALIDATION §6).
- **Acceptance:** `evaluation.md` regenerated with ≥1 real-label fold; the "trained
  only on synthetic" threat-to-validity retired.

### B4 — Sell the intelligence layer, not the glue ⬜
- Reframe the 10 tool bridges as **pluggable connectors** so VYREX drops on top of
  whatever a customer already runs, rather than requiring all ten. Document a
  connector interface; make each bridge independently enable/disable-able (profiles
  already do half of this).
- **Acceptance:** a "connectors" doc + a customer can run VYREX consuming only
  their existing Wazuh/Splunk feed and still get fusion + scoring + explanation.

### B5 — Multi-tenancy & upgrade path ⬜
- Row-level tenant scoping (THREAT-MODEL TB2 IDOR) for MSSP use; a versioned
  schema-migration + rolling-upgrade story.
- **Acceptance:** two tenants' data provably isolated; a documented N→N+1 upgrade.

### B6 — Offline installer bundle ⬜
- Productise the air-gap transfer (PRODUCTION-DEPLOYMENT §3) into **one signed
  bundle** (images + feed mirror + chart + checksums), verified on load.
- **Acceptance:** `install.sh bundle.tar.sig` stands up a site with no other steps.

### B7 — Platform security sign-off ⬜
- Address THREAT-MODEL residual risks in priority order: (1) mandatory auth [B2],
  (2) tenant scoping [B5], (3) feed-signature verification, (4) per-agent ingest
  quota, (5) pin all image digests + Trivy-gate.
- **Acceptance:** each residual risk closed or explicitly accepted with rationale;
  a short pentest write-up (doubles as FYP appendix + sales asset).

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
5. **B1 broaden** e2e smoke test in CI. 1 day.
6. Everything else (B3–B7) as time allows before/after the defense; each is a
   standalone increment.

Items 1–3 alone move the project from "we built a lot" to "we built it and
measured it against baselines" — which is the top-grade differentiator.
