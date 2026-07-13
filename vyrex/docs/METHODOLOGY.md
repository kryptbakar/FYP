# Research methodology

This document gives the FYP report its academic spine. VYREX is an engineering
artifact, so the natural frame is **Design-Science Research (DSR)** — the
Hevner/Peffers paradigm for building and rigorously evaluating an IT artifact
that solves a real organisational problem. This chapter states the problem, the
requirements it must meet, the artifact, and — critically — *how the artifact is
evaluated against those requirements*. Evaluation is what turns "we built a lot"
into a defensible result.

## 1. Problem statement

Public-sector and defence-adjacent organisations in Pakistan (the motivating
stakeholder is PITB) need a Security Operations Centre that can run **fully
air-gapped / on-premises**. Commercial SaaS SIEMs (Splunk Cloud, Microsoft
Sentinel, Elastic Cloud) are non-starters where data cannot leave the premises
and no host may reach the internet. The open-source alternatives solve pieces
(Wazuh for host security, Suricata/Zeek for network, Trivy/Nuclei for
vulnerabilities) but leave the analyst drowning: each tool has its own console,
its own severity scale, and no shared notion of *which finding to work first*.

**The gap VYREX addresses:** not another detector, but the **intelligence layer**
that fuses many independent detectors, prioritises with exploit-aware,
explainable scoring, and does it all without a single live internet call.

## 2. Design-science process (Peffers DSRM)

| DSRM activity | Where it lives in this project |
|---|---|
| 1. Problem identification | §1 above; stakeholder = PITB air-gapped SOC |
| 2. Objectives of a solution | §3 requirements (functional + non-functional) |
| 3. Design & development | The artifact: `vyrex/` — 4 layers, 10 tool integrations, fusion engine (docs/ARCHITECTURE.md) |
| 4. Demonstration | LIVE demo path (README) + attack simulation (docs/VALIDATION-ATTACK-SIM.md) |
| 5. Evaluation | `ml/evaluate.py`, `ml/eval_fusion.py`, docs/BENCHMARKS.md, the attack-sim study |
| 6. Communication | The FYP report + this repo's docs + the DECISIONS log |

The **49 logged design decisions** (docs/DECISIONS.md) are the DSR audit trail:
each records context → decision → rationale → alternatives, which is exactly the
"design as a search process" evidence a DSR evaluation expects. Cite specific
decisions in the report (e.g. D-028 signed command channel, D-048 signed agent
supply chain) rather than describing choices generically.

## 3. Requirements (the yardstick for evaluation)

State requirements as testable objectives so §5 can score each one.

### Functional (FR)

| ID | Requirement | Evaluated by |
|---|---|---|
| FR1 | Collect endpoint telemetry (process, network, FIM, osquery) over a secure channel | Attack-sim: agent findings appear (VALIDATION §5) |
| FR2 | Ingest and normalise ≥10 OSS security tools to one envelope | Integration phases A–E; tool-profile bring-up |
| FR3 | Enrich CVEs with CVSS + EPSS + KEV from a local mirror | `make assess`; enrichment fixtures |
| FR4 | Prioritise findings with an exploit-aware score | `ml/evaluate.py` ranking experiment |
| FR5 | Explain every score (per-finding factor attribution) | SHAP waterfall; composite factor breakdown |
| FR6 | Deduplicate + corroborate across tools (consensus) | `ml/eval_fusion.py` merge-rate study |
| FR7 | Analyst-controlled, signed active response | D-028; response router + audit chain |

### Non-functional (NFR)

| ID | Requirement | Target | Evaluated by |
|---|---|---|---|
| NFR1 | Air-gapped: only `feed-sync` egresses | 0 other egress | `make airgap-verify` |
| NFR2 | Ingest throughput | (set from B1) | docs/BENCHMARKS.md B1 |
| NFR3 | End-to-end latency | p95 target | docs/BENCHMARKS.md B2 |
| NFR4 | API responsiveness under load | p95 < 400 ms | k6 gate (B3) |
| NFR5 | Tamper-evidence of audit + compliance | hash-chain verifies | audit-chain tests |
| NFR6 | Explainable & reproducible ML | R² + fixed seeds | evaluate.py regression + seeds |

## 4. Evaluation strategy

Three complementary methods, each answering a different examiner question:

1. **Controlled experiment (quantitative, in-silico).** `ml/evaluate.py` compares
   three rankers — CVSS-only baseline, VYREX composite, VYREX ML — on a held-out
   population with metrics (Spearman, NDCG@k, precision@k, KEV-capture). This
   isolates the contribution of the intelligence layer. `ml/eval_fusion.py` does
   the same for dedup with pairwise false/missed-merge rates on a labeled sample.
   *Threat to validity (stated openly):* ground truth is synthetic analyst
   judgement until real `analyst_feedback` accrues — the harness re-runs unchanged
   on real labels.
2. **Adversary emulation (behavioural, out-of-distribution).** The Atomic Red
   Team study (docs/VALIDATION-ATTACK-SIM.md) runs real techniques against a
   monitored host and measures detection coverage, latency, fusion lift, and
   explanation fidelity on events the system has never seen.
3. **Performance & resource benchmarking (systems).** docs/BENCHMARKS.md measures
   throughput, latency, and footprint with in-repo harnesses, feeding the capacity
   model in the deployment guide.

## 5. Competitive comparison

The intelligence-layer contribution is clearest against what a buyer would
otherwise deploy. This table belongs in the report's evaluation chapter (verify
each cell against current product docs before submission — capabilities change).

| Capability | Wazuh (alone) | Elastic Security | Splunk ES | **VYREX** |
|---|---|---|---|---|
| Fully air-gapped, no telemetry egress | Yes | Self-managed only | Self-managed only | **Yes, verified (`airgap-verify`)** |
| Host + network + vuln + intel in one pipeline | Host-centric | Broad (paid tiers) | Broad (paid) | **Yes, 10 OSS tools normalised** |
| Cross-tool consensus / dedup as a ranking signal | No | Correlation rules (manual) | Correlation searches (manual) | **Yes, automatic (fusion engine)** |
| Exploit-aware scoring (EPSS + KEV) built in | Partial (CVSS) | Via integrations | Via apps | **Yes, native factor weights** |
| Per-finding ML explanation (SHAP) | No | ML tier, limited explain | MLTK, limited explain | **Yes, exact TreeSHAP per finding** |
| Signed, two-person active response | Limited | Via connectors | Via SOAR (paid) | **Yes, Ed25519 + approval (D-028)** |
| Cost model | Free/OSS | Paid tiers | Licensed | **OSS + on-prem** |
| Analyst re-training loop (feedback → model) | No | Limited | Limited | **Yes (`analyst_feedback` → retrain)** |

The honest framing for the viva: VYREX does **not** out-feature Splunk on breadth
of connectors or scale-out maturity. Its thesis is that for the **air-gapped,
budget-constrained, prioritisation-overwhelmed** SOC, a fusion-and-explanation
layer over best-in-class OSS beats both "one big vendor" and "ten disjoint
consoles." The evaluation in §4 is what substantiates that thesis.

## 6. Ethics & scope

- All attack simulation runs in an isolated lab against systems the team owns
  (docs/VALIDATION-ATTACK-SIM.md §1). No third-party systems are touched.
- Active response is containment-only and requires two-person approval (D-028);
  no destructive actions are automated.
- Threats to the platform itself are analysed in docs/THREAT-MODEL.md.
