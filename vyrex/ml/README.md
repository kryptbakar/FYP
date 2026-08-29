# ml — risk-engine (composite score + XGBoost/SHAP)

**Built in:** Phase 5 · **Language:** Python · **Role:** the intelligence-layer differentiator

Turns enriched findings into a **ranked, explainable risk score**. Two layers:

1. **Composite score** (`scoring.py`) — a transparent weighted sum of 7 factors
   (CVSS, EPSS, KEV, exposure, compliance-impact, age, criticality) → `risk_score` 0..100,
   with each factor's point contribution stored. This is the ranking driver and is fully
   defensible without any model.
2. **ML model** (`train.py`, `explain.py`) — an **XGBoost** regressor that learns the
   **non-linear interactions** the linear score misses (KEV×EPSS, exposure×CVSS,
   attack-phase). Per-finding **SHAP** contributions come from XGBoost's native TreeSHAP
   (`pred_contribs`), plus **counterfactuals** ("if not KEV → score drops 18"). Adds an
   8th *attack_phase* feature (kill-chain ordinal), adapting the Attack-Phase-Aware reference.

```
findings + asset context ──▶ features (8) ──▶ composite (risk_score, components)
                                          └──▶ XGBoost ──▶ ml_risk_score + SHAP + counterfactuals
analyst_feedback ─────────────────────────────────────▶ retrain (higher-weighted labels)
```

## Phase F — the AI Fusion Engine
The engine is now **multi-tool**. Before scoring, `fusion.py` groups findings from all
tools by their `dedup_key` into clusters, records *which* tools agree, and derives a
**consensus weight** (1 tool→0, 2→0.5, 3+→1.0). That weight plus the inherited
threat-intel (MISP IOC) and ATT&CK context (OpenCTI/Sigma) become **3 new features**,
lifting the vector from 8 to **11** and the composite from 7 to **10 weighted factors**
(still summing to 1.0). SHAP now also emits a **waterfall** (base → each factor → final)
for the console. Dedup rules + consensus formula: **[FUSION.md](FUSION.md)**.

## Inapplicable is not zero (2026-08-30, D-063)

The ten weights sum to 1.0 only if all ten questions can be asked of one finding, and
they never can — the factor sets are close to disjoint by finding type. A package
vulnerability has CVSS/EPSS/KEV but cannot match a network IOC; an IP indicator has
threat-intel and consensus but has no CVE, so EPSS and KEV are *undefined* for it.

Scoring the undefined factors 0 charged each type for the other's evidence and capped
**both** below the band thresholds. On 63 real findings that produced **0 critical and 0
high** — including an actively exploited CVSS-10 backdoor (54.7) and a Cobalt Strike C2
beacon three tools agreed on (57.5). Both were at their structural ceiling, and it is why
Phase 0 recorded that an automatic trigger at 60/80 "fires on nothing".

`features.applicability()` now marks the factors a finding *cannot* evidence and
`scoring.composite()` renormalises over the weight actually in play. Components are scaled
by the same divisor, so the XAI waterfall still sums to the score, and an inapplicable
factor is stored as `null` — the console renders it as an em dash, never a confident `0.0`.

**The distinction the whole thing rests on:**

| | meaning | treatment |
|---|---|---|
| `consensus: 0` | one tool reported it — we looked | **real negative, keeps its weight** |
| `threat_intel: 0` on a package | no IOC can match a version string | **undefined, consumes no weight** |

Without that line this is a score-inflation knob, so
`tests/test_applicability.py::test_evidence_bearing_factors_are_never_marked_inapplicable`
asserts the six evidenceable factors can never be excluded.

Measured: bands `0/0/19/42` → **1 critical, 8 high, 40 medium, 14 low**; range 18.9–57.5 →
30.9–83.4. Live three-tool C2 (83.4) now outranks latent KEV CVEs (60.8).

⚠️ **Rank agreement with the XGBoost score FELL, 0.965 → 0.808.** That is expected and is
not a regression: `dataset.py:_label` starts from `composite(fd)`, so the model was trained
on the pre-renormalisation composite and its old agreement was arithmetic, not evidence.
Retraining would deepen the circularity, not resolve it. Only analyst labels can say which
ranking is right — see [EVALUATION-PROTOCOL.md](../docs/EVALUATION-PROTOCOL.md).

`evaluate.py` and `dataset.py` call `composite()` **without** an applicability map, so they
score exactly as before; the harnesses did not silently change meaning.

## Files
`scoring.py` weights/composite (10 factors) · `features.py` 11-feature vector + context ·
`fusion.py` **dedup + consensus front-end (Phase F)** ·
`dataset.py` bootstrapped training set (synthetic + interactions + feedback) ·
`train.py` XGBoost train/eval/save · `explain.py` TreeSHAP + waterfall + counterfactuals ·
`db.py` read findings/context, write risk + consensus + explanations · `run.py` CLI.

## Run

```bash
make feeds-seed && make assess     # produce findings first (Phases 3-4)
make risk-train                    # train XGBoost (synthetic + any analyst feedback)
make risk-score                    # composite + ML + SHAP for every finding
curl localhost:8000/risk/ranking
curl localhost:8000/findings/<id>/explain
```

Why no `shap` package? XGBoost computes exact TreeSHAP itself — same maths, far smaller
image (D-024). Why bootstrap labels? No historical labels at day one; analyst feedback
progressively steers the model (D-025).

## Deferred
Real labeled history (still bootstrapping from synthetic + feedback); the monthly
retraining cadence is wired in code (feedback folded at 5× on every `train`) but the
scheduler itself lands with K3s CronJobs in Phase 8. Model metrics live in
`/models/meta.json`.
