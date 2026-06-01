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

## Files
`scoring.py` weights/composite · `features.py` 8-feature vector + context ·
`dataset.py` bootstrapped training set (synthetic + interactions + feedback) ·
`train.py` XGBoost train/eval/save · `explain.py` TreeSHAP + counterfactuals ·
`db.py` read findings/context, write risk + explanations · `run.py` CLI.

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
MITRE ATT&CK technique mapping (current attack-phase is a coarse kill-chain ordinal);
real labeled history; monthly retraining cron (Phase 8). Model metrics live in
`/models/meta.json`.
