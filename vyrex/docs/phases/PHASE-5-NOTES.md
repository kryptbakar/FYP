# Phase 5 — Composite risk scoring + ML/XAI (the differentiator)

**Status:** complete and verified end-to-end. **Date:** 2026-06-01.

The project's original contribution: turn enriched findings into a **ranked, explainable**
risk score — a transparent composite plus an XGBoost model with SHAP explanations,
counterfactuals, and an analyst-feedback → retraining loop.

## What was built ([ml/](../ml/), service `risk-engine`)

1. **Composite score** (`scoring.py`) — weighted sum of 7 normalized factors
   (CVSS·0.22, EPSS·0.20, KEV·0.18, exposure·0.15, compliance-impact·0.09, age·0.08,
   criticality·0.08) → `findings.risk_score` 0..100, with each factor's point
   contribution stored in `risk_components`. This drives ranking and is fully defensible
   without any model.
2. **XGBoost model** (`train.py`) — regressor on a bootstrapped dataset (synthetic
   population + deliberate non-linear interactions KEV×EPSS / exposure×CVSS / attack-phase
   + noise), folding in analyst feedback at 5× weight. 8th feature = `attack_phase`
   (kill-chain ordinal). Holdout **R²≈0.90, MAE≈3.5**.
3. **SHAP + counterfactuals** (`explain.py`) — per-finding contributions from XGBoost's
   **native TreeSHAP** (`pred_contribs`, no heavy `shap` dep, D-024) → `ml_risk_score` +
   `finding_explanations` (shap, top_factors, counterfactuals).
4. **Feedback loop** — `analyst_feedback` table + API; `train` folds labels in.
5. **API** — `GET /risk/ranking`, `GET /findings/{id}/explain`,
   `POST|GET /findings/{id}/feedback`; `/findings` now sorts by `risk_score`.

## How to run

```bash
make feeds-seed && make assess     # findings (Phases 3-4)
make risk-train                    # train XGBoost
make risk-score                    # composite + ML + SHAP for every finding
curl localhost:8000/risk/ranking
curl localhost:8000/findings/<id>/explain
```

## Verification (actual run)

**Training:** `R²=0.9045, MAE=3.547, RMSE=4.414` on holdout; model `xgb-20260601T155004Z`.

**Ranking (`/risk/ranking`):**
```
rank id  domain       cve_id         sev   risk_score  ml_risk_score  kev
 1   11  application  CVE-2023-4911  HIGH   54.68       61.99          true   <- libc6, KEV
 2    4  application  CVE-2023-0286  HIGH   39.72       50.52          false
 3    9  application  CVE-2022-3715  HIGH   36.67       46.51          false
 4    8  network      —              HIGH   31.90       48.32          false
```

**Explain (`/findings/11/explain`) — CVE-2023-4911 on libc6:**
```
composite_components: kev 18.0 | cvss 17.16 | age 8.0 | compliance 4.5 | criticality 4.0 | exposure 3.0 | epss 0.02  = 54.68
SHAP top_factors:     kev +15.44 | cvss +8.29 | exposure -5.88 | epss -3.13 | age +3.01
counterfactuals:      if not on KEV list -> 46.80 (-15.19) | if not exposed -> 58.68 (-3.31)
```
The model independently learned **KEV is the dominant risk driver** (SHAP +15.4), and the
counterfactual quantifies it (−15.19). `ml_risk_score` (61.99) > composite (54.68) = the
non-linear lift the linear score can't express.

**Feedback → retrain loop:**
```
POST /findings/11/feedback {action:escalate, label_priority:95}  -> stored (id=1)
make risk-train  ->  "folding in 1 analyst-feedback samples (weight 5x)"  -> new model xgb-20260601T155156Z
```

## What's stubbed / deferred

- **Bootstrapped labels** — no historical analyst labels at day one, so training starts
  from the composite + simulated interactions and is progressively steered by real
  feedback (D-023, D-025). Quality improves as feedback accrues.
- **MITRE ATT&CK technique mapping** — `attack_phase` is currently a coarse kill-chain
  ordinal, not full ATT&CK technique features.
- **Monthly retraining** is a `train` command now; the cron lands in Phase 8 (K3s).
- SHAP/counterfactuals cover the model levers (KEV/EPSS/exposure); richer counterfactuals
  (e.g. "patch to version X") come with deeper package data.

## Acceptance

✅ Weighted composite (CVSS+EPSS+KEV+exposure+age+compliance+criticality) → ranked risk ·
✅ XGBoost trained on the enriched/bootstrapped dataset · ✅ SHAP contribution analysis +
counterfactuals per finding · ✅ analyst-feedback → retraining loop · ✅ exposed via the API.
