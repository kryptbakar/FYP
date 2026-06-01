"""Per-finding explanations: SHAP contributions + counterfactuals.

SHAP values come from XGBoost's native TreeSHAP (`pred_contribs=True`) — exact,
fast, and dependency-light. Counterfactuals answer the analyst's "what would lower
this?" by flipping the highest-risk levers (KEV, EPSS, exposure) and re-scoring.
"""
from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import xgboost as xgb

from features import FEATURES

MODEL_PATH = Path(os.getenv("MODEL_DIR", "/models")) / "risk_model.json"


class Explainer:
    def __init__(self, booster: xgb.Booster):
        self.booster = booster

    @classmethod
    def load(cls) -> "Explainer | None":
        if not MODEL_PATH.exists():
            return None
        b = xgb.Booster()
        b.load_model(str(MODEL_PATH))
        return cls(b)

    def predict(self, vectors: list[list[float]]) -> np.ndarray:
        return self.booster.predict(xgb.DMatrix(np.array(vectors, dtype=float), feature_names=FEATURES))

    def explain(self, vector: list[float]) -> dict:
        dm = xgb.DMatrix(np.array([vector], dtype=float), feature_names=FEATURES)
        pred = float(self.booster.predict(dm)[0])
        contribs = self.booster.predict(dm, pred_contribs=True)[0]  # n_features + bias
        base = float(contribs[-1])
        shap = {FEATURES[i]: round(float(contribs[i]), 3) for i in range(len(FEATURES))}
        top = sorted(shap.items(), key=lambda kv: abs(kv[1]), reverse=True)[:5]
        return {
            "ml_risk_score": round(pred, 2),
            "base_value": round(base, 2),
            "shap": shap,
            "top_factors": [{"feature": k, "contribution": v,
                             "direction": "increases" if v >= 0 else "decreases"} for k, v in top],
            "counterfactuals": self._counterfactuals(vector, pred),
        }

    def _counterfactuals(self, vector: list[float], pred: float) -> list[dict]:
        idx = {f: i for i, f in enumerate(FEATURES)}
        out = []
        for feat, label, newval in [
            ("kev", "if not on the KEV list", 0.0),
            ("epss", "if exploitation became unlikely (EPSS≈0)", 0.0),
            ("exposure", "if the asset were not network-exposed", 0.0),
        ]:
            if vector[idx[feat]] == newval:
                continue
            v2 = list(vector)
            v2[idx[feat]] = newval
            new_pred = float(self.predict([v2])[0])
            out.append({"change": label, "new_score": round(new_pred, 2),
                        "delta": round(new_pred - pred, 2)})
        return out
