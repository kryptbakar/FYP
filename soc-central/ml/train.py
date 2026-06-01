"""Train the XGBoost risk-prioritization model and persist it for scoring.

Regression on a 0..100 priority target. Native XGBoost (so we get exact TreeSHAP
via pred_contribs at score time, with no heavy `shap`/`numba` dependency).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import xgboost as xgb

import dataset
from features import FEATURES

log = logging.getLogger("ml.train")

MODEL_DIR = Path(os.getenv("MODEL_DIR", "/models"))
MODEL_PATH = MODEL_DIR / "risk_model.json"
META_PATH = MODEL_DIR / "meta.json"


def _metrics(y, p) -> dict:
    err = p - y
    mae = float(np.mean(np.abs(err)))
    rmse = float(np.sqrt(np.mean(err ** 2)))
    ss_res = float(np.sum(err ** 2))
    ss_tot = float(np.sum((y - np.mean(y)) ** 2)) or 1.0
    return {"mae": round(mae, 3), "rmse": round(rmse, 3), "r2": round(1 - ss_res / ss_tot, 4)}


def train(extra_X: np.ndarray | None = None, extra_y: np.ndarray | None = None,
          extra_w: np.ndarray | None = None, n: int = 6000) -> dict:
    X, y = dataset.generate_synthetic(n)
    w = np.ones(len(y))
    if extra_X is not None and len(extra_X):
        log.info("folding in %d analyst-feedback samples (weight 5x)", len(extra_X))
        X = np.vstack([X, extra_X])
        y = np.concatenate([y, extra_y])
        w = np.concatenate([w, extra_w if extra_w is not None else np.full(len(extra_y), 5.0)])

    # Shuffle + 85/15 split.
    idx = np.random.default_rng(7).permutation(len(y))
    X, y, w = X[idx], y[idx], w[idx]
    cut = int(len(y) * 0.85)
    dtr = xgb.DMatrix(X[:cut], label=y[:cut], weight=w[:cut], feature_names=FEATURES)
    dte = xgb.DMatrix(X[cut:], label=y[cut:], feature_names=FEATURES)

    params = {"objective": "reg:squarederror", "max_depth": 5, "eta": 0.1,
              "subsample": 0.9, "colsample_bytree": 0.9, "min_child_weight": 3, "seed": 7}
    booster = xgb.train(params, dtr, num_boost_round=400,
                        evals=[(dte, "test")], early_stopping_rounds=25, verbose_eval=False)

    metrics = _metrics(y[cut:], booster.predict(dte))
    version = datetime.now(timezone.utc).strftime("xgb-%Y%m%dT%H%M%SZ")
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(MODEL_PATH))
    gain = booster.get_score(importance_type="gain")
    META_PATH.write_text(json.dumps({
        "version": version, "features": FEATURES, "metrics": metrics,
        "n_samples": int(len(y)), "best_iteration": int(booster.best_iteration),
        "importance_gain": {k: round(v, 1) for k, v in gain.items()},
    }, indent=2))
    log.info("trained %s metrics=%s -> %s", version, metrics, MODEL_PATH)
    return {"version": version, "metrics": metrics}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    train()
