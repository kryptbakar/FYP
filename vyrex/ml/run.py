"""risk-engine CLI: train the model, or score findings (composite + ML + SHAP).

  python run.py train          # (re)train XGBoost on synthetic + analyst feedback
  python run.py score          # score every finding once
  python run.py score --loop   # keep scoring on an interval
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path

import numpy as np

import db
import features
import fusion
import scoring
import train as trainer
from explain import Explainer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("risk-engine")

META_PATH = Path(os.getenv("MODEL_DIR", "/models")) / "meta.json"


def dsn() -> str:
    e = os.environ.get
    return (f"host={e('POSTGRES_HOST', 'postgres')} port={e('POSTGRES_PORT_INTERNAL', '5432')} "
            f"dbname={e('POSTGRES_DB', 'soc_central')} user={e('POSTGRES_USER', 'soc')} "
            f"password={e('POSTGRES_PASSWORD', 'soc')}")


def model_version() -> str | None:
    try:
        return json.loads(META_PATH.read_text()).get("version")
    except Exception:
        return None


def do_train() -> None:
    pg = db.connect(dsn())
    db.ensure_schema(pg)
    ctx = db.load_context(pg)
    # Consensus weight is a training feature too: recompute clusters over all findings
    # so each labelled feedback row gets the same _consensus its scoring run saw.
    clusters = fusion.build_clusters(db.load_findings(pg))
    fb = db.load_feedback(pg)
    extra_X, extra_y = [], []
    for row in fb:
        row["_consensus"] = clusters.get(row["id"], {}).get("weight", 0.0)
        fd = features.build(row, ctx)
        extra_X.append(features.to_vector(fd))
        extra_y.append(float(row["label_priority"]))
    pg.close()
    res = trainer.train(
        extra_X=np.array(extra_X) if extra_X else None,
        extra_y=np.array(extra_y) if extra_y else None,
    )
    log.info("training done: %s", res)


def do_score_once(pg, ctx, explainer, mver) -> int:
    findings = db.load_findings(pg)
    # Fusion stage: dedup into clusters + derive each finding's consensus weight, and
    # persist the cluster record (which tools agree) onto every member.
    clusters = fusion.build_clusters(findings)
    corroborated = 0
    band_counts: dict[str, int] = {}
    for fr in findings:
        con = clusters.get(fr["id"])
        if con:
            db.write_consensus(pg, fr["id"], con)
            fr["_consensus"] = con["weight"]
            if con["n_tools"] > 1:
                corroborated += 1
        fd = features.build(fr, ctx)
        comp, components = scoring.composite(fd)
        ml_score = None
        if explainer is not None:
            exp = explainer.explain(features.to_vector(fd))
            ml_score = exp["ml_risk_score"]
            db.upsert_explanation(pg, fr["id"], exp, mver)
        db.write_risk(pg, fr["id"], comp, components, ml_score, mver)
        band_counts[scoring.band(comp)] = band_counts.get(scoring.band(comp), 0) + 1
    db.recompute_ranks(pg)
    log.info("scored %d findings; %d corroborated by >1 tool; composite bands=%s; model=%s",
             len(findings), corroborated, band_counts, mver or "none")
    return len(findings)


def do_score(loop: bool, interval: int) -> None:
    pg = db.connect(dsn())
    db.ensure_schema(pg)
    explainer = Explainer.load()
    if explainer is None:
        log.warning("no model found — composite scoring only (run `train` first for ML/SHAP)")
    ctx = db.load_context(pg)
    mver = model_version()
    do_score_once(pg, ctx, explainer, mver)
    while loop:
        time.sleep(interval)
        try:
            ctx = db.load_context(pg)
            explainer = Explainer.load()
            do_score_once(pg, ctx, explainer, model_version())
        except Exception as e:
            log.error("score loop error: %s", e)
    pg.close()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["train", "score"])
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=int(os.getenv("RISK_INTERVAL", "180")))
    args = ap.parse_args()
    if args.cmd == "train":
        do_train()
    else:
        do_score(args.loop, args.interval)


if __name__ == "__main__":
    main()
