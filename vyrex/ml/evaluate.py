"""Evaluation harness — the evidence that the risk engine *works*, not just runs.

Answers the examiner's question "how do you know your prioritization is better?"
with a controlled experiment. Three rankers are compared on the SAME held-out
population of findings (generated with a seed disjoint from training, so the ML
model has never seen a single row):

  1. cvss_only  — rank purely by CVSS base severity (what a naive scanner UI does,
                  and the de-facto industry baseline).
  2. composite  — VYREX's transparent 10-factor weighted score (scoring.py).
  3. ml         — the trained XGBoost model (train.py), which layers learned
                  non-linear interactions on top of the composite's factors.

Metrics reported per ranker:
  - Spearman rank correlation against the ground-truth priority label.
  - NDCG@k (k = 25/50/100): quality of the top of the queue, where analysts live.
  - Precision@k on "urgent" findings (label >= URGENT_CUTOFF).
  - KEV capture: what fraction of known-exploited (CISA KEV) findings each ranker
    surfaces in its top 10% — the headline "we find the exploited stuff first" number.
  - For the ML model only: held-out MAE / RMSE / R² (regression quality).

Ground truth: the synthetic analyst-judgement label from dataset.py (composite +
non-linear interactions + noise). This is stated explicitly in the report — as real
analyst feedback accrues in the analyst_feedback table it becomes the ground truth
and this same harness re-runs unchanged (see --help). Until then the experiment
still demonstrates the core claim: a linear CVSS view cannot express KEV x EPSS /
exposure x severity interactions, and both VYREX scores rank measurably closer to
analyst judgement.

Usage:
    python evaluate.py                 # train fresh, evaluate, write reports
    python evaluate.py --n-eval 4000   # bigger held-out set
    python evaluate.py --out reports/  # where evaluation.{json,md} land

Runs standalone (no DB, no Docker) so CI executes it on every push.
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import xgboost as xgb

import dataset
import train as train_mod
from features import FEATURES
from scoring import composite

log = logging.getLogger("ml.evaluate")

EVAL_SEED = 1337          # disjoint from dataset.py's training seed (42)
URGENT_CUTOFF = 75.0      # label >= this ==> "urgent" for precision@k
TOP_FRACTION = 0.10       # "top of the queue" for KEV capture
K_LIST = (25, 50, 100)

CVSS_IDX = FEATURES.index("cvss")
KEV_IDX = FEATURES.index("kev")


# ---------------------------------------------------------------- rankers

def rank_scores(X: np.ndarray, booster: xgb.Booster) -> dict[str, np.ndarray]:
    """Score every finding under each of the three rankers."""
    comp = np.array([composite(dict(zip(FEATURES, row)))[0] for row in X])
    ml = booster.predict(xgb.DMatrix(X, feature_names=FEATURES))
    return {
        "cvss_only": X[:, CVSS_IDX] * 100.0,
        "composite": comp,
        "ml": ml.astype(float),
    }


# ---------------------------------------------------------------- metrics

def spearman(a: np.ndarray, b: np.ndarray) -> float:
    from scipy.stats import spearmanr
    rho, _ = spearmanr(a, b)
    return float(rho)


def ndcg_at_k(scores: np.ndarray, relevance: np.ndarray, k: int) -> float:
    """NDCG@k with graded relevance (the 0..100 label)."""
    order = np.argsort(-scores)[:k]
    ideal = np.sort(relevance)[::-1][:k]
    discounts = 1.0 / np.log2(np.arange(2, k + 2))
    dcg = float(np.sum(relevance[order] * discounts))
    idcg = float(np.sum(ideal * discounts)) or 1.0
    return dcg / idcg


def precision_at_k(scores: np.ndarray, urgent: np.ndarray, k: int) -> float:
    order = np.argsort(-scores)[:k]
    return float(np.mean(urgent[order]))


def kev_capture(scores: np.ndarray, kev: np.ndarray, top_fraction: float) -> float:
    """Fraction of KEV-flagged findings that land in the ranker's top X%."""
    n_top = max(1, int(len(scores) * top_fraction))
    top = set(np.argsort(-scores)[:n_top].tolist())
    kev_ids = np.flatnonzero(kev > 0.5)
    if len(kev_ids) == 0:
        return float("nan")
    return float(np.mean([i in top for i in kev_ids]))


def regression_metrics(y: np.ndarray, p: np.ndarray) -> dict:
    err = p - y
    ss_tot = float(np.sum((y - np.mean(y)) ** 2)) or 1.0
    return {
        "mae": round(float(np.mean(np.abs(err))), 3),
        "rmse": round(float(np.sqrt(np.mean(err ** 2))), 3),
        "r2": round(1.0 - float(np.sum(err ** 2)) / ss_tot, 4),
    }


# ---------------------------------------------------------------- experiment

def evaluate(n_eval: int = 3000, retrain: bool = True) -> dict:
    if retrain:
        train_mod.train()
    booster = xgb.Booster()
    booster.load_model(str(train_mod.MODEL_PATH))

    # Held-out population: fresh draw, seed disjoint from training.
    X, y = dataset.generate_synthetic(n_eval, seed=EVAL_SEED)
    urgent = (y >= URGENT_CUTOFF).astype(float)
    kev = X[:, KEV_IDX]
    scores = rank_scores(X, booster)

    per_ranker: dict[str, dict] = {}
    for name, s in scores.items():
        per_ranker[name] = {
            "spearman_vs_label": round(spearman(s, y), 4),
            "ndcg": {f"@{k}": round(ndcg_at_k(s, y, k), 4) for k in K_LIST},
            "precision_urgent": {f"@{k}": round(precision_at_k(s, urgent, k), 4) for k in K_LIST},
            "kev_capture_top10pct": round(kev_capture(s, kev, TOP_FRACTION), 4),
        }
    per_ranker["ml"]["heldout_regression"] = regression_metrics(y, scores["ml"])

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "protocol": {
            "train": "dataset.generate_synthetic(seed=42), 85/15 split, early stopping (train.py)",
            "eval": f"fresh population n={n_eval}, seed={EVAL_SEED} (disjoint from training)",
            "ground_truth": "synthetic analyst-judgement label (dataset._label); "
                            "replaced by analyst_feedback rows as they accrue",
            "urgent_cutoff": URGENT_CUTOFF,
            "kev_top_fraction": TOP_FRACTION,
        },
        "n_eval": n_eval,
        "n_kev_in_eval": int(kev.sum()),
        "n_urgent_in_eval": int(urgent.sum()),
        "rankers": per_ranker,
    }


# ---------------------------------------------------------------- reporting

def to_markdown(r: dict) -> str:
    rk = r["rankers"]
    names = ["cvss_only", "composite", "ml"]
    pretty = {"cvss_only": "CVSS-only (baseline)", "composite": "VYREX composite", "ml": "VYREX ML (XGBoost)"}

    def row(label, fn):
        return "| " + label + " | " + " | ".join(fn(rk[n]) for n in names) + " |"

    lines = [
        "# Risk-engine evaluation report",
        "",
        f"_Auto-generated by `ml/evaluate.py` on {r['generated_at']}. Do not edit by hand — re-run the harness._",
        "",
        "## Protocol",
        "",
        f"- **Training:** {r['protocol']['train']}",
        f"- **Held-out evaluation:** {r['protocol']['eval']}",
        f"- **Ground truth:** {r['protocol']['ground_truth']}",
        f"- Population: {r['n_eval']} findings, of which {r['n_kev_in_eval']} KEV-flagged "
        f"and {r['n_urgent_in_eval']} urgent (label >= {r['protocol']['urgent_cutoff']}).",
        "",
        "## Results",
        "",
        "| Metric | " + " | ".join(pretty[n] for n in names) + " |",
        "|---|---|---|---|",
        row("Spearman vs analyst label", lambda d: f"{d['spearman_vs_label']:.3f}"),
        *[row(f"NDCG@{k}", lambda d, k=k: f"{d['ndcg'][f'@{k}']:.3f}") for k in K_LIST],
        *[row(f"Precision@{k} (urgent)", lambda d, k=k: f"{d['precision_urgent'][f'@{k}']:.3f}") for k in K_LIST],
        row("KEV findings captured in top 10%", lambda d: f"{d['kev_capture_top10pct'] * 100:.1f}%"),
        "",
        "## ML model held-out regression quality",
        "",
        "| MAE | RMSE | R² |",
        "|---|---|---|",
        "| {mae} | {rmse} | {r2} |".format(**rk["ml"]["heldout_regression"]),
        "",
        "## Reading the table",
        "",
        "- **CVSS-only** is the industry-default baseline: it cannot see exploitation "
        "probability (EPSS), known exploitation (KEV), exposure, live IOCs, or multi-tool "
        "consensus, so it mis-ranks exactly the findings that matter most.",
        "- **The composite** is fully linear and fully explainable (10 weighted factors).",
        "- **The ML model** additionally captures the non-linear interactions "
        "(KEV x EPSS, exposure x CVSS, consensus x severity) and is explained per-finding "
        "via exact TreeSHAP.",
        "- The KEV-capture row is the headline: it answers, in one number per ranker, "
        "\"if an analyst only works the top 10% of the queue, what fraction of "
        "known-exploited findings do they touch?\"",
        "- Note the composite typically captures MORE raw-KEV findings than the ML model. "
        "That is by design, not a defect: the composite grants KEV a flat +15-point boost, "
        "while the model learns that a KEV entry with negligible EPSS on an unexposed asset "
        "is genuinely lower priority. Which behaviour is preferable is an analyst-policy "
        "choice — VYREX exposes both scores side by side.",
        "",
        "## Threats to validity (stated, not hidden)",
        "",
        "- The ground-truth label is *synthetic analyst judgement* (composite + documented "
        "interaction boosts + noise), because no historical analyst labels exist yet. The "
        "interactions are the ones exploited-vulnerability research supports (KEV/EPSS "
        "co-occurrence, exposure amplification). As real `analyst_feedback` rows accrue, "
        "they become the ground truth and this identical harness re-runs against them.",
        "- The evaluation population is drawn from the same generative distribution as "
        "training (different seed). The live attack-simulation study "
        "(docs/VALIDATION-ATTACK-SIM.md) provides the out-of-distribution check.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-eval", type=int, default=3000, help="held-out population size")
    ap.add_argument("--out", type=Path, default=Path("reports"), help="output directory")
    ap.add_argument("--no-retrain", action="store_true", help="reuse the existing model in MODEL_DIR")
    args = ap.parse_args()

    report = evaluate(n_eval=args.n_eval, retrain=not args.no_retrain)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "evaluation.json").write_text(json.dumps(report, indent=2))
    (args.out / "evaluation.md").write_text(to_markdown(report))
    log.info("wrote %s and %s", args.out / "evaluation.json", args.out / "evaluation.md")
    print(to_markdown(report))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    main()
