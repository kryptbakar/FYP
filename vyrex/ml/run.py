"""risk-engine CLI: train the model, score findings, or run the evaluation studies.

  python run.py train                  # (re)train XGBoost on synthetic + analyst feedback
  python run.py score                  # score every finding once
  python run.py score --loop          # keep scoring on an interval
  python run.py evaluate              # ranking experiment: CVSS vs composite vs ML
  python run.py evaluate-fusion       # dedup false/missed-merge rates on labeled sample
  python run.py evaluate-scenario     # fusion + ranking on a scripted intrusion
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

import db
import features
import feedback
import fusion
import scoring
import train as trainer
import trigger
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
    # Sanitise analyst feedback BEFORE it can influence the model: drop NaN/inf/
    # out-of-range labels (anti-poisoning, THREAT-MODEL ML pipeline).
    fb = feedback.clean(db.load_feedback(pg))
    extra_X, extra_y = [], []
    for row in fb:
        row["_consensus"] = clusters.get(row["id"], {}).get("weight", 0.0)
        fd = features.build(row, ctx)
        extra_X.append(features.to_vector(fd))
        extra_y.append(float(row["label_priority"]))
    pg.close()
    # Cap feedback influence so even a large hostile batch can only nudge the prior.
    n_syn = trainer.DEFAULT_SYNTHETIC_N
    per_row_w = feedback.cap_feedback(len(extra_y), n_syn)
    extra_w = np.full(len(extra_y), per_row_w) if extra_y else None
    if extra_y:
        log.info("folding %d feedback rows at per-row weight %.3f (capped)", len(extra_y), per_row_w)
    res = trainer.train(
        extra_X=np.array(extra_X) if extra_X else None,
        extra_y=np.array(extra_y) if extra_y else None,
        extra_w=extra_w,
    )
    log.info("training done: %s", res)


def _event_key(finding_id: int, policy, run_started: str) -> str:
    """Identity of one crossing event.

    Stable for everything detected in a single scoring pass (so a retried pass cannot
    double-enqueue), but distinct across passes — a finding that genuinely falls back
    below the threshold and re-crosses next week must be investigated again.
    """
    return f"finding:{finding_id}:{policy.version}:{run_started}"


def do_score_once(pg, ctx, explainer, mver, policy=None) -> int:
    policy = policy or trigger.TriggerPolicy.from_env()
    run_started = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    findings = db.load_findings(pg)
    # Fusion stage: dedup into clusters + derive each finding's consensus weight, and
    # persist the cluster record (which tools agree) onto every member.
    clusters = fusion.build_clusters(findings)
    corroborated = 0
    band_counts: dict[str, int] = {}
    crossings: list[tuple[dict, trigger.Decision]] = []
    enqueued = 0
    for fr in findings:
        con = clusters.get(fr["id"])
        if con:
            db.write_consensus(pg, fr["id"], con)
            fr["_consensus"] = con["weight"]
            if con["n_tools"] > 1:
                corroborated += 1
        fd = features.build(fr, ctx)
        # Pass applicability so factors that cannot exist for this finding type
        # (KEV/EPSS on a non-CVE, threat-intel on a package) consume no weight
        # instead of scoring a silent zero. See features.applicability.
        comp, components = scoring.composite(fd, features.applicability(fr))
        ml_score = None
        if explainer is not None:
            exp = explainer.explain(features.to_vector(fd))
            ml_score = exp["ml_risk_score"]
            db.upsert_explanation(pg, fr["id"], exp, mver)
        # Transactional outbox: the score write and the request-to-investigate it
        # justifies commit together or not at all. write_risk also shifts
        # risk_score -> previous_risk_score and hands back both, so a rise THROUGH the
        # threshold is distinguishable from sitting above it.
        with pg.transaction():
            previous, current = db.write_risk(
                pg, fr["id"], comp, components, ml_score, mver,
                # Persist WHY each excluded factor could not apply. Stored rather than
                # recomputed in the API or the console, because the rule already exists
                # in three places for the fusion key and that has bitten us once — the
                # scorer is the only component that should own this judgement.
                features.inapplicable_reasons(fr))
            decision = trigger.evaluate(previous, current, policy)
            if decision.action == "publish":
                enqueued += db.enqueue_investigation(
                    pg,
                    event_key=_event_key(fr["id"], policy, run_started),
                    subject_type="finding", subject_id=fr["id"],
                    payload={
                        "subject_type": "finding", "subject_id": fr["id"],
                        "asset_id": fr.get("asset_id"),
                        "trigger_type": "automatic",
                        "trigger_score_snapshot": float(current) if current is not None else None,
                        "previous_score": float(previous) if previous is not None else None,
                        "trigger_policy_version": policy.version,
                        "threshold": policy.threshold,
                        "model_version": mver,
                    },
                )
        if decision.fired:
            crossings.append((fr, decision))
        band_counts[scoring.band(comp)] = band_counts.get(scoring.band(comp), 0) + 1
    db.recompute_ranks(pg)
    log.info("scored %d findings; %d corroborated by >1 tool; composite bands=%s; model=%s",
             len(findings), corroborated, band_counts, mver or "none")
    for fr, d in crossings:
        log.info("trigger[%s] finding=%s asset=%s %s -> %s (%s)",
                 d.action, fr["id"], fr.get("asset_id"), d.previous, d.current, d.reason)
    # Always report the policy, even at zero crossings: "nothing fired" is ambiguous
    # between "correctly quiet" and "misconfigured", and the threshold is the difference.
    log.info("trigger policy: %s -> %d crossing(s), %d queued to outbox",
             policy.describe(), len(crossings), enqueued)
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


def do_evaluate(out: Path) -> None:
    import evaluate as eval_mod
    report = eval_mod.evaluate()
    out.mkdir(parents=True, exist_ok=True)
    (out / "evaluation.json").write_text(json.dumps(report, indent=2))
    (out / "evaluation.md").write_text(eval_mod.to_markdown(report))
    log.info("evaluation report -> %s", out / "evaluation.md")
    print(eval_mod.to_markdown(report))


def do_evaluate_fusion(out: Path) -> None:
    import eval_fusion
    findings = json.loads(eval_fusion.DEFAULT_FIXTURE.read_text())["findings"]
    report = eval_fusion.score(findings)
    out.mkdir(parents=True, exist_ok=True)
    (out / "fusion_evaluation.json").write_text(json.dumps(report, indent=2))
    (out / "fusion_evaluation.md").write_text(eval_fusion.to_markdown(report, findings))
    log.info("fusion evaluation report -> %s", out / "fusion_evaluation.md")
    print(eval_fusion.to_markdown(report, findings))


def do_evaluate_scenario(out: Path) -> None:
    import attack_scenario
    report = attack_scenario.run()
    out.mkdir(parents=True, exist_ok=True)
    (out / "attack_scenario.json").write_text(json.dumps(report, indent=2))
    (out / "attack_scenario.md").write_text(attack_scenario.to_markdown(report))
    log.info("attack-scenario report -> %s", out / "attack_scenario.md")
    print(attack_scenario.to_markdown(report))
    if not report["passed"]:
        raise SystemExit("attack-scenario checks FAILED")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["train", "score", "evaluate", "evaluate-fusion", "evaluate-scenario"])
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=int(os.getenv("RISK_INTERVAL", "180")))
    ap.add_argument("--out", type=Path, default=Path(os.getenv("MODEL_DIR", "/models")) / "reports")
    args = ap.parse_args()
    if args.cmd == "train":
        do_train()
    elif args.cmd == "evaluate":
        do_evaluate(args.out)
    elif args.cmd == "evaluate-fusion":
        do_evaluate_fusion(args.out)
    elif args.cmd == "evaluate-scenario":
        do_evaluate_scenario(args.out)
    else:
        do_score(args.loop, args.interval)


if __name__ == "__main__":
    main()
