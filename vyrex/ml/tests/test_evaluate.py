"""Tests for the evaluation harnesses — metric correctness on hand-checkable inputs,
plus a small end-to-end regression gate on the trained model."""
import numpy as np
import pytest

import eval_fusion
import evaluate


# ---------------------------------------------------------------- metric units

def test_ndcg_perfect_ranking_is_one():
    rel = np.array([10.0, 8.0, 5.0, 1.0])
    scores = np.array([4.0, 3.0, 2.0, 1.0])  # same order as relevance
    assert evaluate.ndcg_at_k(scores, rel, 4) == pytest.approx(1.0)


def test_ndcg_worst_ranking_below_one():
    rel = np.array([10.0, 8.0, 5.0, 1.0])
    scores = np.array([1.0, 2.0, 3.0, 4.0])  # inverted
    assert evaluate.ndcg_at_k(scores, rel, 4) < 0.9


def test_precision_at_k():
    scores = np.array([9.0, 8.0, 7.0, 1.0])
    urgent = np.array([1.0, 0.0, 1.0, 0.0])
    assert evaluate.precision_at_k(scores, urgent, 2) == 0.5
    assert evaluate.precision_at_k(scores, urgent, 3) == pytest.approx(2 / 3)


def test_kev_capture():
    scores = np.arange(100, dtype=float)          # top-10% = ids 90..99
    kev = np.zeros(100)
    kev[[95, 96, 10]] = 1.0                        # 2 of 3 KEV in the top decile
    assert evaluate.kev_capture(scores, kev, 0.10) == pytest.approx(2 / 3)


def test_kev_capture_no_kev_is_nan():
    assert np.isnan(evaluate.kev_capture(np.arange(10.0), np.zeros(10), 0.1))


# ---------------------------------------------------------------- fusion pairwise

def test_pairwise_perfect_clustering():
    fs = [
        {"id": 1, "source_tool": "a", "dedup_key": "k1", "severity": "high", "truth_cluster": "X"},
        {"id": 2, "source_tool": "b", "dedup_key": "k1", "severity": "low", "truth_cluster": "X"},
        {"id": 3, "source_tool": "a", "dedup_key": "k2", "severity": "low", "truth_cluster": "Y"},
    ]
    r = eval_fusion.score(fs)
    assert r["pairwise_precision"] == 1.0 and r["pairwise_recall"] == 1.0
    assert r["false_merge_rate"] == 0.0 and r["missed_merge_rate"] == 0.0


def test_pairwise_detects_false_and_missed_merges():
    fs = [
        # false merge: distinct issues sharing a key
        {"id": 1, "source_tool": "a", "dedup_key": "k1", "severity": "high", "truth_cluster": "X"},
        {"id": 2, "source_tool": "b", "dedup_key": "k1", "severity": "low", "truth_cluster": "Y"},
        # missed merge: same issue, one producer stamped no key
        {"id": 3, "source_tool": "a", "dedup_key": "k2", "severity": "low", "truth_cluster": "Z"},
        {"id": 4, "source_tool": "b", "dedup_key": None, "severity": "low", "truth_cluster": "Z"},
    ]
    r = eval_fusion.score(fs)
    assert r["false_merge_pairs"] == [(1, 2)]
    assert r["missed_merge_pairs"] == [(3, 4)]


def test_bundled_fixture_scores_and_reports():
    import json
    findings = json.loads(eval_fusion.DEFAULT_FIXTURE.read_text())["findings"]
    r = eval_fusion.score(findings)
    # Precision-first design goal: false merges must stay rarer than missed merges.
    assert r["false_merge_rate"] < r["missed_merge_rate"]
    md = eval_fusion.to_markdown(r, findings)
    assert "False-merge rate" in md and "Missed-merge rate" in md


# ---------------------------------------------------------------- end-to-end gate

@pytest.mark.slow
def test_model_beats_cvss_baseline(tmp_path, monkeypatch):
    """The defensible claim, as a regression gate: on held-out data both VYREX
    rankers must beat CVSS-only on rank correlation, and the ML model must add
    signal over the linear composite."""
    import train as train_mod
    monkeypatch.setattr(train_mod, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(train_mod, "MODEL_PATH", tmp_path / "risk_model.json")
    monkeypatch.setattr(train_mod, "META_PATH", tmp_path / "meta.json")

    report = evaluate.evaluate(n_eval=1500, retrain=True)
    rk = report["rankers"]
    assert rk["composite"]["spearman_vs_label"] > rk["cvss_only"]["spearman_vs_label"] + 0.2
    assert rk["ml"]["spearman_vs_label"] > rk["composite"]["spearman_vs_label"]
    assert rk["ml"]["heldout_regression"]["r2"] > 0.85
    md = evaluate.to_markdown(report)
    assert "KEV findings captured" in md
