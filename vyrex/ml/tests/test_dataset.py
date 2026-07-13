"""Unit tests for training-data assembly — reproducibility and label sanity."""
import numpy as np

import dataset
from features import FEATURES


def test_shapes_and_bounds():
    X, y = dataset.generate_synthetic(200, seed=1)
    assert X.shape == (200, len(FEATURES))
    assert y.shape == (200,)
    assert np.all(X >= 0.0) and np.all(X <= 1.0)
    assert np.all(y >= 0.0) and np.all(y <= 100.0)


def test_reproducible_by_seed():
    X1, y1 = dataset.generate_synthetic(100, seed=5)
    X2, y2 = dataset.generate_synthetic(100, seed=5)
    assert np.array_equal(X1, X2) and np.array_equal(y1, y2)


def test_different_seeds_differ():
    _, y1 = dataset.generate_synthetic(100, seed=5)
    _, y2 = dataset.generate_synthetic(100, seed=6)
    assert not np.array_equal(y1, y2)


def test_label_rewards_kev_epss_interaction():
    """The core non-linearity: KEV+high-EPSS must outscore the same finding without it."""
    rng = np.random.default_rng(0)
    base = {f: 0.5 for f in FEATURES}
    hot = dict(base, kev=1.0, epss=0.9)
    cold = dict(base, kev=0.0, epss=0.0)
    hot_scores = [dataset._label(hot, rng) for _ in range(50)]
    cold_scores = [dataset._label(cold, rng) for _ in range(50)]
    assert np.mean(hot_scores) > np.mean(cold_scores) + 10
