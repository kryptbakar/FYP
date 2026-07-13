"""Tests for analyst-feedback sanitisation — the anti-poisoning gate (THREAT-MODEL)."""
import math

import feedback


# ---------------------------------------------------------------- valid_label

def test_valid_label_accepts_in_range():
    assert feedback.valid_label(0) == 0.0
    assert feedback.valid_label(100) == 100.0
    assert feedback.valid_label("73.5") == 73.5


def test_valid_label_rejects_out_of_range():
    assert feedback.valid_label(-1) is None
    assert feedback.valid_label(100.1) is None
    assert feedback.valid_label(1e9) is None


def test_valid_label_rejects_nan_inf_and_junk():
    assert feedback.valid_label(float("nan")) is None
    assert feedback.valid_label(float("inf")) is None
    assert feedback.valid_label(None) is None
    assert feedback.valid_label("not-a-number") is None


# ---------------------------------------------------------------- clean

def test_clean_drops_bad_rows_keeps_good():
    rows = [
        {"id": 1, "label_priority": 90},
        {"id": 2, "label_priority": 250},          # out of range
        {"id": 3, "label_priority": float("nan")}, # nan
        {"id": 4, "label_priority": None},         # missing
        {"id": 5, "label_priority": "42"},         # numeric string ok
    ]
    out = feedback.clean(rows)
    assert [r["id"] for r in out] == [1, 5]
    assert out[0]["label_priority"] == 90.0 and out[1]["label_priority"] == 42.0
    assert all(isinstance(r["label_priority"], float) for r in out)


def test_clean_empty():
    assert feedback.clean([]) == []


# ---------------------------------------------------------------- cap_feedback

def test_cap_zero_when_no_feedback():
    assert feedback.cap_feedback(0, 6000) == 0.0
    assert feedback.cap_feedback(10, 0) == 0.0


def test_cap_uses_full_weight_for_small_feedback():
    # a handful of rows against 6000 synthetic: default 5.0 weight is well under the cap
    assert feedback.cap_feedback(5, 6000) == 5.0


def test_cap_reduces_weight_for_flood():
    # a hostile flood: per-row weight must drop so total mass ≤ 25% of the whole
    n_fb, n_syn = 10_000, 6000
    w = feedback.cap_feedback(n_fb, n_syn)
    assert w < 5.0
    mass = n_fb * w
    fraction = mass / (n_syn + mass)
    assert fraction <= feedback.MAX_FEEDBACK_FRACTION + 1e-6


def test_cap_never_inflates_above_requested_weight():
    assert feedback.cap_feedback(1, 10_000, weight=5.0) == 5.0
