"""Known-answer tests for the evaluation metrics.

These four functions will produce the thesis's headline accuracy numbers, and with zero
cases labelled today the decision-quality path in score_labels.py has never executed on
real data. An unexercised metric implementation that silently returns plausible-looking
numbers is the worst possible failure here — it would not crash, it would just be wrong,
and nobody would know until someone recomputed it by hand in a viva.

So every expected value below is worked out by hand in the docstring rather than copied
from a first run of the code, which would only pin whatever the bug was.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from score_labels import (  # noqa: E402
    DISPOSITIONS,
    SEVERITIES,
    cohens_kappa,
    confusion,
    macro_f1,
    per_class_f1,
    weighted_severity_agreement,
)

E, M, D, I = "ESCALATE", "MONITOR", "DISMISS", "INSUFFICIENT_EVIDENCE"


# --- macro-F1 -----------------------------------------------------------

def test_perfect_classifier_scores_one():
    pairs = [(E, E), (M, M), (D, D), (I, I)]
    assert macro_f1(pairs, DISPOSITIONS) == pytest.approx(1.0)


def test_macro_f1_matches_hand_calculation():
    """pairs: (E,E) (E,E) (E,M) (M,M) (M,E)

    ESCALATE: tp=2 fp=1 fn=1 -> prec=2/3, rec=2/3, f1=2/3
    MONITOR : tp=1 fp=1 fn=1 -> prec=1/2, rec=1/2, f1=1/2
    only those two classes have support, so macro = (2/3 + 1/2) / 2 = 0.58333
    """
    pairs = [(E, E), (E, E), (E, M), (M, M), (M, E)]
    assert macro_f1(pairs, DISPOSITIONS) == pytest.approx(0.58333, abs=1e-4)


def test_absent_classes_do_not_drag_the_score_down():
    """A deliberate design choice, so it gets a test rather than a comment.

    Averaging over all four classes when only one was ever labelled would report 0.25
    for a perfect classifier and make a small corpus look far worse than it is.
    """
    pairs = [(E, E), (E, E)]
    assert macro_f1(pairs, DISPOSITIONS) == pytest.approx(1.0)


def test_confidently_wrong_scores_zero():
    pairs = [(E, M), (M, E)]
    assert macro_f1(pairs, DISPOSITIONS) == pytest.approx(0.0)


def test_per_class_support_counts_truth_not_predictions():
    """Support must be the number of TRUE instances; counting predictions instead is a
    classic slip that inflates rare classes the model over-predicts."""
    pairs = [(E, E), (E, M), (M, M)]
    per = per_class_f1(pairs, DISPOSITIONS)
    assert per[E]["support"] == 2
    assert per[M]["support"] == 1
    assert per[D]["support"] == 0


# --- confusion matrix ---------------------------------------------------

def test_confusion_orientation_is_truth_rows_prediction_columns():
    """Getting this backwards silently swaps false positives and false negatives —
    and a missed ESCALATE is not the same mistake as a wrongly-dismissed MONITOR."""
    m = confusion([(E, M)], DISPOSITIONS)
    assert m[E][M] == 1
    assert m[M][E] == 0


# --- Cohen's kappa ------------------------------------------------------

def test_kappa_is_one_for_perfect_agreement():
    pairs = [(E, E), (M, M), (D, D)]
    assert cohens_kappa(pairs, DISPOSITIONS) == pytest.approx(1.0)


def test_kappa_is_zero_at_chance():
    """(A,A) (A,B) (B,A) (B,B): po = 0.5. Each rater used each class twice of four,
    so pe = .5*.5 + .5*.5 = 0.5, and k = (0.5-0.5)/(1-0.5) = 0.

    This is the whole reason to report kappa rather than raw agreement: 50% agreement
    here is exactly what two people guessing independently would produce.
    """
    pairs = [(E, E), (E, M), (M, E), (M, M)]
    assert cohens_kappa(pairs, DISPOSITIONS) == pytest.approx(0.0)


def test_kappa_goes_negative_below_chance():
    pairs = [(E, M), (M, E), (E, M), (M, E)]
    assert cohens_kappa(pairs, DISPOSITIONS) < 0


def test_kappa_on_empty_input_is_zero_not_a_crash():
    assert cohens_kappa([], DISPOSITIONS) == 0.0


# --- ordinal severity agreement ----------------------------------------

def test_exact_severity_match_is_full_credit():
    assert weighted_severity_agreement([("HIGH", "HIGH")]) == pytest.approx(1.0)


def test_one_step_apart_earns_partial_credit():
    """HIGH vs CRITICAL is one step on a 4-point scale: 1 - 1/3 = 0.6667."""
    assert weighted_severity_agreement([("HIGH", "CRITICAL")]) == pytest.approx(2 / 3, abs=1e-4)


def test_opposite_ends_earn_nothing():
    assert weighted_severity_agreement([("LOW", "CRITICAL")]) == pytest.approx(0.0)


def test_severity_agreement_is_symmetric():
    a = weighted_severity_agreement([("LOW", "HIGH")])
    b = weighted_severity_agreement([("HIGH", "LOW")])
    assert a == pytest.approx(b)


def test_unknown_severity_labels_are_skipped_not_scored_as_perfect():
    """A blank or misspelled severity must not quietly count as agreement."""
    assert weighted_severity_agreement([("HIGH", "")]) == pytest.approx(0.0)


def test_severity_scale_is_ordered_low_to_critical():
    """The whole weighting depends on this ordering; a reshuffle would invert the
    partial credit without failing anything else."""
    assert SEVERITIES == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
