"""Trigger policy: edge detection and governance.

The bug this guards against is subtle and expensive: `do_score_once` rescores every
finding every RISK_INTERVAL (180s by default). A level rule ("score >= threshold") would
request a fresh investigation for the same finding on every pass, forever. The trigger
must fire on the RISING EDGE only.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

import trigger

T = 60.0


# --- geometry: crossed() -------------------------------------------------------------

@pytest.mark.parametrize(
    "previous,current,expected,why",
    [
        (55.0, 65.0, True, "rose through the threshold"),
        (59.99, 60.0, True, "landed exactly on it (>= semantics)"),
        (65.0, 70.0, False, "ALREADY above — this is the repeated-fire bug"),
        (60.0, 60.0, False, "sitting on the threshold, not crossing it"),
        (55.0, 59.99, False, "rose but did not reach"),
        (70.0, 55.0, False, "fell through: a downward edge is not a trigger"),
        (10.0, 12.0, False, "moved, but nowhere near"),
        (None, 65.0, True, "never scored before and arrived hot"),
        (None, 55.0, False, "never scored before and arrived cold"),
        (55.0, None, False, "no current score to judge"),
    ],
)
def test_crossed(previous, current, expected, why):
    assert trigger.crossed(previous, current, T) is expected, why


def test_crossed_accepts_decimals_from_postgres():
    """risk_score is `numeric`, so psycopg hands back Decimal, not float."""
    assert trigger.crossed(Decimal("55.00"), Decimal("65.00"), T) is True
    assert trigger.crossed(Decimal("65.00"), Decimal("70.00"), T) is False


def test_repeated_scoring_passes_fire_exactly_once():
    """The whole point: a finding that rises and stays high triggers on ONE pass."""
    scores = [40.0, 45.0, 65.0, 70.0, 68.0, 72.0]   # six scoring passes
    fired = 0
    previous = None
    for current in scores:
        if trigger.crossed(previous, current, T):
            fired += 1
        previous = current
    assert fired == 1


# --- governance: evaluate() ----------------------------------------------------------

def test_disabled_policy_never_acts_even_on_a_real_crossing():
    """Manual-only is the shipping default; a crossing must still be inert."""
    d = trigger.evaluate(55.0, 65.0, trigger.TriggerPolicy(enabled=False))
    assert d.action == "none" and not d.fired
    assert "manual-only" in d.reason


def test_dry_run_logs_but_does_not_publish():
    d = trigger.evaluate(55.0, 65.0, trigger.TriggerPolicy(enabled=True, dry_run=True))
    assert d.action == "log" and d.fired


def test_active_policy_publishes():
    d = trigger.evaluate(55.0, 65.0, trigger.TriggerPolicy(enabled=True, dry_run=False))
    assert d.action == "publish" and d.fired
    assert d.previous == 55.0 and d.current == 65.0


def test_no_crossing_short_circuits_before_governance():
    """An enabled, active policy still does nothing without an edge."""
    d = trigger.evaluate(65.0, 70.0, trigger.TriggerPolicy(enabled=True, dry_run=False))
    assert d.action == "none" and "no upward crossing" in d.reason


def test_decision_carries_the_policy_version():
    """Stored investigations must be attributable to the rule that produced them."""
    p = trigger.TriggerPolicy(enabled=True, dry_run=False, version="test-v9")
    assert trigger.evaluate(55.0, 65.0, p).policy_version == "test-v9"


# --- defaults ------------------------------------------------------------------------

def test_shipping_defaults_are_inert():
    """Nothing fires automatically until someone deliberately calibrates and enables it."""
    p = trigger.TriggerPolicy()
    assert p.enabled is False and p.dry_run is True
    assert trigger.evaluate(0.0, 100.0, p).action == "none"


def test_from_env_defaults_are_inert(monkeypatch):
    for k in ("INVESTIGATION_TRIGGER_ENABLED", "INVESTIGATION_TRIGGER_DRY_RUN",
              "INVESTIGATION_THRESHOLD", "INVESTIGATION_POLICY_VERSION"):
        monkeypatch.delenv(k, raising=False)
    p = trigger.TriggerPolicy.from_env()
    assert p.enabled is False and p.dry_run is True
    assert p.threshold == trigger.DEFAULT_THRESHOLD


def test_from_env_enables_only_on_exact_true(monkeypatch):
    monkeypatch.setenv("INVESTIGATION_TRIGGER_ENABLED", "yes")   # not "true"
    assert trigger.TriggerPolicy.from_env().enabled is False
    monkeypatch.setenv("INVESTIGATION_TRIGGER_ENABLED", "TRUE")  # case-insensitive
    assert trigger.TriggerPolicy.from_env().enabled is True


def test_default_threshold_is_above_the_observed_corpus_max():
    """Guards the calibration note: 54.45 was the live max on 2026-08-21.

    If someone lowers the default below that, automation starts firing on the demo
    corpus without anyone having calibrated it — which is exactly the failure the
    manual-only default exists to prevent.
    """
    assert trigger.DEFAULT_THRESHOLD > 54.45


def test_describe_states_the_mode():
    assert "manual-only" in trigger.TriggerPolicy().describe()
    assert "dry-run" in trigger.TriggerPolicy(enabled=True, dry_run=True).describe()
    assert "ACTIVE" in trigger.TriggerPolicy(enabled=True, dry_run=False).describe()
