"""Analyst-feedback sanitisation — the anti-poisoning gate on the training loop.

Analyst feedback (`analyst_feedback.label_priority`) is folded into training at 5x
weight (train.py), which is exactly what makes it a poisoning vector: a bad or
malicious label can drag the model. THREAT-MODEL.md (ML pipeline) calls for sanity
bounds; this module is them.

The checks are deliberately simple and defensible in a viva:
  1. Type/range: a label must be a real number in [0, 100]; NaN/inf/out-of-range
     rows are dropped, never clipped silently into validity.
  2. Influence cap: even valid feedback can't dominate. We cap the number of feedback
     rows folded in to a multiple of... well, we cap the TOTAL feedback weight as a
     fraction of the synthetic training mass (see `cap_feedback`), so a flood of
     labels can shift the model but never swamp the prior.

Pure functions, no DB — unit-tested in ml/tests/test_feedback.py and called from
run.py:do_train before the rows reach train.py.
"""
from __future__ import annotations

import logging
import math

log = logging.getLogger("ml.feedback")

LABEL_MIN, LABEL_MAX = 0.0, 100.0
# Feedback may contribute at most this fraction of the effective training mass, so
# even a large, hostile batch can only nudge — not overwrite — the synthetic prior.
MAX_FEEDBACK_FRACTION = 0.25
FEEDBACK_WEIGHT = 5.0  # per-row weight (kept in sync with train.py's default)


def valid_label(x) -> float | None:
    """Return the label as a float if it is a finite number in [0, 100], else None."""
    try:
        v = float(x)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(v):
        return None
    if v < LABEL_MIN or v > LABEL_MAX:
        return None
    return v


def clean(rows: list[dict]) -> list[dict]:
    """Drop feedback rows whose label_priority is missing, non-numeric, NaN/inf, or
    outside [0, 100]. Returns rows with a normalised float label_priority."""
    out, rejected = [], 0
    for r in rows:
        v = valid_label(r.get("label_priority"))
        if v is None:
            rejected += 1
            continue
        out.append({**r, "label_priority": v})
    if rejected:
        log.warning("rejected %d/%d feedback rows failing sanity bounds", rejected, len(rows))
    return out


def cap_feedback(n_feedback: int, n_synthetic: int,
                 weight: float = FEEDBACK_WEIGHT,
                 max_fraction: float = MAX_FEEDBACK_FRACTION) -> float:
    """Per-row feedback weight so total feedback mass ≤ max_fraction of the whole.

    Solve  (n_feedback * w) / (n_synthetic + n_feedback * w) ≤ max_fraction  for w,
    capped at the requested `weight` (we only ever *reduce* influence, never inflate).
    Returns 0.0 when there is no feedback.
    """
    if n_feedback <= 0 or n_synthetic <= 0:
        return 0.0
    # max allowed total feedback mass M satisfies M/(n_syn+M)=frac -> M=frac*n_syn/(1-frac)
    max_mass = max_fraction * n_synthetic / (1.0 - max_fraction)
    per_row_cap = max_mass / n_feedback
    return round(min(weight, per_row_cap), 4)
