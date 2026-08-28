"""Investigation trigger policy — when does a score change warrant an investigation?

Deliberately pure: no DB, no clock, no I/O, so it is unit-testable and its behaviour is
auditable from the code alone (same house style as defense.decide()).

WHY A CROSSING AND NOT A LEVEL
------------------------------
`do_score_once` rescores EVERY finding on every pass (default RISK_INTERVAL=180s). A
"score >= threshold" rule would therefore re-fire an investigation for the same finding
every three minutes, forever. The trigger is an *edge*: it fires when a finding rises
THROUGH the threshold, not while it sits above one.

That requires the previous score, which is why `findings.previous_risk_score` exists and
why `db.write_risk` returns both values atomically.

CALIBRATION (measured 2026-08-21, do not skip this when enabling)
-----------------------------------------------------------------
The live corpus is 36 scored findings: 27 low, 3 medium, 6 info — 0 high, 0 critical,
max composite 54.45. The composite is a weighted sum of ten 0..1 factors, so mid-50s is
a realistic ceiling for this data. A threshold of 60 ("high") or 80 ("critical") would
therefore fire on NOTHING and the automation would look broken rather than quiet.

So: automatic triggering ships DISABLED. Enable it in dry-run first, read the log for a
few cycles, and set the threshold from the observed distribution — not from the band
names in scoring.band(), which were chosen for human labels, not for this decision.

Oscillation around the threshold is intentionally NOT handled here. One step of history
cannot distinguish "recovered and genuinely re-crossed" from "jittering". De-duplication
belongs to the outbox (a uniqueness key + cooldown over persisted state), where the full
history is available.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# Bump when the MEANING of a trigger decision changes, so stored investigations can be
# grouped by the rule that produced them. Recorded as `trigger_policy_version`.
POLICY_VERSION = "2026-08-manual-only-v1"

# Not a band boundary — a placeholder above the current observed max (54.45) so that
# enabling automation without calibrating first is loud (fires nothing) rather than
# silently wrong (fires on everything).
DEFAULT_THRESHOLD = 60.0


@dataclass(frozen=True)
class TriggerPolicy:
    """How automatic investigation requests are decided. Frozen: policy is data, not state."""

    version: str = POLICY_VERSION
    enabled: bool = False       # False => manual-only. The shipping default.
    dry_run: bool = True        # True  => log what WOULD fire; publish nothing.
    threshold: float = DEFAULT_THRESHOLD

    @classmethod
    def from_env(cls) -> "TriggerPolicy":
        """Build from env. Defaults are deliberately inert — see module docstring."""
        return cls(
            version=os.getenv("INVESTIGATION_POLICY_VERSION", POLICY_VERSION),
            enabled=os.getenv("INVESTIGATION_TRIGGER_ENABLED", "false").lower() == "true",
            dry_run=os.getenv("INVESTIGATION_TRIGGER_DRY_RUN", "true").lower() == "true",
            threshold=float(os.getenv("INVESTIGATION_THRESHOLD", str(DEFAULT_THRESHOLD))),
        )

    def describe(self) -> str:
        mode = "manual-only" if not self.enabled else ("dry-run" if self.dry_run else "ACTIVE")
        return f"{self.version} mode={mode} threshold={self.threshold}"


def crossed(previous: float | None, current: float | None, threshold: float) -> bool:
    """True when `current` rises THROUGH `threshold` from `previous`.

    `previous is None` means the finding has never been scored before; a first score
    already at/above the threshold is a genuine crossing (the finding arrived hot).

    Values arrive from Postgres `numeric` as Decimal — coerced to float so Decimal/float
    comparisons can't raise or silently misbehave.
    """
    if current is None:
        return False
    cur = float(current)
    if cur < threshold:
        return False
    if previous is None:
        return True
    return float(previous) < threshold


@dataclass(frozen=True)
class Decision:
    """What the caller should do. `action` is one of: publish | log | none."""

    action: str
    reason: str
    previous: float | None = None
    current: float | None = None
    policy_version: str = POLICY_VERSION

    @property
    def fired(self) -> bool:
        return self.action in ("publish", "log")


def evaluate(previous: float | None, current: float | None, policy: TriggerPolicy) -> Decision:
    """Apply `policy` to a score change.

    Separated from `crossed()` so the geometry ("did it cross?") stays independent of the
    governance ("are we allowed to act on that?"). Phase 1 turns `publish` into an outbox
    row; `log` is the calibration mode that writes a line and nothing else.
    """
    if not crossed(previous, current, policy.threshold):
        return Decision("none", "no upward crossing", previous, current, policy.version)
    if not policy.enabled:
        return Decision("none", "automatic triggering disabled (manual-only)",
                        previous, current, policy.version)
    if policy.dry_run:
        return Decision("log", f"would trigger: crossed {policy.threshold}",
                        previous, current, policy.version)
    return Decision("publish", f"crossed {policy.threshold}", previous, current, policy.version)
