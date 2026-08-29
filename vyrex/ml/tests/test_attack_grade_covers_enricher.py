"""Every ATT&CK technique the enricher can assign must have a severity grade.

`services/intel-enricher/attack.py` decides which technique a finding carries.
`ml/features.py::_ATTACK_GRADE` decides how much that technique contributes to the score.
Nothing connected the two, and they drifted: the enricher could tag a finding `T1021`
(Remote Services — lateral movement) while the grade table had no entry for it, so those
findings silently fell through to the 0.5 default and scored as if their ATT&CK context
were unknown.

That failure is invisible from either side. The enricher is doing its job, the scorer is
doing its job, no error is raised, and the only symptom is a slightly-wrong number in a
feature vector. Exactly the kind of thing that survives review and shows up in a viva as
"why does this lateral-movement finding score the same as an untagged one?"

Static parse — no database, no container.
"""
from __future__ import annotations

import pathlib
import re

import pytest

# ml/tests -> ml -> vyrex
VYREX = pathlib.Path(__file__).resolve().parents[2]
ENRICHER = VYREX / "services/intel-enricher/attack.py"

import features  # noqa: E402  (conftest puts ml/ on sys.path)

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _enricher_techniques() -> set[str]:
    return set(TECHNIQUE_RE.findall(ENRICHER.read_text(encoding="utf-8")))


def _graded(technique: str) -> bool:
    """Mirrors the prefix match features.py uses, so sub-techniques inherit the parent."""
    base = technique.split(".")[0]
    return base in features._ATTACK_GRADE


@pytest.mark.skipif(not ENRICHER.exists(), reason="intel-enricher not present in this checkout")
def test_every_assignable_technique_has_a_grade():
    ungraded = sorted(t for t in _enricher_techniques() if not _graded(t))
    assert not ungraded, (
        f"intel-enricher can assign {ungraded} but ml/features.py has no grade for them, "
        f"so those findings fall to the 0.5 default and score as if ATT&CK context were "
        f"unknown. Add them to _ATTACK_GRADE with a weight and a tactic comment."
    )


@pytest.mark.skipif(not ENRICHER.exists(), reason="intel-enricher not present in this checkout")
def test_the_parser_found_techniques():
    """A regex matching nothing would make the test above pass vacuously."""
    found = _enricher_techniques()
    assert len(found) >= 5, f"only found {found} — technique extraction looks broken"
    assert "T1021" in found, "T1021 is the technique that motivated this test"


def test_t1021_is_graded_and_sub_techniques_inherit():
    """The specific regression: T1021 and its sub-techniques (RDP, SSH, SMB)."""
    assert features.attack_ctx("T1021") > 0.5
    assert features.attack_ctx("T1021.001") == features.attack_ctx("T1021")


def test_unknown_techniques_still_get_the_neutral_default():
    """Grading degrades gracefully — an unmapped technique is not an error."""
    assert features.attack_ctx("T9999") == 0.5


def test_no_technique_at_all_scores_zero_not_the_default():
    """`unmapped` and `mapped but unranked` are different facts and must not collapse:
    0.0 says the enricher found nothing, 0.5 says it found something unranked."""
    assert features.attack_ctx(None) == 0.0
    assert features.attack_ctx("") == 0.0


def test_grades_are_ordered_by_kill_chain_progression():
    """Lateral movement sits above initial access and below active C2.

    Pinned because the numbers are hand-set judgement calls: if someone re-tunes them,
    this asserts the ORDERING still expresses the intended story rather than silently
    inverting it.
    """
    g = features._ATTACK_GRADE
    assert g["T1190"] < g["T1021"] < g["T1071"]
    assert g["T1071"] <= g["T1041"]          # C2 no higher than exfiltration
