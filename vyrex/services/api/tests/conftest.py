"""Put services/api on sys.path so tests can `import app...` without installing."""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear the investigation admission-control window between tests.

    The per-requester window is deliberately in-process (app/ratelimit.py explains why),
    which means it is module state shared by every test in the run. Without this, the
    eleventh test to create an investigation gets a 429 from the tenth test's allowance —
    which is exactly what happened to test_list_is_newest_first: it creates ONE
    investigation, and failed anyway because earlier tests had spent the budget.

    Autouse rather than opt-in, because the next person to add a creating test should not
    have to know this exists to have their test pass.
    """
    from app import ratelimit
    ratelimit.reset()
    yield
    ratelimit.reset()
