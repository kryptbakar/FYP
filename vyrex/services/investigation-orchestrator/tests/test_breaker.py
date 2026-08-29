"""Circuit breaker on the Ollama client.

Why it matters here specifically: the orchestrator is serial (ORCH_CONCURRENCY=1) and the
LLM timeout is 240 s. With Ollama down and no breaker, ten queued investigations spend
forty minutes discovering the same failure ten times, and the queue reads as busy rather
than broken for the whole period.

These tests never touch the network. The breaker's decision logic is separated from the
HTTP call precisely so it can be tested without one.
"""
from __future__ import annotations

import pytest

from orchestrator.llm import LLMUnavailable, OllamaClient


class _Clock:
    """Monotonic stand-in, so cooldown behaviour is tested without sleeping."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr("orchestrator.llm.time.monotonic", c)
    return c


def _client(**kw) -> OllamaClient:
    return OllamaClient("http://ollama:11434", "test-model",
                        timeout_s=240, breaker_threshold=3, breaker_cooldown_s=120, **kw)


def _fail(client: OllamaClient, n: int) -> None:
    for _ in range(n):
        client._record_failure()


def test_breaker_starts_closed():
    assert _client()._breaker_is_open() is False


def test_breaker_stays_closed_below_the_threshold(clock):
    c = _client()
    _fail(c, 2)
    assert c._breaker_is_open() is False, "must not trip early; transient failures happen"


def test_breaker_opens_at_the_threshold(clock):
    c = _client()
    _fail(c, 3)
    assert c._breaker_is_open() is True


def test_open_breaker_fails_fast_without_calling(clock):
    """The point of the breaker: no HTTP, no 240 s wait, a typed failure immediately.

    `complete` would raise on a real connection anyway, so the assertion is on the
    MESSAGE — it must say the breaker refused, not that the connection failed.
    """
    c = _client()
    _fail(c, 3)
    with pytest.raises(LLMUnavailable) as exc:
        c.complete("system", "user")
    assert "circuit breaker open" in str(exc.value)


def test_breaker_stays_open_during_cooldown(clock):
    c = _client()
    _fail(c, 3)
    clock.advance(119)
    assert c._breaker_is_open() is True


def test_breaker_goes_half_open_after_cooldown(clock):
    c = _client()
    _fail(c, 3)
    clock.advance(120)
    assert c._breaker_is_open() is False, "one trial call must be allowed through"


def test_a_failed_trial_call_reopens_the_breaker(clock):
    """Half-open must not become permanently open-then-closed on a still-dead service."""
    c = _client()
    _fail(c, 3)
    clock.advance(120)
    assert c._breaker_is_open() is False      # half-open, trial allowed
    c._record_failure()                        # the trial fails
    assert c._breaker_is_open() is True, "a failed trial must re-open the breaker"


def test_success_closes_the_breaker_and_resets_the_count(clock):
    c = _client()
    _fail(c, 3)
    clock.advance(120)
    c._breaker_is_open()                       # half-open
    c._record_success()
    assert c._breaker_is_open() is False
    assert c._consecutive_failures == 0
    # And it must now take a full threshold of new failures to trip again, not one.
    _fail(c, 2)
    assert c._breaker_is_open() is False


def test_an_intermittent_failure_does_not_accumulate_forever(clock):
    """fail, fail, succeed, fail, fail must NOT trip: the counter is consecutive."""
    c = _client()
    _fail(c, 2)
    c._record_success()
    _fail(c, 2)
    assert c._breaker_is_open() is False
