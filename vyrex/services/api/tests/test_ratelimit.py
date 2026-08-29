"""Admission control for POST /investigations.

The interesting property is not "does it count to ten". It is that the endpoint is cheap
and the work is not: each accepted request commits the orchestrator to roughly two minutes
of serial inference, so sixty cheap HTTP calls buy two hours of queue. These tests pin the
behaviours that make the limit actually protect the worker.

Time is injected rather than slept, so the whole file runs in milliseconds.
"""
from __future__ import annotations

import pytest

from app import ratelimit
from app.ratelimit import RateLimited, check_queue_depth, check_window


@pytest.fixture(autouse=True)
def _clean():
    ratelimit.reset()
    yield
    ratelimit.reset()


# --- per-requester window ----------------------------------------------

def test_requests_under_the_limit_are_accepted():
    for i in range(5):
        check_window("analyst-a", limit=5, window_s=60, now=1000.0 + i)


def test_the_request_over_the_limit_is_refused():
    for i in range(5):
        check_window("analyst-a", limit=5, window_s=60, now=1000.0 + i)
    with pytest.raises(RateLimited) as e:
        check_window("analyst-a", limit=5, window_s=60, now=1005.0)
    assert e.value.retry_after >= 1


def test_requesters_are_independent():
    """One noisy client must not lock everyone else out of the queue."""
    for i in range(5):
        check_window("analyst-a", limit=5, window_s=60, now=1000.0 + i)
    check_window("analyst-b", limit=5, window_s=60, now=1005.0)   # must not raise


def test_the_window_slides_rather_than_resetting():
    """The reason this is a sliding window and not a fixed bucket.

    A fixed bucket lets a caller spend the whole allowance in the last second of one
    window and the whole allowance again in the first second of the next — a 2x burst
    exactly at the boundary. For two-minute jobs that is real stolen worker time.

    Here, the oldest entry ages out one at a time, so capacity returns gradually.
    """
    for i in range(5):                                   # entries at t=1000..1004
        check_window("a", limit=5, window_s=60, now=1000.0 + i)
    with pytest.raises(RateLimited):
        check_window("a", limit=5, window_s=60, now=1050.0)       # nothing aged out yet
    # cutoff 1000.5 retires exactly the t=1000 entry, freeing exactly one slot.
    check_window("a", limit=5, window_s=60, now=1060.5)
    # cutoff 1000.6 retires nothing further (t=1001 is still inside), so the window is
    # full again immediately. A fixed bucket would have handed back all five at once.
    with pytest.raises(RateLimited):
        check_window("a", limit=5, window_s=60, now=1060.6)


def test_retry_after_points_past_the_oldest_entry():
    """A client that obeys Retry-After must succeed on the retry, not bounce again."""
    for i in range(3):
        check_window("a", limit=3, window_s=60, now=1000.0 + i)
    with pytest.raises(RateLimited) as e:
        check_window("a", limit=3, window_s=60, now=1010.0)
    check_window("a", limit=3, window_s=60, now=1010.0 + e.value.retry_after)


def test_zero_limit_disables_the_window():
    """Matches INGEST_RATE_PER_SEC's convention, so the two knobs behave alike."""
    for i in range(100):
        check_window("a", limit=0, window_s=60, now=1000.0 + i)


# --- global queue depth -------------------------------------------------

def test_queue_below_the_cap_is_accepted():
    check_queue_depth(pending=5, max_depth=25)


def test_full_queue_is_refused():
    with pytest.raises(RateLimited) as e:
        check_queue_depth(pending=25, max_depth=25)
    assert "queue is full" in e.value.detail


def test_retry_after_estimates_time_until_there_is_room():
    """Not time until the queue drains — time until ONE slot frees.

    The first version estimated the full drain, which at the default depth of 25 was
    already past the 900s cap, so the "scales with backlog" logic collapsed to a constant
    and never did anything. Being one over the limit should mean "ask again in about one
    job", which is what a serial worker actually offers.
    """
    with pytest.raises(RateLimited) as just_full:
        check_queue_depth(pending=25, max_depth=25)      # 1 slot needed -> ~120s
    with pytest.raises(RateLimited) as deep:
        check_queue_depth(pending=30, max_depth=25)      # 6 slots -> ~720s
    assert just_full.value.retry_after < deep.value.retry_after
    assert just_full.value.retry_after == 120


def test_retry_after_is_floored_and_capped():
    """Floored so a refused client cannot hot-loop; capped so the header never tells
    anyone to disappear for hours."""
    with pytest.raises(RateLimited) as huge:
        check_queue_depth(pending=5000, max_depth=25)
    assert huge.value.retry_after == 900
    with pytest.raises(RateLimited) as tiny:
        check_queue_depth(pending=1, max_depth=1)
    assert tiny.value.retry_after >= 60


def test_zero_max_depth_disables_the_cap():
    check_queue_depth(pending=10_000, max_depth=0)


def test_depth_is_checked_without_consuming_window_allowance():
    """Order matters: a caller refused for depth must not also lose their own allowance
    on a request that was never accepted, or a full queue would silently rate-limit
    everyone out of the next window too."""
    with pytest.raises(RateLimited):
        check_queue_depth(pending=25, max_depth=25)
    for i in range(5):
        check_window("a", limit=5, window_s=60, now=1000.0 + i)   # full allowance intact
