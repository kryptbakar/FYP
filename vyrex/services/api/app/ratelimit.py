"""Admission control for expensive, asynchronous work.

Why this is not the usual "requests per second" concern: `POST /investigations` returns in
milliseconds, so it looks cheap at the edge, but each accepted request commits the
orchestrator to roughly two minutes of CPU-bound model inference — and the orchestrator is
deliberately serial (ORCH_CONCURRENCY=1, because two concurrent 3B generations swap on a
5.8 GiB Docker VM). One `for` loop over the finding list therefore buys hours of queue with
sixty-odd cheap HTTP calls.

The existing partial unique index stops duplicate work on the *same* subject. It does
nothing about many different subjects, which is the actual exhaustion path.

Two independent limits, because they fail differently:

  * a **sliding window per requester** — stops one client monopolising the worker;
  * a **global queue-depth cap** — stops the queue growing past the point where the answer
    would arrive too late to matter. Beyond that, accepting work is not throughput, it is
    just latency the caller cannot see.

Both return 429 with `Retry-After`, so a well-behaved client backs off rather than retrying
into the wall.

**Honest limitation, stated rather than discovered later:** the per-requester window is
in-process. It is correct for the single API instance this ships as, and it becomes
per-replica if the API is ever scaled out — at which point the effective limit is N times
higher, not the configured one. The queue-depth cap has no such problem because it reads
committed database state, which is the reason it exists as a separate control rather than
as a second bucket. Moving the window to Postgres or Redis is the fix when it is needed;
pretending it already works across replicas would be worse than saying so.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

# requester -> timestamps of accepted requests inside the window
_WINDOW: dict[str, deque[float]] = defaultdict(deque)


class RateLimited(Exception):
    """Raised instead of returning a bool so a caller cannot forget to check."""

    def __init__(self, detail: str, retry_after: int) -> None:
        super().__init__(detail)
        self.detail = detail
        self.retry_after = retry_after


def check_window(requester: str, limit: int, window_s: int, now: float | None = None) -> None:
    """Sliding window, not a fixed bucket.

    A fixed bucket lets a caller spend the whole allowance in the last second of one
    window and again in the first second of the next — a 2x burst exactly at the boundary,
    which for two-minute jobs is a meaningful amount of stolen worker time.
    """
    if limit <= 0:                       # 0 disables, matching INGEST_RATE_PER_SEC
        return
    now = time.monotonic() if now is None else now
    seen = _WINDOW[requester]
    cutoff = now - window_s
    while seen and seen[0] <= cutoff:
        seen.popleft()
    if len(seen) >= limit:
        retry = max(1, int(seen[0] + window_s - now) + 1)
        raise RateLimited(
            f"{limit} investigation requests per {window_s}s exceeded for this requester. "
            f"Each accepted request commits ~2 minutes of serial inference.",
            retry_after=retry,
        )
    seen.append(now)


def check_queue_depth(pending: int, max_depth: int) -> None:
    """Refuse work the queue cannot get to in a useful timeframe.

    Deliberately checked BEFORE the window is consumed, so a caller who is refused for
    depth does not also burn their own allowance on a request that was never accepted.
    """
    if max_depth <= 0:
        return
    if pending >= max_depth:
        # Time until there is ROOM, not until the queue drains. Estimating the full drain
        # sends a caller away for the whole backlog when one finished job would let them
        # in — and at the default depth of 25 that estimate was already past the 900s cap,
        # so it collapsed to a constant and the scaling never did anything.
        slots_needed = pending - max_depth + 1
        raise RateLimited(
            f"investigation queue is full ({pending} pending, max {max_depth}). "
            f"The orchestrator runs one investigation at a time by design.",
            # ~120s per job on this hardware; floored so a client cannot hot-loop, and
            # capped so the header never tells anyone to disappear for hours.
            retry_after=min(900, max(60, slots_needed * 120)),
        )


def reset() -> None:
    """Tests only — module state would otherwise leak between cases."""
    _WINDOW.clear()
