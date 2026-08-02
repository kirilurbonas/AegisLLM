"""Rate and token quotas — OWASP LLM10, Unbounded Consumption.

Inference is expensive in a way ordinary web requests are not: a single large
prompt can cost orders of magnitude more than a small one, so a request-count
limit alone is not a spend limit. Both are enforced.

This is a per-process sliding window, which is honest about its scope: with more
than one replica each holds its own counters, so the effective cluster limit is
`replicas x limit`. A real deployment moves the window to Redis or enforces it at
the mesh. The comment exists so nobody reads this as a distributed quota.
"""

from __future__ import annotations

import collections
import threading
import time

WINDOW_SECONDS = 60.0


class RateLimiter:
    def __init__(self, requests_per_minute: int, tokens_per_minute: int) -> None:
        self.requests_per_minute = requests_per_minute
        self.tokens_per_minute = tokens_per_minute
        self._events: dict[str, collections.deque] = collections.defaultdict(
            collections.deque
        )
        # FastAPI serves requests from a thread pool, so the counters are shared
        # mutable state and need a lock.
        self._lock = threading.Lock()

    def check(self, client: str, estimated_tokens: int = 0) -> tuple[bool, str]:
        now = time.monotonic()
        with self._lock:
            window = self._events[client]
            while window and now - window[0][0] > WINDOW_SECONDS:
                window.popleft()

            if len(window) >= self.requests_per_minute:
                return False, "requests-per-minute"

            spent = sum(tokens for _, tokens in window)
            if spent + estimated_tokens > self.tokens_per_minute:
                return False, "tokens-per-minute"

            window.append((now, estimated_tokens))
            return True, ""

    def snapshot(self, client: str) -> dict[str, int]:
        """Current usage — surfaced to Prometheus in Pillar 5."""
        now = time.monotonic()
        with self._lock:
            window = self._events.get(client, collections.deque())
            live = [(t, n) for t, n in window if now - t <= WINDOW_SECONDS]
            return {
                "requests": len(live),
                "tokens": sum(n for _, n in live),
                "requests_limit": self.requests_per_minute,
                "tokens_limit": self.tokens_per_minute,
            }
