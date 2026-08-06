"""Rate and token quotas — OWASP LLM10, Unbounded Consumption.

Inference is expensive in a way ordinary web requests are not: a single large
prompt can cost orders of magnitude more than a small one, so a request-count
limit alone is not a spend limit. Both are enforced.

Two backends:

* ``RedisRateLimiter`` — a sliding window in a shared sorted set, so the quota is
  the *cluster's*, not each replica's. This is the one that makes the configured
  number mean what it says.
* ``RateLimiter`` — the in-process fallback. Correct for a single replica and
  used when Redis is not configured or has gone away.

**On what happens when Redis is unreachable.** The limiter degrades to local
counting rather than refusing all traffic. That is a deliberate availability
choice and it is a real weakening: during an outage the effective limit rises to
`replicas x limit`, which is where this started. Failing closed would convert a
Redis blip into a full outage of the model service, which is the wrong trade for
a quota — quotas exist to bound cost and abuse, not to be a safety interlock. The
degradation is logged and counted so it is visible rather than silent, and the
gateway's other controls (auth, guardrails, egress lockdown) are unaffected.
"""

from __future__ import annotations

import collections
import logging
import os
import threading
import time

LOG = logging.getLogger("aegis.gateway")

WINDOW_SECONDS = 60.0


class RateLimiter:
    """Per-process sliding window. Correct for one replica."""

    kind = "in-process"

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


# Sliding window in Redis, evaluated server-side so the read-decide-write cycle
# cannot interleave between replicas. Doing this in three round trips instead
# would let two pods both observe "59 requests used" and both allow one more.
_SLIDING_WINDOW_LUA = """
local key      = KEYS[1]
local now      = tonumber(ARGV[1])
local window   = tonumber(ARGV[2])
local req_max  = tonumber(ARGV[3])
local tok_max  = tonumber(ARGV[4])
local tokens   = tonumber(ARGV[5])
local member   = ARGV[6]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

local entries = redis.call('ZRANGE', key, 0, -1)
local used_requests = #entries
local used_tokens = 0
for _, entry in ipairs(entries) do
  -- members are "<uuid>:<tokens>"
  local cost = tonumber(string.match(entry, ':(%d+)$')) or 0
  used_tokens = used_tokens + cost
end

if used_requests >= req_max then
  return {0, 'requests-per-minute'}
end
if used_tokens + tokens > tok_max then
  return {0, 'tokens-per-minute'}
end

redis.call('ZADD', key, now, member)
-- Expire a little after the window so idle keys do not accumulate forever.
redis.call('EXPIRE', key, math.ceil(window) + 10)
return {1, ''}
"""


class RedisRateLimiter:
    """Cluster-wide sliding window.

    The whole check runs as one Lua script inside Redis, so it is atomic. Split
    across separate GET/SET calls, two replicas could each read the same count and
    each decide there was room — which is exactly the race that makes a
    distributed quota leak.
    """

    kind = "redis"

    def __init__(
        self,
        requests_per_minute: int,
        tokens_per_minute: int,
        url: str,
        fallback: RateLimiter | None = None,
    ) -> None:
        import redis  # imported here so the dependency is optional

        self.requests_per_minute = requests_per_minute
        self.tokens_per_minute = tokens_per_minute
        self._fallback = fallback or RateLimiter(requests_per_minute, tokens_per_minute)
        # Timeouts sized for a mesh, not a loopback. 250ms looked appropriately
        # strict and was in fact too tight for the first connection through an
        # mTLS sidecar: every request timed out, the limiter degraded to local
        # counting, and the "cluster-wide" quota silently was not one. Still
        # short enough that a genuinely dead Redis cannot stall inference.
        self._client = redis.Redis.from_url(
            url,
            socket_timeout=1.0,
            socket_connect_timeout=1.0,
            health_check_interval=30,
        )
        self._script = self._client.register_script(_SLIDING_WINDOW_LUA)
        # Captured at construction because `redis` is an optional dependency and
        # cannot be imported at module scope. Narrow on purpose: a bug in the Lua
        # script or this code should surface as a 500, not be silently swallowed
        # as "Redis is having a moment".
        self._transport_errors = (redis.RedisError, OSError, TimeoutError)
        self._degraded = False

    def check(self, client: str, estimated_tokens: int = 0) -> tuple[bool, str]:
        import uuid

        try:
            allowed, reason = self._script(
                keys=[f"aegis:quota:{client}"],
                args=[
                    time.time(),
                    WINDOW_SECONDS,
                    self.requests_per_minute,
                    self.tokens_per_minute,
                    max(estimated_tokens, 0),
                    f"{uuid.uuid4().hex}:{max(estimated_tokens, 0)}",
                ],
            )
            if self._degraded:
                LOG.info('{"event":"quota_backend_recovered","backend":"redis"}')
                self._degraded = False
            reason = reason.decode() if isinstance(reason, bytes) else reason
            return bool(allowed), reason or ""
        except self._transport_errors as exc:
            # Degrade to local counting rather than taking the service down. This
            # weakens the quota to per-replica for the duration — logged loudly so
            # it is an operational signal, not a silent regression.
            if not self._degraded:
                LOG.warning(
                    '{"event":"quota_backend_degraded","backend":"redis","error":"%s"}',
                    type(exc).__name__,
                )
                self._degraded = True
            return self._fallback.check(client, estimated_tokens)

    def snapshot(self, client: str) -> dict[str, int]:
        try:
            key = f"aegis:quota:{client}"
            now = time.time()
            self._client.zremrangebyscore(key, "-inf", now - WINDOW_SECONDS)
            entries = [e.decode() for e in self._client.zrange(key, 0, -1)]
            return {
                "requests": len(entries),
                "tokens": sum(int(e.rsplit(":", 1)[-1]) for e in entries if ":" in e),
                "requests_limit": self.requests_per_minute,
                "tokens_limit": self.tokens_per_minute,
            }
        except self._transport_errors:
            return self._fallback.snapshot(client)


def build_limiter(requests_per_minute: int, tokens_per_minute: int) -> RateLimiter:
    """Pick a backend from the environment.

    No Redis configured means a single-replica deployment or local development,
    where the in-process window is genuinely correct. Configuring Redis is what
    makes the number a cluster-wide limit.
    """
    url = os.getenv("AEGIS_REDIS_URL", "").strip()
    if not url:
        return RateLimiter(requests_per_minute, tokens_per_minute)
    try:
        return RedisRateLimiter(requests_per_minute, tokens_per_minute, url)
    except ImportError:
        LOG.warning('{"event":"quota_backend_unavailable","reason":"redis package missing"}')
        return RateLimiter(requests_per_minute, tokens_per_minute)
