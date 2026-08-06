"""Quota enforcement, including what happens when the shared backend fails.

The Redis tests run against a real Redis when `AEGIS_TEST_REDIS_URL` is set and
skip otherwise, so the suite stays runnable on a laptop with no services up
while still exercising the Lua path in CI or against the cluster.
"""

from __future__ import annotations

import os

import pytest

from gateway.limits import RateLimiter, RedisRateLimiter, build_limiter

REDIS_URL = os.getenv("AEGIS_TEST_REDIS_URL", "")
needs_redis = pytest.mark.skipif(not REDIS_URL, reason="AEGIS_TEST_REDIS_URL not set")


# --------------------------------------------------------------------------
# In-process limiter
# --------------------------------------------------------------------------

def test_request_limit_is_enforced():
    limiter = RateLimiter(requests_per_minute=2, tokens_per_minute=10**6)

    assert limiter.check("a")[0]
    assert limiter.check("a")[0]
    allowed, reason = limiter.check("a")

    assert not allowed
    assert reason == "requests-per-minute"


def test_token_limit_is_separate_from_the_request_limit():
    """One huge prompt can cost more than many small ones, so counting requests
    alone is not a spend limit."""
    limiter = RateLimiter(requests_per_minute=100, tokens_per_minute=10)

    allowed, reason = limiter.check("a", estimated_tokens=50)

    assert not allowed
    assert reason == "tokens-per-minute"


def test_quotas_are_per_client():
    limiter = RateLimiter(requests_per_minute=1, tokens_per_minute=10**6)
    limiter.check("a")

    assert not limiter.check("a")[0]
    assert limiter.check("b")[0]


def test_build_limiter_defaults_to_in_process(monkeypatch):
    monkeypatch.delenv("AEGIS_REDIS_URL", raising=False)

    assert build_limiter(10, 10).kind == "in-process"


# --------------------------------------------------------------------------
# Redis limiter — the point is that the quota is the *cluster's*
# --------------------------------------------------------------------------

@pytest.fixture
def redis_limiters():
    """Two limiter instances sharing one Redis, standing in for two replicas."""
    import uuid

    import redis

    client = redis.Redis.from_url(REDIS_URL)
    prefix = uuid.uuid4().hex[:8]

    def make(rpm=2, tpm=10**6):
        return RedisRateLimiter(rpm, tpm, REDIS_URL)

    yield make, prefix
    for key in client.scan_iter("aegis:quota:*"):
        client.delete(key)


@needs_redis
def test_two_replicas_share_one_quota(redis_limiters):
    """The regression this fixes: with per-process counters the real limit was
    `replicas x limit`, so the configured number meant nothing."""
    make, prefix = redis_limiters
    replica_one, replica_two = make(rpm=2), make(rpm=2)
    client = f"{prefix}-shared"

    assert replica_one.check(client)[0]
    assert replica_two.check(client)[0]

    # Third request, on either replica, must be refused — the budget is spent.
    allowed_one, reason_one = replica_one.check(client)
    allowed_two, _ = replica_two.check(client)

    assert not allowed_one
    assert not allowed_two
    assert reason_one == "requests-per-minute"


@needs_redis
def test_token_budget_is_also_shared(redis_limiters):
    make, prefix = redis_limiters
    replica_one, replica_two = make(rpm=1000, tpm=100), make(rpm=1000, tpm=100)
    client = f"{prefix}-tokens"

    replica_one.check(client, estimated_tokens=80)
    allowed, reason = replica_two.check(client, estimated_tokens=50)

    assert not allowed, "the second replica must see the first one's spend"
    assert reason == "tokens-per-minute"


@needs_redis
def test_distinct_clients_do_not_share_a_budget(redis_limiters):
    make, prefix = redis_limiters
    limiter = make(rpm=1)

    assert limiter.check(f"{prefix}-one")[0]
    assert limiter.check(f"{prefix}-two")[0]


# --------------------------------------------------------------------------
# Degradation
# --------------------------------------------------------------------------

def test_unreachable_redis_degrades_to_local_counting_and_logs(caplog):
    """Availability choice, stated explicitly: a Redis outage must not take the
    model service down, but it must not be silent either."""
    limiter = RedisRateLimiter(
        requests_per_minute=1,
        tokens_per_minute=10**6,
        # Port 1 is reserved and never bound, so the connection is refused
        # immediately. Picking a plausible-looking spare port invites exactly the
        # collision that made this test fail the first time it was run alongside
        # a real Redis.
        url="redis://127.0.0.1:1/0",
    )

    with caplog.at_level("WARNING", logger="aegis.gateway"):
        first = limiter.check("a")
        second = limiter.check("a")

    assert first[0], "traffic keeps flowing"
    assert not second[0], "the local fallback still enforces a limit"
    assert any("quota_backend_degraded" in r.getMessage() for r in caplog.records)


def test_degradation_is_logged_once_not_per_request(caplog):
    """A per-request warning during an outage would bury every other signal."""
    limiter = RedisRateLimiter(10**6, 10**6, url="redis://127.0.0.1:1/0")

    with caplog.at_level("WARNING", logger="aegis.gateway"):
        for _ in range(5):
            limiter.check("a")

    degraded = [r for r in caplog.records if "quota_backend_degraded" in r.getMessage()]
    assert len(degraded) == 1
