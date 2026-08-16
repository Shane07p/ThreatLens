import pytest

from threatlens.ingest.fetch import TokenBucket


class FakeClock:
    """Injectable clock that records sleep calls instead of blocking."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_allows_burst_up_to_rate():
    """Five requests at rate=5 should all go through without sleeping."""
    c = FakeClock()
    b = TokenBucket(rate=5, per_seconds=30.0, clock=c.time, sleep=c.sleep)
    for _ in range(5):
        b.acquire()
    assert c.slept == []


def test_sleeps_when_budget_exhausted():
    """The sixth request at rate=5 must trigger a sleep."""
    c = FakeClock()
    b = TokenBucket(rate=5, per_seconds=30.0, clock=c.time, sleep=c.sleep)
    for _ in range(6):
        b.acquire()
    assert len(c.slept) == 1
    assert c.slept[0] > 0


def test_refills_over_time():
    """After exhausting the bucket, waiting a full window should refill it."""
    c = FakeClock()
    b = TokenBucket(rate=5, per_seconds=30.0, clock=c.time, sleep=c.sleep)
    for _ in range(5):
        b.acquire()
    c.now += 30.0  # full refill window
    b.acquire()
    assert c.slept == []


def test_partial_refill():
    """Waiting half the window should refill roughly half the tokens."""
    c = FakeClock()
    b = TokenBucket(rate=10, per_seconds=10.0, clock=c.time, sleep=c.sleep)
    for _ in range(10):
        b.acquire()
    c.now += 5.0  # half window → ~5 tokens
    for _ in range(5):
        b.acquire()
    assert c.slept == []


def test_single_token_rate():
    """Edge case: rate=1 should allow exactly one, then block."""
    c = FakeClock()
    b = TokenBucket(rate=1, per_seconds=1.0, clock=c.time, sleep=c.sleep)
    b.acquire()
    assert c.slept == []
    b.acquire()
    assert len(c.slept) == 1


def test_rate_limit_with_api_key():
    """When an API key is configured, rate limit is 50 requests per 30 seconds."""
    c = FakeClock()
    b = TokenBucket(api_key="test-key-123", clock=c.time, sleep=c.sleep)
    assert b.get_rate() == 50
    for _ in range(50):
        b.acquire()
    assert c.slept == []
    b.acquire()
    assert len(c.slept) == 1
    assert pytest.approx(c.slept[0], rel=1e-3) == 0.6


def test_rate_limit_without_api_key():
    """When no API key is configured, rate limit is 5 requests per 30 seconds."""
    c = FakeClock()
    b = TokenBucket(api_key=None, clock=c.time, sleep=c.sleep)
    assert b.get_rate() == 5
    for _ in range(5):
        b.acquire()
    assert c.slept == []
    b.acquire()
    assert len(c.slept) == 1
    assert pytest.approx(c.slept[0], rel=1e-3) == 6.0


def test_key_isolation_between_api_keys():
    """Rate limiting is per API key; exhausting key A does not affect key B or None."""
    c = FakeClock()
    b = TokenBucket(clock=c.time, sleep=c.sleep)

    for _ in range(50):
        b.acquire(api_key="key-A")
    assert c.slept == []

    for _ in range(50):
        b.acquire(api_key="key-B")
    assert c.slept == []

    for _ in range(5):
        b.acquire(api_key=None)
    assert c.slept == []

    b.acquire(api_key="key-A")
    assert len(c.slept) == 1
