import pytest

from scam_detector.ratelimit import RateLimited, RateLimiter, client_address


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_per_minute_limit_and_recovery():
    clock = Clock()
    rl = RateLimiter(per_minute=3, per_day=100, global_per_day=100, clock=clock)
    for _ in range(3):
        rl.check("1.2.3.4")
    with pytest.raises(RateLimited) as e:
        rl.check("1.2.3.4")
    assert e.value.scope == "minute" and 1 <= e.value.retry_after <= 61
    clock.t += 61
    rl.check("1.2.3.4")                       # a minute later it works again


def test_visitors_are_counted_separately():
    rl = RateLimiter(per_minute=1, per_day=100, global_per_day=100, clock=Clock())
    rl.check("1.1.1.1")
    rl.check("2.2.2.2")                       # someone else isn't blocked
    with pytest.raises(RateLimited):
        rl.check("1.1.1.1")


def test_daily_limit_resets_next_day():
    clock = Clock(86400 * 20000 + 100)        # early in a UTC day
    rl = RateLimiter(per_minute=100, per_day=2, global_per_day=100, clock=clock)
    rl.check("a")
    clock.t += 120
    rl.check("a")
    clock.t += 120
    with pytest.raises(RateLimited) as e:
        rl.check("a")
    assert e.value.scope == "day"
    clock.t += 86400
    rl.check("a")


def test_global_limit_protects_the_budget():
    rl = RateLimiter(per_minute=100, per_day=100, global_per_day=3, clock=Clock())
    for ip in ("a", "b", "c"):
        rl.check(ip)
    with pytest.raises(RateLimited) as e:
        rl.check("d")                         # a new visitor is still refused
    assert e.value.scope == "global"


def test_addresses_are_not_stored_readably():
    rl = RateLimiter(clock=Clock())
    rl.check("203.0.113.7")
    assert all("203.0.113.7" not in k for k in rl._daily)


def test_client_address_uses_last_forwarded_entry():
    # A visitor can fake earlier entries; Cloud Run appends the real address last
    assert client_address({"x-forwarded-for": "6.6.6.6, 198.51.100.4"}, "10.0.0.1") == "198.51.100.4"
    assert client_address({}, "127.0.0.1") == "127.0.0.1"
