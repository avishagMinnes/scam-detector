"""Rate limiting: cap how many checks one visitor, and the whole app, can run.

Protects the free tier (and later, real money), keeps one visitor from blocking others,
and slows down anyone trying hundreds of rewordings to find one the detector misses.

Counts live only in memory, for at most a day. Visitor addresses are stored as salted
hashes with a salt that changes on every restart, so they can't be read back or
linked across restarts. Nothing is logged or written to disk.

In-memory counting is correct here because the service runs at most one copy
(max_instance_count = 1 in infra/main.tf). With several copies it would need a shared store.
"""
import hashlib
import os
import secrets
import threading
import time
from collections import defaultdict, deque


class RateLimited(Exception):
    def __init__(self, scope, retry_after):
        super().__init__(scope)
        self.scope = scope              # "minute", "day" or "global"
        self.retry_after = int(retry_after) + 1


class RateLimiter:
    def __init__(self, per_minute=10, per_day=100, global_per_day=2000, clock=time.time):
        self.per_minute = per_minute
        self.per_day = per_day
        self.global_per_day = global_per_day
        self._clock = clock
        self._salt = secrets.token_bytes(16)
        self._lock = threading.Lock()
        self._recent = defaultdict(deque)       # visitor -> timestamps in the last minute
        self._daily = defaultdict(int)          # visitor -> checks today
        self._global = 0
        self._day = self._today()

    @classmethod
    def from_env(cls):
        return cls(per_minute=int(os.environ.get("RATE_PER_MINUTE", 10)),
                   per_day=int(os.environ.get("RATE_PER_DAY", 100)),
                   global_per_day=int(os.environ.get("RATE_GLOBAL_PER_DAY", 2000)))

    def _today(self):
        return int(self._clock() // 86400)      # UTC day number

    def _seconds_to_midnight(self):
        return 86400 - self._clock() % 86400

    def _key(self, address):
        return hashlib.sha256(self._salt + address.encode()).hexdigest()[:16]

    def check(self, address):
        """Count one check for this visitor, or raise RateLimited."""
        now = self._clock()
        key = self._key(address)
        with self._lock:
            if self._today() != self._day:      # new day: forget everything
                self._day = self._today()
                self._daily.clear()
                self._recent.clear()
                self._global = 0

            if self._global >= self.global_per_day:
                raise RateLimited("global", self._seconds_to_midnight())
            if self._daily[key] >= self.per_day:
                raise RateLimited("day", self._seconds_to_midnight())
            recent = self._recent[key]
            while recent and recent[0] <= now - 60:
                recent.popleft()
            if len(recent) >= self.per_minute:
                raise RateLimited("minute", recent[0] + 60 - now)

            recent.append(now)
            self._daily[key] += 1
            self._global += 1


def client_address(headers, peer):
    """The visitor's address. Behind Cloud Run, the real address is the LAST entry of
    X-Forwarded-For (Google appends it; earlier entries can be faked by the visitor)."""
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return peer or "unknown"
