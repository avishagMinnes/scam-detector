"""Remember recent checks briefly, so 👍/👎 feedback can be tied to a real check.

Each check gets a random id (not derived from the message). For one hour the server
keeps: id -> result and warning-sign ids. Never the message text. Feedback is
accepted only for a check that really happened, and only once per check, so the
statistics can't be flooded with made-up votes.

In memory only; correct because the service runs at most one copy.
"""
import secrets
import threading
import time
from collections import OrderedDict

VERDICTS = ("correct", "wrong")


class RecentChecks:
    def __init__(self, keep_seconds=3600, max_items=5000, clock=time.time):
        self.keep_seconds = keep_seconds
        self.max_items = max_items
        self._clock = clock
        self._items = OrderedDict()          # id -> {"risk_level", "signs", "at", "answered"}
        self._lock = threading.Lock()

    def remember(self, risk_level, signs):
        check_id = secrets.token_urlsafe(12)
        with self._lock:
            self._prune()
            self._items[check_id] = {"risk_level": risk_level, "signs": sorted(signs),
                                     "at": self._clock(), "answered": False}
            while len(self._items) > self.max_items:
                self._items.popitem(last=False)
        return check_id

    def take_feedback(self, check_id, verdict):
        """The check's result and signs if feedback is allowed now, else None."""
        if verdict not in VERDICTS:
            return None
        with self._lock:
            self._prune()
            item = self._items.get(check_id)
            if item is None or item["answered"]:
                return None
            item["answered"] = True
            return {"risk_level": item["risk_level"], "signs": item["signs"]}

    def _prune(self):
        cutoff = self._clock() - self.keep_seconds
        while self._items and next(iter(self._items.values()))["at"] < cutoff:
            self._items.popitem(last=False)
