"""One check, the same way for every channel (web page, Telegram bot):
rate limit -> analyze -> anonymous record -> remember the check for feedback."""
import time

from scam_detector import classifier, eventlog
from scam_detector.detector import analyze
from scam_detector.feedback import RecentChecks
from scam_detector.ratelimit import RateLimiter

limiter = RateLimiter.from_env()
recent = RecentChecks()


def run_check(text, visitor, channel):
    """Raises ratelimit.RateLimited when over a limit. Returns (result, check_id)."""
    limiter.check(visitor)
    started = time.perf_counter()
    try:
        result = analyze(text)
    except Exception as error:
        eventlog.check_failed(error)
        raise
    signs = [s["id"] for s in result["red_flags"]]
    check_id = recent.remember(result["risk_level"], signs)
    eventlog.check_done(result, (time.perf_counter() - started) * 1000, classifier.MODEL_KIND,
                        check_id, channel)
    return result, check_id


def give_feedback(check_id, verdict, channel):
    """True if accepted (a real, recent, not-yet-rated check)."""
    check = recent.take_feedback(check_id, verdict)
    if check is None:
        return False
    eventlog.feedback(check_id, verdict, check, channel)
    return True
