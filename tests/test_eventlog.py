import json

import pytest
from fastapi.testclient import TestClient

from api import app
from scam_detector import classifier, eventlog
from scam_detector.ratelimit import RateLimiter

needs_model = pytest.mark.skipif(not classifier.MODEL_PATH.exists(),
                                 reason="model not trained; run train/train.py")

SECRET_MESSAGE = ("שלום [NAME] ישראלי, החוב שלך 38.70 ש\"ח: https://secret-link.top/abc "
                  "התקשר 052-1234567")
LEAKS = ["secret-link", "052-1234567", "+972521234567", "38.70", "ישראלי", "החוב", "198.51.100.23"]


def records(capsys):
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()
            if line.startswith("{")]


@needs_model
def test_check_record_has_no_message_content_or_address(capsys):
    client = TestClient(app)
    app.state.limiter = RateLimiter()
    res = client.post("/api/check", json={"text": SECRET_MESSAGE},
                      headers={"x-forwarded-for": "198.51.100.23"})
    assert res.status_code == 200
    recs = records(capsys)
    assert [r["event"] for r in recs] == ["check"]
    line = json.dumps(recs, ensure_ascii=False)
    for leak in LEAKS:
        assert leak not in line, f"log record leaked {leak!r}"
    rec = recs[0]
    assert rec["risk_level"] in ("high", "medium", "low")
    assert "risky_domain_ending" in rec["signs"]
    assert set(rec) <= {"severity", "message", "event", "risk_level", "signs", "reassuring",
                        "model_score", "language", "latency_ms", "model"}


def test_failure_record_has_only_the_error_type(capsys):
    eventlog.check_failed(ValueError(f"could not parse {SECRET_MESSAGE}"))
    rec = records(capsys)[0]
    assert rec == {"severity": "ERROR", "message": "check_failed", "event": "check_failed",
                   "error_type": "ValueError"}


@needs_model
def test_rate_limited_record(capsys):
    client = TestClient(app)
    app.state.limiter = RateLimiter(per_minute=1)
    try:
        client.post("/api/check", json={"text": "Ok see you at 7"})
        capsys.readouterr()
        assert client.post("/api/check", json={"text": "Ok see you at 7"}).status_code == 429
        assert records(capsys) == [{"severity": "WARNING", "message": "rate_limited",
                                    "event": "rate_limited", "scope": "minute"}]
    finally:
        app.state.limiter = RateLimiter()
