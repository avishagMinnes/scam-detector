import json

import pytest
from fastapi.testclient import TestClient

from api import app
from scam_detector import classifier, service
from scam_detector.feedback import RecentChecks
from scam_detector.ratelimit import RateLimiter

needs_model = pytest.mark.skipif(not classifier.MODEL_PATH.exists(),
                                 reason="model not trained; run train/train.py")


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def test_feedback_only_once_per_real_check():
    rc = RecentChecks(clock=Clock())
    cid = rc.remember("high", ["lookalike_domain"])
    assert rc.take_feedback(cid, "correct") == {"risk_level": "high", "signs": ["lookalike_domain"]}
    assert rc.take_feedback(cid, "wrong") is None          # second vote refused
    assert rc.take_feedback("made-up-id", "correct") is None
    assert rc.take_feedback(rc.remember("low", []), "maybe") is None   # unknown verdict


def test_feedback_expires():
    clock = Clock()
    rc = RecentChecks(keep_seconds=3600, clock=clock)
    cid = rc.remember("low", [])
    clock.t += 3601
    assert rc.take_feedback(cid, "correct") is None


def test_ids_are_random_not_from_content():
    rc = RecentChecks(clock=Clock())
    assert rc.remember("high", []) != rc.remember("high", [])


def test_memory_is_bounded():
    rc = RecentChecks(max_items=3, clock=Clock())
    first = rc.remember("low", [])
    for _ in range(3):
        rc.remember("low", [])
    assert rc.take_feedback(first, "correct") is None       # oldest dropped


@needs_model
def test_feedback_api_and_record(capsys):
    client = TestClient(app)
    service.limiter = RateLimiter()
    check = client.post("/api/check", json={"text": "החוב שלך: https://secret-link.top/abc"}).json()
    capsys.readouterr()
    ok = client.post("/api/feedback", json={"check_id": check["check_id"], "verdict": "correct"})
    assert ok.status_code == 200
    rec = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rec["event"] == "feedback" and rec["verdict"] == "correct"
    assert rec["risk_level"] == check["risk_level"]
    assert "secret-link" not in json.dumps(rec)
    again = client.post("/api/feedback", json={"check_id": check["check_id"], "verdict": "wrong"})
    assert again.status_code == 409
    assert client.post("/api/feedback", json={"check_id": "nope", "verdict": "correct"}).status_code == 409
    assert client.post("/api/feedback", json={"check_id": check["check_id"], "verdict": "x"}).status_code == 422
