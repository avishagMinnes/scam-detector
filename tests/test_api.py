import pytest
from fastapi.testclient import TestClient

from api import app
from scam_detector import classifier
from scam_detector.ratelimit import RateLimiter

client = TestClient(app)
needs_model = pytest.mark.skipif(not classifier.MODEL_PATH.exists(),
                                 reason="model not trained; run train/train.py")


def test_page_is_served():
    res = client.get("/")
    assert res.status_code == 200
    assert 'dir="rtl"' in res.text


@needs_model
def test_check_scam():
    res = client.post("/api/check", json={"text": "כדי לקבל פיצויי המלחמה רשמו באתר הזה https://taxesgov.net/he"})
    assert res.status_code == 200
    body = res.json()
    assert body["risk_level"] == "high"
    assert body["found"]["links"][0]["domain"] == "taxesgov.net"
    assert {"id", "strength", "he", "en"} == set(body["red_flags"][0])


def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_rejects_empty_and_too_long():
    assert client.post("/api/check", json={"text": ""}).status_code == 422
    assert client.post("/api/check", json={"text": "   "}).status_code == 422
    assert client.post("/api/check", json={"text": "א" * 5001}).status_code == 422


@needs_model
def test_check_is_rate_limited():
    original = app.state.limiter
    app.state.limiter = RateLimiter(per_minute=2, per_day=100, global_per_day=100)
    try:
        body = {"text": "Ok see you at 7"}
        assert client.post("/api/check", json=body).status_code == 200
        assert client.post("/api/check", json=body).status_code == 200
        res = client.post("/api/check", json=body)
        assert res.status_code == 429
        assert res.json()["scope"] == "minute"
        assert int(res.headers["Retry-After"]) > 0
    finally:
        app.state.limiter = original


def test_examples_are_drafts_only():
    ids = [e["id"] for e in client.get("/api/examples").json()]
    assert ids and all("-d" in i for i in ids)
