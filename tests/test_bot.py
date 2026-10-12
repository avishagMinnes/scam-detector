import pytest
from fastapi.testclient import TestClient

import bot
from scam_detector import classifier, service
from scam_detector.ratelimit import RateLimiter

needs_model = pytest.mark.skipif(not classifier.MODEL_PATH.exists(),
                                 reason="model not trained; run train/train.py")
SECRET = "test-secret"
ME = 111


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("TELEGRAM_ALLOWED_USERS", f"{ME},222")
    service.limiter = RateLimiter()
    return TestClient(bot.app)


def send(client, text, user=ME, chat_type="private", secret=SECRET):
    update = {"update_id": 1, "message": {"message_id": 5, "text": text,
              "chat": {"id": user, "type": chat_type}, "from": {"id": user}}}
    return client.post("/telegram/webhook", json=update,
                       headers={"X-Telegram-Bot-Api-Secret-Token": secret} if secret else {})


def test_requests_without_the_secret_are_refused(client):
    assert send(client, "hi", secret=None).status_code == 403
    assert send(client, "hi", secret="wrong").status_code == 403


def test_users_not_on_the_list_get_their_id_only(client):
    body = send(client, "שלום", user=999).json()
    assert body["method"] == "sendMessage" and body["chat_id"] == 999
    assert "999" in body["text"] and "בדיקה פרטית" in body["text"]
    assert "reply_markup" not in body


def test_groups_are_ignored(client):
    assert send(client, "hi", chat_type="group").json() == {}


def test_start_shows_privacy_note(client):
    text = send(client, "/start").json()["text"]
    assert "טלגרם" in text and "לא נשמרת" in text


@needs_model
def test_scam_gets_result_and_feedback_buttons(client):
    body = send(client, "כדי לקבל פיצויי המלחמה רשמו באתר הזה https://taxesgov.net/he").json()
    assert body["method"] == "sendMessage" and body["parse_mode"] == "HTML"
    assert body["text"].startswith("🔴")
    buttons = body["reply_markup"]["inline_keyboard"][0]
    assert [b["callback_data"].split(":")[2] for b in buttons] == ["correct", "wrong"]

    cb = {"update_id": 2, "callback_query": {"id": "q1", "from": {"id": ME},
          "data": buttons[0]["callback_data"]}}
    headers = {"X-Telegram-Bot-Api-Secret-Token": SECRET}
    first = client.post("/telegram/webhook", json=cb, headers=headers).json()
    assert first["method"] == "answerCallbackQuery" and first["text"].startswith("תודה")
    again = client.post("/telegram/webhook", json=cb, headers=headers).json()
    assert again["text"].startswith("כבר")


@needs_model
def test_message_text_is_escaped(client):
    body = send(client, "<b>זכית!</b> https://evil.top/<script>").json()
    assert "<script>" not in body["text"]


def test_rate_limited_user_gets_friendly_message(client):
    service.limiter = RateLimiter(per_minute=0)
    assert "נסו שוב" in send(client, "hello").json()["text"]
    service.limiter = RateLimiter()
