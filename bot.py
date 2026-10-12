"""Telegram bot: forward a suspicious message, get the risk level, warning signs and advice.

Runs as its own Cloud Run service (scam-detector-bot), which must be reachable by
Telegram. It only accepts requests carrying the secret token set with setWebhook
(header X-Telegram-Bot-Api-Secret-Token); everything else gets 403.

It replies inside the webhook response (Telegram allows one Bot API method there), so
the cloud never needs the bot's own token.

Private testing: only Telegram user ids in TELEGRAM_ALLOWED_USERS get answers.
Like the web app: nothing stored, one anonymous record per check, rate limited.

Run locally: uvicorn bot:app --port 8001 --no-access-log
"""
import hmac
import html
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request

from scam_detector import classifier, eventlog, service
from scam_detector.detector import HIGH, LOW, MEDIUM_RISK
from scam_detector.ratelimit import RateLimited

MAX_CHARS = 5000
ICON = {HIGH: "🔴", MEDIUM_RISK: "🟠", LOW: "⚪"}

TEXT = {
    "welcome": (
        "שלום! 👋 אני בודק הודעות חשודות.\n\n"
        "העבירו (Forward) אליי הודעה חשודה, או הדביקו את הטקסט שלה, ואגיד לכם אם היא נראית כמו הונאה, "
        "מה סימני האזהרה ומה כדאי לעשות.\n\n"
        "🔒 <b>פרטיות:</b> ההודעה עוברת דרך השרתים של טלגרם. אצלנו היא נבדקת ולא נשמרת, והקישורים לא נפתחים.\n\n"
        "ℹ️ זה כלי עזר, לא ערובה. במקרה של ספק, פנו ישירות לגוף הרשמי."
    ),
    "not_allowed": (
        "הבוט עדיין בבדיקה פרטית ועונה רק למשתתפים שאושרו.\n"
        "מספר הזיהוי שלך בטלגרם: <code>{user_id}</code>"
    ),
    "need_text": "שלחו הודעה עם טקסט (או העבירו את ההודעה החשודה). תמונות בלי טקסט עוד לא נתמכות.",
    "too_long": "ההודעה ארוכה מדי לבדיקה (עד 5,000 תווים).",
    "limited": {
        "minute": "בדקתם הרבה הודעות ברצף. נסו שוב בעוד דקה.",
        "day": "הגעתם למספר הבדיקות היומי. אפשר לנסות שוב מחר.",
        "global": "השירות עמוס היום. אפשר לנסות שוב מחר.",
    },
    "error": "משהו השתבש בבדיקה. נסו שוב בעוד רגע.",
    "signs": {"he": "סימני אזהרה", "en": "Warning signs"},
    "reassuring": {"he": "סימנים מרגיעים", "en": "Reassuring signs"},
    "todo": {"he": "מה לעשות", "en": "What to do"},
    "ask": {"he": "האם התשובה נכונה?", "en": "Is this answer right?"},
    "yes": {"he": "👍 נכון", "en": "👍 Yes"},
    "no": {"he": "👎 לא נכון", "en": "👎 No"},
    "thanks": "תודה! זה עוזר לשפר את הבדיקה.",
    "already": "כבר התקבל דירוג להודעה הזו (או שעבר יותר משעה).",
}


def allowed_users():
    return {u.strip() for u in os.environ.get("TELEGRAM_ALLOWED_USERS", "").split(",") if u.strip()}


@asynccontextmanager
async def lifespan(app):
    if classifier.MODEL_PATH.exists():
        classifier.warm_up()
    yield


app = FastAPI(title="Scam checker Telegram bot", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.get("/api/health")
def health():
    return {"status": "ok", "model": classifier.MODEL_KIND}


def reply(chat_id, text, keyboard=None):
    method = {"method": "sendMessage", "chat_id": chat_id, "text": text, "parse_mode": "HTML",
              "disable_web_page_preview": True}
    if keyboard:
        method["reply_markup"] = {"inline_keyboard": keyboard}
    return method


def format_result(r):
    """The detector's answer as a Telegram message. Every piece of message-derived text
    (e.g. a link's host inside a warning sign) is HTML-escaped."""
    lang = r["language"]
    e = html.escape
    lines = [f"{ICON[r['risk_level']]} <b>{e(r['risk_text'][lang])}</b>"]
    if r["red_flags"]:
        lines += ["", f"⚠️ <b>{TEXT['signs'][lang]}</b>"] + [f"• {e(s[lang])}" for s in r["red_flags"]]
    if r["reassuring"]:
        lines += ["", f"✅ <b>{TEXT['reassuring'][lang]}</b>"] + [f"• {e(s[lang])}" for s in r["reassuring"]]
    lines += ["", f"🛡️ <b>{TEXT['todo'][lang]}</b>"] + [f"{i}. {e(a)}" for i, a in enumerate(r["what_to_do"], 1)]
    lines += ["", f"<i>{TEXT['ask'][lang]}</i>"]
    return "\n".join(lines)


def handle_message(msg):
    chat, user = msg.get("chat", {}), msg.get("from", {})
    if chat.get("type") != "private":
        return None                                        # ignore groups and channels
    chat_id, user_id = chat["id"], str(user.get("id", ""))
    text = (msg.get("text") or msg.get("caption") or "").strip()

    if user_id not in allowed_users():
        return reply(chat_id, TEXT["not_allowed"].format(user_id=html.escape(user_id)))
    if text in ("/start", "/help"):
        return reply(chat_id, TEXT["welcome"])
    if not text:
        return reply(chat_id, TEXT["need_text"])
    if len(text) > MAX_CHARS:
        return reply(chat_id, TEXT["too_long"])
    try:
        r, check_id = service.run_check(text, f"telegram:{user_id}", "telegram")
    except RateLimited as exc:
        eventlog.rate_limited(exc.scope)
        return reply(chat_id, TEXT["limited"][exc.scope])
    except Exception:
        return reply(chat_id, TEXT["error"])               # check_failed already recorded
    lang = r["language"]
    keyboard = [[{"text": TEXT["yes"][lang], "callback_data": f"fb:{check_id}:correct"},
                 {"text": TEXT["no"][lang], "callback_data": f"fb:{check_id}:wrong"}]]
    return reply(chat_id, format_result(r), keyboard)


def handle_callback(cb):
    parts = (cb.get("data") or "").split(":")
    ok = (len(parts) == 3 and parts[0] == "fb"
          and str(cb.get("from", {}).get("id", "")) in allowed_users()
          and service.give_feedback(parts[1], parts[2], "telegram"))
    return {"method": "answerCallbackQuery", "callback_query_id": cb["id"],
            "text": TEXT["thanks"] if ok else TEXT["already"]}


@app.post("/telegram/webhook")
async def webhook(request: Request):
    expected = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")
    given = request.headers.get("x-telegram-bot-api-secret-token", "")
    if not expected or not hmac.compare_digest(given, expected):
        raise HTTPException(403, "forbidden")
    update = await request.json()
    if "message" in update:
        return handle_message(update["message"]) or {}
    if "callback_query" in update:
        return handle_callback(update["callback_query"])
    return {}                                              # other update types: ignore
