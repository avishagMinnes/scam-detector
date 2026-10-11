"""Combine the trained model and the warning-sign rules into one answer.

analyze(text) is the only function the app (and later the Telegram bot) calls.
The answer is never "safe": the lowest level is "no warning signs found".
"""
import re

from scam_detector import classifier
from scam_detector.extract import _URL_RE, extract_all
from scam_detector.rules import MEDIUM, STRONG, VERY_STRONG, check

HIGH, MEDIUM_RISK, LOW = "high", "medium", "low"

LEVEL_TEXT = {
    HIGH: {"he": "נראה כמו הונאה", "en": "Looks like a scam"},
    MEDIUM_RISK: {"he": "חשוד", "en": "Suspicious"},
    LOW: {"he": "לא נמצאו סימני אזהרה", "en": "No warning signs found"},
}

LEVEL_ADVICE = {
    HIGH: {"he": "אל תלחצו על קישורים ואל תשיבו. חסמו את השולח ומחקו את ההודעה.",
           "en": "Don't open links or reply. Block the sender and delete the message."},
    MEDIUM_RISK: {"he": "אל תפעלו דרך ההודעה. בדקו מול הגוף עצמו, דרך האתר או האפליקציה הרשמיים.",
                  "en": "Don't act through the message. Check with the organization through its official site or app."},
    LOW: {"he": "זה לא אומר שההודעה בטוחה. אם מבקשים ממך כסף, קוד או פרטים אישיים, עצרו ובדקו.",
          "en": "This doesn't mean the message is safe. If it asks for money, a code or personal details, stop and check."},
}

MODEL_SIGN = {
    "id": "model_score", "strength": MEDIUM,
    "he": "הניסוח דומה להודעות הונאה מוכרות", "en": "The wording is similar to known scam messages",
    "advice_he": "", "advice_en": "",
}

_HEBREW_LETTER = re.compile(r"[א-ת]")
_LATIN_LETTER = re.compile(r"[A-Za-z]")


def detect_language(text):
    """'he' if the message has more Hebrew letters than Latin ones, else 'en'.
    Links are left out: a long Latin-letter link in a Hebrew message isn't English."""
    words = _URL_RE.sub(" ", text)
    return "he" if len(_HEBREW_LETTER.findall(words)) >= len(_LATIN_LETTER.findall(words)) else "en"


def combine(probability, cutoff, high_cutoff, signs, reassuring):
    """Decide the risk level. Pure function, so it can be tested without the model.

    high:   a very strong sign; or two strong signs; or a strong sign the model agrees with;
            or the model is very confident on its own
    medium: one strong sign; or the model finds it suspicious; or two medium signs
    low:    otherwise
    Links that all go to official sites (gov.il) lower the level by one step,
    unless there is a very strong sign.
    """
    strengths = [s["strength"] for s in signs]
    very_strong = strengths.count(VERY_STRONG)
    strong = strengths.count(STRONG)
    medium = strengths.count(MEDIUM)
    model_suspicious = probability > cutoff

    if very_strong or strong >= 2 or (strong and model_suspicious) or probability > high_cutoff:
        level = HIGH
    elif strong or model_suspicious or medium >= 2:
        level = MEDIUM_RISK
    else:
        level = LOW

    if reassuring and not very_strong:
        level = {HIGH: MEDIUM_RISK, MEDIUM_RISK: LOW, LOW: LOW}[level]
    return level


def analyze(text):
    text = text.strip()
    found = extract_all(text)
    signs, reassuring = check(text, found)
    probability = classifier.scam_probability(text)
    cutoff, high_cutoff = classifier.thresholds()
    level = combine(probability, cutoff, high_cutoff, signs, reassuring)

    red_flags = sorted(signs, key=lambda s: [VERY_STRONG, STRONG, MEDIUM].index(s["strength"]))
    if probability > cutoff:
        red_flags.append(MODEL_SIGN)

    language = detect_language(text)
    advice = [LEVEL_ADVICE[level][language]]
    if level != LOW:
        for s in red_flags:
            tip = s[f"advice_{language}"]
            if tip and tip not in advice:
                advice.append(tip)

    return {
        "risk_level": level,
        "risk_text": LEVEL_TEXT[level],
        "language": language,
        "red_flags": red_flags,
        "reassuring": reassuring,
        "what_to_do": advice,
        "model_score": round(probability, 3),
        "extracted": found,
    }
