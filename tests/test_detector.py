import pytest

from scam_detector import classifier
from scam_detector.detector import HIGH, LOW, MEDIUM_RISK, analyze, combine, detect_language
from scam_detector.rules import MEDIUM, STRONG, VERY_STRONG

CUT, HIGH_CUT = 0.40, 0.52
OFFICIAL = [{"id": "official_links_only"}]


def sign(strength):
    return {"id": "x", "strength": strength}


@pytest.mark.parametrize("prob, signs, reassuring, expected", [
    (0.10, [], [], LOW),
    (0.10, [sign(MEDIUM)], [], LOW),
    (0.10, [sign(MEDIUM), sign(MEDIUM)], [], MEDIUM_RISK),
    (0.10, [sign(STRONG)], [], MEDIUM_RISK),
    (0.45, [], [], MEDIUM_RISK),                       # model suspicious
    (0.60, [], [], HIGH),                              # model confident
    (0.10, [sign(VERY_STRONG)], [], HIGH),
    (0.10, [sign(STRONG), sign(STRONG)], [], HIGH),
    (0.45, [sign(STRONG)], [], HIGH),                  # strong sign + model agrees
    (0.45, [], OFFICIAL, LOW),                         # official links lower one step
    (0.45, [sign(STRONG)], OFFICIAL, MEDIUM_RISK),
    (0.10, [sign(VERY_STRONG)], OFFICIAL, HIGH),       # but never a very strong sign
])
def test_combine(prob, signs, reassuring, expected):
    assert combine(prob, CUT, HIGH_CUT, signs, reassuring) == expected


def test_detect_language():
    assert detect_language("לקוח יקר, הכרטיס שלך נחסם https://x.com") == "he"
    assert detect_language("Your package is waiting") == "en"
    # A long link must not turn a short Hebrew message into "English"
    assert detect_language('החוב שלך 38.70 ש"ח: https://secret-link.top/abc התקשר 052-1234567') == "he"
    assert detect_language("Pay now: https://example.com/a") == "en"


needs_model = pytest.mark.skipif(not classifier.MODEL_PATH.exists(),
                                 reason="model not trained; run train/train.py")


@needs_model
def test_analyze_scam_end_to_end():
    result = analyze("כדי לקבל פיצויי המלחמה רשמו באתר הזה https://taxesgov.net/he")
    assert result["risk_level"] == HIGH
    assert result["language"] == "he"
    assert result["red_flags"][0]["id"] == "lookalike_domain"
    assert result["what_to_do"][0].startswith("אל תלחצו")


@needs_model
def test_analyze_never_says_safe():
    result = analyze("Ok see you at 7")
    assert result["risk_level"] == LOW
    assert "safe" not in result["risk_text"]["en"].lower()
    assert "doesn't mean the message is safe" in result["what_to_do"][0]
