from scam_detector.normalize import normalize


def test_invisible_characters_removed_and_counted():
    text, found = normalize("ח\u200bו\u200cב פתוח: https://kvish6\u200b-pay.com")
    assert text == "חוב פתוח: https://kvish6-pay.com"
    assert found["invisible_chars"] == 3


def test_emoji_joiners_and_direction_marks_are_innocent():
    family = "👨\u200d👩\u200d👧"
    text, found = normalize(f"משפחה {family} \u200fשבת שלום")
    assert family in text and "\u200f" in text
    assert found["invisible_chars"] == 0


def test_mixed_alphabet_words_fixed_russian_words_left_alone():
    text, found = normalize("Ваш заказ готов: httрs://kvish6-рау.соm/gov")
    assert "https://kvish6-pay.com/gov" in text
    assert "Ваш заказ готов" in text            # real Russian stays Russian
    assert found["mixed_alphabet"] == ["https://kvish6-pay.com/gov"]


def test_disguised_links_rebuilt():
    for disguised in ("hxxps://secret-link[.]top/abc", "secret-link(dot)top/abc", "secret-link . top/abc"):
        text, found = normalize(f"לתשלום: {disguised}")
        assert "secret-link.top/abc" in text, disguised
        assert found["disguised_link"], disguised


def test_normal_sentences_with_dots_untouched():
    msg = 'מחיר 38.70 ש"ח. נתראה מחר . תודה!'
    text, found = normalize(msg)
    assert text == msg and not found["disguised_link"]


def test_split_letters_rejoined():
    text, found = normalize("נמצא ח-ו-ב על שמך, יש ל ה ס ד י ר עד ה.י.ו.ם")
    assert "חוב" in text and "להסדיר" in text and "היום" in text
    assert found["split_letters"] == 3


def test_ordinary_text_unchanged():
    msg = "היי אמא, אגיע בשבע. I am at the station, see you soon"
    text, found = normalize(msg)
    assert text == msg
    assert found == {"invisible_chars": 0, "mixed_alphabet": [], "disguised_link": False,
                     "split_letters": 0}
