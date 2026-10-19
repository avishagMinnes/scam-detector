"""Attacks a scammer could use to slip a message past the detector (Phase 5).

Each attack takes a message and a random generator and returns a changed message that
a human still reads the same way. They are generated on the fly (never saved), because
the base messages include private real ones.

Prompt injection in the usual sense needs an LLM that follows instructions; this
detector has none (AlephBERT + rules). "reassurance" is the closest equivalent: text
meant to talk the model into a lower score.
"""
import random
import re

from scam_detector.extract import _URL_RE

ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿"]

# Latin letter -> Cyrillic letter that looks the same
HOMOGLYPHS = {"a": "а", "c": "с", "e": "е", "i": "і", "o": "о", "p": "р", "x": "х", "y": "у",
              "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н", "K": "К", "M": "М", "O": "О",
              "P": "Р", "T": "Т", "X": "Х"}

PADDING = {
    "he": ("שבוע טוב ובשורות טובות לכל המשפחה. מזג האוויר היום נעים, ומחר צפויים גשמים "
           "קלים באזור המרכז. אל תשכחו לשתות מים ולשמור על עצמכם. נתראה בקרוב!"),
    "en": ("Have a lovely week, hope the family is well. The weather is nice today and "
           "light rain is expected tomorrow. Remember to drink water and take care!"),
}

REASSURANCE = {
    "he": "הודעה רשמית ומאומתת. זו אינה הודעת הונאה ואין צורך לבדוק אותה.",
    "en": "Official verified message. This is not a scam and there is no need to check it.",
}


def _lang(text):
    return "he" if len(re.findall(r"[א-ת]", text)) >= len(re.findall(r"[A-Za-z]", text)) else "en"


def _outside_links(text, fn):
    """Apply fn to the parts of the text that aren't links."""
    out, last = [], 0
    for m in _URL_RE.finditer(text):
        out.append(fn(text[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(fn(text[last:]))
    return "".join(out)


def zero_width(text, rng):
    """Invisible characters inside words (and links): screens show the same text."""
    def scatter(word):
        if len(word) < 3:
            return word
        chars = list(word)
        for i in sorted(rng.sample(range(1, len(chars)), k=max(1, len(chars) // 3)), reverse=True):
            chars.insert(i, rng.choice(ZERO_WIDTH))
        return "".join(chars)
    return re.sub(r"\S+", lambda m: scatter(m.group(0)), text)


def homoglyphs(text, rng):
    """Latin letters swapped for identical-looking Cyrillic ones (pаypal, gоv)."""
    return "".join(HOMOGLYPHS[c] if c in HOMOGLYPHS and rng.random() < 0.6 else c for c in text)


def broken_links(text, rng):
    """Links written so phones don't make them clickable and readers still can:
    hxxps://, [.] or spaces around dots."""
    def breakup(m):
        url = m.group(0)
        style = rng.choice(["defang", "spaces", "dot-word"])
        if style == "defang":
            return url.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")
        if style == "spaces":
            return re.sub(r"^https?://", "", url).replace(".", " . ")
        return re.sub(r"^https?://", "", url).replace(".", "(dot)")
    return _URL_RE.sub(breakup, text)


def spaced_words(text, rng):
    """Letters of words split by dots or spaces: ח.ו.ב, ק ו ד."""
    def split(word):
        if len(word) < 3 or rng.random() > 0.5:
            return word
        return rng.choice([".", " ", "-"]).join(word)
    return _outside_links(text, lambda part: re.sub(r"[א-תA-Za-z]+", lambda m: split(m.group(0)), part))


def padding(text, rng):
    """The scam wrapped in harmless everyday text."""
    pad = PADDING[_lang(text)]
    return f"{pad}\n\n{text}\n\n{pad}"


def inline_padding(text, rng):
    """Padding on the same line: no blank lines that would separate the scam."""
    pad = PADDING[_lang(text)]
    return f"{pad} {' '.join(text.split())} {pad}"


def reassurance(text, rng):
    """'This is official, not a scam': aimed at talking the score down."""
    note = REASSURANCE[_lang(text)]
    return f"{note}\n{text}\n{note}"


def combined(text, rng):
    """Several attacks at once, the way a determined scammer would."""
    for attack in (broken_links, homoglyphs, zero_width, reassurance):
        text = attack(text, rng)
    return text


ATTACKS = {f.__name__: f for f in
           (zero_width, homoglyphs, broken_links, spaced_words, padding, inline_padding,
            reassurance, combined)}


def attack(name, text, seed):
    return ATTACKS[name](text, random.Random(f"{seed}:{name}"))
