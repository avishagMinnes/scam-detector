"""Undo the tricks scammers use to hide words and links from detectors (Phase 5).

normalize(text) returns the cleaned text that the rules and the model read, plus what
was found. Finding a trick is itself a warning sign: real organizations don't hide
characters inside words, mix alphabets in a link, or write links as hxxps://x[.]com.

Careful with innocent text:
- Joiners between emoji (family emoji, skin tones) are kept and not counted.
- Right-to-left/left-to-right marks (U+200E/U+200F) are normal in Hebrew; left alone.
- Whole Russian (Cyrillic) words are left alone; only words MIXING alphabets are fixed.
"""
import re

_INVISIBLE = "​‌‍⁠﻿­"
_INVISIBLE_IN_WORD = re.compile(rf"(?<=[\w./:-])[{_INVISIBLE}]+(?=[\w./:-])")
_INVISIBLE_ANY = re.compile(rf"[{_INVISIBLE}]")

# Cyrillic and Greek letters that look like Latin ones
_CONFUSABLE = str.maketrans({
    "а": "a", "с": "c", "е": "e", "і": "i", "о": "o", "р": "p", "х": "x", "у": "y",
    "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "К": "K", "М": "M", "О": "O",
    "Р": "P", "Т": "T", "Х": "X", "У": "Y", "І": "I",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "ρ": "p", "τ": "t", "ν": "v", "κ": "k",
    "Ο": "O", "Α": "A", "Ε": "E", "Ι": "I", "Ρ": "P", "Τ": "T", "Κ": "K", "Μ": "M", "Ν": "N",
})
_LATIN = re.compile(r"[A-Za-z]")
_LOOKALIKE = re.compile(r"[Ͱ-ϿЀ-ӿ]")
_TOKEN = re.compile(r"\S+")

# Defanged links: hxxps://, example[.]com, example(dot)com, "example . com"
_HXXP = re.compile(r"\bhxxp(s?)(?=\s*(?::|\[:\])\s*//)", re.IGNORECASE)
_BRACKET_COLON = re.compile(r"(?<=https)\[:\]|(?<=http)\[:\]", re.IGNORECASE)
_FAKE_DOT = re.compile(r"(?<=[A-Za-z0-9-])\s*(?:\[\.\]|\(\.\)|\[dot\]|\(dot\)|\{dot\}| \. )\s*(?=[A-Za-z0-9])",
                       re.IGNORECASE)

# Letters split by one separator, the same one throughout: ח-ו-ב, ק ו ד, ה.י.ו.ם (3+ letters)
_SPLIT_LETTERS = re.compile(r"(?<![\w.-])([א-תA-Za-z])(([.\- ])[א-תA-Za-z](?:\3[א-תA-Za-z])+)(?![\w])")


def _fix_mixed(token):
    if _LATIN.search(token) and _LOOKALIKE.search(token):
        return token.translate(_CONFUSABLE), True
    return token, False


def normalize(text):
    found = {"invisible_chars": 0, "mixed_alphabet": [], "disguised_link": False,
             "split_letters": 0}

    found["invisible_chars"] = len(_INVISIBLE_IN_WORD.findall(text))
    # Remove invisible characters, except joiners that sit between emoji
    text = _INVISIBLE_ANY.sub(
        lambda m: m.group(0) if m.group(0) == "‍" and _between_emoji(text, m.start()) else "", text)

    def fix(m):
        token, mixed = _fix_mixed(m.group(0))
        if mixed:
            found["mixed_alphabet"].append(token)
        return token
    text = _TOKEN.sub(fix, text)

    before = text
    text = _HXXP.sub(lambda m: "http" + m.group(1), text)
    text = _BRACKET_COLON.sub(":", text)
    text = _FAKE_DOT.sub(".", text)
    found["disguised_link"] = text != before

    def join(m):
        found["split_letters"] += 1
        return m.group(1) + re.sub(r"[.\- ]", "", m.group(2))
    text = _SPLIT_LETTERS.sub(join, text)
    return text, found


def _between_emoji(text, i):
    def is_emoji(ch):
        return ord(ch) >= 0x2600
    return 0 < i < len(text) - 1 and is_emoji(text[i - 1]) and is_emoji(text[i + 1])
