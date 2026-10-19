"""The trained scam classifier: text preparation, and loading the saved model.

Two model kinds (trained by train/train.py):
  alephbert  AlephBERT meaning vectors + logistic regression (default, Phase 3)
  tfidf      word counts + logistic regression (Phase 2 baseline, kept as fallback)
Pick one with the SCAM_MODEL environment variable; default is alephbert.

The same text preparation is used when training and when the app runs.
"""
import os
import re
from pathlib import Path

from scam_detector.normalize import normalize

MODELS = Path(__file__).resolve().parent.parent / "models"
MODEL_FILES = {"alephbert": MODELS / "alephbert.joblib", "tfidf": MODELS / "baseline.joblib"}
MODEL_KIND = os.environ.get("SCAM_MODEL", "alephbert")
MODEL_PATH = MODEL_FILES[MODEL_KIND]

# Placeholders added when personal details were removed. Real messages contain real
# names instead, so no model may learn "[NAME] means legit".
_PLACEHOLDER = re.compile(r"\[(?:NAME|PHONE|EMAIL|ADDRESS|ACCOUNT|BRANCH|MERCHANT|ORDER|GROUP|STORE)\]")
_DIGIT = re.compile(r"\d")
_SPACES = re.compile(r"\s+")


def reader_text(text):
    """For AlephBERT: hiding tricks undone, placeholders removed, otherwise as written."""
    return _SPACES.sub(" ", _PLACEHOLDER.sub(" ", normalize(text)[0])).strip()


_PARAGRAPH = re.compile(r"\n\s*\n")
_SENTENCE = re.compile(r"\n+|(?<=[!?])\s+|(?<=[א-תA-Za-z)\"'][.])\s+")
# Parts must look like whole messages to the model: small fragments of normal messages
# score erratically (tried MIN_PART=60: real-message AUC fell 0.89 -> 0.77). With these
# sizes AUC stays 0.89 and padded scams are caught as often as plain ones (LOG.md).
LONG_MESSAGE = 300   # shorter messages are scored as a whole only
MIN_PART = 160       # paragraphs / sentence groups shorter than this aren't scored alone
# A short scam wrapped in harmless paragraphs never reaches MIN_PART on its own, so
# short paragraphs of long messages are scored too, but they count only when the model
# is near-certain: their middling scores are noise (the MIN_PART=60 lesson above).
MIN_SHORT_PART = 20
SHORT_PART_TRUST = 0.95


def parts(text):
    """The whole message, then (for longer messages) its paragraphs and sentence groups.

    The model scores every part and keeps the highest score (message_score), so
    harmless text wrapped around a scam can't dilute it (Phase 5 "padding" attack).
    Short paragraphs come last. train.py chooses the
    cutoffs with the same max-over-parts scoring, so legit messages aren't penalized.
    """
    text = normalize(text)[0].strip()
    if len(text) < LONG_MESSAGE:
        return [text]
    found = [text]
    all_paragraphs = [p.strip() for p in _PARAGRAPH.split(text) if p.strip()]
    paragraphs = [p for p in all_paragraphs if len(p) >= MIN_PART]
    if len(paragraphs) > 1:
        found += paragraphs
    group = ""
    for sentence in (s.strip() for s in _SENTENCE.split(text)):
        if not sentence:
            continue
        group = f"{group} {sentence}".strip()
        if len(group) >= MIN_PART:
            found.append(group)
            group = ""
    if group and len(found) > 1:
        found[-1] = f"{found[-1]} {group}"
    found += [p for p in all_paragraphs if MIN_SHORT_PART <= len(p) < MIN_PART]
    return list(dict.fromkeys(found))   # drop exact repeats, keep order


def message_score(pieces, probs):
    """One score for a message from the scores of its parts (same order as parts()).

    The whole message and large parts count as they are; a short part (see
    SHORT_PART_TRUST) counts only when the model is near-certain about it.
    """
    best = 0.0
    for i, (piece, prob) in enumerate(zip(pieces, probs)):
        if i == 0 or len(piece) >= MIN_PART or prob >= SHORT_PART_TRUST:
            best = max(best, float(prob))
    return best


def clean_text(text):
    """For TF-IDF: also digits -> 0 and lowercase."""
    text = _DIGIT.sub("0", reader_text(text))   # 052-9991904 and 054-1234567 look the same
    return text.lower()


_saved = None


def _load():
    global _saved
    if _saved is None:
        import joblib
        _saved = joblib.load(MODEL_PATH)  # {"kind", "model", "threshold", "high_threshold"}
    return _saved


def part_features(kind, pieces):
    if kind == "alephbert":
        from scam_detector.embedder import embed
        return embed([reader_text(p) for p in pieces])
    return [clean_text(p) for p in pieces]


def scam_probability(text):
    """Model score (0-1): the highest score of the whole message and its parts."""
    saved = _load()
    pieces = parts(text)
    features = part_features(saved.get("kind", "tfidf"), pieces)
    return message_score(pieces, saved["model"].predict_proba(features)[:, 1])


def warm_up():
    """Load the model now (AlephBERT takes ~20 s), so the first visitor doesn't wait."""
    scam_probability("warm up")


def thresholds():
    """(cutoff, high_cutoff) chosen in train.py: above cutoff the model finds the message
    suspicious; above high_cutoff it is confident on its own."""
    saved = _load()
    return saved["threshold"], saved["high_threshold"]
