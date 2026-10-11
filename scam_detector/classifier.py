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
    """For AlephBERT: placeholders removed, otherwise the text as written."""
    return _SPACES.sub(" ", _PLACEHOLDER.sub(" ", text)).strip()


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


def scam_probability(text):
    """Model score (0-1) for the message; higher means more scam-like."""
    saved = _load()
    if saved.get("kind") == "alephbert":
        from scam_detector.embedder import embed
        features = embed([reader_text(text)])
    else:
        features = [clean_text(text)]
    return float(saved["model"].predict_proba(features)[0, 1])


def warm_up():
    """Load the model now (AlephBERT takes ~20 s), so the first visitor doesn't wait."""
    scam_probability("warm up")


def thresholds():
    """(cutoff, high_cutoff) chosen in train.py: above cutoff the model finds the message
    suspicious; above high_cutoff it is confident on its own."""
    saved = _load()
    return saved["threshold"], saved["high_threshold"]
