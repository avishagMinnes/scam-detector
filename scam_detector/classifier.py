"""The trained scam classifier: text cleanup, and loading the saved model.

The same clean_text() is used when training and when the app runs, so the model
always sees text prepared the same way.
"""
import re
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "baseline.joblib"

# Placeholders added when personal details were removed. Real messages contain real
# names instead, so the model must not learn "[NAME] means legit".
_PLACEHOLDER = re.compile(r"\[(?:NAME|PHONE|EMAIL|ADDRESS|ACCOUNT|BRANCH|MERCHANT|ORDER|GROUP|STORE)\]")
_DIGIT = re.compile(r"\d")
_SPACES = re.compile(r"\s+")


def clean_text(text):
    text = _PLACEHOLDER.sub(" ", text)
    text = _DIGIT.sub("0", text)   # 052-9991904 and 054-1234567 look the same to the model
    return _SPACES.sub(" ", text).strip().lower()


_saved = None


def _load():
    global _saved
    if _saved is None:
        import joblib
        _saved = joblib.load(MODEL_PATH)  # {"model": pipeline, "threshold": float}
    return _saved


def scam_probability(text):
    """Model score (0-1) for the message; higher means more scam-like."""
    return float(_load()["model"].predict_proba([clean_text(text)])[0, 1])


def threshold():
    """Score above which the classifier calls a message a scam (chosen in train.py)."""
    return _load()["threshold"]
