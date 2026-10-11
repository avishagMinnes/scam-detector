"""Turn messages into meaning vectors with AlephBERT (a pretrained Hebrew language model).

"Reader" approach: the language model is used as-is, never changed. Each message
becomes the average of its last-layer token vectors (768 numbers); a small model
trained in train.py learns scam vs legit from those vectors.

The same function is used in training and in the app, so vectors always match.
"""
import os
from pathlib import Path

import numpy as np

HUB_ID = "onlplab/alephbert-base"
# Exact model version, so a later upload to the hub can't silently change results
REVISION = "1745fb3ff5137e41e9eb4d6246e0758f63b93e46"
MAX_TOKENS = 256
BATCH = 16

_tok = _model = None


def _is_downloaded():
    home = Path(os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface"))
    snapshot = home / "hub" / f"models--{HUB_ID.replace('/', '--')}" / "snapshots" / REVISION
    return (snapshot / "config.json").exists()


def _load():
    global _tok, _model
    if _model is None:
        if _is_downloaded():
            # Never contact the hub when the pinned version is already on disk (no network
            # needed, nothing sent anywhere). Must be set before transformers is imported.
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
        from transformers import AutoModel, AutoTokenizer
        from transformers.utils import logging
        logging.set_verbosity_error()   # hide the harmless "unused pretraining layers" report
        _tok = AutoTokenizer.from_pretrained(HUB_ID, revision=REVISION)   # first run downloads ~500 MB
        _model = AutoModel.from_pretrained(HUB_ID, revision=REVISION).eval()
    return _tok, _model


def embed(texts):
    """List of messages -> array of shape (len(texts), 768)."""
    import torch
    tok, model = _load()
    out = []
    with torch.no_grad():
        for i in range(0, len(texts), BATCH):
            batch = tok(list(texts[i:i + BATCH]), padding=True, truncation=True,
                        max_length=MAX_TOKENS, return_tensors="pt")
            hidden = model(**batch).last_hidden_state
            mask = batch["attention_mask"].unsqueeze(-1)
            out.append(((hidden * mask).sum(1) / mask.sum(1)).numpy())
    return np.vstack(out)
