"""Phase 3: compare the TF-IDF baseline with Hebrew language models used as "readers".

Reader approach: a pretrained model turns each message into a vector (mean of its last
layer), and logistic regression learns scam vs legit from those vectors. The language
model itself isn't changed (no fine-tuning), which suits our small data.

Same training data, template groups and grouped 5-fold cross-validation as train.py.
TRAINING DATA ONLY: the locked test set is never read.

Vectors are cached in models/embeddings/ so re-runs are fast.
Needs: pip install torch --index-url https://download.pytorch.org/whl/cpu ; pip install transformers
"""
import hashlib
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "train"))
from train import (CUTOFF_ORIGINS, SEED, choose_threshold, load_training_data,  # noqa: E402
                   make_model, template_groups)

CACHE = ROOT / "models" / "embeddings"
READERS = {
    "AlephBERT": "onlplab/alephbert-base",
    "DictaBERT": "dicta-il/dictabert",
}
MAX_TOKENS = 256


def embed(texts, model_name):
    """Mean-pooled last-layer vectors, cached per model and text."""
    import torch
    from transformers import AutoModel, AutoTokenizer

    key = hashlib.sha256(("\n\x00".join(texts) + model_name).encode()).hexdigest()[:16]
    path = CACHE / f"{model_name.replace('/', '__')}_{key}.npy"
    if path.exists():
        return np.load(path)

    tok = AutoTokenizer.from_pretrained(model_name)
    model = AutoModel.from_pretrained(model_name).eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(texts), 16):
            batch = tok(texts[i:i + 16], padding=True, truncation=True,
                        max_length=MAX_TOKENS, return_tensors="pt")
            hidden = model(**batch).last_hidden_state
            mask = batch["attention_mask"].unsqueeze(-1)
            out.append(((hidden * mask).sum(1) / mask.sum(1)).numpy())
    vectors = np.vstack(out)
    CACHE.mkdir(parents=True, exist_ok=True)
    np.save(path, vectors)
    return vectors


def reader_model():
    return make_pipeline(StandardScaler(),
                         LogisticRegression(class_weight="balanced", C=0.05, max_iter=5000))


def scores(name, df, prob):
    y = df.y.values
    real = df.origin.isin(CUTOFF_ORIGINS).values
    real_he = real & (df.language == "he").values
    cut = choose_threshold(y[real], prob[real])          # same cutoff rule as train.py
    caught = (prob[real & (y == 1)] > cut).mean()
    alarms = (prob[real & (y == 0)] > cut).mean()
    return {"model": name,
            "AUC all": roc_auc_score(y, prob),
            "AUC real": roc_auc_score(y[real], prob[real]),
            "AUC real Hebrew": roc_auc_score(y[real_he], prob[real_he]),
            "real scams caught": caught,
            "real legit flagged": alarms}


def main():
    df = load_training_data()
    groups = template_groups(df)
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    # readers get the text as written, minus the [NAME]-style placeholders (they appear
    # mostly in real legit messages, so they'd be an unfair hint)
    from scam_detector.classifier import reader_text
    texts = df.text.map(reader_text).tolist()
    print(f"Training data: {len(df)} messages, {df.y.sum()} scams\n")

    results, probs = [], {}
    probs["TF-IDF baseline"] = cross_val_predict(make_model(), df.clean, df.y, groups=groups,
                                                 cv=cv, method="predict_proba")[:, 1]
    for name, hub_id in READERS.items():
        t = time.time()
        X = embed(texts, hub_id)
        print(f"{name}: {X.shape[1]}-number vectors for {len(texts)} messages in {time.time() - t:.0f}s")
        probs[name] = cross_val_predict(reader_model(), X, df.y, groups=groups, cv=cv,
                                        method="predict_proba")[:, 1]
    # A simple blend: average of the baseline and the best reader
    best_reader = max(READERS, key=lambda n: roc_auc_score(df.y, probs[n]))
    probs[f"average: TF-IDF + {best_reader}"] = (probs["TF-IDF baseline"] + probs[best_reader]) / 2

    for name, p in probs.items():
        results.append(scores(name, df, p))
    table = pd.DataFrame(results).set_index("model")
    pd.set_option("display.width", 140)
    print("\n" + table.to_string(float_format=lambda v: f"{v:.2f}"))
    print("\n'real scams caught' / 'real legit flagged' use the same cutoff rule as the app "
          "(max 10% false alarms on real training messages).")

    with_rules(df, probs)


def with_rules(df, probs):
    """Each model score inside the full detector (model + warning-sign rules), on real
    training messages, with cutoffs chosen exactly as train.py does."""
    from scam_detector.detector import HIGH, LOW, combine
    from scam_detector.rules import check
    from train import MAX_FALSE_ALARM_RATE_HIGH

    y = df.y.values
    real = df.origin.isin(CUTOFF_ORIGINS).values
    signs = [check(t) for t in df.text]
    rows = []
    for name, p in probs.items():
        cut = choose_threshold(y[real], p[real])
        high = choose_threshold(y[real], p[real], MAX_FALSE_ALARM_RATE_HIGH)
        level = np.array([combine(pi, cut, high, s, r) for pi, (s, r) in zip(p, signs)])
        sc, lg = real & (y == 1), real & (y == 0)
        rows.append({"model inside detector": name,
                     "scams flagged": f"{(level[sc] != LOW).sum()} of {sc.sum()}",
                     "scams as high": int((level[sc] == HIGH).sum()),
                     "legit flagged": f"{(level[lg] != LOW).sum()} of {lg.sum()}",
                     "legit as high": int((level[lg] == HIGH).sum()),
                     "missed": ", ".join(df.id[sc & (level == LOW)])})
    print("\nFULL DETECTOR (model + rules), real training messages:")
    print(pd.DataFrame(rows).set_index("model inside detector").to_string())


if __name__ == "__main__":
    main()
