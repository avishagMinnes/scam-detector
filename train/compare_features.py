"""Compare feature types and regularization with grouped cross-validation (training data only).

Result on 2026-10-08 (194 training messages): word 1-2 grams beat character n-grams on
every measure, including real Hebrew messages. See LOG.md.
"""
import sys
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import make_pipeline, make_union

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "train"))
sys.path.insert(0, str(ROOT))
from train import load_training_data, template_groups  # noqa: E402

df = load_training_data()
groups = template_groups(df)
cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=20261008)


def recall_at_fa(y, p, fa=0.10):
    legit = np.sort(p[y == 0])
    thr = legit[int(np.ceil((1 - fa) * len(legit))) - 1]
    return (p[y == 1] > thr).mean(), thr


def vec(kind, ngr):
    if kind == "word":
        return TfidfVectorizer(analyzer="word", ngram_range=ngr, sublinear_tf=True, token_pattern=r"(?u)\b\w+\b")
    return TfidfVectorizer(analyzer=kind, ngram_range=ngr, sublinear_tf=True)


configs = {
    "word 1-2": lambda: vec("word", (1, 2)),
    "char_wb 2-5": lambda: vec("char_wb", (2, 5)),
    "char_wb 3-5": lambda: vec("char_wb", (3, 5)),
    "char 3-6": lambda: vec("char", (3, 6)),
    "word1-2 + char_wb3-5": lambda: make_union(vec("word", (1, 2)), vec("char_wb", (3, 5))),
}
print(f"{'features':24}{'C':>5}{'AUC':>6}{'AP':>6}{'AUC he-real':>12}{'recall@10%FA':>13}")
for name, mk in configs.items():
    for C in (1, 10, 100):
        model = make_pipeline(mk(), LogisticRegression(class_weight="balanced", C=C, max_iter=3000))
        p = cross_val_predict(model, df.clean, df.y, groups=groups, cv=cv, method="predict_proba")[:, 1]
        y = df.y.values
        m = ((df.origin == "real") & (df.language == "he")).values
        r, _ = recall_at_fa(y, p)
        print(f"{name:24}{C:5}{roc_auc_score(y, p):6.2f}{average_precision_score(y, p):6.2f}"
              f"{roc_auc_score(y[m], p[m]):12.2f}{r:13.0%}")
