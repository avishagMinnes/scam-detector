"""Train the baseline scam classifier: TF-IDF (words) + logistic regression.

Uses TRAINING data only (the locked test set is never read here):
  - real messages marked "train" in data/split.csv
  - data/uci_relabeled.csv (English)
  - data/draft_examples.csv (written examples)

Steps: grouped cross-validation, choose the cutoff, show mistakes and what the model
relies on, then train on all training data and save models/baseline.joblib.
Why words and not characters: see train/compare_features.py.
"""
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.sparse.csgraph import connected_components
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import make_pipeline

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scam_detector.classifier import MODEL_PATH, clean_text  # noqa: E402

DATA = ROOT / "data"
SEED = 20261008
# Missed scams are worse than false alarms: accept up to this share of legit messages
# being flagged, and set the cutoff as low as that allows.
MAX_FALSE_ALARM_RATE = 0.10


def load_training_data():
    real = pd.read_csv(DATA / "labeled_messages.csv", encoding="utf-8-sig")
    split = pd.read_csv(DATA / "split.csv")
    real = real.merge(split, on="id", how="left")
    unsplit = real[real.split.isna()]
    if len(unsplit):
        print(f"Note: {len(unsplit)} labeled messages aren't in split.csv yet; skipped:",
              list(unsplit.id))
    real = real[real.split == "train"].assign(origin="real")
    uci = pd.read_csv(DATA / "uci_relabeled.csv", encoding="utf-8-sig").assign(origin="uci")
    drafts = pd.read_csv(DATA / "draft_examples.csv", encoding="utf-8-sig").assign(origin="draft")
    df = pd.concat([real, uci, drafts], ignore_index=True)
    df["clean"] = df.text.map(clean_text)
    df["y"] = (df.label == "scam").astype(int)
    return df


def template_groups(df, threshold=0.6):
    """Near-identical messages share a group, so cross-validation never trains on one
    copy of a template and tests on another."""
    X = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)).fit_transform(df.clean)
    _, groups = connected_components(cosine_similarity(X) >= threshold, directed=False)
    return groups


def make_model():
    return make_pipeline(
        TfidfVectorizer(analyzer="word", ngram_range=(1, 2), sublinear_tf=True,
                        token_pattern=r"(?u)\b\w+\b"),
        LogisticRegression(class_weight="balanced", C=10, max_iter=2000),
    )


def choose_threshold(y, prob):
    """Lowest cutoff that keeps false alarms at or below MAX_FALSE_ALARM_RATE."""
    legit = np.sort(prob[y == 0])
    return float(legit[int(np.ceil((1 - MAX_FALSE_ALARM_RATE) * len(legit))) - 1])


def report(df, prob, threshold):
    pred = prob > threshold
    print(f"\n=== Cross-validation, cutoff {threshold:.2f} ===")
    print(f"{'subset':16}{'scams':>6}{'caught':>8}{'recall':>8}{'legit':>7}{'false alarms':>14}{'AUC':>6}")
    subsets = [("all", np.ones(len(df), bool)),
               ("hebrew", (df.language == "he").values),
               ("english", (df.language == "en").values),
               ("real messages", (df.origin == "real").values)]
    for label, mask in subsets:
        y, p = df.y.values[mask], pred[mask]
        scams, legit = y.sum(), (1 - y).sum()
        tp, fp = (p & (y == 1)).sum(), (p & (y == 0)).sum()
        auc = roc_auc_score(y, prob[mask])
        print(f"{label:16}{scams:6}{tp:8}{tp / scams:8.0%}{legit:7}{fp:9} ({fp / legit:4.0%}){auc:6.2f}")


def show_mistakes(df, prob, threshold):
    wrong = (prob > threshold) != (df.y == 1)
    print("\nMistakes on real messages (cross-validation):")
    for r in df[wrong & (df.origin == "real")].assign(prob=prob[wrong & (df.origin == "real")]).sort_values("prob").itertuples():
        kind = "MISSED SCAM " if r.y == 1 else "FALSE ALARM "
        print(f"  {kind}{r.prob:4.2f} {r.id:8} {r.text[:60].replace(chr(10), ' ')}")


def show_top_features(model, n=20):
    vec, clf = model.named_steps["tfidfvectorizer"], model.named_steps["logisticregression"]
    names, coef = vec.get_feature_names_out(), clf.coef_[0]
    order = np.argsort(coef)
    print("\nWords pushing towards SCAM: ", [names[i] for i in order[::-1][:n]])
    print("Words pushing towards LEGIT:", [names[i] for i in order[:n]])


def main():
    df = load_training_data()
    groups = template_groups(df)
    print(f"Training data: {len(df)} messages, {df.y.sum()} scams "
          f"({df.groupby('origin').size().to_dict()}); {len(set(groups))} template groups")

    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    prob = cross_val_predict(make_model(), df.clean, df.y, groups=groups, cv=cv,
                             method="predict_proba")[:, 1]
    threshold = choose_threshold(df.y.values, prob)
    report(df, prob, threshold)
    show_mistakes(df, prob, threshold)

    model = make_model().fit(df.clean, df.y)
    show_top_features(model)
    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump({"model": model, "threshold": threshold}, MODEL_PATH)
    print(f"\nSaved {MODEL_PATH}")


if __name__ == "__main__":
    main()
