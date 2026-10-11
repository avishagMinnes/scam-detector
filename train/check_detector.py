"""How the combined detector (model + rules) does on TRAINING data, compared with the
model alone and the rules alone.

Model scores are out-of-fold (each message scored by a model that didn't train on it),
so this is fair for the model part. The locked test set is not used.
"""
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "train"))
from scam_detector.detector import HIGH, LOW, MEDIUM_RISK, combine  # noqa: E402
from scam_detector.rules import check  # noqa: E402
from train import (CUTOFF_ORIGINS, MAX_FALSE_ALARM_RATE_HIGH, choose_threshold,  # noqa: E402
                   load_training_data, out_of_fold_probabilities, template_groups)

df = load_training_data()
prob = out_of_fold_probabilities(df, template_groups(df))
pick = df.origin.isin(CUTOFF_ORIGINS).values
cutoff = choose_threshold(df.y.values[pick], prob[pick])
high_cutoff = choose_threshold(df.y.values[pick], prob[pick], MAX_FALSE_ALARM_RATE_HIGH)
print(f"cutoffs: suspicious > {cutoff:.2f}, confident > {high_cutoff:.2f}\n")

rows = []
for r, p in zip(df.itertuples(), prob):
    signs, reassuring = check(r.text)
    rows.append({
        "id": r.id, "label": r.label, "origin": r.origin, "text": r.text, "p": p,
        "combined": combine(p, cutoff, high_cutoff, signs, reassuring),
        "rules_only": combine(0, 1, 1, signs, reassuring),
        "model_only": combine(p, cutoff, high_cutoff, [], []),
    })


def summary(name, key, subset):
    scams = [r for r in subset if r["label"] == "scam"]
    legit = [r for r in subset if r["label"] == "legit"]
    s, l = Counter(r[key] for r in scams), Counter(r[key] for r in legit)
    print(f"{name:12} scams: high {s[HIGH]:3} medium {s[MEDIUM_RISK]:3} low {s[LOW]:3} "
          f"| flagged {(s[HIGH] + s[MEDIUM_RISK]) / len(scams):4.0%}   "
          f"legit: high {l[HIGH]:3} medium {l[MEDIUM_RISK]:3} low {l[LOW]:3} "
          f"| flagged {(l[HIGH] + l[MEDIUM_RISK]) / len(legit):4.0%}")


for title, subset in [("ALL TRAINING DATA", rows),
                      ("REAL MESSAGES ONLY", [r for r in rows if r["origin"] == "real"])]:
    print(title)
    for name, key in [("model only", "model_only"), ("rules only", "rules_only"), ("combined", "combined")]:
        summary(name, key, subset)
    print()

print("Real messages the combined detector gets wrong:")
for r in sorted(rows, key=lambda r: r["p"]):
    if r["origin"] != "real":
        continue
    if r["label"] == "scam" and r["combined"] == LOW:
        print(f"  MISSED      {r['p']:.2f} {r['id']:8} {r['text'][:55].replace(chr(10), ' ')}")
    if r["label"] == "legit" and r["combined"] == HIGH:
        print(f"  HIGH ALARM  {r['p']:.2f} {r['id']:8} {r['text'][:55].replace(chr(10), ' ')}")
    if r["label"] == "legit" and r["combined"] == MEDIUM_RISK:
        print(f"  suspicious  {r['p']:.2f} {r['id']:8} {r['text'][:55].replace(chr(10), ' ')}")
