"""How often each rule fires on scams vs legit messages, on TRAINING data only.

A good rule fires on many scams and few legit messages. Rules were written from the
Directorate warnings and general scam patterns; this shows whether they hold up.
"""
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "train"))
from scam_detector.rules import check  # noqa: E402
from train import load_training_data  # noqa: E402

df = load_training_data()
fired = {"scam": Counter(), "legit": Counter()}
strongest = {}
for r in df.itertuples():
    signs, reassuring = check(r.text)
    for s in signs:
        fired[r.label][s["id"]] += 1
    for x in reassuring:
        fired[r.label][x["id"]] += 1
    strongest[r.id] = (r.label, {s["strength"] for s in signs}, r.text, r.origin, r.language)

n = df.label.value_counts()
print(f"Training data: {n['scam']} scams, {n['legit']} legit\n")
print(f"{'rule':28}{'scams':>7}{'legit':>7}")
for rid in sorted(set(fired["scam"]) | set(fired["legit"]), key=lambda k: -fired["scam"][k]):
    print(f"{rid:28}{fired['scam'][rid]:7}{fired['legit'][rid]:7}")

print("\nLegit messages with a very strong or strong sign (possible false alarms):")
for mid, (label, strengths, text, origin, lang) in strongest.items():
    if label == "legit" and strengths & {"very_strong", "strong"}:
        print(f"  {mid:9} {sorted(strengths)} {text[:60].replace(chr(10), ' ')}")

print("\nScams with no sign at all (real + drafts, Hebrew):")
for mid, (label, strengths, text, origin, lang) in strongest.items():
    if label == "scam" and not strengths and origin != "uci":
        print(f"  {mid:9} {text[:60].replace(chr(10), ' ')}")
