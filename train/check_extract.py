"""Run extract.py on every real and draft message and report what it found and missed.

"Missed" uses a deliberately loose pattern: any word containing a dot followed by
letters (like site.com), or http/www. A human then reads the misses.
"""
import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scam_detector.extract import extract_all  # noqa: E402

LOOSE = re.compile(r"https?://\S+|www\.\S+|\b[\w-]+\.[a-zA-Z]{2,}(?:/\S*)?", re.ASCII)

frames = [pd.read_csv(ROOT / "data" / f, encoding="utf-8-sig")
          for f in ("labeled_messages.csv", "draft_examples.csv")]
df = pd.concat(frames, ignore_index=True)

totals = Counter()
problems = []
for r in df.itertuples():
    found = extract_all(r.text)
    totals["messages"] += 1
    for k in ("links", "phones", "amounts"):
        totals[k] += len(found[k])
        totals[f"messages_with_{k}"] += bool(found[k])
    got = " ".join(l["url"].lower() for l in found["links"])
    for cand in LOOSE.findall(r.text):
        core = cand.rstrip(".,;:!?)'\"").lower()
        core = re.sub(r"^https?://", "", core)
        if core and core not in got:
            problems.append((r.id, cand))

print("Totals:", dict(totals))
print(f"\nPossible misses ({len(problems)}):")
for mid, cand in problems:
    print(f"  {mid:8} {cand}")

if "--show" in sys.argv:
    for r in df.itertuples():
        f = extract_all(r.text)
        print(f"\n{r.id} [{r.label}]")
        print("  links:  ", [l["url"] for l in f["links"]])
        print("  phones: ", [(p["number"], p["source"]) for p in f["phones"]])
        print("  amounts:", [a["text"] for a in f["amounts"]])
