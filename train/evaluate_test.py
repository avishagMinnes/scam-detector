"""Score the detector on the LOCKED TEST SET.

Run rarely, write the result in LOG.md, and don't tune rules or the model on what you
see here: each change made because of a test message makes the test less honest.

Uses the saved model (trained on training data only) and the current rules.
Writes results/test_<date>.json so later runs can be compared.
"""
import json
import math
import sys
from collections import Counter
from datetime import date
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scam_detector import classifier  # noqa: E402
from scam_detector.detector import HIGH, LOW, MEDIUM_RISK, combine  # noqa: E402
from scam_detector.rules import check  # noqa: E402


def wilson(k, n, z=1.96):
    """95% range for a rate measured as k out of n (honest for small n)."""
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0, centre - half), min(1, centre + half)


def main():
    labeled = pd.read_csv(ROOT / "data" / "labeled_messages.csv", encoding="utf-8-sig")
    split = pd.read_csv(ROOT / "data" / "split.csv")
    test = labeled.merge(split, on="id")
    test = test[test.split == "test"].reset_index(drop=True)

    cutoff, high_cutoff = classifier.thresholds()
    rows = []
    for r in test.itertuples():
        p = classifier.scam_probability(r.text)
        signs, reassuring = check(r.text)
        rows.append({
            "id": r.id, "label": r.label, "scam_type": r.scam_type, "language": r.language,
            "score": round(p, 3),
            "combined": combine(p, cutoff, high_cutoff, signs, reassuring),
            "model_only": combine(p, cutoff, high_cutoff, [], []),
            "rules_only": combine(0, 1, 1, signs, reassuring),
            "signs": [s["id"] for s in signs],
        })
    df = pd.DataFrame(rows)
    scams, legit = df[df.label == "scam"], df[df.label == "legit"]
    print(f"Locked test set: {len(df)} messages ({len(scams)} scams, {len(legit)} legit)\n")

    summary = {}
    print(f"{'':12}{'scams flagged':>16}{'95% range':>14}{'as high':>9}   {'legit flagged':>14}{'as high':>9}")
    for key in ("model_only", "rules_only", "combined"):
        s_flag = (scams[key] != LOW).sum()
        s_high = (scams[key] == HIGH).sum()
        l_flag = (legit[key] != LOW).sum()
        l_high = (legit[key] == HIGH).sum()
        lo, hi = wilson(s_flag, len(scams))
        print(f"{key:12}{s_flag:>9} of {len(scams):<4}{lo:>7.0%}-{hi:<5.0%}{s_high:>7}   "
              f"{l_flag:>7} of {len(legit):<4}{l_high:>7}")
        summary[key] = {"scams_flagged": int(s_flag), "scams_high": int(s_high),
                        "legit_flagged": int(l_flag), "legit_high": int(l_high)}

    print("\nCombined detector by scam type:")
    for stype, g in scams.groupby("scam_type"):
        c = Counter(g.combined)
        print(f"  {stype:26} {len(g)} scams: high {c[HIGH]}, medium {c[MEDIUM_RISK]}, missed {c[LOW]}")

    print("\nLegit messages flagged (combined):",
          ", ".join(f"{r.id} ({r.combined})" for r in legit[legit.combined != LOW].itertuples()) or "none")
    print("Scams missed (combined):",
          ", ".join(f"{r.id} ({r.scam_type})" for r in scams[scams.combined == LOW].itertuples()) or "none")

    out = ROOT / "results" / f"test_{date.today().isoformat()}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"date": date.today().isoformat(), "cutoff": cutoff,
                               "high_cutoff": high_cutoff, "n_scams": len(scams),
                               "n_legit": len(legit), "summary": summary,
                               "per_message": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
