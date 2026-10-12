"""Phase 5: how often does each attack slip a scam past the detector?

Base messages: scams the detector currently flags (high or medium), from the training
data (real training messages, published examples, drafts). The locked test set is never
used. An attack "succeeds" when the attacked version comes back "low" (no warning signs);
a "downgrade" is high -> medium.

Caveat: the model was trained on these base messages, so its scores on them are higher
than on unseen ones; real attack success is likely somewhat higher than measured here.

Writes results/attacks_<date>.json with outcomes only (ids, levels), never message text.
Run: python train/attack_eval.py [label]    e.g. label "before-defenses"
"""
import json
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "train"))
from attacks import ATTACKS, attack  # noqa: E402
from scam_detector.detector import HIGH, LOW, MEDIUM_RISK, analyze  # noqa: E402
from train import load_training_data  # noqa: E402

RANK = {LOW: 0, MEDIUM_RISK: 1, HIGH: 2}


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "run"
    df = load_training_data()
    scams = df[(df.label == "scam") & df.origin.isin(["real", "web", "draft"])]

    base = []
    for r in scams.itertuples():
        level = analyze(r.text)["risk_level"]
        if level != LOW:
            base.append((r.id, r.origin, r.language, r.text, level))
    print(f"Base: {len(base)} of {len(scams)} training scams are flagged now "
          f"({sum(b[4] == HIGH for b in base)} high, {sum(b[4] == MEDIUM_RISK for b in base)} medium)\n")

    rows, stats = [], defaultdict(lambda: {"n": 0, "evaded": 0, "downgraded": 0})
    for mid, origin, lang, text, level in base:
        for name in ATTACKS:
            new = analyze(attack(name, text, seed=mid))["risk_level"]
            s = stats[name]
            s["n"] += 1
            s["evaded"] += new == LOW
            s["downgraded"] += RANK[new] < RANK[level]
            rows.append({"id": mid, "origin": origin, "language": lang, "attack": name,
                         "before": level, "after": new})

    print(f"{'attack':14}{'tried':>7}{'got past (low)':>16}{'rated lower':>13}")
    for name, s in stats.items():
        print(f"{name:14}{s['n']:7}{s['evaded']:9} ({s['evaded'] / s['n']:4.0%}){s['downgraded']:8} ({s['downgraded'] / s['n']:4.0%})")
    total = {k: sum(s[k] for s in stats.values()) for k in ("n", "evaded", "downgraded")}
    print(f"{'ALL':14}{total['n']:7}{total['evaded']:9} ({total['evaded'] / total['n']:4.0%})"
          f"{total['downgraded']:8} ({total['downgraded'] / total['n']:4.0%})")

    out = ROOT / "results" / f"attacks_{date.today().isoformat()}_{label}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"label": label, "date": date.today().isoformat(),
                               "base_messages": len(base), "per_attack": stats, "total": total,
                               "rows": rows}, indent=1), encoding="utf-8")
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
