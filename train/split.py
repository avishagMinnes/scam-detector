"""Lock the test set: put about a third of the real messages aside for testing.

Messages from the same template or campaign stay together (all train or all test),
so the test doesn't reward memorising a template.

Run without arguments to preview the split; run with --write to save data/split.csv.
Once saved, never re-run with --write: new messages get added with add_to_split later.
"""
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
LABELED = ROOT / "data" / "labeled_messages.csv"
SPLIT = ROOT / "data" / "split.csv"
TEST_FRACTION = 1 / 3
SEED = 20261008

# Same template or same campaign (checked by text similarity plus reading them)
GROUPS = {
    "tax_dear_citizen": ["he-p054", "he-p065"],
    "shipment_stopped": ["he-p017", "he-p045"],
    "package_still_waiting": ["he-p018", "he-p061"],
    "loan_cancel_link": ["he-p040", "he-p069", "he-p094"],
    "cannabis_wa_me": ["he-p007", "he-p008"],
    "cannabis_1d_is": ["he-p078", "he-p082"],
    "atj_tax_refund": ["he-p043", "he-p046", "he-p050", "he-p063"],
    "party_whatsapp": ["he-p087", "he-p089", "he-p091", "he-p093"],
    "minister_channel": ["he-p055", "he-p058", "he-p067"],
    "care_laser": ["he-p036", "he-p037"],
    "receipt_link": ["he-p006", "he-p033"],
}


def make_split(df):
    group_of = {mid: g for g, ids in GROUPS.items() for mid in ids}
    df = df.assign(group=[group_of.get(i, i) for i in df.id])

    # Stratum: scams by scam type, legit by language
    def stratum(rows):
        r = rows.iloc[0]
        return f"scam/{r.scam_type}" if r.label == "scam" else f"legit/{r.language}"

    groups = [(g, rows) for g, rows in df.groupby("group")]
    rng = random.Random(SEED)
    rng.shuffle(groups)

    by_stratum = defaultdict(list)
    for g, rows in groups:
        assert rows.label.nunique() == 1, f"group {g} mixes labels"
        by_stratum[stratum(rows)].append((g, rows))

    split = {}
    for s, items in by_stratum.items():
        n = sum(len(r) for _, r in items)
        target = n * TEST_FRACTION
        if n >= 2:
            target = max(target, 1)
        in_test = 0
        # random order (already shuffled), so the test set isn't dominated by big campaigns
        for g, rows in items:
            put_test = n >= 2 and in_test + len(rows) <= target + 0.5
            for mid in rows.id:
                split[mid] = "test" if put_test else "train"
            in_test += len(rows) if put_test else 0

    df["split"] = df.id.map(split)
    return df


def main():
    df = pd.read_csv(LABELED, encoding="utf-8-sig")
    if SPLIT.exists() and "--write" in sys.argv:
        sys.exit(f"{SPLIT} already exists: the test set is locked. Not overwriting.")

    df = make_split(df)

    print(pd.crosstab([df.label, df.scam_type.where(df.label == "scam", "-"), df.language], df.split, margins=True))
    print("\nTest set:")
    for r in df[df.split == "test"].sort_values(["label", "scam_type"]).itertuples():
        grp = f" [{r.group}]" if r.group != r.id else ""
        print(f"  {r.id:8} {r.label:5} {r.scam_type:24} {r.text[:45].replace(chr(10), ' ')}{grp}")

    if "--write" in sys.argv:
        df[["id", "split", "group"]].to_csv(SPLIT, index=False, encoding="utf-8")
        print(f"\nSaved {SPLIT}")
    else:
        print("\nPreview only. Run with --write to lock it.")


if __name__ == "__main__":
    main()
