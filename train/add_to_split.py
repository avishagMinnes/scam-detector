"""Give newly labeled messages a place in the locked split, without moving any old ones.

About one in three new messages goes to the test set, chosen by a hash of the id so the
choice is fixed and can't be nudged. A message that belongs to a template group already
in the split follows that group.

Run after adding rows to data/labeled_messages.csv.
"""
import hashlib
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
LABELED = ROOT / "data" / "labeled_messages.csv"
SPLIT = ROOT / "data" / "split.csv"

# New message id -> existing template group (fill in by hand when a new message
# is a copy of an existing template)
SAME_TEMPLATE_AS = {}


def side_for(message_id):
    digest = hashlib.sha256(message_id.encode()).digest()
    return "test" if digest[0] % 3 == 0 else "train"


def main():
    labeled = pd.read_csv(LABELED, encoding="utf-8-sig")
    split = pd.read_csv(SPLIT)
    new_ids = [i for i in labeled.id if i not in set(split.id)]
    if not new_ids:
        print("Nothing new.")
        return
    group_side = split.drop_duplicates("group").set_index("group").split
    rows = []
    for mid in new_ids:
        group = SAME_TEMPLATE_AS.get(mid, mid)
        side = group_side.get(group, side_for(mid))
        rows.append({"id": mid, "split": side, "group": group})
        print(f"{mid}: {side}")
    pd.concat([split, pd.DataFrame(rows)]).to_csv(SPLIT, index=False, encoding="utf-8")


if __name__ == "__main__":
    main()
