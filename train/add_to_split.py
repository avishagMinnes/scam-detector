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

# New message id -> template group: an existing group (it follows that group's side) or a
# new group name (all its messages land on the same side, chosen by the group name)
SAME_TEMPLATE_AS = {
    # screenshots 2026-10-11
    "he-w003": "mami_atj", "he-w004": "mami_atj",
    "he-w005": "walter_party", "he-w006": "walter_party",
    "he-w007": "ofer_malls", "he-w008": "ofer_malls",
    "he-w009": "he-p047", "he-w010": "he-p047",          # CARGO, same template as he-p047
    "he-w014": "app_1824", "he-w015": "app_1824",
    "he-w018": "bit_transfer", "he-w019": "bit_transfer",
    "he-w024": "mashbir", "he-w025": "mashbir",
    "en-w026": "shein_sms", "en-w027": "shein_sms",
    "he-w028": "ontopo", "he-w029": "ontopo", "he-w030": "ontopo",
    # screenshots 2026-10-12: same Enforcement Authority campaign, new domains
    "he-w032": "he-p097", "he-w033": "he-p097",
    # screenshots 2026-10-13 (family member)
    "he-y003": "tax_refund_average", "he-y004": "tax_refund_average",
    "he-y005": "he-w035",                                # GOLD-TAX, same sender/domain
}


def side_for(key):
    digest = hashlib.sha256(key.encode()).digest()
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
        side = group_side.get(group, side_for(group))
        rows.append({"id": mid, "split": side, "group": group})
        print(f"{mid}: {side}")
    pd.concat([split, pd.DataFrame(rows)]).to_csv(SPLIT, index=False, encoding="utf-8")


if __name__ == "__main__":
    main()
