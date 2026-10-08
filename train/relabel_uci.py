"""Relabel a sample of the UCI SMS Spam Collection from spam/ham to scam/legit.

UCI "spam" mixes real scams (fake prizes, fake voicemails) with ordinary marketing
(ringtones, competitions with stated prices). Our detector cares about scams, so each
sampled spam message was read and relabeled by hand. Sampled ham is kept as legit.

Dataset: Almeida & Gómez Hidalgo, SMS Spam Collection v.1, UCI Machine Learning
Repository (CC BY 4.0). Download it to data/external/sms_spam/ first.

Output: data/uci_relabeled.csv, used for TRAINING ONLY (never in the test set).
"""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "data" / "external" / "sms_spam" / "SMSSpamCollection"
OUT = ROOT / "data" / "uci_relabeled.csv"
SEED = 20261008

# Decisions for the sampled spam, keyed by UCI row number (1-based line in the file)
SCAM_PRIZE = [1986, 2671, 3422, 4207, 5295, 3261, 3299, 9, 4902, 3894, 5013, 5471,
              3969, 4846, 593, 3820, 4787, 1106, 1467, 3829, 2643]
SCAM_OTHER = {
    4298: "'Urgent message waiting', premium-rate callback",
    5029: "Fake account statement with points to claim via premium number",
    1197: "Fake voicemail notice, premium-rate callback",
    3865: "'I found your number again' lure, charged reply",
    1046: "'Someone fancies you' lure, premium-rate number",
    241: "Secret admirer lure, premium-rate number",
    832: "Secret admirer lure, premium-rate number",
    3886: "'A link to your picture has been sent' lure link",
}
DROP = {
    4250: "fragment", 714: "fragment", 5123: "fragment", 956: "fragment",
    661: "unclear what it is",
    798: "could be real carrier marketing or impersonation; can't tell",
    5373: "a person's comment about spam, not spam",
    2431: "odd personal web page ad; can't tell",
}
PRIZE_NOTE = "Prize/award you never entered, claim via premium-rate number or text"


def main():
    df = pd.read_csv(SRC, sep="\t", header=None, names=["uci_label", "text"],
                     quoting=3, encoding="utf-8")
    df["uci_row"] = df.index + 1
    df = df.drop_duplicates("text")
    sample = pd.concat([
        df[df.uci_label == "spam"].sample(80, random_state=SEED),
        df[df.uci_label == "ham"].sample(40, random_state=SEED),
    ])

    rows = []
    for r in sample.itertuples():
        if r.uci_row in DROP:
            continue
        if r.uci_row in SCAM_PRIZE:
            label, stype, note = "scam", "prize", PRIZE_NOTE
        elif r.uci_row in SCAM_OTHER:
            label, stype, note = "scam", "other", SCAM_OTHER[r.uci_row]
        elif r.uci_label == "spam":
            label, stype, note = "legit", "none", "Marketing with stated price/terms (UCI: spam)"
        else:
            label, stype, note = "legit", "none", ""
        rows.append({
            "id": f"en-u{r.uci_row:04d}", "text": r.text, "language": "en",
            "label": label, "scam_type": stype,
            "source": f"uci_sms_spam (uci label: {r.uci_label})",
            "date_received": "", "notes": note,
        })

    out = pd.DataFrame(rows)
    known = set(SCAM_PRIZE) | set(SCAM_OTHER) | set(DROP)
    missing = known - set(sample.uci_row)
    assert not missing, f"decisions for rows not in the sample: {missing}"
    out.to_csv(OUT, index=False, encoding="utf-8-sig")
    print(out.groupby(["label", "scam_type"]).size().to_string())
    print(f"\n{len(out)} rows saved to {OUT} ({len(DROP)} dropped)")


if __name__ == "__main__":
    main()
