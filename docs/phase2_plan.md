# Phase 2 plan: first working version (weeks 4–7)

Updated 2026-10-08 for the new project plan: **zero cost**, with **your own trained
classifier as the main detector**. An LLM is optional and only writes explanations.

**Outcome:** a rough web app where you paste a message and get a risk level, the warning
signs and what to do. Shown to 3–5 people.

## Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Language | Python 3.12 | Already installed; scikit-learn is free and runs on any CPU |
| Main detector | TF-IDF + logistic regression (scikit-learn) | The new plan's baseline. Trains in seconds, free to run, easy to understand |
| Text features | Character n-grams (2–5 characters), not whole words | Hebrew glues prefixes onto words (ו, ה, ב, ל, ש): "החבילה", "לחבילה" and "בחבילה" are different words but share "חביל". Character n-grams also catch link fragments like `.ru` and `bit.ly` |
| Warning signs | Rules (plain Python), not an LLM | Free, instant, and always explainable: "asks for a code", "link domain isn't gov.il" |
| Explanations | Templates first; Gemini free tier optional, later | Templates built from the rules are enough for a first version. Gemini only with personal details masked first |
| Web app | Streamlit | A page in ~30 lines; deploys free on Hugging Face Spaces in Phase 4 |

## The data problem (most important part of this phase)

A trained model needs **training data that is separate from the test data**. If it's tested on
messages it learned from, the score is meaningless. Right now you have about 100 real messages
(30 scams), which is very little for both.

**Plan:**
1. **Lock a test set now.** Set aside about a third of the real messages, mixed fairly by
   label and scam type. Nobody trains or tunes on these until Phase 3.
2. **Keep repeated templates together.** The "shipment stopped" message (3 versions) and the
   tax-refund ad (4 versions) must be entirely in training or entirely in testing.
   Otherwise the test is partly a memory test.
3. **Training data comes from:**
   - the other two thirds of the real messages
   - `data/draft_examples.csv` (written examples are fine for training, never for testing)
   - the UCI SMS Spam Collection (English; spam isn't always a scam, so relabel a sample)
   - every new message family and friends send you
4. **While developing, use cross-validation on the training data** to compare settings.
   Look at the locked test set only at the end of the phase.

Expect a weak Hebrew baseline at first. That's normal and it's the point: Phase 3 measures it
and tries AlephBERT.

## How it works

```
message ──► extract.py ──► links, phone numbers, amounts
   │                             │
   ├──► rules.py ◄───────────────┘   warning signs (code request, payment link,
   │        │                         domain doesn't match the claimed sender...)
   ├──► classifier.py                 scam probability 0–1 (TF-IDF + logistic regression)
   │        │
   ▼        ▼
 detector.py: combine → risk_level, red_flags, what_to_do
   │
   ▼
 app.py (Streamlit page)
```

**Combining (first version, simple on purpose):** high risk if the classifier is confident
*or* a very strong rule fires (asks for a verification code, asks you to install an app from
a link); medium if one of them is borderline; otherwise "no warning signs found". Never "safe".

### Project layout
```
scam_detector/
  extract.py      links (including bare domains like did.li/Route6), phones, amounts
  rules.py        warning-sign rules, each with a Hebrew and an English explanation
  classifier.py   load the trained model, return a scam probability
  detector.py     analyze(text) -> result; the only function the app calls
train/
  split.py        create the locked test set (once)
  train.py        train and save the model, with cross-validation scores
app.py            Streamlit page
models/           saved model file
tests/            small tests for extract.py and rules.py
```

## Rules from day one
- **Locked test set stays locked** until the end of the phase.
- **Never open links.** They are only read as text.
- **Don't store messages.** The app doesn't save what people paste.
- **Nothing leaves the computer** in this phase. If Gemini is added later: mask personal
  details first, and tell users an outside service sees the message.

## Week by week

### Week 4: data and extraction
- [ ] Set up Git again and a Python virtual environment (scikit-learn, pandas, streamlit)
- [ ] `split.py`: lock the test set (fair mix, templates kept together)
- [ ] Download the UCI SMS Spam Collection; relabel ~100 English messages as scam or legit
- [ ] `extract.py`: links, Israeli phone numbers, ₪ / shekel amounts; check it on all real messages

### Week 5: the classifier
- [ ] `train.py`: TF-IDF (character n-grams) + logistic regression
- [ ] Cross-validation on the training data: how many scams does it catch, how many false alarms?
- [ ] Look at the words and fragments it relies on most. Do they make sense?

### Week 6: rules and the web page
- [ ] `rules.py`: the strongest warning signs from `docs/cyber_directorate_summary.md`
- [ ] `detector.py`: combine classifier + rules
- [ ] `app.py`: text box, colored result card, warning signs, advice, right-to-left for Hebrew

### Week 7: first number and first users
- [ ] Run the locked test set once; write down the result in `LOG.md`
- [ ] Show it to 3–5 people; note what confused them and what they liked
- [ ] List the top problems for Phase 3
