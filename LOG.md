# Weekly log

## Week 1 (from 2026-10-08)
- Set up the repo and the Phase 1 structure
- Done: summarized Cyber Directorate warnings (docs/cyber_directorate_summary.md), drafted 16 practice examples (data/draft_examples.csv)
- Done: split, anonymized and pre-labeled 94 messages from my own phone (data/review_my_phone.csv)
- Done: labeled my phone messages; test set now 96 real messages (28 scam, 68 legit) in data/labeled_messages.csv
- Learned: SMS inbox has no 'Hi Mom', investment or prize scams; those need to come from WhatsApp / family
- Done: set up Git; locked the test set (data/split.csv): 32 test / 66 train, 9 test scams
- Done: extract.py (links, phones, amounts) with tests; relabeled 112 UCI English messages for training (28 scam, 84 legit)
- Done: baseline model (train/train.py). Word features beat character n-grams in grouped CV (AUC 0.85 vs 0.80; real Hebrew 0.84 vs 0.73), so I switched. Cutoff 0.38 (max 10% false alarms): CV recall 75% overall, 67% on real messages
- Learned: the model leans on 'call + phone number' from the old UK data and on Hebrew function words (את, של), because English legit is personal chat while Hebrew legit is marketing. Misses fake-government and bank alerts with no obvious words; rules must cover those
- Done: rules.py - 16 warning-sign rules with Hebrew/English explanations and advice, 17 tests. On training data only 1 legit message gets a strong sign. Fixed a UCI label (4846 is a prize scam); retrained: real-message CV recall moved 67% -> 57% from that one change, so small-data numbers are noisy
- Done: detector.py - combines model + rules into high / medium / low (never 'safe'). Training-data check (out-of-fold): real scams flagged 81% (model alone 57%, rules alone 62%); real legit: 0 high, 7 of 45 'suspicious'. 47 tests pass
- Done: Streamlit page (app.py): paste, one-click check, colored card, RTL for Hebrew, examples from drafts, links shown as text only, no storage. Tested Hebrew/English, desktop/phone. Pinned requirements.txt + .venv
- Done: replaced Streamlit with FastAPI (api.py) + own Hebrew-first phone page (web/index.html): light/dark, paste button, examples, results via textContent only. 51 tests
- Done: new real scam he-s003 (fake police traffic fine, iMessage from softbank.jp, wj-gov.top) -> train via add_to_split.py. New rule reply_to_enable_link (iPhone link-unblock trick); court/license threats. 54 tests
- Next: Week 7 - run the locked test set once; show the page to 3-5 people
