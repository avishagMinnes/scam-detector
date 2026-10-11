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
- PHASE 2 BASELINE on locked test set (32 msgs: 9 scam, 23 legit), results/test_2026-10-11.json:
  combined: scams flagged 6/9 (95% range 35-88%), 3 as high; legit flagged 11/23 (48%), 4 as high
  model only: 3/9 scams, 7/23 legit; rules only: 4/9 scams, 7/23 legit
- Learned: false alarms far above cross-validation (13%). 7 of 11 come from the model: its cutoff was chosen on training data where most legit messages are easy English chat, so it is too low for Hebrew marketing. Rules: payment_via_link and install_from_link fire on real marketing. Not tuned on test messages
- Done (Phase 3 start): cutoffs now chosen on real training messages only (train.py CUTOFF_ORIGINS): 0.42/0.50 -> 0.45/0.61. Real training data (out-of-fold): scams flagged 19/22 either way; legit flagged 7/45 -> 5/45, legit as high 1 -> 0. Test set NOT re-run (keep it honest; re-run at end of Phase 3 with new test messages)
- Learned: the cutoff explains only part of the test gap (training legit 7/45 flagged even with old cutoffs vs test 11/23). Bigger cause is likely the model/data: too few Hebrew everyday legit messages
- Done: payment_via_link now needs a debt/fine/fee or a direct order to pay (not just the word payment); install_from_link stays strong only when an install/update is required, plain app invitations are a new medium sign app_download_link. Designed from the Directorate patterns, tests in my own wording (not test-set messages). Training: payment rule still 6 scams, legit 1 -> 0; mortgage-refund scam he-p094 loses the payment sign (correct: it offers money) but stays medium. 58 tests
- Done: 27 messages from own phone screenshots (26 legit everyday/marketing incl. bit, Maccabi, max, CARGO, HFD, Ontopo; 1 illegal-gambling scam). 22 train / 5 test (add_to_split now keeps new template groups together). Labels to confirm: he-w010, he-w011, en-w026/27
- Learned: more real Hebrew legit made the model more cautious: real training scams caught by model alone 68% -> 45%, combined 86% -> 77%; legit flagged ~10%. Real data now 22 scams vs 67 legit: the model now needs more real Hebrew SCAMS. Only high false alarm: CARGO 'update your address' (he-w010) - looks exactly like a delivery scam
- Done: user confirmed he-w010 (legit), he-w011 (scam), en-w026/27 (legit)
- Done: 37 scams quoted verbatim in published warnings (news, Cyber Directorate, consumer sites; sources in the file) -> data/web_examples.csv, TRAINING ONLY. No overlap >=0.5 with any real message. Covers the missing types (Hi Mom, code request, investment, prize, job), mostly English for Hi Mom/prize
- Result (real training msgs, out-of-fold): model alone 45% -> 59% of scams, AUC 0.81 -> 0.87; combined unchanged 77% scams / 10% legit flagged. Cutoffs 0.51/0.63
- Next: WhatsApp request sent to family/friends (drafted); add their scams as they arrive
