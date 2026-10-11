# Scam Detector

Paste or forward a suspicious message and get a risk level, the warning signs, and what to do.
Hebrew and English first.

Personal project: built on my own time and equipment.

## Phases
| # | Focus | Weeks | Status |
|---|-------|-------|--------|
| 1 | Learn scams, build the test set | 1–3 | Done |
| 2 | First working version | 4–7 | In progress |
| 3 | Measure and improve | 8–11 | |
| 4 | Cloud done properly | 12–15 | |
| 5 | Security and privacy | 16–19 | |
| 6 | Real users and analytics | 20–24 | |

## Layout
- `data/labeled_messages.csv`: the labeled test set that everything is measured against
- `data/raw/`: unprocessed examples (git-ignored, may contain personal details)
- `docs/scam_types.md`: scam type taxonomy and red flags
- `docs/labeling_guide.md`: how to label and anonymize messages
- `LOG.md`: weekly log

## Run it
```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python train\train.py          # trains models/baseline.joblib (needs the private data files)
.venv\Scripts\python -m uvicorn api:app --port 8000  # then open http://localhost:8000
.venv\Scripts\python -m pytest tests          # run the tests
```