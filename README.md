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
.venv\Scripts\python -m pip install -r requirements-dev.txt --extra-index-url https://download.pytorch.org/whl/cpu
.venv\Scripts\python train\train.py          # trains models/alephbert.joblib + baseline.joblib (needs the private data files; first run downloads AlephBERT, ~500 MB)
.venv\Scripts\python -m uvicorn api:app --port 8000  # then open http://localhost:8000
.venv\Scripts\python -m pytest tests          # run the tests
```
The app uses the AlephBERT model by default. To use the older word-count model instead, set `SCAM_MODEL=tfidf` before starting the server.
## Run it in Docker
Needs Docker Desktop and a trained `models/alephbert.joblib`.
```
docker build -t scam-detector .
docker run --rm -p 8080:8080 scam-detector     # then open http://localhost:8080
```
The image contains only the app, the page, the draft examples and the AlephBERT model
(see `.dockerignore`): never the private messages or the TF-IDF model.
## Cloud (Google Cloud Run, private)
Project `scam-detector-511311`, region `us-central1`, gcloud configuration `scam-detector`
(personal account; the default gcloud configuration is left alone).
```
powershell -File deploy\deploy.ps1      # build, push, roll out a new image
powershell -File infra\tf.ps1 plan      # cloud setup (Terraform): see differences
powershell -File infra\tf.ps1 apply     # cloud setup (Terraform): apply changes
```
To open the private service in a browser:
`gcloud run services proxy scam-detector --region=us-central1 --port=8090 --configuration=scam-detector`, then http://localhost:8090
The service needs a login (anonymous requests get 403). Max 1 instance, 0 when idle.
Monitoring: dashboard "Scam detector" in Google Cloud Monitoring; email alerts for failing
checks, rate-limit bursts and slowness. Logs hold one anonymous record per check (no text,
no addresses); Cloud Run's request log is excluded because it contains visitor addresses.