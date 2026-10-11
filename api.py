"""Web API and page server.

Run:  .venv\\Scripts\\python -m uvicorn api:app --port 8000
Then open http://localhost:8000

POST /api/check     {"text": "..."} -> risk level, warning signs, advice
GET  /api/examples  written practice examples (not real messages)
GET  /api/health    ready check for the cloud service
GET  /              the page in web/

Messages are analyzed in memory and never stored or logged.
"""
from contextlib import asynccontextmanager
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from scam_detector import classifier
from scam_detector.detector import analyze

ROOT = Path(__file__).resolve().parent
MAX_CHARS = 5000
EXAMPLE_IDS = ["he-d01", "he-d04", "he-d05", "he-d09", "he-d10", "en-d01"]

@asynccontextmanager
async def lifespan(app):
    # Load the model at startup, so the first visitor doesn't wait ~20 s for AlephBERT
    if classifier.MODEL_PATH.exists():
        classifier.warm_up()
    yield


app = FastAPI(title="Scam message checker", docs_url=None, redoc_url=None, lifespan=lifespan)


class CheckRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_CHARS)


@app.get("/api/health")
def health():
    """For the cloud service: answers only once the model is loaded (startup waits for it)."""
    return {"status": "ok", "model": classifier.MODEL_KIND}


@app.post("/api/check")
def check(req: CheckRequest):
    if not req.text.strip():
        raise HTTPException(422, "empty message")
    if not classifier.MODEL_PATH.exists():
        raise HTTPException(503, "model not trained")
    r = analyze(req.text)
    return {
        "risk_level": r["risk_level"],
        "risk_text": r["risk_text"],
        "language": r["language"],
        "red_flags": [{k: s[k] for k in ("id", "strength", "he", "en")} for s in r["red_flags"]],
        "reassuring": r["reassuring"],
        "what_to_do": r["what_to_do"],
        "found": {
            "links": [{"url": l["url"], "domain": l["domain"]} for l in r["extracted"]["links"]],
            "phones": [p["number"] for p in r["extracted"]["phones"]],
            "amounts": [a["text"] for a in r["extracted"]["amounts"]],
        },
        "model_score": r["model_score"],
    }


@app.get("/api/examples")
def examples():
    df = pd.read_csv(ROOT / "data" / "draft_examples.csv", encoding="utf-8-sig")
    df = df.set_index("id").loc[EXAMPLE_IDS]
    return [{"id": i, "text": t} for i, t in df.text.items()]


# Mounted last so /api/* routes take priority
app.mount("/", StaticFiles(directory=ROOT / "web", html=True), name="web")
