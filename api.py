"""Web API and page server.

Run:  .venv\\Scripts\\python -m uvicorn api:app --port 8000 --no-access-log
Then open http://localhost:8000

POST /api/check     {"text": "..."} -> risk level, warning signs, advice, check_id
POST /api/feedback  {"check_id": "...", "verdict": "correct"|"wrong"} -> 👍/👎 on a recent check
GET  /api/examples  written practice examples (not real messages)
GET  /api/health    ready check for the cloud service
GET  /              the page in web/

Messages are analyzed in memory and never stored or logged. Each check writes one
anonymous event record (scam_detector/eventlog.py): result type only, no text, no address.
Run uvicorn with --no-access-log so it doesn't log visitor addresses either.
/api/check is rate limited per visitor and for the whole app (scam_detector/ratelimit.py;
limits from RATE_PER_MINUTE, RATE_PER_DAY, RATE_GLOBAL_PER_DAY).
"""
from contextlib import asynccontextmanager
from pathlib import Path

import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from scam_detector import classifier, eventlog, service
from scam_detector.feedback import VERDICTS
from scam_detector.ratelimit import RateLimited, client_address

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


@app.exception_handler(RateLimited)
def too_many(request, exc):
    eventlog.rate_limited(exc.scope)
    return JSONResponse(status_code=429, headers={"Retry-After": str(exc.retry_after)},
                        content={"detail": "rate limited", "scope": exc.scope,
                                 "retry_after": exc.retry_after})


class CheckRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_CHARS)


class FeedbackRequest(BaseModel):
    check_id: str = Field(min_length=1, max_length=64)
    verdict: str


@app.get("/api/health")
def health():
    """For the cloud service: answers only once the model is loaded (startup waits for it)."""
    return {"status": "ok", "model": classifier.MODEL_KIND}


@app.post("/api/check")
def check(req: CheckRequest, request: Request):
    if not req.text.strip():
        raise HTTPException(422, "empty message")
    if not classifier.MODEL_PATH.exists():
        raise HTTPException(503, "model not trained")
    peer = request.client.host if request.client else None
    r, check_id = service.run_check(req.text, client_address(request.headers, peer), "web")
    return {
        "check_id": check_id,
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


@app.post("/api/feedback")
def feedback(req: FeedbackRequest):
    if req.verdict not in VERDICTS:
        raise HTTPException(422, "verdict must be correct or wrong")
    if not service.give_feedback(req.check_id, req.verdict, "web"):
        raise HTTPException(409, "unknown, expired or already rated check")
    return {"status": "thanks"}


@app.get("/api/examples")
def examples():
    df = pd.read_csv(ROOT / "data" / "draft_examples.csv", encoding="utf-8-sig")
    df = df.set_index("id").loc[EXAMPLE_IDS]
    return [{"id": i, "text": t} for i, t in df.text.items()]


# Mounted last so /api/* routes take priority
app.mount("/", StaticFiles(directory=ROOT / "web", html=True), name="web")
