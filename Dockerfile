# Scam message checker: FastAPI + AlephBERT reader, CPU only.
#
# Build:  docker build -t scam-detector .
# Run:    docker run --rm -p 8080:8080 scam-detector     then open http://localhost:8080
#
# Needs models/alephbert.joblib in the folder (train it with train/train.py).
# The image never contains the private message data or the TF-IDF model (which holds
# words from private messages): see .dockerignore.

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/app/hf \
    SCAM_MODEL=alephbert \
    PORT=8080

WORKDIR /app

# 1. Libraries (cached as long as requirements.txt doesn't change)
COPY requirements.txt .
RUN pip install -r requirements.txt --extra-index-url https://download.pytorch.org/whl/cpu

# 2. AlephBERT itself, baked in at the pinned version, so the server never downloads it
COPY scam_detector/embedder.py /tmp/embedder.py
RUN python -c "import importlib.util as u; s=u.spec_from_file_location('e','/tmp/embedder.py'); \
e=u.module_from_spec(s); s.loader.exec_module(e); \
from huggingface_hub import snapshot_download; \
snapshot_download(e.HUB_ID, revision=e.REVISION, allow_patterns=['*.json','*.txt','*.bin'])" \
 && rm /tmp/embedder.py

# 3. The app
COPY api.py ./
COPY scam_detector/ scam_detector/
COPY web/ web/
COPY data/draft_examples.csv data/
COPY models/alephbert.joblib models/

# Run as a normal user, not root
RUN useradd --create-home app && chown -R app /app
USER app

# Offline at runtime: everything needed is already inside the image
ENV HF_HUB_OFFLINE=1

EXPOSE 8080
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT}"]
