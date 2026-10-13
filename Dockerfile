# AIops server (FastAPI dashboard + agentic troubleshooter).
FROM python:3.12-slim

# Network tools the diagnostics use (ping, ip route) inside the container.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINEL_IN_DOCKER=1 \
    SENTINEL_DB_PATH=/data/sentinel.db \
    SENTINEL_MODELS_DIR=/app/models

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY agent ./agent
COPY frontend ./frontend

RUN mkdir -p /data /app/models
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=4)"

# One worker on purpose: live session events and agent task wake-ups are in-process.
# uvloop + httptools (from uvicorn[standard]) make the async server faster.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--loop", "uvloop", "--http", "httptools", "--no-access-log"]
