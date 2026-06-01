# feed-sync — the only internet-facing job. Run as a one-shot:
#   docker compose run --rm feed-sync --seed
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY services/feed-sync/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/feed-sync/ ./
ENTRYPOINT ["python", "sync.py"]
