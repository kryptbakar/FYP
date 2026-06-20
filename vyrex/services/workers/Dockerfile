# telemetry workers. Build context is the REPO ROOT so we can bake in the shared
# telemetry schema (see docker-compose: context: ., dockerfile: ...).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY services/workers/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/workers/ ./
COPY schema/telemetry/v1/envelope.schema.json ./schema/envelope.schema.json

RUN useradd --uid 10001 appuser && chown -R appuser /app
USER appuser

CMD ["python", "worker.py"]
