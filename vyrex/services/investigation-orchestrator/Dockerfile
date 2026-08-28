# Investigation orchestrator: durable, evidence-grounded LangGraph investigations.
# Build context is the repo root, consistent with the other services.
FROM python:3.12-slim
WORKDIR /app

COPY services/investigation-orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/investigation-orchestrator/orchestrator/ ./orchestrator/

# Runs as a non-root user like the other services; it only needs Postgres and Ollama.
RUN useradd --uid 10001 appuser
USER appuser

ENTRYPOINT ["python", "-m", "orchestrator.main"]